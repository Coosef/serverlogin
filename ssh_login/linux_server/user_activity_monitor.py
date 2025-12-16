#!/usr/bin/env python3
"""
Kapsamlı Kullanıcı Aktivite İzleme Sistemi - Linux
Tüm kullanıcı aktivitelerini izler: login, logout, komutlar, sudo, dosya erişimleri
"""

import os
import re
import json
import time
import socket
import subprocess
import logging
import threading
from datetime import datetime, timezone
from collections import defaultdict, deque
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' paketi bulunamadı. Lütfen 'pip install requests' çalıştırın.")
    exit(1)

# =========================
#  Yapılandırma
# =========================

ENV_PATH = "/opt/user_activity_monitor.env"
LOG_DIR = "/var/log/user_activity_monitor"
LOG_FILE = os.path.join(LOG_DIR, "activity_monitor.log")

# Logging yapılandırması
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Regex pattern'leri
RE_SSH_INVALID_USER = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)")
RE_SSH_FAILED_LOGIN = re.compile(r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)")
RE_SSH_SUCCESS_LOGIN = re.compile(r"Accepted .* for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)")
RE_SSH_LOGOUT = re.compile(r"Received disconnect from (\d+\.\d+\.\d+\.\d+)")
RE_SUDO = re.compile(r"(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)")
RE_SUDO_FAILED = re.compile(r"(\S+) : (\d+) incorrect password attempts")

# IP -> son hatalı denemelerin zamanları
fail_events = defaultdict(deque)

# İzlenen kullanıcılar ve son aktiviteleri
user_activities = defaultdict(list)


# =========================
#  Yardımcı Fonksiyonlar
# =========================

def load_env(path: str) -> dict:
    """Linux .env dosyasını okur"""
    env = {}
    if not os.path.exists(path):
        logging.warning(f"[WARN] Env dosyası bulunamadı: {path}")
        return env

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                env[key] = value
        logging.info(f"[INFO] Env dosyası yüklendi: {path}")
    except Exception as e:
        logging.error(f"[ERROR] Env dosyası okunurken hata: {e}")
    
    return env


def get_primary_ip() -> str:
    """Sunucunun ana IP adresini bulur"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ban_ip(ip: str, ssh_port: int = 22):
    """iptables ile IP'yi banlar"""
    try:
        # Mevcut kuralı kontrol et
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            # Kural yoksa ekle
            add_cmd = ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
            subprocess.run(add_cmd, check=False, timeout=5)
            logging.info(f"[BAN] {ip} banlandı (iptables)")
            return True
        else:
            logging.debug(f"[DEBUG] {ip} zaten banlı")
            return False
    except Exception as e:
        logging.error(f"[ERROR] IP banlama hatası ({ip}): {e}")
        return False


def send_to_webhook(webhook_url: str, payload: dict, max_retries: int = 3):
    """n8n webhook'a gönderir, retry mekanizması ile"""
    for attempt in range(max_retries):
        try:
            r = requests.post(webhook_url, json=payload, timeout=5)
            r.raise_for_status()
            logging.debug(f"[WEBHOOK] Başarılı: {payload.get('event_type')}")
            return True
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                logging.warning(f"[WEBHOOK] Deneme {attempt + 1}/{max_retries} başarısız, tekrar deneniyor...")
                time.sleep(2)
            else:
                logging.error(f"[WEBHOOK] {max_retries} deneme sonrası başarısız: {e}")
                # Yerel log'a yaz
                error_log = os.path.join(LOG_DIR, "webhook_errors.log")
                try:
                    with open(error_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "error": str(e),
                            "payload": payload
                        }) + "\n")
                except Exception:
                    pass
                return False
    return False


def track_fail_and_check_ban(ip: str, now_ts: float, time_window: int, max_attempts: int):
    """Başarısız denemeleri takip eder ve ban kontrolü yapar"""
    dq = fail_events[ip]
    dq.append(now_ts)
    
    cutoff = now_ts - time_window
    while dq and dq[0] < cutoff:
        dq.popleft()
    
    fail_count = len(dq)
    ban_triggered = fail_count >= max_attempts
    return fail_count, ban_triggered


def read_command_history(user: str):
    """Kullanıcının komut geçmişini okur"""
    history_files = [
        f"/home/{user}/.bash_history",
        f"/home/{user}/.zsh_history",
        f"/root/.bash_history",
        f"/root/.zsh_history"
    ]
    
    commands = []
    for hist_file in history_files:
        if os.path.exists(hist_file):
            try:
                # Son 10 komutu oku
                with open(hist_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    commands.extend(lines[-10:])
            except Exception as e:
                logging.debug(f"[DEBUG] History okuma hatası ({hist_file}): {e}")
    
    return commands[-10:] if commands else []


def get_active_users():
    """Aktif kullanıcıları listeler (who, w komutu)"""
    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        users = []
        for line in result.stdout.strip().split("\n"):
            if line:
                parts = line.split()
                if parts:
                    users.append({
                        "user": parts[0],
                        "tty": parts[1] if len(parts) > 1 else "",
                        "time": " ".join(parts[2:4]) if len(parts) > 3 else "",
                        "ip": parts[-1] if len(parts) > 4 else ""
                    })
        return users
    except Exception as e:
        logging.debug(f"[DEBUG] Aktif kullanıcı listesi hatası: {e}")
        return []


def monitor_auth_log():
    """auth.log veya journalctl'den eventleri izler"""
    auth_log = "/var/log/auth.log"
    if os.path.exists(auth_log):
        logging.info(f"[INFO] {auth_log} bulundu, tail -F ile izlenecek...")
        cmd = ["tail", "-F", auth_log]
    else:
        logging.info("[INFO] auth.log yok, journalctl ile izlenecek...")
        cmd = ["journalctl", "-f", "-n", "0", "-o", "cat"]
    
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    return proc


def monitor_command_history():
    """Kullanıcı komut geçmişlerini periyodik olarak kontrol eder"""
    last_checks = {}
    
    while True:
        try:
            active_users = get_active_users()
            for user_info in active_users:
                user = user_info["user"]
                hist_file = f"/home/{user}/.bash_history"
                if not os.path.exists(hist_file):
                    hist_file = f"/root/.bash_history" if user == "root" else None
                
                if hist_file and os.path.exists(hist_file):
                    mtime = os.path.getmtime(hist_file)
                    last_check = last_checks.get(user, 0)
                    
                    if mtime > last_check:
                        # Yeni komutlar var
                        commands = read_command_history(user)
                        if commands:
                            # Son komutları gönder
                            for cmd in commands[-5:]:  # Son 5 komut
                                payload = {
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "event_type": "command_executed",
                                    "user": user,
                                    "command": cmd.strip(),
                                    "source": "history"
                                }
                                # Webhook'a gönder (ana thread'den)
                                logging.info(f"[COMMAND] {user}: {cmd.strip()}")
                        
                        last_checks[user] = mtime
            
            time.sleep(30)  # 30 saniyede bir kontrol et
            
        except Exception as e:
            logging.error(f"[ERROR] Komut geçmişi izleme hatası: {e}")
            time.sleep(60)


def parse_auth_event(line: str):
    """auth.log satırını parse eder"""
    line = line.strip()
    
    # SSH Invalid User
    m = RE_SSH_INVALID_USER.search(line)
    if m:
        return {
            "event_type": "ssh_invalid_user",
            "user": m.group(1),
            "ip": m.group(2),
            "port": m.group(3),
            "raw": line
        }
    
    # SSH Failed Login
    m = RE_SSH_FAILED_LOGIN.search(line)
    if m:
        return {
            "event_type": "ssh_failed_login",
            "user": m.group(2),
            "ip": m.group(3),
            "port": m.group(4),
            "raw": line
        }
    
    # SSH Success Login
    m = RE_SSH_SUCCESS_LOGIN.search(line)
    if m:
        return {
            "event_type": "ssh_success_login",
            "user": m.group(1),
            "ip": m.group(2),
            "port": m.group(3),
            "raw": line
        }
    
    # SSH Logout
    m = RE_SSH_LOGOUT.search(line)
    if m:
        return {
            "event_type": "ssh_logout",
            "ip": m.group(1),
            "raw": line
        }
    
    # Sudo kullanımı
    m = RE_SUDO.search(line)
    if m:
        return {
            "event_type": "sudo_command",
            "user": m.group(1),
            "tty": m.group(2),
            "pwd": m.group(3),
            "target_user": m.group(4),
            "command": m.group(5),
            "raw": line
        }
    
    # Sudo başarısız
    m = RE_SUDO_FAILED.search(line)
    if m:
        return {
            "event_type": "sudo_failed",
            "user": m.group(1),
            "attempts": m.group(2),
            "raw": line
        }
    
    # Login (genel)
    if "session opened" in line.lower() or "logged in" in line.lower():
        return {
            "event_type": "session_opened",
            "raw": line
        }
    
    # Logout (genel)
    if "session closed" in line.lower() or "logged out" in line.lower():
        return {
            "event_type": "session_closed",
            "raw": line
        }
    
    return None


# =========================
#  Ana Fonksiyon
# =========================

def main():
    """Ana döngü"""
    logging.info("=" * 60)
    logging.info("Kullanıcı Aktivite İzleme Sistemi - Linux")
    logging.info("=" * 60)
    
    # .env dosyasını yükle
    env = load_env(ENV_PATH)
    
    # Gerekli ayarları kontrol et
    webhook_url = env.get("WEBHOOK_URL", "").strip()
    if not webhook_url:
        logging.error("[FATAL] WEBHOOK_URL .env dosyasında tanımlı değil!")
        logging.error(f"[FATAL] Lütfen {ENV_PATH} dosyasını düzenleyin.")
        return
    
    # Sunucu bilgileri
    hostname = socket.gethostname()
    primary_ip = get_primary_ip()
    server_name = env.get("SERVER_NAME", "").strip() or hostname
    server_ip = env.get("SERVER_IP", "").strip() or primary_ip
    server_env = env.get("SERVER_ENV", "Production")
    
    # Güvenlik ayarları
    max_attempts = int(env.get("MAX_ATTEMPTS", "5"))
    time_window_sec = int(env.get("TIME_WINDOW_SEC", "120"))
    ban_duration = int(env.get("BAN_DURATION", "3600"))
    alert_on_success = env.get("ALERT_ON_SUCCESS", "1") in ("1", "true", "True", "YES", "yes")
    
    # İzleme ayarları
    monitor_commands = env.get("MONITOR_COMMANDS", "1") in ("1", "true", "True", "YES", "yes")
    monitor_sudo = env.get("MONITOR_SUDO", "1") in ("1", "true", "True", "YES", "yes")
    monitor_logins = env.get("MONITOR_LOGINS", "1") in ("1", "true", "True", "YES", "yes")
    
    # Whitelist
    whitelist_ips = []
    whitelist_str = env.get("WHITELIST_IPS", "").strip()
    if whitelist_str:
        whitelist_ips = [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]
    
    logging.info(f"[INFO] Webhook URL: {webhook_url}")
    logging.info(f"[INFO] Sunucu: {server_name} ({server_ip}) | Ortam: {server_env}")
    logging.info(f"[INFO] Eşik: {max_attempts} deneme / {time_window_sec} saniye")
    logging.info(f"[INFO] İzleme: Komutlar={monitor_commands}, Sudo={monitor_sudo}, Login={monitor_logins}")
    
    # Komut geçmişi izleme thread'i başlat
    if monitor_commands:
        history_thread = threading.Thread(target=monitor_command_history, daemon=True)
        history_thread.start()
        logging.info("[INFO] Komut geçmişi izleme başlatıldı")
    
    # Auth log izleme
    proc = monitor_auth_log()
    
    try:
        for line in proc.stdout:
            if not line:
                continue
            line = line.strip()
            
            now = datetime.now(timezone.utc)
            now_ts = now.timestamp()
            
            # Event'i parse et
            event = parse_auth_event(line)
            if not event:
                continue
            
            event_type = event["event_type"]
            
            # Base payload
            base_payload = {
                "timestamp": now.isoformat(),
                "service": "user_activity",
                "server_name": server_name,
                "server_ip": server_ip,
                "server_env": server_env,
                "event_type": event_type,
                "raw_log": event.get("raw", line)
            }
            
            # SSH başarısız girişler
            if event_type in ("ssh_invalid_user", "ssh_failed_login"):
                if not monitor_logins:
                    continue
                
                ip = event.get("ip")
                user = event.get("user")
                
                if ip in whitelist_ips:
                    continue
                
                fail_count, ban_triggered = track_fail_and_check_ban(
                    ip, now_ts, time_window_sec, max_attempts
                )
                
                if ban_triggered:
                    ban_ip(ip)
                
                base_payload.update({
                    "user": user,
                    "ip": ip,
                    "port": event.get("port"),
                    "fail_count_window": fail_count,
                    "ban_triggered": ban_triggered
                })
                send_to_webhook(webhook_url, base_payload)
            
            # SSH başarılı giriş
            elif event_type == "ssh_success_login":
                if not monitor_logins:
                    continue
                
                ip = event.get("ip")
                user = event.get("user")
                
                if ip in fail_events:
                    fail_events[ip].clear()
                
                if alert_on_success:
                    base_payload.update({
                        "user": user,
                        "ip": ip,
                        "port": event.get("port")
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            # SSH logout
            elif event_type == "ssh_logout":
                if monitor_logins:
                    base_payload.update({
                        "ip": event.get("ip")
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            # Sudo komutları
            elif event_type == "sudo_command":
                if monitor_sudo:
                    base_payload.update({
                        "user": event.get("user"),
                        "target_user": event.get("target_user"),
                        "command": event.get("command"),
                        "tty": event.get("tty"),
                        "pwd": event.get("pwd")
                    })
                    send_to_webhook(webhook_url, base_payload)
                    logging.warning(f"[SUDO] {event.get('user')} -> {event.get('command')}")
            
            # Sudo başarısız
            elif event_type == "sudo_failed":
                if monitor_sudo:
                    base_payload.update({
                        "user": event.get("user"),
                        "attempts": event.get("attempts")
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            # Genel session açma/kapama
            elif event_type in ("session_opened", "session_closed"):
                if monitor_logins:
                    send_to_webhook(webhook_url, base_payload)
    
    except KeyboardInterrupt:
        logging.info("[INFO] Kullanıcı tarafından durduruldu.")
    except Exception as e:
        logging.error(f"[FATAL] Beklenmeyen hata: {e}", exc_info=True)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()

