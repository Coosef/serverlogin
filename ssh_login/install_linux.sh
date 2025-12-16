#!/bin/bash
# Kullanıcı Aktivite İzleme Sistemi - Linux
# Tek Komutla Otomatik Kurulum
# Kullanım: curl -sSL https://your-domain.com/install_linux.sh | sudo bash
# Veya: wget -qO- https://your-domain.com/install_linux.sh | sudo bash
# Veya: sudo bash install_linux.sh

set -e

echo "========================================"
echo "Kullanıcı Aktivite İzleme Sistemi"
echo "Linux - Otomatik Kurulum"
echo "========================================"
echo ""

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "[HATA] Bu script root olarak çalıştırılmalıdır (sudo ile)."
    exit 1
fi

# Yapılandırma
SCRIPT_PATH="/opt/user_activity_monitor.py"
ENV_PATH="/opt/user_activity_monitor.env"
SERVICE_PATH="/etc/systemd/system/user_activity_monitor.service"
LOG_DIR="/var/log/user_activity_monitor"

echo "[1/6] Python ve bağımlılıklar kuruluyor..."
apt-get update -y >/dev/null 2>&1
apt-get install -y python3 python3-pip >/dev/null 2>&1
pip3 install requests --quiet --break-system-packages 2>/dev/null || pip3 install requests --quiet

echo "[2/6] Klasörler oluşturuluyor..."
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

echo "[3/6] Python scripti oluşturuluyor..."
cat > "$SCRIPT_PATH" << 'PYTHON_SCRIPT'
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
# SFTP ve bağlantı türü pattern'leri
RE_SFTP_SUBSYSTEM = re.compile(r"subsystem request for (sftp)")
RE_SESSION_OPENED = re.compile(r"pam_unix\(sshd:session\): session opened for user (\S+)")
RE_SESSION_CLOSED = re.compile(r"pam_unix\(sshd:session\): session closed for user (\S+)")
RE_SSH_CONNECTION = re.compile(r"Connection from (\d+\.\d+\.\d+\.\d+) port (\d+)")

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
    """iptables ile IP'yi banlar (UFW desteği ile)"""
    try:
        # UFW kullanılıyor mu kontrol et
        ufw_check = subprocess.run(["which", "ufw"], capture_output=True, text=True, timeout=2)
        use_ufw = ufw_check.returncode == 0
        
        if use_ufw:
            # UFW kullanılıyorsa ufw-user-input chain'ine ekle
            chain = "ufw-user-input"
            check_cmd = ["iptables", "-C", chain, "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
            add_cmd = ["iptables", "-A", chain, "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
        else:
            # Normal iptables INPUT chain
            chain = "INPUT"
            check_cmd = ["iptables", "-C", chain, "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
            add_cmd = ["iptables", "-A", chain, "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
        
        # Mevcut kuralı kontrol et
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            # Kural yoksa ekle
            add_result = subprocess.run(add_cmd, capture_output=True, text=True, timeout=5)
            if add_result.returncode == 0:
                logging.info(f"[BAN] {ip} banlandı (iptables {chain})")
                # Ban durumunu doğrula
                verify_cmd = ["iptables", "-C", chain, "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
                verify_result = subprocess.run(verify_cmd, capture_output=True, timeout=5)
                if verify_result.returncode == 0:
                    logging.info(f"[BAN] {ip} ban durumu doğrulandı")
                    return True
                else:
                    logging.warning(f"[BAN] {ip} ban eklendi ama doğrulanamadı")
                    return True
            else:
                logging.error(f"[BAN] {ip} ban eklenirken hata: {add_result.stderr}")
                return False
        else:
            logging.debug(f"[BAN] {ip} zaten banlı")
            return True
    except subprocess.TimeoutExpired:
        logging.error(f"[ERROR] IP banlama timeout ({ip})")
        return False
    except Exception as e:
        logging.error(f"[ERROR] IP banlama hatası ({ip}): {e}", exc_info=True)
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
                        commands = read_command_history(user)
                        if commands:
                            for cmd in commands[-5:]:
                                logging.info(f"[COMMAND] {user}: {cmd.strip()}")
                        
                        last_checks[user] = mtime
            
            time.sleep(30)
            
        except Exception as e:
            logging.error(f"[ERROR] Komut geçmişi izleme hatası: {e}")
            time.sleep(60)


def parse_auth_event(line: str):
    """auth.log satırını parse eder"""
    line = line.strip()
    
    m = RE_SSH_INVALID_USER.search(line)
    if m:
        return {
            "event_type": "ssh_invalid_user",
            "user": m.group(1),
            "ip": m.group(2),
            "port": m.group(3),
            "raw": line
        }
    
    m = RE_SSH_FAILED_LOGIN.search(line)
    if m:
        return {
            "event_type": "ssh_failed_login",
            "user": m.group(2),
            "ip": m.group(3),
            "port": m.group(4),
            "raw": line
        }
    
    m = RE_SSH_SUCCESS_LOGIN.search(line)
    if m:
        return {
            "event_type": "ssh_success_login",
            "user": m.group(1),
            "ip": m.group(2),
            "port": m.group(3),
            "raw": line
        }
    
    m = RE_SSH_LOGOUT.search(line)
    if m:
        return {
            "event_type": "ssh_logout",
            "ip": m.group(1),
            "raw": line
        }
    
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
    
    m = RE_SUDO_FAILED.search(line)
    if m:
        return {
            "event_type": "sudo_failed",
            "user": m.group(1),
            "attempts": m.group(2),
            "raw": line
        }
    
    # SFTP subsystem tespiti
    m = RE_SFTP_SUBSYSTEM.search(line)
    if m:
        return {
            "event_type": "sftp_connection",
            "subsystem": m.group(1),
            "raw": line
        }
    
    # Session opened - SFTP veya normal SSH kontrolü
    m = RE_SESSION_OPENED.search(line)
    if m:
        user = m.group(1)
        # SFTP olup olmadığını kontrol et:
        # 1. Kullanıcı adında "sftp" var mı?
        # 2. Log satırında "sftp" veya "subsystem" var mı?
        # 3. SFTP kullanıcıları genelde "sftp" ile biten isimler kullanır
        is_sftp = (
            "sftp" in user.lower() or 
            "sftp" in line.lower() or 
            "subsystem" in line.lower() or
            user.endswith("sftp") or
            user.startswith("sftp")
        )
        return {
            "event_type": "sftp_session_opened" if is_sftp else "session_opened",
            "user": user,
            "connection_type": "SFTP" if is_sftp else "SSH",
            "raw": line
        }
    
    # Session closed
    m = RE_SESSION_CLOSED.search(line)
    if m:
        user = m.group(1)
        # SFTP kontrolü (kullanıcı adı veya log içeriği)
        is_sftp = (
            "sftp" in user.lower() or 
            "sftp" in line.lower() or 
            "subsystem" in line.lower() or
            user.endswith("sftp") or
            user.startswith("sftp")
        )
        return {
            "event_type": "sftp_session_closed" if is_sftp else "session_closed",
            "user": user,
            "connection_type": "SFTP" if is_sftp else "SSH",
            "raw": line
        }
    
    # Connection from (IP ve port bilgisi)
    m = RE_SSH_CONNECTION.search(line)
    if m:
        return {
            "event_type": "ssh_connection",
            "ip": m.group(1),
            "port": m.group(2),
            "raw": line
        }
    
    # Genel session kontrolleri (fallback)
    if "session opened" in line.lower() or "logged in" in line.lower():
        is_sftp = "sftp" in line.lower()
        return {
            "event_type": "sftp_session_opened" if is_sftp else "session_opened",
            "connection_type": "SFTP" if is_sftp else "SSH",
            "raw": line
        }
    
    if "session closed" in line.lower() or "logged out" in line.lower():
        is_sftp = "sftp" in line.lower()
        return {
            "event_type": "sftp_session_closed" if is_sftp else "session_closed",
            "connection_type": "SFTP" if is_sftp else "SSH",
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
    
    env = load_env(ENV_PATH)
    
    webhook_url = env.get("WEBHOOK_URL", "").strip()
    if not webhook_url:
        logging.error("[FATAL] WEBHOOK_URL .env dosyasında tanımlı değil!")
        logging.error(f"[FATAL] Lütfen {ENV_PATH} dosyasını düzenleyin.")
        return
    
    hostname = socket.gethostname()
    primary_ip = get_primary_ip()
    # SERVER_NAME boşsa hostname kullan, hostname de boşsa "unknown" kullan
    server_name = env.get("SERVER_NAME", "").strip() or hostname or "unknown-server"
    server_ip = env.get("SERVER_IP", "").strip() or primary_ip
    server_env = env.get("SERVER_ENV", "Production")
    
    max_attempts = int(env.get("MAX_ATTEMPTS", "5"))
    time_window_sec = int(env.get("TIME_WINDOW_SEC", "120"))
    ban_duration = int(env.get("BAN_DURATION", "3600"))
    alert_on_success = env.get("ALERT_ON_SUCCESS", "1") in ("1", "true", "True", "YES", "yes")
    
    monitor_commands = env.get("MONITOR_COMMANDS", "1") in ("1", "true", "True", "YES", "yes")
    monitor_sudo = env.get("MONITOR_SUDO", "1") in ("1", "true", "True", "YES", "yes")
    monitor_logins = env.get("MONITOR_LOGINS", "1") in ("1", "true", "True", "YES", "yes")
    
    whitelist_ips = []
    whitelist_str = env.get("WHITELIST_IPS", "").strip()
    if whitelist_str:
        whitelist_ips = [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]
    
    logging.info(f"[INFO] Webhook URL: {webhook_url}")
    logging.info(f"[INFO] Sunucu: {server_name} ({server_ip}) | Ortam: {server_env}")
    logging.info(f"[INFO] Eşik: {max_attempts} deneme / {time_window_sec} saniye")
    logging.info(f"[INFO] İzleme: Komutlar={monitor_commands}, Sudo={monitor_sudo}, Login={monitor_logins}")
    
    if monitor_commands:
        history_thread = threading.Thread(target=monitor_command_history, daemon=True)
        history_thread.start()
        logging.info("[INFO] Komut geçmişi izleme başlatıldı")
    
    proc = monitor_auth_log()
    
    # Son N satırı buffer'da tut (IP bilgisini eşleştirmek için)
    log_buffer = deque(maxlen=20)  # Son 20 satırı tut (SFTP için daha fazla)
    
    # Kullanıcı -> IP mapping (son bağlantılar için)
    user_ip_map = {}  # {user: {"ip": ip, "port": port, "time": timestamp}}
    
    try:
        for line in proc.stdout:
            if not line:
                continue
            line = line.strip()
            
            # Buffer'a ekle
            log_buffer.append(line)
            
            now = datetime.now(timezone.utc)
            now_ts = now.timestamp()
            
            event = parse_auth_event(line)
            if not event:
                continue
            
            event_type = event["event_type"]
            
            # SSH başarılı girişlerde kullanıcı-IP mapping'i kaydet
            if event_type == "ssh_success_login":
                user = event.get("user")
                ip = event.get("ip")
                port = event.get("port")
                if user and ip:
                    user_ip_map[user] = {
                        "ip": ip,
                        "port": port,
                        "time": now_ts
                    }
                    # Eski kayıtları temizle (1 saatten eski)
                    cutoff = now_ts - 3600
                    user_ip_map = {k: v for k, v in user_ip_map.items() if v["time"] > cutoff}
            
            # Session event'lerinde IP bilgisini buffer'dan veya mapping'den bul
            if event_type in ("session_opened", "session_closed", "sftp_session_opened", "sftp_session_closed"):
                # Eğer event'te zaten IP yoksa ara
                if not event.get("ip"):
                    ip = None
                    port = None
                    user = event.get("user")
                    
                    # Önce kullanıcı mapping'inden kontrol et
                    if user and user in user_ip_map:
                        mapping = user_ip_map[user]
                        # Mapping 5 dakikadan yeni ise kullan
                        if (now_ts - mapping["time"]) < 300:
                            ip = mapping["ip"]
                            port = mapping["port"]
                    
                    # Mapping'de yoksa buffer'da ara
                    if not ip:
                        # Buffer'ı ters sırada kontrol et (en yeni satırlardan başla)
                        for buffered_line in reversed(list(log_buffer)):
                            # Connection from IP port X pattern'i
                            conn_match = re.search(r"Connection from (\d+\.\d+\.\d+\.\d+) port (\d+)", buffered_line)
                            if conn_match:
                                ip = conn_match.group(1)
                                port = conn_match.group(2)
                                break
                            # Alternatif: Accepted ... from IP port X
                            accepted_match = re.search(r"Accepted .* from (\d+\.\d+\.\d+\.\d+) port (\d+)", buffered_line)
                            if accepted_match:
                                ip = accepted_match.group(1)
                                port = accepted_match.group(2)
                                break
                            # Alternatif: Herhangi bir satırda IP port pattern'i
                            any_ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+) port (\d+)", buffered_line)
                            if any_ip_match:
                                ip = any_ip_match.group(1)
                                port = any_ip_match.group(2)
                                break
                    
                    # Bulunan IP/Port bilgisini event'e ekle
                    if ip:
                        event["ip"] = ip
                    if port:
                        event["port"] = port
            
            base_payload = {
                "timestamp": now.isoformat(),
                "service": "user_activity",
                "server_name": server_name,
                "server_ip": server_ip,
                "server_env": server_env,
                "event_type": event_type,
                "raw_log": event.get("raw", line)
            }
            
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
            
            elif event_type == "ssh_logout":
                if monitor_logins:
                    base_payload.update({
                        "ip": event.get("ip")
                    })
                    send_to_webhook(webhook_url, base_payload)
            
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
            
            elif event_type == "sudo_failed":
                if monitor_sudo:
                    base_payload.update({
                        "user": event.get("user"),
                        "attempts": event.get("attempts")
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            elif event_type in ("session_opened", "session_closed", "sftp_session_opened", "sftp_session_closed", "sftp_connection"):
                if monitor_logins:
                    # SFTP bağlantı bilgilerini ekle
                    if "sftp" in event_type or event.get("connection_type") == "SFTP":
                        base_payload.update({
                            "connection_type": "SFTP",
                            "user": event.get("user", ""),
                            "subsystem": event.get("subsystem", "sftp")
                        })
                    else:
                        base_payload.update({
                            "connection_type": event.get("connection_type", "SSH"),
                            "user": event.get("user", "")
                        })
                    
                    # IP ve port bilgisi varsa ekle
                    if event.get("ip"):
                        base_payload["ip"] = event.get("ip")
                    if event.get("port"):
                        base_payload["port"] = event.get("port")
                    
                    send_to_webhook(webhook_url, base_payload)
            
            # SSH connection (IP/Port bilgisi)
            elif event_type == "ssh_connection":
                if monitor_logins:
                    base_payload.update({
                        "ip": event.get("ip"),
                        "port": event.get("port"),
                        "connection_type": "SSH"
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            # SSH connection (IP/Port bilgisi)
            elif event_type == "ssh_connection":
                if monitor_logins:
                    base_payload.update({
                        "ip": event.get("ip"),
                        "port": event.get("port"),
                        "connection_type": "SSH"
                    })
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
PYTHON_SCRIPT

chmod 700 "$SCRIPT_PATH"
echo "       Script oluşturuldu: $SCRIPT_PATH"

echo "[4/6] .env dosyası oluşturuluyor..."
if [ -f "$ENV_PATH" ]; then
    echo "       .env dosyası zaten var, üzerine yazılmadı."
else
    cat > "$ENV_PATH" << 'ENV_FILE'
# Kullanıcı Aktivite İzleme Sistemi - Yapılandırma Dosyası (Linux)
# Değişiklik yaptıktan sonra: sudo systemctl restart user_activity_monitor.service

# ============================================
#  ZORUNLU AYARLAR
# ============================================

# n8n webhook URL (zorunlu) - BURAYI DÜZENLEYİN!
WEBHOOK_URL="https://n8vp.yeb.one/webhook/useractivity"

# ============================================
#  GÜVENLİK AYARLARI
# ============================================

# Kaç başarısız denemeden sonra IP banlansın?
MAX_ATTEMPTS=5

# Kaç saniyelik zaman penceresi içinde sayılacak? (örn: 120 = 2 dakika)
TIME_WINDOW_SEC=120

# Ban süresi (saniye) - şimdilik sadece bilgi amaçlı
BAN_DURATION=3600

# Banlanmayacak IP'ler (virgülle ayrılmış)
# Örnek: WHITELIST_IPS="1.2.3.4,5.6.7.8"
WHITELIST_IPS=""

# ============================================
#  SUNUCU BİLGİLERİ
# ============================================

# Sunucu adı (boş bırakırsan hostname kullanılır)
SERVER_NAME=""

# Sunucu IP (boş bırakırsan otomatik tespit edilir)
SERVER_IP=""

# Ortam bilgisi (Production, Staging, Development vb.)
SERVER_ENV="Production"

# ============================================
#  İZLEME AYARLARI
# ============================================

# Başarılı girişler için de bildirim gönderilsin mi? (1 = evet, 0 = hayır)
ALERT_ON_SUCCESS=1

# Komut geçmişini izle? (1 = evet, 0 = hayır)
MONITOR_COMMANDS=1

# Sudo komutlarını izle? (1 = evet, 0 = hayır)
MONITOR_SUDO=1

# Login/logout olaylarını izle? (1 = evet, 0 = hayır)
MONITOR_LOGINS=1

# Dosya erişimlerini izle? (1 = evet, 0 = hayır) - auditd gerekir
MONITOR_FILE_ACCESS=0
ENV_FILE

    chmod 600 "$ENV_PATH"
    echo "       .env dosyası oluşturuldu: $ENV_PATH"
    echo ""
    echo "       ⚠️  ÖNEMLİ: WEBHOOK_URL'i düzenlemeniz gerekiyor!"
    echo "       Dosya: $ENV_PATH"
    echo ""
fi

echo "[5/6] systemd servisini oluşturuyoruz..."
cat > "$SERVICE_PATH" << 'SERVICE_FILE'
[Unit]
Description=User Activity Monitor (n8n webhook + ban engine)
After=network.target ssh.service
ConditionPathExists=/opt/user_activity_monitor.py

[Service]
Type=simple
User=root
WorkingDirectory=/opt
EnvironmentFile=/opt/user_activity_monitor.env
ExecStart=/usr/bin/python3 /opt/user_activity_monitor.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_FILE

echo "[6/6] Servisi başlatıyoruz..."
systemctl daemon-reload
systemctl enable user_activity_monitor.service >/dev/null 2>&1
systemctl restart user_activity_monitor.service

echo ""
echo "========================================"
echo "✓ Kurulum tamamlandı!"
echo "========================================"
echo ""
echo "Servis Bilgileri:"
echo "  Adı: user_activity_monitor.service"
echo "  Durum: $(systemctl is-active user_activity_monitor.service)"
echo "  Script: $SCRIPT_PATH"
echo "  Config: $ENV_PATH"
echo "  Loglar: $LOG_DIR"
echo ""
echo "Yararlı Komutlar:"
echo "  Servis durumu:     sudo systemctl status user_activity_monitor"
echo "  Servis durdur:     sudo systemctl stop user_activity_monitor"
echo "  Servis başlat:     sudo systemctl start user_activity_monitor"
echo "  Servis yeniden:    sudo systemctl restart user_activity_monitor"
echo "  Logları görüntüle:  sudo tail -f $LOG_DIR/activity_monitor.log"
echo ""
echo "⚠️  ÖNEMLİ: .env dosyasında WEBHOOK_URL'i düzenleyin!"
echo "   Dosya: $ENV_PATH"
echo "   Düzenleme sonrası: sudo systemctl restart user_activity_monitor"
echo ""
echo "📝 Örnek:"
echo "   sudo nano $ENV_PATH"
echo "   # WEBHOOK_URL=\"https://your-n8n-url.com/webhook/...\" satırını düzenleyin"
echo "   sudo systemctl restart user_activity_monitor"
echo ""

