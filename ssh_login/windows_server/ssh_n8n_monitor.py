#!/usr/bin/env python3
"""
SSH Login Monitor for Windows Server
Monitors Windows Event Log for SSH login attempts and sends webhooks to n8n
Automatically bans IPs after failed attempts using Windows Firewall
"""

import os
import re
import json
import time
import socket
import subprocess
import logging
from datetime import datetime, timezone
from collections import defaultdict, deque

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' paketi bulunamadı. Lütfen 'pip install requests' çalıştırın.")
    exit(1)

# =========================
#  Yapılandırma
# =========================

ENV_PATH = r"C:\ProgramData\ssh_n8n_monitor\ssh_n8n_monitor.env"
LOG_DIR = r"C:\ProgramData\ssh_n8n_monitor\logs"
LOG_FILE = os.path.join(LOG_DIR, "ssh_monitor.log")

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

# Regex pattern'leri - Windows Event Log formatına göre
RE_INVALID_USER = re.compile(
    r"Invalid user\s+(\S+).*?from\s+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)
RE_FAILED_LOGIN = re.compile(
    r"Failed\s+(?:password|authentication).*?user[:\s]+(\S+).*?from\s+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)
RE_SUCCESS_LOGIN = re.compile(
    r"Accepted\s+(?:password|publickey).*?user[:\s]+(\S+).*?from\s+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

# IP -> son hatalı denemelerin zamanları
fail_events = defaultdict(deque)


# =========================
#  Yardımcı Fonksiyonlar
# =========================

def load_env(path: str) -> dict:
    """Windows .env dosyasını okur"""
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
    """Windows'ta ana IP adresini bulur"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ban_ip_windows(ip: str, ssh_port: int = 22):
    """Windows Firewall ile IP'yi banlar"""
    try:
        rule_name = f"SSH_BAN_{ip.replace('.', '_')}"
        
        # Mevcut kuralı kontrol et
        check_cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name={rule_name}"
        ]
        result = subprocess.run(
            check_cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Kural yoksa ekle
        if "No rules match" in result.stdout or result.returncode != 0:
            add_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "protocol=tcp",
                f"localport={ssh_port}",
                "enable=yes"
            ]
            subprocess.run(add_cmd, check=False, capture_output=True, timeout=5)
            logging.info(f"[BAN] {ip} Windows Firewall ile banlandı (kural: {rule_name})")
            return True
        else:
            logging.info(f"[INFO] {ip} zaten banlı (kural: {rule_name})")
            return False
    except Exception as e:
        logging.error(f"[ERROR] IP banlama hatası ({ip}): {e}")
        return False


def unban_ip_windows(ip: str):
    """Windows Firewall'dan IP banını kaldırır"""
    try:
        rule_name = f"SSH_BAN_{ip.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"[UNBAN] {ip} banı kaldırıldı")
            return True
        else:
            logging.warning(f"[WARN] {ip} banı kaldırılamadı: {result.stderr}")
            return False
    except Exception as e:
        logging.error(f"[ERROR] IP ban kaldırma hatası ({ip}): {e}")
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
                log_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": str(e),
                    "payload": payload
                }
                error_log = os.path.join(LOG_DIR, "webhook_errors.log")
                try:
                    with open(error_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps(log_entry) + "\n")
                except Exception:
                    pass
                return False
    return False


def parse_ssh_event(message: str):
    """Windows Event Log mesajını parse eder"""
    message = message.strip()
    
    # Invalid user
    m = RE_INVALID_USER.search(message)
    if m:
        return {
            "event_type": "invalid_user",
            "user": m.group(1),
            "ip": m.group(2)
        }
    
    # Failed login
    m = RE_FAILED_LOGIN.search(message)
    if m:
        return {
            "event_type": "failed_login",
            "user": m.group(1),
            "ip": m.group(2)
        }
    
    # Success login
    m = RE_SUCCESS_LOGIN.search(message)
    if m:
        return {
            "event_type": "success_login",
            "user": m.group(1),
            "ip": m.group(2)
        }
    
    return None


def track_fail_and_check_ban(ip: str, now_ts: float, time_window: int, max_attempts: int):
    """Başarısız denemeleri takip eder ve ban kontrolü yapar"""
    dq = fail_events[ip]
    dq.append(now_ts)
    
    # Zaman penceresi dışındakileri temizle
    cutoff = now_ts - time_window
    while dq and dq[0] < cutoff:
        dq.popleft()
    
    fail_count = len(dq)
    ban_triggered = fail_count >= max_attempts
    return fail_count, ban_triggered


def read_ssh_events_powershell():
    """PowerShell ile Windows Event Log'dan SSH eventlerini okur"""
    ps_script = """
    Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $time = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $id = $_.Id
        $msg = $_.Message
        Write-Output "$time|$id|$msg"
    }
    """
    
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except Exception as e:
        logging.error(f"[ERROR] PowerShell event okuma hatası: {e}")
        return ""


def follow_ssh_events():
    """SSH eventlerini sürekli izler (PowerShell ile)"""
    last_event_time = datetime.now(timezone.utc)
    
    while True:
        try:
            # PowerShell ile son eventleri oku
            events = read_ssh_events_powershell()
            
            for line in events.strip().split("\n"):
                if not line or "|" not in line:
                    continue
                
                try:
                    parts = line.split("|", 2)
                    if len(parts) < 3:
                        continue
                    
                    event_time_str, event_id, message = parts
                    event_time = datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S")
                    event_time = event_time.replace(tzinfo=timezone.utc)
                    
                    # Sadece yeni eventleri işle
                    if event_time > last_event_time:
                        yield {
                            "time": event_time,
                            "id": event_id,
                            "message": message
                        }
                        last_event_time = event_time
                except Exception as e:
                    logging.debug(f"[DEBUG] Event parse hatası: {e}")
                    continue
            
            time.sleep(5)  # 5 saniyede bir kontrol et
            
        except Exception as e:
            logging.error(f"[ERROR] Event izleme hatası: {e}")
            time.sleep(10)


# =========================
#  Ana Fonksiyon
# =========================

def main():
    """Ana döngü"""
    logging.info("=" * 60)
    logging.info("SSH n8n Monitor - Windows Server")
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
    
    # Whitelist (opsiyonel)
    whitelist_ips = []
    whitelist_str = env.get("WHITELIST_IPS", "").strip()
    if whitelist_str:
        whitelist_ips = [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]
    
    logging.info(f"[INFO] Webhook URL: {webhook_url}")
    logging.info(f"[INFO] Sunucu: {server_name} ({server_ip}) | Ortam: {server_env}")
    logging.info(f"[INFO] Eşik: {max_attempts} deneme / {time_window_sec} saniye")
    logging.info(f"[INFO] Ban süresi: {ban_duration} saniye")
    logging.info(f"[INFO] Başarılı giriş bildirimi: {alert_on_success}")
    if whitelist_ips:
        logging.info(f"[INFO] Whitelist IP'ler: {', '.join(whitelist_ips)}")
    
    logging.info("[INFO] SSH event izleme başlatılıyor...")
    
    # Ana döngü
    try:
        for event in follow_ssh_events():
            message = event.get("message", "")
            event_time = event.get("time", datetime.now(timezone.utc))
            
            # Event'i parse et
            parsed = parse_ssh_event(message)
            if not parsed:
                continue
            
            event_type = parsed["event_type"]
            ip = parsed.get("ip")
            user = parsed.get("user")
            
            # Whitelist kontrolü
            if ip in whitelist_ips:
                logging.debug(f"[DEBUG] Whitelist IP atlandı: {ip}")
                continue
            
            # Base payload
            base_payload = {
                "timestamp": event_time.isoformat(),
                "service": "ssh",
                "server_name": server_name,
                "server_ip": server_ip,
                "server_env": server_env,
                "event_type": event_type,
                "ip": ip,
                "user": user,
                "raw_log": message,
                "time_window_sec": time_window_sec,
            }
            
            now_ts = event_time.timestamp()
            
            # Başarısız giriş veya invalid user
            if event_type in ("failed_login", "invalid_user"):
                fail_count, ban_triggered = track_fail_and_check_ban(
                    ip, now_ts, time_window_sec, max_attempts
                )
                
                if ban_triggered:
                    ban_ip_windows(ip)
                    base_payload["ban_triggered"] = True
                    logging.warning(f"[BAN] IP banlandı: {ip} ({fail_count} deneme)")
                else:
                    base_payload["ban_triggered"] = False
                
                base_payload["fail_count_window"] = fail_count
                send_to_webhook(webhook_url, base_payload)
            
            # Başarılı giriş
            elif event_type == "success_login":
                # Başarılı giriş olduğunda o IP için eski kayıtları temizle
                if ip in fail_events:
                    fail_events[ip].clear()
                    logging.info(f"[INFO] Başarılı giriş, {ip} için kayıtlar temizlendi")
                
                if alert_on_success:
                    base_payload["fail_count_window"] = 0
                    base_payload["ban_triggered"] = False
                    send_to_webhook(webhook_url, base_payload)
                    logging.info(f"[SUCCESS] Başarılı giriş: {user} @ {ip}")
    
    except KeyboardInterrupt:
        logging.info("[INFO] Kullanıcı tarafından durduruldu.")
    except Exception as e:
        logging.error(f"[FATAL] Beklenmeyen hata: {e}", exc_info=True)


if __name__ == "__main__":
    main()

