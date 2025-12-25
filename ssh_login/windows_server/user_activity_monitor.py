#!/usr/bin/env python3
"""
Kapsamlı Kullanıcı Aktivite İzleme Sistemi - Windows Server
Tüm kullanıcı aktivitelerini izler: login, logout, process, file access, registry
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

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' paketi bulunamadı. Lütfen 'pip install requests' çalıştırın.")
    exit(1)

# =========================
#  Yapılandırma
# =========================

ENV_PATH = r"C:\ProgramData\user_activity_monitor\user_activity_monitor.env"
LOG_DIR = r"C:\ProgramData\user_activity_monitor\logs"
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

# Windows Event ID'leri
EVENT_LOGON_SUCCESS = 4624
EVENT_LOGON_FAILED = 4625
EVENT_LOGOFF = 4634
EVENT_ACCOUNT_LOCKED = 4740
EVENT_PROCESS_CREATE = 4688
EVENT_FILE_ACCESS = 4663  # Object Access (File)
EVENT_REGISTRY_ACCESS = 4657  # Registry Access

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
        check_cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name={rule_name}"
        ]
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        
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
            logging.info(f"[BAN] {ip} Windows Firewall ile banlandı")
            return True
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
                logging.warning(f"[WEBHOOK] Deneme {attempt + 1}/{max_retries} başarısız...")
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


def read_windows_events(log_name: str, event_ids: list, max_events: int = 100):
    """PowerShell ile Windows Event Log'dan eventleri okur"""
    event_ids_str = ",".join(map(str, event_ids))
    # PowerShell script - $ karakterlerini escape etmek için backtick kullan
    ps_template = 'Get-WinEvent -LogName "{log_name}" -MaxEvents {max_events} -ErrorAction SilentlyContinue | Where-Object {{ `$_.Id -in @({event_ids_str}) }} | ForEach-Object {{ `$time = `$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"); `$id = `$_.Id; `$msg = `$_.Message; `$xml = `$_.ToXml(); Write-Output "`$time|`$id|`$xml|`$msg" }}'
    ps_script = ps_template.format(log_name=log_name, max_events=max_events, event_ids_str=event_ids_str)
    
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


def parse_event_xml(xml_str: str):
    """Event XML'den bilgileri çıkarır"""
    data = {}
    try:
        # Basit XML parsing (EventData içindeki Data elementleri)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_str)
        
        # EventData içindeki Data elementlerini bul
        for data_elem in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                data[name.lower()] = value
        
        # System içindeki bilgiler
        system = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
        if system is not None:
            event_id_elem = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
            if event_id_elem is not None:
                data["event_id"] = event_id_elem.text
        
    except Exception as e:
        logging.debug(f"[DEBUG] XML parse hatası: {e}")
    
    return data


def get_powershell_history(user: str = None):
    """PowerShell komut geçmişini okur"""
    history_paths = [
        r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt".format(user or os.getenv("USERNAME")),
        r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt".format(os.getenv("USERNAME"))
    ]
    
    commands = []
    for hist_path in history_paths:
        if os.path.exists(hist_path):
            try:
                with open(hist_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    commands.extend(lines[-10:])
            except Exception:
                pass
    
    return commands[-10:] if commands else []


def monitor_powershell_history():
    """PowerShell komut geçmişini periyodik olarak kontrol eder"""
    last_checks = {}
    
    while True:
        try:
            # Tüm kullanıcıların history dosyalarını kontrol et
            users_dir = r"C:\Users"
            if os.path.exists(users_dir):
                for user_dir in os.listdir(users_dir):
                    user_path = os.path.join(users_dir, user_dir)
                    if os.path.isdir(user_path):
                        hist_file = os.path.join(
                            user_path,
                            r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                        )
                        if os.path.exists(hist_file):
                            mtime = os.path.getmtime(hist_file)
                            last_check = last_checks.get(hist_file, 0)
                            
                            if mtime > last_check:
                                # Yeni komutlar var
                                try:
                                    with open(hist_file, "r", encoding="utf-8", errors="ignore") as f:
                                        lines = f.readlines()
                                        new_commands = lines[-5:]  # Son 5 komut
                                        
                                        for cmd in new_commands:
                                            logging.info(f"[POWERSHELL] {user_dir}: {cmd.strip()}")
                                except Exception:
                                    pass
                                
                                last_checks[hist_file] = mtime
            
            time.sleep(30)  # 30 saniyede bir kontrol et
            
        except Exception as e:
            logging.error(f"[ERROR] PowerShell history izleme hatası: {e}")
            time.sleep(60)


def follow_windows_events():
    """Windows Event Log'larını sürekli izler"""
    last_event_times = {
        "Security": datetime.now(timezone.utc),
        "OpenSSH/Operational": datetime.now(timezone.utc)
    }
    
    # İzlenecek event ID'leri
    security_events = [
        EVENT_LOGON_SUCCESS,
        EVENT_LOGON_FAILED,
        EVENT_LOGOFF,
        EVENT_PROCESS_CREATE,
        EVENT_FILE_ACCESS,
        EVENT_REGISTRY_ACCESS
    ]
    
    ssh_events = [4, 5, 6]  # OpenSSH event ID'leri
    
    while True:
        try:
            # Security Log
            events = read_windows_events("Security", security_events, 50)
            for line in events.strip().split("\n"):
                if not line or "|" not in line:
                    continue
                
                try:
                    parts = line.split("|", 3)
                    if len(parts) < 4:
                        continue
                    
                    event_time_str, event_id, xml_data, message = parts
                    event_time = datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S")
                    event_time = event_time.replace(tzinfo=timezone.utc)
                    
                    if event_time > last_event_times["Security"]:
                        event_data = parse_event_xml(xml_data)
                        event_data["event_id"] = event_id
                        event_data["time"] = event_time
                        event_data["message"] = message
                        event_data["log_name"] = "Security"
                        
                        yield event_data
                        last_event_times["Security"] = event_time
                except Exception as e:
                    logging.debug(f"[DEBUG] Event parse hatası: {e}")
                    continue
            
            # OpenSSH Log
            events = read_windows_events("OpenSSH/Operational", ssh_events, 50)
            for line in events.strip().split("\n"):
                if not line or "|" not in line:
                    continue
                
                try:
                    parts = line.split("|", 3)
                    if len(parts) < 4:
                        continue
                    
                    event_time_str, event_id, xml_data, message = parts
                    event_time = datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S")
                    event_time = event_time.replace(tzinfo=timezone.utc)
                    
                    if event_time > last_event_times["OpenSSH/Operational"]:
                        event_data = parse_event_xml(xml_data)
                        event_data["event_id"] = event_id
                        event_data["time"] = event_time
                        event_data["message"] = message
                        event_data["log_name"] = "OpenSSH/Operational"
                        
                        yield event_data
                        last_event_times["OpenSSH/Operational"] = event_time
                except Exception as e:
                    logging.debug(f"[DEBUG] SSH event parse hatası: {e}")
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
    logging.info("Kullanıcı Aktivite İzleme Sistemi - Windows Server")
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
    monitor_processes = env.get("MONITOR_PROCESSES", "1") in ("1", "true", "True", "YES", "yes")
    monitor_logins = env.get("MONITOR_LOGINS", "1") in ("1", "true", "True", "YES", "yes")
    monitor_file_access = env.get("MONITOR_FILE_ACCESS", "0") in ("1", "true", "True", "YES", "yes")
    
    # Whitelist
    whitelist_ips = []
    whitelist_str = env.get("WHITELIST_IPS", "").strip()
    if whitelist_str:
        whitelist_ips = [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]
    
    logging.info(f"[INFO] Webhook URL: {webhook_url}")
    logging.info(f"[INFO] Sunucu: {server_name} ({server_ip}) | Ortam: {server_env}")
    logging.info(f"[INFO] Eşik: {max_attempts} deneme / {time_window_sec} saniye")
    logging.info(f"[INFO] İzleme: Komutlar={monitor_commands}, Process={monitor_processes}, Login={monitor_logins}")
    
    # PowerShell history izleme thread'i başlat
    if monitor_commands:
        history_thread = threading.Thread(target=monitor_powershell_history, daemon=True)
        history_thread.start()
        logging.info("[INFO] PowerShell komut geçmişi izleme başlatıldı")
    
    # Event Log izleme
    logging.info("[INFO] Windows Event Log izleme başlatılıyor...")
    
    try:
        for event in follow_windows_events():
            event_id = int(event.get("event_id", 0))
            event_time = event.get("time", datetime.now(timezone.utc))
            message = event.get("message", "")
            
            # Base payload
            base_payload = {
                "timestamp": event_time.isoformat(),
                "service": "user_activity",
                "server_name": server_name,
                "server_ip": server_ip,
                "server_env": server_env,
                "event_id": event_id,
                "raw_log": message
            }
            
            now_ts = event_time.timestamp()
            
            # Logon Success (4624)
            if event_id == EVENT_LOGON_SUCCESS:
                if not monitor_logins:
                    continue
                
                username = event.get("targetusername", event.get("subjectusername", ""))
                ip = event.get("ipaddress", event.get("ip", ""))
                logon_type = event.get("logontype", "")
                
                if alert_on_success and ip and ip not in whitelist_ips:
                    base_payload.update({
                        "event_type": "logon_success",
                        "user": username,
                        "ip": ip,
                        "logon_type": logon_type
                    })
                    send_to_webhook(webhook_url, base_payload)
                    logging.info(f"[LOGON] {username} @ {ip}")
            
            # Logon Failed (4625)
            elif event_id == EVENT_LOGON_FAILED:
                if not monitor_logins:
                    continue
                
                username = event.get("targetusername", event.get("subjectusername", ""))
                ip = event.get("ipaddress", event.get("ip", ""))
                
                if ip and ip not in whitelist_ips:
                    fail_count, ban_triggered = track_fail_and_check_ban(
                        ip, now_ts, time_window_sec, max_attempts
                    )
                    
                    if ban_triggered:
                        ban_ip_windows(ip)
                    
                    base_payload.update({
                        "event_type": "logon_failed",
                        "user": username,
                        "ip": ip,
                        "fail_count_window": fail_count,
                        "ban_triggered": ban_triggered
                    })
                    send_to_webhook(webhook_url, base_payload)
                    logging.warning(f"[LOGON FAILED] {username} @ {ip}")
            
            # Logoff (4634)
            elif event_id == EVENT_LOGOFF:
                if monitor_logins:
                    username = event.get("targetusername", event.get("subjectusername", ""))
                    base_payload.update({
                        "event_type": "logoff",
                        "user": username
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            # Process Create (4688)
            elif event_id == EVENT_PROCESS_CREATE:
                if monitor_processes:
                    username = event.get("subjectusername", "")
                    process_name = event.get("processname", "")
                    command_line = event.get("commandline", "")
                    
                    # Sadece önemli process'leri bildir (opsiyonel filtreleme)
                    base_payload.update({
                        "event_type": "process_create",
                        "user": username,
                        "process_name": process_name,
                        "command_line": command_line
                    })
                    send_to_webhook(webhook_url, base_payload)
                    logging.info(f"[PROCESS] {username}: {process_name}")
            
            # File Access (4663)
            elif event_id == EVENT_FILE_ACCESS:
                if monitor_file_access:
                    username = event.get("subjectusername", "")
                    object_name = event.get("objectname", "")
                    
                    base_payload.update({
                        "event_type": "file_access",
                        "user": username,
                        "file_path": object_name
                    })
                    send_to_webhook(webhook_url, base_payload)
            
            # SSH Events (OpenSSH/Operational)
            elif event.get("log_name") == "OpenSSH/Operational":
                # SSH başarısız giriş
                if "failed" in message.lower() or "invalid" in message.lower():
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
                    user_match = re.search(r"user[:\s]+(\S+)", message, re.IGNORECASE)
                    
                    if ip_match and user_match:
                        ip = ip_match.group(1)
                        user = user_match.group(1)
                        
                        if ip not in whitelist_ips:
                            fail_count, ban_triggered = track_fail_and_check_ban(
                                ip, now_ts, time_window_sec, max_attempts
                            )
                            
                            if ban_triggered:
                                ban_ip_windows(ip)
                            
                            base_payload.update({
                                "event_type": "ssh_failed_login",
                                "user": user,
                                "ip": ip,
                                "fail_count_window": fail_count,
                                "ban_triggered": ban_triggered
                            })
                            send_to_webhook(webhook_url, base_payload)
                
                # SSH başarılı giriş
                elif "accepted" in message.lower():
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
                    user_match = re.search(r"user[:\s]+(\S+)", message, re.IGNORECASE)
                    
                    if ip_match and user_match and alert_on_success:
                        ip = ip_match.group(1)
                        user = user_match.group(1)
                        
                        if ip in fail_events:
                            fail_events[ip].clear()
                        
                        base_payload.update({
                            "event_type": "ssh_success_login",
                            "user": user,
                            "ip": ip
                        })
                        send_to_webhook(webhook_url, base_payload)
    
    except KeyboardInterrupt:
        logging.info("[INFO] Kullanıcı tarafından durduruldu.")
    except Exception as e:
        logging.error(f"[FATAL] Beklenmeyen hata: {e}", exc_info=True)


if __name__ == "__main__":
    main()

