# Kullanıcı Aktivite İzleme Sistemi - Windows Server
# Tek Komutla Otomatik Kurulum
# Kullanım: PowerShell'i Yönetici olarak açın ve çalıştırın:
#   .\install_windows.ps1
# Veya: Invoke-WebRequest -Uri "https://your-domain.com/install_windows.ps1" -OutFile install.ps1; .\install.ps1

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Kullanıcı Aktivite İzleme Sistemi" -ForegroundColor Cyan
Write-Host "Windows - Otomatik Kurulum" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Yönetici kontrolü
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[HATA] Bu script YÖNETİCİ olarak çalıştırılmalıdır!" -ForegroundColor Red
    Write-Host "PowerShell'i 'Yönetici olarak çalıştır' ile açın." -ForegroundColor Yellow
    exit 1
}

# Yapılandırma
$InstallDir = "C:\ProgramData\user_activity_monitor"
$ScriptPath = "$InstallDir\user_activity_monitor.py"
$EnvPath = "$InstallDir\user_activity_monitor.env"
$ServiceName = "UserActivityMonitor"
$NSSMPath = "$InstallDir\nssm.exe"
$LogDir = "$InstallDir\logs"

Write-Host "[1/8] Python kontrol ediliyor..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python bulunamadı"
    }
    Write-Host "       Python bulundu: $pythonVersion" -ForegroundColor Green
    $pythonPath = (Get-Command python).Source
    Write-Host "       Python yolu: $pythonPath" -ForegroundColor Gray
} catch {
    Write-Host "[HATA] Python bulunamadı!" -ForegroundColor Red
    Write-Host "       Lütfen Python 3.x kurun: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "       Kurulum sırasında 'Add Python to PATH' seçeneğini işaretleyin." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[2/8] Python paketleri kontrol ediliyor..." -ForegroundColor Yellow
try {
    $null = python -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "       ✓ requests yüklü" -ForegroundColor Green
    } else {
        Write-Host "       requests kuruluyor..." -ForegroundColor Yellow
        python -m pip install requests --quiet
        Write-Host "       ✓ requests kuruldu" -ForegroundColor Green
    }
} catch {
    Write-Host "[HATA] Paket kurulumu başarısız!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[3/8] Kurulum klasörü oluşturuluyor..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "       Klasör oluşturuldu: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "       Klasör zaten var: $InstallDir" -ForegroundColor Gray
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Host ""
Write-Host "[4/8] Python scripti oluşturuluyor..." -ForegroundColor Yellow

# Python script içeriği (here-string ile)
$pythonScript = @'
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

ENV_PATH = r"C:\ProgramData\user_activity_monitor\user_activity_monitor.env"
LOG_DIR = r"C:\ProgramData\user_activity_monitor\logs"
LOG_FILE = os.path.join(LOG_DIR, "activity_monitor.log")

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

EVENT_LOGON_SUCCESS = 4624
EVENT_LOGON_FAILED = 4625
EVENT_LOGOFF = 4634
EVENT_PROCESS_CREATE = 4688
EVENT_FILE_ACCESS = 4663

fail_events = defaultdict(deque)

def load_env(path: str) -> dict:
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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def ban_ip_windows(ip: str, ssh_port: int = 22):
    try:
        rule_name = f"SSH_BAN_{ip.replace('.', '_')}"
        check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        if "No rules match" in result.stdout or result.returncode != 0:
            add_cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}", "protocol=tcp", f"localport={ssh_port}", "enable=yes"]
            subprocess.run(add_cmd, check=False, capture_output=True, timeout=5)
            logging.info(f"[BAN] {ip} Windows Firewall ile banlandı")
            return True
        return False
    except Exception as e:
        logging.error(f"[ERROR] IP banlama hatası ({ip}): {e}")
        return False

def send_to_webhook(webhook_url: str, payload: dict, max_retries: int = 3):
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
                        f.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "error": str(e), "payload": payload}) + "\n")
                except Exception:
                    pass
                return False
    return False

def track_fail_and_check_ban(ip: str, now_ts: float, time_window: int, max_attempts: int):
    dq = fail_events[ip]
    dq.append(now_ts)
    cutoff = now_ts - time_window
    while dq and dq[0] < cutoff:
        dq.popleft()
    fail_count = len(dq)
    ban_triggered = fail_count >= max_attempts
    return fail_count, ban_triggered

def read_windows_events(log_name: str, event_ids: list, max_events: int = 100):
    event_ids_str = ",".join(map(str, event_ids))
    # PowerShell script'inde $ karakterlerini escape et
    ps_script = f"Get-WinEvent -LogName `"{log_name}`" -MaxEvents {max_events} -ErrorAction SilentlyContinue | Where-Object {{ `$_.Id -in @({event_ids_str}) }} | ForEach-Object {{ `$time = `$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); `$id = `$_.Id; `$msg = `$_.Message; `$xml = `$_.ToXml(); Write-Output \"`$time|`$id|`$xml|`$msg\" }}"
    try:
        result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True, timeout=10)
        return result.stdout
    except Exception as e:
        logging.error(f"[ERROR] PowerShell event okuma hatası: {e}")
        return ""

def parse_event_xml(xml_str: str):
    data = {}
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_str)
        for data_elem in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                data[name.lower()] = value
        system = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
        if system is not None:
            event_id_elem = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
            if event_id_elem is not None:
                data["event_id"] = event_id_elem.text
    except Exception as e:
        logging.debug(f"[DEBUG] XML parse hatası: {e}")
    return data

def follow_windows_events():
    last_event_times = {"Security": datetime.now(timezone.utc), "OpenSSH/Operational": datetime.now(timezone.utc)}
    security_events = [EVENT_LOGON_SUCCESS, EVENT_LOGON_FAILED, EVENT_LOGOFF, EVENT_PROCESS_CREATE, EVENT_FILE_ACCESS]
    ssh_events = [4, 5, 6]
    while True:
        try:
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
            time.sleep(5)
        except Exception as e:
            logging.error(f"[ERROR] Event izleme hatası: {e}")
            time.sleep(10)

def main():
    logging.info("=" * 60)
    logging.info("Kullanıcı Aktivite İzleme Sistemi - Windows Server")
    logging.info("=" * 60)
    env = load_env(ENV_PATH)
    webhook_url = env.get("WEBHOOK_URL", "").strip()
    if not webhook_url:
        logging.error("[FATAL] WEBHOOK_URL .env dosyasında tanımlı değil!")
        logging.error(f"[FATAL] Lütfen {ENV_PATH} dosyasını düzenleyin.")
        return
    hostname = socket.gethostname()
    primary_ip = get_primary_ip()
    server_name = env.get("SERVER_NAME", "").strip() or hostname
    server_ip = env.get("SERVER_IP", "").strip() or primary_ip
    server_env = env.get("SERVER_ENV", "Production")
    max_attempts = int(env.get("MAX_ATTEMPTS", "5"))
    time_window_sec = int(env.get("TIME_WINDOW_SEC", "120"))
    ban_duration = int(env.get("BAN_DURATION", "3600"))
    alert_on_success = env.get("ALERT_ON_SUCCESS", "1") in ("1", "true", "True", "YES", "yes")
    monitor_commands = env.get("MONITOR_COMMANDS", "1") in ("1", "true", "True", "YES", "yes")
    monitor_processes = env.get("MONITOR_PROCESSES", "1") in ("1", "true", "True", "YES", "yes")
    monitor_logins = env.get("MONITOR_LOGINS", "1") in ("1", "true", "True", "YES", "yes")
    monitor_file_access = env.get("MONITOR_FILE_ACCESS", "0") in ("1", "true", "True", "YES", "yes")
    whitelist_ips = []
    whitelist_str = env.get("WHITELIST_IPS", "").strip()
    if whitelist_str:
        whitelist_ips = [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]
    logging.info(f"[INFO] Webhook URL: {webhook_url}")
    logging.info(f"[INFO] Sunucu: {server_name} ({server_ip}) | Ortam: {server_env}")
    logging.info(f"[INFO] Eşik: {max_attempts} deneme / {time_window_sec} saniye")
    logging.info(f"[INFO] İzleme: Komutlar={monitor_commands}, Process={monitor_processes}, Login={monitor_logins}")
    logging.info("[INFO] Windows Event Log izleme başlatılıyor...")
    try:
        for event in follow_windows_events():
            event_id = int(event.get("event_id", 0))
            event_time = event.get("time", datetime.now(timezone.utc))
            message = event.get("message", "")
            base_payload = {"timestamp": event_time.isoformat(), "service": "user_activity", "server_name": server_name, "server_ip": server_ip, "server_env": server_env, "event_id": event_id, "raw_log": message}
            now_ts = event_time.timestamp()
            if event_id == EVENT_LOGON_SUCCESS:
                if not monitor_logins:
                    continue
                username = event.get("targetusername", event.get("subjectusername", ""))
                ip = event.get("ipaddress", event.get("ip", ""))
                logon_type = event.get("logontype", "")
                if alert_on_success and ip and ip not in whitelist_ips:
                    base_payload.update({"event_type": "logon_success", "user": username, "ip": ip, "logon_type": logon_type})
                    send_to_webhook(webhook_url, base_payload)
                    logging.info(f"[LOGON] {username} @ {ip}")
            elif event_id == EVENT_LOGON_FAILED:
                if not monitor_logins:
                    continue
                username = event.get("targetusername", event.get("subjectusername", ""))
                ip = event.get("ipaddress", event.get("ip", ""))
                if ip and ip not in whitelist_ips:
                    fail_count, ban_triggered = track_fail_and_check_ban(ip, now_ts, time_window_sec, max_attempts)
                    if ban_triggered:
                        ban_ip_windows(ip)
                    base_payload.update({"event_type": "logon_failed", "user": username, "ip": ip, "fail_count_window": fail_count, "ban_triggered": ban_triggered})
                    send_to_webhook(webhook_url, base_payload)
                    logging.warning(f"[LOGON FAILED] {username} @ {ip}")
            elif event_id == EVENT_LOGOFF:
                if monitor_logins:
                    username = event.get("targetusername", event.get("subjectusername", ""))
                    base_payload.update({"event_type": "logoff", "user": username})
                    send_to_webhook(webhook_url, base_payload)
            elif event_id == EVENT_PROCESS_CREATE:
                if monitor_processes:
                    username = event.get("subjectusername", "")
                    process_name = event.get("processname", "")
                    command_line = event.get("commandline", "")
                    base_payload.update({"event_type": "process_create", "user": username, "process_name": process_name, "command_line": command_line})
                    send_to_webhook(webhook_url, base_payload)
                    logging.info(f"[PROCESS] {username}: {process_name}")
            elif event_id == EVENT_FILE_ACCESS:
                if monitor_file_access:
                    username = event.get("subjectusername", "")
                    object_name = event.get("objectname", "")
                    base_payload.update({"event_type": "file_access", "user": username, "file_path": object_name})
                    send_to_webhook(webhook_url, base_payload)
            elif event.get("log_name") == "OpenSSH/Operational":
                if "failed" in message.lower() or "invalid" in message.lower():
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
                    user_match = re.search(r"user[:\s]+(\S+)", message, re.IGNORECASE)
                    if ip_match and user_match:
                        ip = ip_match.group(1)
                        user = user_match.group(1)
                        if ip not in whitelist_ips:
                            fail_count, ban_triggered = track_fail_and_check_ban(ip, now_ts, time_window_sec, max_attempts)
                            if ban_triggered:
                                ban_ip_windows(ip)
                            base_payload.update({"event_type": "ssh_failed_login", "user": user, "ip": ip, "fail_count_window": fail_count, "ban_triggered": ban_triggered})
                            send_to_webhook(webhook_url, base_payload)
                elif "accepted" in message.lower():
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
                    user_match = re.search(r"user[:\s]+(\S+)", message, re.IGNORECASE)
                    if ip_match and user_match and alert_on_success:
                        ip = ip_match.group(1)
                        user = user_match.group(1)
                        if ip in fail_events:
                            fail_events[ip].clear()
                        base_payload.update({"event_type": "ssh_success_login", "user": user, "ip": ip})
                        send_to_webhook(webhook_url, base_payload)
    except KeyboardInterrupt:
        logging.info("[INFO] Kullanıcı tarafından durduruldu.")
    except Exception as e:
        logging.error(f"[FATAL] Beklenmeyen hata: {e}", exc_info=True)

if __name__ == "__main__":
    main()
"@

$pythonScript | Out-File -FilePath $ScriptPath -Encoding UTF8
Write-Host "       Script oluşturuldu: $ScriptPath" -ForegroundColor Green

Write-Host ""
Write-Host "[5/8] .env dosyası oluşturuluyor..." -ForegroundColor Yellow
if (-not (Test-Path $EnvPath)) {
    $envContent = @"
# Kullanıcı Aktivite İzleme Sistemi - Yapılandırma Dosyası (Windows)
# Değişiklik yaptıktan sonra: Restart-Service UserActivityMonitor

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

# PowerShell komut geçmişini izle? (1 = evet, 0 = hayır)
MONITOR_COMMANDS=1

# Process oluşturma olaylarını izle? (1 = evet, 0 = hayır)
MONITOR_PROCESSES=1

# Login/logout olaylarını izle? (1 = evet, 0 = hayır)
MONITOR_LOGINS=1

# Dosya erişimlerini izle? (1 = evet, 0 = hayır) - File System Audit gerekir
MONITOR_FILE_ACCESS=0
"@
    $envContent | Out-File -FilePath $EnvPath -Encoding UTF8
    Write-Host "       .env dosyası oluşturuldu: $EnvPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "       ⚠️  ÖNEMLİ: WEBHOOK_URL'i düzenlemeniz gerekiyor!" -ForegroundColor Yellow
    Write-Host "       Dosya: $EnvPath" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "       .env dosyası zaten var, üzerine yazılmadı." -ForegroundColor Gray
}

Write-Host ""
Write-Host "[6/8] NSSM kontrol ediliyor..." -ForegroundColor Yellow
if (-not (Test-Path $NSSMPath)) {
    Write-Host "       NSSM bulunamadı." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       NSSM'i otomatik indirmeyi deniyoruz..." -ForegroundColor Cyan
    
    # NSSM'i otomatik indirmeyi dene
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$InstallDir\nssm.zip"
    $nssmExtract = "$InstallDir\nssm_extract"
    
    try {
        Write-Host "       NSSM indiriliyor..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        $nssmExe = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" | Select-Object -First 1
        if ($nssmExe) {
            Copy-Item $nssmExe.FullName -Destination $NSSMPath -Force
            Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
            Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "       ✓ NSSM otomatik indirildi ve kuruldu" -ForegroundColor Green
        } else {
            throw "nssm.exe bulunamadı"
        }
    } catch {
        Write-Host "       ⚠️  Otomatik indirme başarısız, manuel kurulum gerekli" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "       Manuel kurulum:" -ForegroundColor Cyan
        Write-Host "       1. https://nssm.cc/download adresinden indirin" -ForegroundColor White
        Write-Host "       2. nssm.exe dosyasını şuraya kopyalayın:" -ForegroundColor White
        Write-Host "          $NSSMPath" -ForegroundColor White
        Write-Host ""
        Write-Host "       Alternatif: Chocolatey ile kurulum:" -ForegroundColor Cyan
        Write-Host "       choco install nssm" -ForegroundColor White
        Write-Host ""
        
        $continue = Read-Host "       NSSM'i manuel olarak indirdiniz mi? (E/H)"
        if ($continue -ne "E" -and $continue -ne "e") {
            Write-Host "[HATA] NSSM gerekli, kurulum iptal edildi." -ForegroundColor Red
            exit 1
        }
        
        if (-not (Test-Path $NSSMPath)) {
            Write-Host "[HATA] NSSM hala bulunamadı: $NSSMPath" -ForegroundColor Red
            exit 1
        }
    }
} else {
    Write-Host "       ✓ NSSM bulundu" -ForegroundColor Green
}

Write-Host ""
Write-Host "[7/8] Windows Service kuruluyor..." -ForegroundColor Yellow

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "       Mevcut servis durduruluyor..." -ForegroundColor Gray
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "       Mevcut servis kaldırılıyor..." -ForegroundColor Gray
    & $NSSMPath remove $ServiceName confirm
}

Write-Host "       Servis yükleniyor..." -ForegroundColor Gray
& $NSSMPath install $ServiceName $pythonPath $ScriptPath

if ($LASTEXITCODE -ne 0) {
    Write-Host "[HATA] Servis kurulumu başarısız!" -ForegroundColor Red
    exit 1
}

Write-Host "       Servis ayarları yapılandırılıyor..." -ForegroundColor Gray
& $NSSMPath set $ServiceName AppDirectory $InstallDir
& $NSSMPath set $ServiceName DisplayName "User Activity Monitor"
& $NSSMPath set $ServiceName Description "Comprehensive User Activity Monitor with n8n webhook and auto-ban for Windows"
& $NSSMPath set $ServiceName Start SERVICE_AUTO_START
& $NSSMPath set $ServiceName AppStdout "$LogDir\service_stdout.log"
& $NSSMPath set $ServiceName AppStderr "$LogDir\service_stderr.log"

Write-Host ""
Write-Host "[8/8] Servis başlatılıyor..." -ForegroundColor Yellow
Start-Service -Name $ServiceName

Start-Sleep -Seconds 2

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ Kurulum başarıyla tamamlandı!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Servis Bilgileri:" -ForegroundColor Cyan
    Write-Host "  Adı: $ServiceName" -ForegroundColor White
    Write-Host "  Durum: $($service.Status)" -ForegroundColor White
    Write-Host "  Script: $ScriptPath" -ForegroundColor White
    Write-Host "  Config: $EnvPath" -ForegroundColor White
    Write-Host "  Loglar: $LogDir" -ForegroundColor White
    Write-Host ""
    Write-Host "Yararlı Komutlar:" -ForegroundColor Cyan
    Write-Host "  Servis durumu:     Get-Service $ServiceName" -ForegroundColor White
    Write-Host "  Servis durdur:     Stop-Service $ServiceName" -ForegroundColor White
    Write-Host "  Servis başlat:     Start-Service $ServiceName" -ForegroundColor White
    Write-Host "  Servis yeniden:    Restart-Service $ServiceName" -ForegroundColor White
    Write-Host "  Logları görüntüle: Get-Content $LogDir\activity_monitor.log -Tail 50" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  ÖNEMLİ: .env dosyasında WEBHOOK_URL'i düzenleyin!" -ForegroundColor Yellow
    Write-Host "   Dosya: $EnvPath" -ForegroundColor Yellow
    Write-Host "   Düzenleme sonrası: Restart-Service $ServiceName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📝 Örnek:" -ForegroundColor Cyan
    Write-Host "   notepad $EnvPath" -ForegroundColor White
    Write-Host "   # WEBHOOK_URL=`"https://your-n8n-url.com/webhook/...`" satırını düzenleyin" -ForegroundColor White
    Write-Host "   Restart-Service $ServiceName" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "[UYARI] Servis kuruldu ancak başlatılamadı!" -ForegroundColor Yellow
    Write-Host "        Lütfen manuel olarak kontrol edin:" -ForegroundColor Yellow
    Write-Host "        Get-Service $ServiceName" -ForegroundColor White
    Write-Host "        Get-Content $LogDir\service_stderr.log" -ForegroundColor White
}

