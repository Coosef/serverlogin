#!/bin/bash
# SSH + n8n + Ban Engine Installer
# /opt altına Python scripti, .env ve systemd servisini kurar.

set -e

PY_SCRIPT_PATH="/opt/ssh_n8n_monitor.py"
ENV_PATH="/opt/ssh_n8n_monitor.env"
SERVICE_PATH="/etc/systemd/system/ssh_n8n_monitor.service"

echo "=== SSH Monitor Installer ==="

if [ "$EUID" -ne 0 ]; then
    echo "[HATA] Lütfen scripti root olarak çalıştırın (sudo ile)."
    exit 1
fi

echo "[1] Python bağımlılıklarını kuruyoruz (python3, requests)..."
apt-get update -y >/dev/null
apt-get install -y python3 python3-requests >/dev/null

echo "[2] Python scriptini yazıyoruz: $PY_SCRIPT_PATH"

cat << 'EOF' > "$PY_SCRIPT_PATH"
#!/usr/bin/env python3
import os
import re
import socket
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests

ENV_FILE = "/opt/ssh_n8n_monitor.env"


def load_env(path: str) -> dict:
    """Basit .env okuyucu (KEY=VALUE, # yorum satırı)."""
    env = {}
    if not os.path.exists(path):
        return env

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            env[key] = val
    return env


ENV = load_env(ENV_FILE)


def get_server_info():
    """Hostname ve ana IP adresini döndürür."""
    hostname = socket.gethostname()
    ip = "127.0.0.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
    except Exception:
        pass
    return hostname, ip


hostname, primary_ip = get_server_info()

WEBHOOK_URL = ENV.get("WEBHOOK_URL", "").strip()
if not WEBHOOK_URL:
    print("[ERROR] WEBHOOK_URL .env içinde tanımlı değil! Çıkılıyor.")
    raise SystemExit(1)

MAX_ATTEMPTS = int(ENV.get("MAX_ATTEMPTS", "5"))
TIME_WINDOW_SEC = int(ENV.get("TIME_WINDOW_SEC", "120"))
BAN_DURATION = int(ENV.get("BAN_DURATION", "3600"))  # Şimdilik sadece bilgi amaçlı
ALERT_ON_SUCCESS = ENV.get("ALERT_ON_SUCCESS", "1") == "1"

SERVER_NAME = ENV.get("SERVER_NAME", "").strip() or hostname
SERVER_ENV = ENV.get("SERVER_ENV", "Production").strip() or "Production"

print("[INFO] SSH n8n monitor başlıyor...")
print(f"[INFO] Webhook: {WEBHOOK_URL}")
print(f"[INFO] Sunucu: {SERVER_NAME} ({primary_ip}) | Env: {SERVER_ENV}")
print(f"[INFO] MAX_ATTEMPTS={MAX_ATTEMPTS}, TIME_WINDOW_SEC={TIME_WINDOW_SEC}, BAN_DURATION={BAN_DURATION}s")
print(f"[INFO] ALERT_ON_SUCCESS={ALERT_ON_SUCCESS}")

# IP -> son denemelerin zamanları
fail_windows = defaultdict(lambda: deque())


def parse_auth_line(line: str):
    """
    auth.log / journalctl satırını parse eder.
    Örnek satırlar:
      Invalid user es from 167.71.9.132 port 60284
      Failed password for root from 45.78.216.103 port 54428 ssh2
      Accepted password for root from 1.2.3.4 port 55555 ssh2
    """
    line = line.strip()

    # invalid_user
    m = re.search(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)", line)
    if m:
        return {
            "event_type": "invalid_user",
            "user": m.group("user"),
            "ip": m.group("ip"),
            "port": m.group("port"),
            "raw": line,
        }

    # failed_login
    m = re.search(
        r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
        line,
    )
    if m:
        return {
            "event_type": "failed_login",
            "user": m.group("user"),
            "ip": m.group("ip"),
            "port": m.group("port"),
            "raw": line,
        }

    # successful_login
    m = re.search(
        r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
        line,
    )
    if m:
        return {
            "event_type": "success",
            "user": m.group("user"),
            "ip": m.group("ip"),
            "port": m.group("port"),
            "raw": line,
        }

    return None


def ban_ip(ip: str):
    """
    iptables-nft (ufw-user-input chain) üzerinden IP'yi banlar.
    Aynı kural varsa yeniden eklemeye çalışmaz.
    """
    try:
        # TCP
        check_cmd = [
            "iptables",
            "-C",
            "ufw-user-input",
            "-s",
            f"{ip}/32",
            "-p",
            "tcp",
            "-m",
            "tcp",
            "--dport",
            "22",
            "-j",
            "DROP",
        ]
        add_cmd = [
            "iptables",
            "-A",
            "ufw-user-input",
            "-s",
            f"{ip}/32",
            "-p",
            "tcp",
            "-m",
            "tcp",
            "--dport",
            "22",
            "-j",
            "DROP",
        ]
        r = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            subprocess.run(add_cmd, check=False)
            print(f"[BAN] {ip} için TCP 22 DROP eklendi.")

        # UDP
        check_cmd_udp = [
            "iptables",
            "-C",
            "ufw-user-input",
            "-s",
            f"{ip}/32",
            "-p",
            "udp",
            "-m",
            "udp",
            "--dport",
            "22",
            "-j",
            "DROP",
        ]
        add_cmd_udp = [
            "iptables",
            "-A",
            "ufw-user-input",
            "-s",
            f"{ip}/32",
            "-p",
            "udp",
            "-m",
            "udp",
            "--dport",
            "22",
            "-j",
            "DROP",
        ]
        r = subprocess.run(check_cmd_udp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            subprocess.run(add_cmd_udp, check=False)
            print(f"[BAN] {ip} için UDP 22 DROP eklendi.")
    except Exception as e:
        print(f"[ERROR] iptables üzerinde ban eklenirken hata: {e}")


def send_to_webhook(event: dict, fail_count: int, banned: bool):
    data = {
        "event_type": event["event_type"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "ssh",
        "user": event.get("user") or "-",
        "ip": event.get("ip") or "-",
        "port": event.get("port") or "-",
        "raw_log": event.get("raw", ""),
        "fail_count_window": fail_count,
        "time_window_sec": TIME_WINDOW_SEC,
        "ban_triggered": banned,
        "server_name": SERVER_NAME,
        "server_ip": primary_ip,
        "server_env": SERVER_ENV,
    }

    try:
        r = requests.post(WEBHOOK_URL, json=data, timeout=5)
        if r.status_code >= 400:
            print(f"[ERROR] n8n webhook HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[ERROR] n8n webhook'a gönderirken hata: {e}")


def handle_event(event: dict):
    etype = event["event_type"]
    ip = event.get("ip")

    now = datetime.now(timezone.utc)

    # Başarılı giriş
    if etype == "success":
        if ALERT_ON_SUCCESS:
            send_to_webhook(event, fail_count=0, banned=False)
        # Aynı IP için eski kayıtları temizle
        if ip and ip in fail_windows:
            fail_windows[ip].clear()
        return

    # Sadece başarısız ve invalid user için pencere hesabı yap
    fail_count = 0
    banned = False

    if ip:
        window = fail_windows[ip]
        window.append(now)
        # Pencere dışı olanları temizle
        while window and (now - window[0]).total_seconds() > TIME_WINDOW_SEC:
            window.popleft()
        fail_count = len(window)

        if fail_count >= MAX_ATTEMPTS:
            banned = True
            ban_ip(ip)

    send_to_webhook(event, fail_count=fail_count, banned=banned)


def follow_logs():
    """
    /var/log/auth.log varsa tail -F ile, yoksa journalctl -u ssh ile izler.
    """
    if os.path.exists("/var/log/auth.log"):
        cmd = ["tail", "-F", "/var/log/auth.log"]
        print("[INFO] /var/log/auth.log üzerinden izleniyor (tail -F)...")
    else:
        cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0", "-o", "cat"]
        print("[INFO] journalctl üzerinden izleniyor (ssh unit)...")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            event = parse_auth_line(line)
            if not event:
                continue
            handle_event(event)
    except KeyboardInterrupt:
        print("[INFO] Ctrl+C alındı, çıkılıyor...")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    follow_logs()
EOF

chmod 700 "$PY_SCRIPT_PATH"

echo "[3] .env dosyasını kontrol ediyoruz: $ENV_PATH"

if [ -f "$ENV_PATH" ]; then
    echo "[BİLGİ] $ENV_PATH zaten var, ÜZERİNE YAZMIYORUM."
    echo "       Gerekirse elle düzenleyebilirsin."
else
    cat << 'EOF' > "$ENV_PATH"
# ssh_n8n_monitor ayar dosyası
# Değişiklik yaptıktan sonra:
#   sudo systemctl restart ssh_n8n_monitor.service

# n8n webhook URL (zorunlu)
WEBHOOK_URL="https://n8vp.yeb.one/webhook-test/sshloginfail"

# Kaç denemeden sonra banlansın?
MAX_ATTEMPTS=5

# Kaç saniyelik pencere içinde sayılacak? (örn: 120 sn)
TIME_WINDOW_SEC=120

# Ban süresi (şimdilik sadece bilgi amaçlı)
BAN_DURATION=3600

# Sunucunun görünen adı (boş bırakırsan hostname kullanılır)
SERVER_NAME=""

# Ortam bilgisi (Telegram tarafında gösterim için)
SERVER_ENV="Production"

# Başarılı girişler için de uyarı gönderilsin mi? (1 = evet, 0 = hayır)
ALERT_ON_SUCCESS=1
EOF
    chmod 600 "$ENV_PATH"
    echo "[BİLGİ] Örnek .env oluşturuldu. WEBHOOK_URL vb. ayarları kontrol etmeyi unutma."
fi

echo "[4] systemd servisini yazıyoruz: $SERVICE_PATH"

cat << EOF > "$SERVICE_PATH"
[Unit]
Description=SSH Login Monitor (n8n webhook + ban engine)
After=network.target ssh.service
ConditionPathExists=$PY_SCRIPT_PATH

[Service]
Type=simple
User=root
WorkingDirectory=/opt
EnvironmentFile=$ENV_PATH
ExecStart=/usr/bin/python3 $PY_SCRIPT_PATH
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[5] systemd daemon reload + enable + restart..."

systemctl daemon-reload
systemctl enable ssh_n8n_monitor.service >/dev/null
systemctl restart ssh_n8n_monitor.service

echo "=== Kurulum tamamlandı! ==="
systemctl --no-pager status ssh_n8n_monitor.service || true
