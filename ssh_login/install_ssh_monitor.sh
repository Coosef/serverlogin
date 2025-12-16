#!/bin/bash

echo "=== SSH Monitor Installer ==="

SCRIPT_PATH="/opt/ssh_n8n_monitor.py"
ENV_PATH="/opt/ssh_n8n_monitor.env"
SERVICE_PATH="/etc/systemd/system/ssh_n8n_monitor.service"

echo "[1] Python bağımlılıklarını kuruyoruz..."
sudo apt update -y
sudo apt install -y python3 python3-requests

echo "[2] Script dosyasını oluşturuyoruz: $SCRIPT_PATH"
cat << 'EOF' > $SCRIPT_PATH
#!/usr/bin/env python3
import re
import time
import os
import json
import urllib.request
import socket
import subprocess

ENV_FILE = "/opt/ssh_n8n_monitor.env"

def load_env():
    cfg = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r") as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    key, val = line.strip().split("=", 1)
                    cfg[key] = val
    return cfg

CONFIG = load_env()

WEBHOOK_URL = CONFIG.get("WEBHOOK_URL", "")
MAX_ATTEMPTS = int(CONFIG.get("MAX_ATTEMPTS", 5))
BAN_DURATION = int(CONFIG.get("BAN_DURATION", 3600))
SERVER_ENV = CONFIG.get("SERVER_ENV", "Production")
SERVER_NAME = socket.gethostname().upper()
ALERT_ON_SUCCESS = CONFIG.get("ALERT_ON_SUCCESS", "0") == "1"

failed_attempts = {}

def send_webhook(event_type, ip, username, raw_log):
    payload = {
        "server": SERVER_NAME,
        "environment": SERVER_ENV,
        "event_type": event_type,
        "ip": ip,
        "username": username,
        "timestamp": int(time.time()),
        "raw_log": raw_log
    }

    print("[WEBHOOK] Gönderiliyor:", payload)

    try:
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5).read()
        print("[WEBHOOK] Başarılı gönderildi")
    except Exception as e:
        print("[WEBHOOK] Hata:", e)

def ban_ip(ip):
    print(f"[BAN] {ip} banlanıyor...")
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "DROP"])
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-p", "udp", "--dport", "22", "-j", "DROP"])

def monitor():
    print("[INFO] SSH izleme başlatıldı (journalctl üzerinden)")

    cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    for line in process.stdout:
        if not line.strip():
            continue

        log = line.strip()

        # Başarısız deneme
        failed_match = re.search(r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)", log)
        if failed_match:
            username = failed_match.group(2)
            ip = failed_match.group(3)

            print(f"[FAILED LOGIN] {username} @ {ip}")

            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

            send_webhook("failed_login", ip, username, log)

            if failed_attempts[ip] >= MAX_ATTEMPTS:
                ban_ip(ip)
                send_webhook("ip_banned", ip, username, log)

            continue

        # Başarılı login
        success_match = re.search(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)", log)
        if success_match and ALERT_ON_SUCCESS:
            username = success_match.group(1)
            ip = success_match.group(2)

            print(f"[SUCCESS LOGIN] {username} @ {ip}")

            send_webhook("success_login", ip, username, log)

if __name__ == "__main__":
    monitor()
EOF

chmod +x $SCRIPT_PATH

echo "[3] Env dosyasını oluşturuyoruz: $ENV_PATH"
cat << 'EOF' > $ENV_PATH
# n8n webhook URL
WEBHOOK_URL="https://n8vp.yeb.one/webhook-test/6b9056d8-a9d5-4378-9482-c09df6f766d5"

# Kaç denemeden sonra banlansın?
MAX_ATTEMPTS=5

# Ban süresi (şimdilik kullanılmıyor)
BAN_DURATION=3600

# Sunucu ortamı
SERVER_ENV="Production"

# Başarılı giriş alerti
ALERT_ON_SUCCESS=1
EOF

echo "[4] Servisi oluşturuyoruz: $SERVICE_PATH"
cat << EOF > $SERVICE_PATH
[Unit]
Description=SSH Login Monitor (n8n webhook + ban engine)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_PATH
Restart=always
RestartSec=5
User=root
EnvironmentFile=$ENV_PATH

[Install]
WantedBy=multi-user.target
EOF

echo "[5] Servisi aktif ediyoruz..."
sudo systemctl daemon-reload
sudo systemctl enable ssh_n8n_monitor.service
sudo systemctl start ssh_n8n_monitor.service

echo "=== Kurulum tamamlandı! ==="
sudo systemctl status ssh_n8n_monitor.service --no-pager
