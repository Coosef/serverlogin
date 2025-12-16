#!/usr/bin/env python3
import os
import re
import socket
import datetime
import logging
import subprocess
from collections import defaultdict, deque

import requests

# =========================
#  Genel Ayarlar
# =========================

ENV_PATH = "/opt/ssh_n8n_monitor.env"

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

# Log pattern'leri
RE_INVALID_USER = re.compile(
    r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
RE_FAILED_LOGIN = re.compile(
    r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
RE_SUCCESS_LOGIN = re.compile(
    r"Accepted .* for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)

# IP -> son hatalı denemelerin zamanları (ts listesi)
fail_events = defaultdict(deque)


# =========================
#  Yardımcı Fonksiyonlar
# =========================

def load_env(path: str) -> dict:
    env = {}
    if not os.path.exists(path):
        logging.warning("[WARN] Env dosyası yok: %s", path)
        return env

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
    logging.info("[INFO] Env dosyası yüklendi: %s", path)
    return env


def get_primary_ip() -> str:
    """Sunucunun dış IP’sini bulmaya çalışır, olmazsa 127.0.0.1 döner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def send_to_n8n(webhook_url: str, payload: dict):
    try:
        r = requests.post(webhook_url, json=payload, timeout=5)
        r.raise_for_status()
    except Exception as e:
        logging.error("[ERROR] n8n webhook hatası: %s | payload=%s", e, payload)


def ip_already_banned(ip: str) -> bool:
    try:
        result = subprocess.run(
            ["iptables", "-S"],
            capture_output=True,
            text=True,
            check=False
        )
        return ip in result.stdout
    except FileNotFoundError:
        logging.error("[ERROR] iptables komutu bulunamadı!")
        return False


def ban_ip(ip: str, ssh_port: int = 22):
    if ip_already_banned(ip):
        logging.info("[INFO] IP zaten banlı: %s", ip)
        return

    logging.info("[INFO] IP banlanıyor: %s", ip)

    rules = [
        ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"],
        ["iptables", "-A", "INPUT", "-s", ip, "-p", "udp", "--dport", str(ssh_port), "-j", "DROP"],
        # UFW kullanıyorsan ufw-user-input chain'ine de yazalım
        ["iptables", "-A", "ufw-user-input", "-s", ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"],
        ["iptables", "-A", "ufw-user-input", "-s", ip, "-p", "udp", "--dport", str(ssh_port), "-j", "DROP"],
    ]

    for cmd in rules:
        try:
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            logging.error("[ERROR] iptables bulunamadı: %s", cmd)
            break


def track_fail_and_check_ban(ip: str, now_ts: float, time_window: int, max_attempts: int):
    dq = fail_events[ip]
    dq.append(now_ts)

    cutoff = now_ts - time_window
    while dq and dq[0] < cutoff:
        dq.popleft()

    fail_count = len(dq)
    ban_triggered = fail_count >= max_attempts
    return fail_count, ban_triggered


def follow_auth_log():
    """
    /var/log/auth.log varsa tail -F, yoksa journalctl -u ssh -f -n 0
    (önceki çalışan davranışa yakın tutuyoruz)
    """
    auth_log = "/var/log/auth.log"
    if os.path.exists(auth_log):
        logging.info("[INFO] %s bulundu, tail -F ile izlenecek...", auth_log)
        cmd = ["tail", "-F", auth_log]
    else:
        logging.info("[INFO] auth.log yok, journalctl ile izlenecek (ssh servisi)...")
        cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0"]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    return proc


# =========================
#  Ana Döngü
# =========================

def main():
    env = load_env(ENV_PATH)

    webhook_url = env.get("WEBHOOK_URL", "").strip()
    if not webhook_url:
        logging.error("[FATAL] WEBHOOK_URL tanımlı değil, çıkılıyor.")
        return

    # Dinamik sunucu adı/IP (env varsa override)
    hostname = socket.gethostname()
    primary_ip = get_primary_ip()

    server_name = env.get("SERVER_NAME", "").strip() or hostname
    server_ip = env.get("SERVER_IP", "").strip() or primary_ip
    server_env = env.get("SERVER_ENV", "Production")

    max_attempts = int(env.get("MAX_ATTEMPTS", "5"))
    time_window_sec = int(env.get("TIME_WINDOW_SEC", "120"))
    ban_duration = int(env.get("BAN_DURATION", "3600"))  # şimdilik sadece log’ta
    alert_on_success = env.get("ALERT_ON_SUCCESS", "1") in ("1", "true", "True", "YES", "yes")

    logging.info("[INFO] SSH monitor başlıyor...")
    logging.info("[INFO] Webhook: %s", webhook_url)
    logging.info("[INFO] Sunucu: %s (%s) | Env: %s", server_name, server_ip, server_env)
    logging.info("[INFO] Eşik: %d deneme / %d sn | Ban süresi (log): %d sn",
                 max_attempts, time_window_sec, ban_duration)

    proc = follow_auth_log()

    try:
        for line in proc.stdout:
            if not line:
                continue
            line = line.strip()

            now = datetime.datetime.now(datetime.timezone.utc)
            now_ts = now.timestamp()

            base_payload = {
                "timestamp": now.isoformat(),
                "service": "ssh",
                "server_name": server_name,
                "server_ip": server_ip,
                "server_env": server_env,
                "time_window_sec": time_window_sec,
            }

            # -------- INVALID USER --------
            m = RE_INVALID_USER.search(line)
            if m:
                user, ip, port = m.group(1), m.group(2), m.group(3)
                fail_count, ban_triggered = track_fail_and_check_ban(
                    ip, now_ts, time_window_sec, max_attempts
                )

                if ban_triggered:
                    ban_ip(ip)

                payload = {
                    **base_payload,
                    "event_type": "invalid_user",
                    "user": user,
                    "ip": ip,
                    "port": port,
                    "raw_log": line,
                    "fail_count_window": fail_count,
                    "ban_triggered": ban_triggered,
                }
                send_to_n8n(webhook_url, payload)
                continue

            # -------- FAILED LOGIN --------
            m = RE_FAILED_LOGIN.search(line)
            if m:
                _inv_prefix, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
                fail_count, ban_triggered = track_fail_and_check_ban(
                    ip, now_ts, time_window_sec, max_attempts
                )

                if ban_triggered:
                    ban_ip(ip)

                payload = {
                    **base_payload,
                    "event_type": "failed_login",
                    "user": user,
                    "ip": ip,
                    "port": port,
                    "raw_log": line,
                    "fail_count_window": fail_count,
                    "ban_triggered": ban_triggered,
                }
                send_to_n8n(webhook_url, payload)
                continue

            # -------- SUCCESS LOGIN (opsiyonel) --------
            m = RE_SUCCESS_LOGIN.search(line)
            if m:
                user, ip, port = m.group(1), m.group(2), m.group(3)
                if alert_on_success:
                    payload = {
                        **base_payload,
                        "event_type": "success_login",
                        "user": user,
                        "ip": ip,
                        "port": port,
                        "raw_log": line,
                        "fail_count_window": 0,
                        "ban_triggered": False,
                    }
                    send_to_n8n(webhook_url, payload)
                continue

    except KeyboardInterrupt:
        logging.info("[INFO] Kullanıcı tarafından durduruldu.")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()
