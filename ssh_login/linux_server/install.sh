#!/bin/bash
# Kullanıcı Aktivite İzleme Sistemi - Linux Kurulum Scripti
# Kullanım: sudo ./install.sh

set -e

echo "========================================"
echo "Kullanıcı Aktivite İzleme Sistemi"
echo "Linux Kurulum"
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

echo "[1/6] Python bağımlılıklarını kuruyoruz..."
apt-get update -y >/dev/null
apt-get install -y python3 python3-pip >/dev/null
pip3 install requests --quiet

echo "[2/6] Klasörleri oluşturuyoruz..."
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

echo "[3/6] Python scriptini kopyalıyoruz..."
if [ -f "user_activity_monitor.py" ]; then
    cp user_activity_monitor.py "$SCRIPT_PATH"
    chmod 700 "$SCRIPT_PATH"
    echo "       Script kopyalandı: $SCRIPT_PATH"
else
    echo "[HATA] user_activity_monitor.py bulunamadı!"
    exit 1
fi

echo "[4/6] .env dosyasını kontrol ediyoruz..."
if [ -f "$ENV_PATH" ]; then
    echo "       .env dosyası zaten var, üzerine yazılmadı."
    echo "       Mevcut dosya: $ENV_PATH"
else
    if [ -f "user_activity_monitor.env.template" ]; then
        cp user_activity_monitor.env.template "$ENV_PATH"
        chmod 600 "$ENV_PATH"
        echo "       .env dosyası oluşturuldu: $ENV_PATH"
        echo ""
        echo "       ⚠️  ÖNEMLİ: WEBHOOK_URL'i düzenlemeniz gerekiyor!"
        echo "       Dosya: $ENV_PATH"
        echo ""
    else
        echo "[HATA] .env template bulunamadı!"
        exit 1
    fi
fi

echo "[5/6] systemd servisini oluşturuyoruz..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=User Activity Monitor (n8n webhook + ban engine)
After=network.target ssh.service
ConditionPathExists=$SCRIPT_PATH

[Service]
Type=simple
User=root
WorkingDirectory=/opt
EnvironmentFile=$ENV_PATH
ExecStart=/usr/bin/python3 $SCRIPT_PATH
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[6/6] Servisi başlatıyoruz..."
systemctl daemon-reload
systemctl enable user_activity_monitor.service >/dev/null
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

