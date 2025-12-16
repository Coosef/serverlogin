#!/bin/bash
# Güvenli Script Güncelleme
# Mevcut scripti yedekler ve günceller

set -e

echo "========================================"
echo "Güvenli Script Güncelleme"
echo "========================================"
echo ""

SCRIPT_PATH="/opt/user_activity_monitor.py"
BACKUP_PATH="/opt/user_activity_monitor.py.backup.$(date +%Y%m%d_%H%M%S)"

# Yedek oluştur
echo "[1/4] Mevcut script yedekleniyor..."
if [ -f "$SCRIPT_PATH" ]; then
    cp "$SCRIPT_PATH" "$BACKUP_PATH"
    echo "       ✓ Yedek oluşturuldu: $BACKUP_PATH"
else
    echo "       ⚠️  Script bulunamadı: $SCRIPT_PATH"
    exit 1
fi

# Yeni scripti kontrol et
echo ""
echo "[2/4] Yeni script kontrol ediliyor..."
if [ ! -f "install_linux.sh" ]; then
    echo "       ⚠️  install_linux.sh bulunamadı!"
    echo "       Lütfen güncel install_linux.sh dosyasını bu klasöre kopyalayın."
    exit 1
fi

# Python scriptini extract et (install_linux.sh'den)
echo ""
echo "[3/4] Yeni script çıkarılıyor..."
# install_linux.sh içindeki Python scriptini geçici dosyaya çıkar
sed -n '/^cat > "$SCRIPT_PATH" <</,/^PYTHON_SCRIPT$/p' install_linux.sh | \
    sed '1d;$d' > /tmp/new_script.py

if [ ! -s /tmp/new_script.py ]; then
    echo "       ⚠️  Script çıkarılamadı!"
    echo "       Manuel olarak güncelleme yapmanız gerekiyor."
    exit 1
fi

# Yeni scripti kopyala
cp /tmp/new_script.py "$SCRIPT_PATH"
chmod 700 "$SCRIPT_PATH"
rm /tmp/new_script.py
echo "       ✓ Yeni script kopyalandı"

# Servisi yeniden başlat
echo ""
echo "[4/4] Servis yeniden başlatılıyor..."
systemctl restart user_activity_monitor.service
sleep 2

# Durum kontrolü
echo ""
echo "Servis durumu:"
systemctl status user_activity_monitor.service --no-pager -l | head -10

echo ""
echo "========================================"
echo "✓ Güncelleme tamamlandı!"
echo "========================================"
echo ""
echo "Yedek dosya: $BACKUP_PATH"
echo ""
echo "Eğer sorun olursa yedekten geri yükleyin:"
echo "  sudo cp $BACKUP_PATH $SCRIPT_PATH"
echo "  sudo systemctl restart user_activity_monitor.service"
echo ""

