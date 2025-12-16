#!/bin/bash
# Hızlı Düzeltme Scripti
# Eski servisi durdurur, yeni servisi başlatır

echo "========================================"
echo "Hızlı Düzeltme - Servis Kontrolü"
echo "========================================"
echo ""

# Eski servisleri durdur
echo "[1/4] Eski servisleri kontrol ediliyor..."
if systemctl is-active --quiet ssh_n8n_monitor.service 2>/dev/null; then
    echo "       Eski servis (ssh_n8n_monitor) bulundu, durduruluyor..."
    sudo systemctl stop ssh_n8n_monitor.service
    sudo systemctl disable ssh_n8n_monitor.service
    echo "       ✓ Eski servis durduruldu"
else
    echo "       Eski servis bulunamadı (zaten durdurulmuş)"
fi

# Yeni servisi kontrol et
echo ""
echo "[2/4] Yeni servis kontrol ediliyor..."
if systemctl is-active --quiet user_activity_monitor.service; then
    echo "       ✓ Yeni servis çalışıyor"
else
    echo "       ⚠️  Yeni servis çalışmıyor, başlatılıyor..."
    sudo systemctl start user_activity_monitor.service
    sudo systemctl enable user_activity_monitor.service
fi

# Servisi yeniden başlat
echo ""
echo "[3/4] Servis yeniden başlatılıyor..."
sudo systemctl restart user_activity_monitor.service
sleep 2

# Durum kontrolü
echo ""
echo "[4/4] Servis durumu kontrol ediliyor..."
sudo systemctl status user_activity_monitor.service --no-pager -l

echo ""
echo "========================================"
echo "✓ İşlem tamamlandı!"
echo "========================================"
echo ""
echo "Logları kontrol etmek için:"
echo "  sudo tail -f /var/log/user_activity_monitor/activity_monitor.log"
echo ""
echo "Webhook hatalarını kontrol etmek için:"
echo "  sudo tail -f /var/log/user_activity_monitor/webhook_errors.log"
echo ""

