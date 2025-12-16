#!/bin/bash
# Banlanan IP'leri Listeleme Scripti
# Kullanım: sudo ./ban_kontrol.sh

echo "========================================"
echo "Banlanan IP'leri Listeleme"
echo "========================================"
echo ""

# UFW kullanılıyor mu?
if command -v ufw &> /dev/null; then
    echo "[1] UFW kullanılıyor - ufw-user-input chain kontrol ediliyor..."
    echo ""
    echo "Banlanan IP'ler (ufw-user-input):"
    sudo iptables -L ufw-user-input -n -v --line-numbers | grep -E "DROP|REJECT" | grep -E "tcp.*22|tcp.*dpt:22"
    echo ""
    echo "Tüm ufw-user-input kuralları:"
    sudo iptables -L ufw-user-input -n -v --line-numbers
else
    echo "[1] UFW kullanılmıyor - INPUT chain kontrol ediliyor..."
    echo ""
    echo "Banlanan IP'ler (INPUT):"
    sudo iptables -L INPUT -n -v --line-numbers | grep -E "DROP|REJECT" | grep -E "tcp.*22|tcp.*dpt:22"
    echo ""
    echo "Tüm INPUT kuralları:"
    sudo iptables -L INPUT -n -v --line-numbers
fi

echo ""
echo "========================================"
echo "Banlanan IP Sayısı:"
if command -v ufw &> /dev/null; then
    COUNT=$(sudo iptables -L ufw-user-input -n | grep -c "DROP.*tcp.*22")
else
    COUNT=$(sudo iptables -L INPUT -n | grep -c "DROP.*tcp.*22")
fi
echo "Toplam: $COUNT IP banlı"
echo "========================================"
echo ""
echo "Belirli bir IP'yi kontrol etmek için:"
echo "  sudo iptables -L -n -v | grep IP_ADDRESS"
echo ""
echo "Ban'ı kaldırmak için:"
if command -v ufw &> /dev/null; then
    echo "  sudo iptables -D ufw-user-input -s IP_ADDRESS -p tcp --dport 22 -j DROP"
else
    echo "  sudo iptables -D INPUT -s IP_ADDRESS -p tcp --dport 22 -j DROP"
fi
echo ""

