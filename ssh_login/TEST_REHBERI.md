# Test Rehberi - Kullanıcı Aktivite İzleme Sistemi

Bu rehber, sistemin tüm özelliklerini test etmek için adım adım talimatlar içerir.

## 🔧 Ön Hazırlık

### 1. Sunucu Adı Sorunu Düzeltme

Eğer sunucu adı görünmüyorsa:

```bash
# .env dosyasını düzenle
sudo nano /opt/user_activity_monitor.env

# SERVER_NAME satırını düzenle (örnek):
SERVER_NAME="production-server-01"

# Servisi yeniden başlat
sudo systemctl restart user_activity_monitor.service
```

Veya otomatik hostname kullanmak için:
```bash
# Hostname'i kontrol et
hostname

# Eğer hostname boşsa, ayarla
sudo hostnamectl set-hostname "my-server-name"
sudo systemctl restart user_activity_monitor.service
```

## 🧪 Test Senaryoları

### 1. SSH Başarısız Giriş Testi

**Amaç:** Başarısız SSH giriş denemelerini test etmek

**Adımlar:**
```bash
# Başka bir terminal/cihazdan yanlış şifre ile SSH denemesi yap
ssh user@your-server-ip
# Yanlış şifre gir (3-5 kez)

# veya script ile test et
for i in {1..5}; do
  sshpass -p 'wrongpassword' ssh -o StrictHostKeyChecking=no user@your-server-ip 2>&1
  sleep 2
done
```

**Beklenen Sonuç:**
- Telegram'da `ssh_failed_login` eventi gelmeli
- `fail_count_window` artmalı (1, 2, 3, 4, 5)
- 5. denemede `ban_triggered: true` olmalı
- IP otomatik banlanmalı

**Kontrol:**
```bash
# Ban durumunu kontrol et
sudo iptables -L -n | grep IP_ADDRESS

# Logları kontrol et
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log
```

---

### 2. SSH Geçersiz Kullanıcı Testi

**Amaç:** Var olmayan kullanıcı ile giriş denemesini test etmek

**Adımlar:**
```bash
# Var olmayan bir kullanıcı ile SSH denemesi
ssh nonexistentuser@your-server-ip
# Şifre sorulduğunda yanlış şifre gir
```

**Beklenen Sonuç:**
- Telegram'da `ssh_invalid_user` eventi gelmeli
- Kullanıcı adı: `nonexistentuser`
- `fail_count_window` artmalı

---

### 3. SSH Başarılı Giriş Testi

**Amaç:** Başarılı SSH girişlerini test etmek (ALERT_ON_SUCCESS=1 ise)

**Adımlar:**
```bash
# Doğru kullanıcı ve şifre ile SSH girişi yap
ssh user@your-server-ip
# Doğru şifre gir
```

**Beklenen Sonuç:**
- Telegram'da `ssh_success_login` eventi gelmeli (ALERT_ON_SUCCESS=1 ise)
- IP için eski başarısız deneme kayıtları temizlenmeli

**Kontrol:**
```bash
# .env dosyasında ALERT_ON_SUCCESS kontrol et
grep ALERT_ON_SUCCESS /opt/user_activity_monitor.env
```

---

### 4. SSH Logout Testi

**Amaç:** SSH çıkışlarını test etmek

**Adımlar:**
```bash
# SSH ile bağlan
ssh user@your-server-ip

# Çıkış yap
exit
```

**Beklenen Sonuç:**
- Telegram'da `ssh_logout` eventi gelmeli
- IP adresi görünmeli

---

### 5. Sudo Komut Testi

**Amaç:** Sudo komutlarını test etmek

**Adımlar:**
```bash
# SSH ile bağlan
ssh user@your-server-ip

# Sudo komutu çalıştır
sudo ls /root
# Şifre gir

# Başka bir sudo komutu
sudo systemctl status ssh
```

**Beklenen Sonuç:**
- Telegram'da `sudo_command` eventi gelmeli
- Komut: `ls /root` veya `systemctl status ssh`
- Kullanıcı adı görünmeli
- Hedef kullanıcı (genelde root) görünmeli

**Kontrol:**
```bash
# Sudo loglarını kontrol et
sudo tail -f /var/log/auth.log | grep sudo
```

---

### 6. Sudo Başarısız Deneme Testi

**Amaç:** Yanlış sudo şifresi denemelerini test etmek

**Adımlar:**
```bash
# SSH ile bağlan
ssh user@your-server-ip

# Yanlış şifre ile sudo denemesi (3-5 kez)
sudo ls /root
# Yanlış şifre gir (3-5 kez)
```

**Beklenen Sonuç:**
- Telegram'da `sudo_failed` eventi gelmeli
- Deneme sayısı görünmeli

---

### 7. Komut Geçmişi Testi

**Amaç:** Komut geçmişi izleme özelliğini test etmek

**Adımlar:**
```bash
# SSH ile bağlan
ssh user@your-server-ip

# Birkaç komut çalıştır
ls -la
cd /tmp
cat /etc/passwd
whoami
```

**Beklenen Sonuç:**
- 30 saniye içinde komutlar loglanmalı
- Log dosyasında `[COMMAND]` mesajları görünmeli

**Kontrol:**
```bash
# Komut geçmişi loglarını kontrol et
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log | grep COMMAND

# History dosyasını kontrol et
tail -f ~/.bash_history
```

**Not:** Komut geçmişi izleme periyodik olarak çalışır (30 saniyede bir), bu yüzden biraz beklemek gerekebilir.

---

### 8. Session Açma/Kapama Testi

**Amaç:** Genel session olaylarını test etmek

**Adımlar:**
```bash
# SSH ile bağlan
ssh user@your-server-ip

# Çıkış yap
exit

# Tekrar bağlan
ssh user@your-server-ip
```

**Beklenen Sonuç:**
- `session_opened` ve `session_closed` eventleri gelmeli

---

### 9. IP Ban Testi

**Amaç:** Otomatik IP banlama özelliğini test etmek

**Adımlar:**
```bash
# Test IP'sinden (farklı bir sunucudan) 5+ başarısız deneme yap
# veya script ile:
for i in {1..6}; do
  sshpass -p 'wrong' ssh -o StrictHostKeyChecking=no testuser@TARGET_IP 2>&1
  sleep 1
done
```

**Beklenen Sonuç:**
- 5. denemede IP banlanmalı
- `ban_triggered: true` olmalı
- iptables'ta IP görünmeli

**Kontrol:**
```bash
# Ban durumunu kontrol et
sudo iptables -L -n -v | grep BANNED_IP

# Ban'ı kaldırmak için:
sudo iptables -D INPUT -s BANNED_IP -p tcp --dport 22 -j DROP
```

---

### 10. Whitelist Testi

**Amaç:** Whitelist IP'lerin banlanmadığını test etmek

**Adımlar:**
```bash
# .env dosyasını düzenle
sudo nano /opt/user_activity_monitor.env

# WHITELIST_IPS satırına kendi IP'nizi ekleyin
WHITELIST_IPS="YOUR_IP_ADDRESS"

# Servisi yeniden başlat
sudo systemctl restart user_activity_monitor.service

# Whitelist IP'den yanlış şifre ile deneme yap (5+ kez)
```

**Beklenen Sonuç:**
- Eventler gelmeli ama IP banlanmamalı
- `ban_triggered: false` olmalı

---

## 🔍 Genel Kontroller

### Servis Durumu
```bash
# Servis durumunu kontrol et
sudo systemctl status user_activity_monitor

# Servis loglarını kontrol et
sudo journalctl -u user_activity_monitor -f
```

### Log Dosyaları
```bash
# Ana log dosyası
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log

# Webhook hataları
sudo tail -f /var/log/user_activity_monitor/webhook_errors.log
```

### Yapılandırma Kontrolü
```bash
# .env dosyasını kontrol et
cat /opt/user_activity_monitor.env

# Python scriptini kontrol et
cat /opt/user_activity_monitor.py | head -20
```

### n8n Webhook Testi
```bash
# Manuel webhook testi
curl -X POST https://your-n8n-webhook-url \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T10:30:45Z",
    "service": "user_activity",
    "server_name": "test-server",
    "server_ip": "192.168.1.100",
    "server_env": "Production",
    "event_type": "ssh_failed_login",
    "user": "testuser",
    "ip": "1.2.3.4",
    "port": "54321",
    "fail_count_window": 1,
    "ban_triggered": false,
    "raw_log": "Failed password for testuser from 1.2.3.4 port 54321 ssh2"
  }'
```

---

## 🐛 Sorun Giderme

### Eventler gelmiyor

1. **Servis çalışıyor mu?**
   ```bash
   sudo systemctl status user_activity_monitor
   ```

2. **Log dosyalarını kontrol et:**
   ```bash
   sudo tail -f /var/log/user_activity_monitor/activity_monitor.log
   ```

3. **auth.log okunuyor mu?**
   ```bash
   sudo tail -f /var/log/auth.log
   ```

4. **Webhook URL doğru mu?**
   ```bash
   grep WEBHOOK_URL /opt/user_activity_monitor.env
   ```

### Sunucu adı görünmüyor

1. **Hostname kontrol:**
   ```bash
   hostname
   ```

2. **.env dosyasında SERVER_NAME ayarla:**
   ```bash
   sudo nano /opt/user_activity_monitor.env
   # SERVER_NAME="my-server-name" ekle
   sudo systemctl restart user_activity_monitor.service
   ```

### IP banlanmıyor

1. **iptables kurulu mu?**
   ```bash
   which iptables
   ```

2. **Root yetkisi var mı?**
   ```bash
   sudo iptables -L
   ```

3. **Ban eşiği kontrol:**
   ```bash
   grep MAX_ATTEMPTS /opt/user_activity_monitor.env
   ```

---

## 📊 Test Checklist

- [ ] SSH başarısız giriş testi
- [ ] SSH geçersiz kullanıcı testi
- [ ] SSH başarılı giriş testi (ALERT_ON_SUCCESS=1)
- [ ] SSH logout testi
- [ ] Sudo komut testi
- [ ] Sudo başarısız deneme testi
- [ ] Komut geçmişi testi
- [ ] Session açma/kapama testi
- [ ] IP ban testi (5+ deneme)
- [ ] Whitelist testi
- [ ] Sunucu adı görünüyor mu?
- [ ] Telegram mesajları düzgün formatlanmış mı?
- [ ] Webhook hataları var mı?

---

## 💡 İpuçları

1. **Test için ayrı bir test kullanıcısı oluşturun:**
   ```bash
   sudo useradd -m testuser
   sudo passwd testuser
   ```

2. **Test IP'si için geçici whitelist ekleyin:**
   ```bash
   # Test bitince kaldırın
   ```

3. **Log dosyalarını gerçek zamanlı izleyin:**
   ```bash
   sudo tail -f /var/log/user_activity_monitor/activity_monitor.log
   ```

4. **n8n'de webhook'u test edin:**
   - n8n'de webhook node'unu test modunda çalıştırın
   - Gelen verileri kontrol edin

5. **Telegram mesaj formatını test edin:**
   - Code Node çıktısını kontrol edin
   - MarkdownV2 formatını doğrulayın

