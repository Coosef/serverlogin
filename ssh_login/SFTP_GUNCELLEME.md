# SFTP Tespiti Güncellemesi

## 🎯 Yapılan Değişiklikler

SFTP bağlantılarını daha detaylı tespit etmek için script güncellendi.

### Yeni Özellikler:

1. **SFTP Bağlantı Tespiti:**
   - Kullanıcı adında "sftp" varsa otomatik SFTP olarak işaretlenir
   - Log satırında "sftp" veya "subsystem" kelimesi varsa SFTP olarak işaretlenir
   - Örnek: `coosefsftp` kullanıcısı → SFTP bağlantısı

2. **Yeni Event Tipleri:**
   - `sftp_session_opened` - SFTP bağlantısı açıldı
   - `sftp_session_closed` - SFTP bağlantısı kapandı
   - `sftp_connection` - SFTP subsystem isteği
   - `ssh_connection` - SSH bağlantı isteği (IP/Port bilgisi)

3. **Telegram Mesajlarında:**
   - Bağlantı türü gösterilir (SFTP/SSH)
   - SFTP için özel emoji: 📁
   - SSH için emoji: 🔌

## 📋 Güncelleme Adımları

### Yöntem 1: Otomatik (Önerilen)

```bash
# Güvenli güncelleme scriptini kullan
chmod +x guvenli_guncelleme.sh
sudo ./guvenli_guncelleme.sh
```

### Yöntem 2: Manuel

```bash
# 1. Yedek al
sudo cp /opt/user_activity_monitor.py /opt/user_activity_monitor.py.backup

# 2. install_linux.sh'yi tekrar çalıştır
sudo bash install_linux.sh

# 3. Servisi yeniden başlat
sudo systemctl restart user_activity_monitor.service
```

### Yöntem 3: Sadece Python Script Güncelleme

Eğer sadece Python scriptini güncellemek isterseniz:

```bash
# install_linux.sh dosyasından Python script kısmını çıkarıp
# /opt/user_activity_monitor.py dosyasını güncelleyin
```

## ✅ Güncelleme Sonrası Kontrol

```bash
# 1. Servis durumu
sudo systemctl status user_activity_monitor.service

# 2. Logları kontrol et
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log

# 3. SFTP bağlantısı test et
# Başka bir terminalden SFTP ile bağlan
sftp user@server

# 4. Telegram mesajını kontrol et
# "SFTP Bağlantısı Açıldı" mesajı gelmeli
```

## 📊 Beklenen Sonuç

### Önceki Mesaj:
```
🔓 Event: Session Açıldı
👤 Kullanıcı: coosefsftp
```

### Yeni Mesaj:
```
📁 Event: SFTP Bağlantısı Açıldı
👤 Kullanıcı: coosefsftp
📁 Bağlantı Türü: SFTP
```

## 🔍 SFTP Tespit Mantığı

Script şu durumlarda bağlantıyı SFTP olarak işaretler:

1. **Kullanıcı adı kontrolü:**
   - Kullanıcı adında "sftp" varsa
   - Kullanıcı adı "sftp" ile bitiyorsa
   - Kullanıcı adı "sftp" ile başlıyorsa
   - Örnek: `coosefsftp`, `sftpuser`, `user_sftp`

2. **Log içeriği kontrolü:**
   - Log satırında "sftp" kelimesi varsa
   - Log satırında "subsystem" kelimesi varsa

3. **Subsystem kontrolü:**
   - `subsystem request for sftp` log'u varsa

## 💡 Notlar

- Normal SSH bağlantıları `SSH` olarak işaretlenir
- SFTP bağlantıları `SFTP` olarak işaretlenir
- Her iki durumda da kullanıcı, IP ve port bilgileri gösterilir
- Bağlantı türü Telegram mesajında açıkça belirtilir

## 🆘 Sorun Giderme

### SFTP görünmüyor

1. Logları kontrol edin:
   ```bash
   sudo tail -f /var/log/auth.log | grep sftp
   ```

2. Kullanıcı adını kontrol edin:
   - SFTP kullanıcı adında "sftp" olmalı
   - Veya log satırında "sftp" kelimesi olmalı

3. Script'i yeniden başlatın:
   ```bash
   sudo systemctl restart user_activity_monitor.service
   ```

### Yanlış tespit

Eğer normal SSH bağlantısı SFTP olarak görünüyorsa:
- Kullanıcı adında "sftp" kelimesi olmamalı
- Log satırında "sftp" kelimesi olmamalı

