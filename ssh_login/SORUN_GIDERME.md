# Sorun Giderme - Webhook 404 Hatası

## 🔴 Sorun: Webhook 404 Hatası

Görülen hata:
```
[ERROR] n8n webhook hatası: 404 Client Error: Not Found for url: https://n8vp.yeb.one/webhook/sshloginfail
```

### Çözüm Adımları

#### 1. Webhook URL'ini Kontrol Edin

```bash
# .env dosyasını kontrol et
cat /opt/user_activity_monitor.env | grep WEBHOOK_URL

# veya
sudo nano /opt/user_activity_monitor.env
```

**Doğru URL formatı:**
```
WEBHOOK_URL="https://n8vp.yeb.one/webhook/useractivity"
```

**Yanlış URL (eski sistem):**
```
WEBHOOK_URL="https://n8vp.yeb.one/webhook/sshloginfail"  # ❌ Eski endpoint
```

#### 2. n8n'de Webhook Endpoint'ini Kontrol Edin

1. n8n'de workflow'unuzu açın
2. Webhook node'unu kontrol edin
3. Webhook path'ini kontrol edin:
   - Örnek: `/webhook/useractivity` veya `/webhook-test/server_log`
4. Tam URL'yi kopyalayın

**n8n Webhook URL Formatı:**
```
https://n8vp.yeb.one/webhook/[WORKFLOW_ID]
veya
https://n8vp.yeb.one/webhook-test/[PATH]
```

#### 3. .env Dosyasını Güncelleyin

```bash
sudo nano /opt/user_activity_monitor.env
```

**WEBHOOK_URL satırını düzenleyin:**
```env
WEBHOOK_URL="https://n8vp.yeb.one/webhook-test/server_log"
```

**Kaydedin ve servisi yeniden başlatın:**
```bash
sudo systemctl restart user_activity_monitor.service
```

#### 4. Webhook'u Test Edin

```bash
# Manuel test
curl -X POST https://n8vp.yeb.one/webhook-test/server_log \
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
    "raw_log": "Test log message"
  }'
```

Eğer 200 OK alırsanız, webhook çalışıyor demektir.

---

## 🔴 Sorun: Eski Script Hala Çalışıyor

Mesajda `service: "ssh"` görünüyorsa, eski script hala çalışıyor olabilir.

### Çözüm: Eski Servisi Durdurun

```bash
# Eski servisi kontrol et
sudo systemctl status ssh_n8n_monitor.service

# Eski servisi durdur
sudo systemctl stop ssh_n8n_monitor.service
sudo systemctl disable ssh_n8n_monitor.service

# Yeni servisi kontrol et
sudo systemctl status user_activity_monitor.service

# Yeni servisi başlat (eğer çalışmıyorsa)
sudo systemctl start user_activity_monitor.service
sudo systemctl enable user_activity_monitor.service
```

### Hangi Script Çalışıyor?

```bash
# Tüm ilgili servisleri kontrol et
sudo systemctl list-units | grep -E "(ssh|activity|monitor)"

# Çalışan Python processlerini kontrol et
ps aux | grep -E "(ssh_n8n|user_activity)" | grep -v grep
```

---

## ✅ Doğru Kurulum Kontrolü

### 1. Servis Kontrolü

```bash
# Yeni servis çalışıyor mu?
sudo systemctl status user_activity_monitor.service

# Aktif ve çalışıyor olmalı
# Active: active (running)
```

### 2. Log Kontrolü

```bash
# Yeni log dosyasını kontrol et
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log

# "service": "user_activity" görmelisiniz
```

### 3. Webhook Testi

```bash
# Log dosyasında webhook hatalarını kontrol et
sudo tail -f /var/log/user_activity_monitor/webhook_errors.log

# Hata olmamalı
```

---

## 🔧 Hızlı Düzeltme Scripti

Tüm sorunları otomatik düzeltmek için:

```bash
# 1. Eski servisi durdur
sudo systemctl stop ssh_n8n_monitor.service 2>/dev/null
sudo systemctl disable ssh_n8n_monitor.service 2>/dev/null

# 2. Webhook URL'ini kontrol et ve düzenle
echo "Mevcut WEBHOOK_URL:"
grep WEBHOOK_URL /opt/user_activity_monitor.env

echo ""
echo "Lütfen doğru webhook URL'ini .env dosyasına ekleyin:"
echo "sudo nano /opt/user_activity_monitor.env"
echo ""
echo "Örnek: WEBHOOK_URL=\"https://n8vp.yeb.one/webhook-test/server_log\""

# 3. Yeni servisi yeniden başlat
sudo systemctl restart user_activity_monitor.service

# 4. Durumu kontrol et
sudo systemctl status user_activity_monitor.service
```

---

## 📋 Kontrol Listesi

- [ ] Eski servis durduruldu (`ssh_n8n_monitor`)
- [ ] Yeni servis çalışıyor (`user_activity_monitor`)
- [ ] Webhook URL doğru ve çalışıyor
- [ ] Log dosyasında "service": "user_activity" görünüyor
- [ ] Webhook hataları yok
- [ ] Telegram mesajları geliyor

---

## 🆘 Hala Çalışmıyorsa

1. **Log dosyalarını kontrol edin:**
   ```bash
   sudo tail -50 /var/log/user_activity_monitor/activity_monitor.log
   sudo tail -50 /var/log/user_activity_monitor/webhook_errors.log
   ```

2. **n8n workflow'unu kontrol edin:**
   - Webhook node aktif mi?
   - Workflow çalışıyor mu?
   - Code node doğru mu?

3. **Manuel webhook testi:**
   ```bash
   curl -X POST YOUR_WEBHOOK_URL \
     -H "Content-Type: application/json" \
     -d '{"test": "data"}'
   ```

4. **Servis loglarını kontrol edin:**
   ```bash
   sudo journalctl -u user_activity_monitor -n 50
   ```

