# n8n Code Node - Telegram Mesaj Formatı

Kullanıcı Aktivite İzleme Sistemi için n8n'de kullanılacak Code Node scriptleri.

## 📁 Dosyalar

1. **n8n_code_node_telegram.js** - Detaylı versiyon (tüm bilgileri içerir)
2. **n8n_code_node_telegram_compact.js** - Kompakt versiyon (kısa mesajlar)

## 🚀 Kullanım

### n8n'de Kurulum

1. **Webhook Node** ekleyin (gelen verileri alır)
2. **Code Node** ekleyin
3. Code Node'un içine scripti yapıştırın
4. **Telegram Node** ekleyin ve Code Node'dan gelen `message` değerini kullanın

### n8n Workflow Örneği

```
Webhook (POST) 
  → Code Node (telegram.js)
    → Telegram Node (Send Message)
```

### Code Node Ayarları

1. Code Node'u açın
2. "JavaScript" seçin
3. İlgili script dosyasının içeriğini yapıştırın
4. "Execute Once for All Items" seçeneğini açın (eğer birden fazla item varsa)

### Telegram Node Ayarları

- **Chat ID**: Telegram chat ID'nizi girin
- **Text**: `{{ $json.message }}` (Code Node'dan gelen message)
- **Parse Mode**: `MarkdownV2` (Code Node'da zaten ayarlı)

## 📊 Desteklenen Event Tipleri

### Linux:
- `ssh_invalid_user` - Geçersiz kullanıcı denemesi
- `ssh_failed_login` - Başarısız SSH girişi
- `ssh_success_login` - Başarılı SSH girişi
- `ssh_logout` - SSH çıkışı
- `sudo_command` - Sudo komutu çalıştırıldı
- `sudo_failed` - Sudo başarısız deneme
- `session_opened` - Session açıldı
- `session_closed` - Session kapandı

### Windows:
- `logon_success` - Başarılı Windows girişi
- `logon_failed` - Başarısız Windows girişi
- `logoff` - Windows çıkışı
- `process_create` - Yeni process oluşturuldu
- `file_access` - Dosya erişimi

## 📝 Mesaj Formatı

### Detaylı Versiyon Örneği:

```
🚨 Kullanıcı Aktivite Olayı
ID: 20240115103045-server01

🖥 Sunucu: server01 (192.168.1.100)
🌍 Ortam: Production

❌ Event: Başarısız SSH Girişi
📊 Tip: ssh_failed_login
📌 Durum: 🚨 Kritik

👤 Kullanıcı: root
🌐 Kaynak IP: 1.2.3.4
🔌 Port: 54321

🔒 Güvenlik Bilgileri:
   ⏱ Zaman Penceresi: 120 saniye
   ➜ Son 120 sn içinde deneme: 3
   ➜ Ban Durumu: ❌ Hayır

📅 Zaman (UTC): 2024-01-15T10:30:45.123456+00:00

🧾 Ham Log:
Failed password for root from 1.2.3.4 port 54321 ssh2
```

### Kompakt Versiyon Örneği:

```
❌ ssh_failed_login
🖥 server01 (192.168.1.100)
👤 root | 🌐 1.2.3.4
🕐 10:30:45 UTC
```

## ⚙️ Özelleştirme

### Mesaj Formatını Değiştirme

Script içindeki `lines.push()` satırlarını düzenleyerek mesaj formatını özelleştirebilirsiniz.

### Emoji Değiştirme

`getEventInfo()` veya `getEventEmoji()` fonksiyonlarını düzenleyerek emojileri değiştirebilirsiniz.

### Filtreleme Ekleme

Sadece kritik eventleri göndermek için Code Node'un başına filtre ekleyin:

```javascript
// Sadece kritik eventleri gönder
const criticalEvents = ['ssh_failed_login', 'ssh_invalid_user', 'logon_failed', 'sudo_command'];
if (!criticalEvents.includes(body.event_type)) {
  return { json: { skip: true } };
}
```

Sonra Telegram Node'da Condition ekleyin: `{{ $json.skip }}` ise mesaj gönderme.

## 🔧 Sorun Giderme

### Mesaj gönderilmiyor

1. Code Node'un çıktısını kontrol edin
2. Telegram Node'da `parse_mode: MarkdownV2` olduğundan emin olun
3. MarkdownV2 kaçış karakterlerinin doğru olduğundan emin olun

### Format hatası

Telegram MarkdownV2 çok katıdır. Tüm özel karakterler kaçışlanmalıdır. `esc()` fonksiyonu bunu yapar.

### Mesaj çok uzun

Telegram mesaj limiti 4096 karakterdir. Kompakt versiyonu kullanın veya mesajı kısaltın.

## 📚 Örnek n8n Workflow

```
1. Webhook (POST) - /webhook/useractivity
2. Code Node - telegram.js scripti
3. IF Node - Sadece kritik eventler için
   - Condition: event_type kritik mi?
4. Telegram Node - Mesaj gönder
```

## 💡 İpuçları

- **Filtreleme**: Sadece kritik eventleri göndermek için IF Node kullanın
- **Rate Limiting**: Çok fazla mesaj geliyorsa, n8n'de rate limiting ekleyin
- **Gruplama**: Aynı IP'den gelen çok sayıda eventi gruplayın
- **Özet**: Günlük/haftalık özet mesajları gönderin

