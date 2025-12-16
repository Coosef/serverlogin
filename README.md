# Kullanıcı Aktivite İzleme Sistemi

Kapsamlı kullanıcı aktivite izleme sistemi - Hem Linux hem Windows Server için.

## 🎯 Özellikler

### İzlenen Aktivite Türleri

#### Linux:
- ✅ SSH giriş/çıkış (başarılı/başarısız)
- ✅ SFTP bağlantıları (detaylı IP bilgisi ile)
- ✅ Tüm login/logout olayları
- ✅ Komut geçmişi (bash/zsh history)
- ✅ Sudo komutları ve başarısız denemeler
- ✅ Session açma/kapama
- ✅ Otomatik IP banlama (iptables/UFW)

#### Windows:
- ✅ Windows Logon/Logoff (Event ID 4624, 4634)
- ✅ Başarısız giriş denemeleri (Event ID 4625)
- ✅ SSH giriş/çıkış (OpenSSH Event Log)
- ✅ Process oluşturma (Event ID 4688)
- ✅ Dosya erişimleri (Event ID 4663) - opsiyonel
- ✅ PowerShell komut geçmişi
- ✅ Otomatik IP banlama (Windows Firewall)

### Genel Özellikler:
- ✅ n8n webhook entegrasyonu
- ✅ Telegram bildirimleri (n8n Code Node ile)
- ✅ Zaman penceresi bazlı banlama
- ✅ Whitelist desteği
- ✅ Detaylı loglama
- ✅ Windows Service / Linux systemd servisi
- ✅ Otomatik başlatma
- ✅ Yapılandırılabilir izleme seçenekleri
- ✅ Tek komutla kurulum

## 🚀 Hızlı Kurulum

### Linux

```bash
# Tek komutla kurulum
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/serverlogin/main/ssh_login/install_linux.sh | sudo bash

# Veya dosyayı indirip çalıştır
wget https://raw.githubusercontent.com/YOUR_USERNAME/serverlogin/main/ssh_login/install_linux.sh
sudo bash install_linux.sh
```

### Windows

```powershell
# PowerShell'i Yönetici olarak açın
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/serverlogin/main/ssh_login/install_windows.ps1" -OutFile install.ps1
.\install.ps1
```

## 📋 Gereksinimler

### Linux:
- Ubuntu 18.04+ / Debian 10+ / CentOS 7+
- Python 3.7+
- Root yetkileri
- OpenSSH Server

### Windows:
- Windows Server 2016+
- Python 3.7+
- Yönetici yetkileri
- OpenSSH Server (opsiyonel)
- NSSM (otomatik indirilir)

## ⚙️ Yapılandırma

Kurulum sonrası `.env` dosyasını düzenleyin:

```bash
# Linux
sudo nano /opt/user_activity_monitor.env

# Windows
notepad C:\ProgramData\user_activity_monitor\user_activity_monitor.env
```

**Zorunlu ayar:**
```env
WEBHOOK_URL="https://your-n8n-url.com/webhook/..."
```

## 📡 n8n Entegrasyonu

n8n'de Code Node kullanarak Telegram mesajları gönderebilirsiniz.

Detaylı bilgi için: [n8n Code Node Rehberi](ssh_login/n8n_code_node_telegram_README.md)

## 📚 Dokümantasyon

- [Ana README](ssh_login/README.md) - Detaylı kullanım kılavuzu
- [Test Rehberi](ssh_login/TEST_REHBERI.md) - Tüm özellikleri test etme
- [Sorun Giderme](ssh_login/SORUN_GIDERME.md) - Yaygın sorunlar ve çözümleri
- [SFTP Güncelleme](ssh_login/SFTP_GUNCELLEME.md) - SFTP tespiti hakkında

## 🔧 Kullanım

### Linux

```bash
# Servis durumu
sudo systemctl status user_activity_monitor

# Logları görüntüle
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log
```

### Windows

```powershell
# Servis durumu
Get-Service UserActivityMonitor

# Logları görüntüle
Get-Content C:\ProgramData\user_activity_monitor\logs\activity_monitor.log -Tail 50
```

## 📁 Proje Yapısı

```
serverlogin/
├── ssh_login/
│   ├── install_linux.sh              # Linux tek komut kurulum
│   ├── install_windows.ps1           # Windows tek komut kurulum
│   ├── linux_server/                 # Linux manuel kurulum dosyaları
│   ├── windows_server/               # Windows manuel kurulum dosyaları
│   ├── n8n_code_node_telegram.js    # n8n Telegram mesaj formatı
│   ├── README.md                     # Detaylı dokümantasyon
│   ├── TEST_REHBERI.md              # Test senaryoları
│   └── SORUN_GIDERME.md             # Sorun giderme
└── README.md                         # Bu dosya
```

## 🔐 Güvenlik

- .env dosyaları `.gitignore`'da (güvenlik için)
- Tüm loglar yerel olarak saklanır
- Webhook gönderimi retry mekanizması ile
- Whitelist ile kendi IP'leriniz banlanmaz

## 📝 Lisans

Bu proje açık kaynak kodludur. İstediğiniz gibi kullanabilirsiniz.

## 🤝 Katkıda Bulunma

Pull request'ler memnuniyetle karşılanır. Büyük değişiklikler için önce bir issue açarak neyi değiştirmek istediğinizi tartışın.

## 📞 Destek

Sorun yaşarsanız:
1. [Sorun Giderme](ssh_login/SORUN_GIDERME.md) dokümantasyonunu kontrol edin
2. [Test Rehberi](ssh_login/TEST_REHBERI.md) ile test edin
3. GitHub Issues'da yeni bir issue açın

## ⭐ Özellikler

- ✅ Tek komutla kurulum
- ✅ Otomatik IP banlama
- ✅ SFTP bağlantı tespiti
- ✅ Detaylı Telegram bildirimleri
- ✅ Çoklu sunucu desteği
- ✅ Yapılandırılabilir izleme

