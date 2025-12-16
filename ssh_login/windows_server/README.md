# SSH n8n Monitor - Windows Server

Windows Server'larda SSH giriş denemelerini izleyen, otomatik IP banlama yapan ve n8n webhook'a bildirim gönderen sistem.

## 🎯 Özellikler

- ✅ Windows Event Log'dan SSH girişlerini izler
- ✅ Başarısız giriş denemelerini tespit eder
- ✅ Otomatik IP banlama (Windows Firewall)
- ✅ n8n webhook'a bildirim gönderir
- ✅ Zaman penceresi bazlı banlama (örn: 120 saniye içinde 5 deneme)
- ✅ Whitelist desteği
- ✅ Windows Service olarak çalışır (otomatik başlatma)
- ✅ Detaylı loglama

## 📋 Gereksinimler

- Windows Server 2016 veya üzeri
- Python 3.7 veya üzeri
- Yönetici yetkileri
- OpenSSH Server kurulu ve çalışıyor olmalı

## 🚀 Hızlı Kurulum

### 1. Dosyaları İndirin

Tüm dosyaları Windows sunucunuza kopyalayın:
- `ssh_n8n_monitor.py`
- `ssh_n8n_monitor.env.template`
- `install.ps1`

### 2. Kurulum Scriptini Çalıştırın

PowerShell'i **Yönetici olarak** açın ve şu komutu çalıştırın:

```powershell
cd C:\path\to\windows_server
.\install.ps1
```

Script otomatik olarak:
- Python kontrolü yapar
- Gerekli paketleri kurar (`requests`)
- Klasörleri oluşturur
- Python scriptini kopyalar
- .env dosyasını oluşturur
- NSSM kurulumunu yönlendirir
- Windows Service'i kurar ve başlatır

### 3. NSSM Kurulumu

Eğer NSSM yoksa:

**Seçenek 1: Manuel İndirme**
1. https://nssm.cc/download adresinden indirin
2. `nssm.exe` dosyasını `C:\ProgramData\ssh_n8n_monitor\` klasörüne kopyalayın

**Seçenek 2: Chocolatey**
```powershell
choco install nssm
```

### 4. Yapılandırma

`.env` dosyasını düzenleyin:

```powershell
notepad C:\ProgramData\ssh_n8n_monitor\ssh_n8n_monitor.env
```

**Zorunlu ayar:**
```env
WEBHOOK_URL="https://n8vp.yeb.one/webhook/sshloginfail"
```

Değişiklik sonrası servisi yeniden başlatın:
```powershell
Restart-Service SSHn8nMonitor
```

## ⚙️ Yapılandırma

`.env` dosyasındaki tüm ayarlar:

| Ayar | Açıklama | Varsayılan |
|------|----------|------------|
| `WEBHOOK_URL` | n8n webhook URL'i (zorunlu) | - |
| `MAX_ATTEMPTS` | Ban eşiği (kaç deneme) | 5 |
| `TIME_WINDOW_SEC` | Zaman penceresi (saniye) | 120 |
| `BAN_DURATION` | Ban süresi (saniye) | 3600 |
| `WHITELIST_IPS` | Banlanmayacak IP'ler | - |
| `SERVER_NAME` | Sunucu adı | hostname |
| `SERVER_IP` | Sunucu IP | otomatik |
| `SERVER_ENV` | Ortam (Production/Staging) | Production |
| `ALERT_ON_SUCCESS` | Başarılı giriş bildirimi | 1 |

## 📊 Kullanım

### Servis Yönetimi

```powershell
# Servis durumu
Get-Service SSHn8nMonitor

# Servis başlat
Start-Service SSHn8nMonitor

# Servis durdur
Stop-Service SSHn8nMonitor

# Servis yeniden başlat
Restart-Service SSHn8nMonitor
```

### Logları Görüntüleme

```powershell
# Ana log
Get-Content C:\ProgramData\ssh_n8n_monitor\logs\ssh_monitor.log -Tail 50

# Webhook hataları
Get-Content C:\ProgramData\ssh_n8n_monitor\logs\webhook_errors.log -Tail 50

# Servis çıktıları
Get-Content C:\ProgramData\ssh_n8n_monitor\logs\service_stdout.log -Tail 50
```

### IP Ban Yönetimi

**Banlanan IP'leri görüntüle:**
```powershell
netsh advfirewall firewall show rule name=all | Select-String "SSH_BAN"
```

**IP banını kaldır:**
```powershell
netsh advfirewall firewall delete rule name="SSH_BAN_1_2_3_4"
```

## 🔧 Sorun Giderme

### Servis başlamıyor

1. Logları kontrol edin:
   ```powershell
   Get-Content C:\ProgramData\ssh_n8n_monitor\logs\service_stderr.log
   ```

2. Python path'i kontrol edin:
   ```powershell
   python --version
   ```

3. .env dosyasını kontrol edin:
   ```powershell
   Get-Content C:\ProgramData\ssh_n8n_monitor\ssh_n8n_monitor.env
   ```

### Webhook gönderilmiyor

1. WEBHOOK_URL'in doğru olduğundan emin olun
2. İnternet bağlantısını kontrol edin
3. `webhook_errors.log` dosyasını kontrol edin

### Event'ler yakalanmıyor

1. OpenSSH Server'ın çalıştığından emin olun:
   ```powershell
   Get-Service sshd
   ```

2. Event Log'u kontrol edin:
   ```powershell
   Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 10
   ```

## 📁 Dosya Yapısı

```
C:\ProgramData\ssh_n8n_monitor\
├── ssh_n8n_monitor.py          # Ana Python scripti
├── ssh_n8n_monitor.env         # Yapılandırma dosyası
├── nssm.exe                     # NSSM (service manager)
└── logs\
    ├── ssh_monitor.log          # Ana log dosyası
    ├── webhook_errors.log       # Webhook hata logları
    ├── service_stdout.log       # Servis stdout
    └── service_stderr.log       # Servis stderr
```

## 🔄 Güncelleme

1. Yeni `ssh_n8n_monitor.py` dosyasını kopyalayın
2. Servisi yeniden başlatın:
   ```powershell
   Restart-Service SSHn8nMonitor
   ```

## 🆘 Destek

Sorun yaşarsanız:
1. Log dosyalarını kontrol edin
2. Servis durumunu kontrol edin
3. .env dosyasındaki ayarları doğrulayın

## 📝 Notlar

- Servis SYSTEM hesabıyla çalışır
- Windows Firewall kuralları otomatik oluşturulur
- Banlanan IP'ler `SSH_BAN_` prefix'i ile saklanır
- Loglar UTF-8 encoding ile yazılır

