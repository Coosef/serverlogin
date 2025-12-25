# Windows Server Kurulum Rehberi

Windows Server'a Kullanıcı Aktivite İzleme Sistemi kurulum adımları.

## 📋 Ön Gereksinimler

1. **Windows Server 2016 veya üzeri**
2. **Python 3.7+** (kurulu olmalı)
3. **Yönetici yetkileri**
4. **İnternet bağlantısı** (NSSM indirmek için)

## 🚀 Kurulum Adımları

### Adım 1: Python Kontrolü

PowerShell'i **Yönetici olarak** açın ve Python'un kurulu olduğunu kontrol edin:

```powershell
python --version
```

**Eğer Python yoksa:**
1. https://www.python.org/downloads/ adresinden Python 3.7+ indirin
2. Kurulum sırasında **"Add Python to PATH"** seçeneğini işaretleyin
3. Kurulumdan sonra PowerShell'i kapatıp tekrar açın

### Adım 2: Kurulum Dosyalarını İndirin

**Seçenek 1: GitHub'dan İndir (Önerilen)**

```powershell
# PowerShell'i Yönetici olarak açın
cd C:\
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coosef/serverlogin/main/ssh_login/install_windows.ps1" -OutFile install_windows.ps1
```

**Seçenek 2: Manuel İndir**

1. https://github.com/Coosef/serverlogin adresine gidin
2. `Code` → `Download ZIP` ile indirin
3. ZIP'i açın ve `ssh_login/install_windows.ps1` dosyasını bulun

### Adım 3: Kurulum Scriptini Çalıştırın

```powershell
# PowerShell'i Yönetici olarak açın
cd C:\  # veya install_windows.ps1'in bulunduğu klasör
.\install_windows.ps1
```

**Not:** İlk çalıştırmada execution policy hatası alırsanız:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Adım 4: NSSM Kurulumu

Script otomatik olarak NSSM'i indirmeye çalışır. Eğer başarısız olursa:

**Manuel Kurulum:**

1. https://nssm.cc/download adresinden NSSM indirin
2. ZIP'i açın ve `win64` veya `win32` klasöründen `nssm.exe` dosyasını kopyalayın
3. `C:\ProgramData\user_activity_monitor\` klasörüne yapıştırın
4. Script'i tekrar çalıştırın

**Veya Chocolatey ile:**

```powershell
choco install nssm
```

### Adım 5: Yapılandırma

Kurulum tamamlandıktan sonra `.env` dosyasını düzenleyin:

```powershell
notepad C:\ProgramData\user_activity_monitor\user_activity_monitor.env
```

**Zorunlu ayar:**
```env
WEBHOOK_URL="https://your-n8n-url.com/webhook/..."
```

**Kaydedin ve servisi yeniden başlatın:**
```powershell
Restart-Service UserActivityMonitor
```

## ✅ Kurulum Kontrolü

### Servis Durumu

```powershell
Get-Service UserActivityMonitor
```

**Beklenen çıktı:**
```
Status   Name               DisplayName
------   ----               -----------
Running  UserActivityMonitor User Activity Monitor
```

### Logları Kontrol Et

```powershell
# Ana log
Get-Content C:\ProgramData\user_activity_monitor\logs\activity_monitor.log -Tail 50

# Webhook hataları
Get-Content C:\ProgramData\user_activity_monitor\logs\webhook_errors.log -Tail 50

# Servis çıktıları
Get-Content C:\ProgramData\user_activity_monitor\logs\service_stdout.log -Tail 50
```

## 🔧 Servis Yönetimi

### Servis Komutları

```powershell
# Servis durumu
Get-Service UserActivityMonitor

# Servis başlat
Start-Service UserActivityMonitor

# Servis durdur
Stop-Service UserActivityMonitor

# Servis yeniden başlat
Restart-Service UserActivityMonitor

# Servis durumunu detaylı görüntüle
Get-Service UserActivityMonitor | Format-List *
```

### Servis Logları (Event Viewer)

```powershell
# Windows Event Viewer'da servis loglarını görüntüle
eventvwr.msc
# Applications and Services Logs → User Activity Monitor
```

## 📊 Test Etme

### 1. SSH Bağlantı Testi

Başka bir terminalden Windows sunucuya SSH ile bağlanın:

```bash
ssh user@windows-server-ip
```

Telegram'da bildirim gelmeli.

### 2. Windows Logon Testi

Windows sunucuda oturum açıp kapatın. Event Log'dan logon/logoff eventleri yakalanmalı.

### 3. Process Testi

Windows sunucuda yeni bir process başlatın (örnek: notepad). Process create eventi yakalanmalı.

## 🐛 Sorun Giderme

### Servis başlamıyor

```powershell
# Hata loglarını kontrol et
Get-Content C:\ProgramData\user_activity_monitor\logs\service_stderr.log

# Python path kontrolü
python --version
where python

# .env dosyası kontrolü
Get-Content C:\ProgramData\user_activity_monitor\user_activity_monitor.env
```

### Webhook gönderilmiyor

```powershell
# WEBHOOK_URL kontrolü
Select-String -Path "C:\ProgramData\user_activity_monitor\user_activity_monitor.env" -Pattern "WEBHOOK_URL"

# Webhook hatalarını kontrol et
Get-Content C:\ProgramData\user_activity_monitor\logs\webhook_errors.log
```

### Event'ler yakalanmıyor

```powershell
# Event Log kontrolü
Get-WinEvent -LogName "Security" -MaxEvents 10
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 10

# OpenSSH Server çalışıyor mu?
Get-Service sshd
```

### NSSM bulunamadı

```powershell
# NSSM path kontrolü
Test-Path C:\ProgramData\user_activity_monitor\nssm.exe

# Manuel olarak kopyalayın:
# 1. https://nssm.cc/download indirin
# 2. nssm.exe'yi C:\ProgramData\user_activity_monitor\ klasörüne kopyalayın
```

## 📁 Dosya Yapısı

```
C:\ProgramData\user_activity_monitor\
├── user_activity_monitor.py          # Ana Python scripti
├── user_activity_monitor.env         # Yapılandırma dosyası
├── nssm.exe                          # NSSM (service manager)
└── logs\
    ├── activity_monitor.log          # Ana log dosyası
    ├── webhook_errors.log           # Webhook hata logları
    ├── service_stdout.log           # Servis stdout
    └── service_stderr.log           # Servis stderr
```

## 🔄 Güncelleme

### Yeni Script Güncelleme

```powershell
# 1. Yeni install_windows.ps1'i indirin
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coosef/serverlogin/main/ssh_login/install_windows.ps1" -OutFile install_windows.ps1

# 2. Script'i tekrar çalıştırın (sadece Python script güncellenir)
.\install_windows.ps1

# 3. Servisi yeniden başlatın
Restart-Service UserActivityMonitor
```

## 📝 Önemli Notlar

- Servis **SYSTEM** hesabıyla çalışır
- Windows Firewall kuralları otomatik oluşturulur
- Loglar UTF-8 encoding ile yazılır
- .env dosyası değişikliklerinde servisi yeniden başlatın
- NSSM olmadan Windows Service çalışmaz

## 🆘 Yardım

Sorun yaşarsanız:
1. Log dosyalarını kontrol edin
2. Servis durumunu kontrol edin
3. .env dosyasındaki ayarları doğrulayın
4. GitHub Issues'da sorun bildirin

