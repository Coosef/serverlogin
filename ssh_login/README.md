# Kullanıcı Aktivite İzleme Sistemi

Kapsamlı kullanıcı aktivite izleme sistemi - Hem Linux hem Windows Server için.

## 🎯 Özellikler

### İzlenen Aktivite Türleri

#### Linux:
- ✅ SSH giriş/çıkış (başarılı/başarısız)
- ✅ Tüm login/logout olayları
- ✅ Komut geçmişi (bash/zsh history)
- ✅ Sudo komutları ve başarısız denemeler
- ✅ Session açma/kapama
- ✅ Otomatik IP banlama (iptables)

#### Windows:
- ✅ Windows Logon/Logoff (Event ID 4624, 4634)
- ✅ Başarısız giriş denemeleri (Event ID 4625)
- ✅ SSH giriş/çıkış (OpenSSH Event Log)
- ✅ Process oluşturma (Event ID 4688)
- ✅ Dosya erişimleri (Event ID 4663) - opsiyonel
- ✅ Registry erişimleri (Event ID 4657) - opsiyonel
- ✅ PowerShell komut geçmişi
- ✅ Otomatik IP banlama (Windows Firewall)

### Genel Özellikler:
- ✅ n8n webhook entegrasyonu
- ✅ Zaman penceresi bazlı banlama
- ✅ Whitelist desteği
- ✅ Detaylı loglama
- ✅ Windows Service / Linux systemd servisi
- ✅ Otomatik başlatma
- ✅ Yapılandırılabilir izleme seçenekleri

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
- NSSM (Non-Sucking Service Manager)

## 🚀 Kurulum (Tek Komutla!)

### Linux Kurulumu (En Basit Yöntem)

**Tek komutla kurulum:**

```bash
# Yöntem 1: curl ile (önerilen)
curl -sSL https://your-domain.com/install_linux.sh | sudo bash

# Yöntem 2: wget ile
wget -qO- https://your-domain.com/install_linux.sh | sudo bash

# Yöntem 3: Dosyayı indirip çalıştır
wget https://your-domain.com/install_linux.sh
sudo bash install_linux.sh
```

**Kurulum sonrası yapılandırma:**
```bash
sudo nano /opt/user_activity_monitor.env
# WEBHOOK_URL="https://your-n8n-url.com/webhook/..." satırını düzenleyin
sudo systemctl restart user_activity_monitor.service
```

### Windows Kurulumu (En Basit Yöntem)

**PowerShell'i Yönetici olarak açın ve çalıştırın:**

```powershell
# Yöntem 1: Doğrudan indirip çalıştır (önerilen)
Invoke-WebRequest -Uri "https://your-domain.com/install_windows.ps1" -OutFile install.ps1
.\install.ps1

# Yöntem 2: Dosyayı indirip çalıştır
# install_windows.ps1 dosyasını indirin, sonra:
.\install_windows.ps1
```

**Not:** NSSM otomatik olarak indirilmeye çalışılır. Başarısız olursa manuel kurulum gerekir.

**Kurulum sonrası yapılandırma:**
```powershell
notepad C:\ProgramData\user_activity_monitor\user_activity_monitor.env
# WEBHOOK_URL="https://your-n8n-url.com/webhook/..." satırını düzenleyin
Restart-Service UserActivityMonitor
```

### Alternatif: Manuel Kurulum

Eğer tek dosya kurulumunu tercih etmiyorsanız, klasör içindeki dosyaları kullanabilirsiniz:

**Linux:**
```bash
cd linux_server
sudo ./install.sh
```

**Windows:**
```powershell
cd windows_server
.\user_activity_install.ps1
```

## ⚙️ Yapılandırma

### .env Dosyası Ayarları

| Ayar | Açıklama | Varsayılan |
|------|----------|------------|
| `WEBHOOK_URL` | n8n webhook URL'i (zorunlu) | - |
| `MAX_ATTEMPTS` | Ban eşiği (kaç deneme) | 5 |
| `TIME_WINDOW_SEC` | Zaman penceresi (saniye) | 120 |
| `BAN_DURATION` | Ban süresi (saniye) | 3600 |
| `WHITELIST_IPS` | Banlanmayacak IP'ler | - |
| `SERVER_NAME` | Sunucu adı | hostname |
| `SERVER_IP` | Sunucu IP | otomatik |
| `SERVER_ENV` | Ortam | Production |
| `ALERT_ON_SUCCESS` | Başarılı giriş bildirimi | 1 |
| `MONITOR_COMMANDS` | Komut geçmişi izleme | 1 |
| `MONITOR_SUDO` | Sudo izleme (Linux) | 1 |
| `MONITOR_PROCESSES` | Process izleme (Windows) | 1 |
| `MONITOR_LOGINS` | Login/logout izleme | 1 |
| `MONITOR_FILE_ACCESS` | Dosya erişimi izleme | 0 |

## 📊 Kullanım

### Linux

```bash
# Servis durumu
sudo systemctl status user_activity_monitor

# Servis başlat
sudo systemctl start user_activity_monitor

# Servis durdur
sudo systemctl stop user_activity_monitor

# Servis yeniden başlat
sudo systemctl restart user_activity_monitor

# Logları görüntüle
sudo tail -f /var/log/user_activity_monitor/activity_monitor.log
```

### Windows

```powershell
# Servis durumu
Get-Service UserActivityMonitor

# Servis başlat
Start-Service UserActivityMonitor

# Servis durdur
Stop-Service UserActivityMonitor

# Servis yeniden başlat
Restart-Service UserActivityMonitor

# Logları görüntüle
Get-Content C:\ProgramData\user_activity_monitor\logs\activity_monitor.log -Tail 50
```

## 📡 n8n Webhook Formatı

Sistem aşağıdaki event tiplerini gönderir:

### Event Tipleri

#### Linux:
- `ssh_invalid_user` - Geçersiz kullanıcı denemesi
- `ssh_failed_login` - Başarısız SSH girişi
- `ssh_success_login` - Başarılı SSH girişi
- `ssh_logout` - SSH çıkışı
- `sudo_command` - Sudo komutu çalıştırıldı
- `sudo_failed` - Sudo başarısız deneme
- `session_opened` - Session açıldı
- `session_closed` - Session kapandı
- `command_executed` - Komut çalıştırıldı

#### Windows:
- `logon_success` - Başarılı Windows girişi
- `logon_failed` - Başarısız Windows girişi
- `logoff` - Windows çıkışı
- `process_create` - Yeni process oluşturuldu
- `file_access` - Dosya erişimi (opsiyonel)
- `ssh_success_login` - Başarılı SSH girişi
- `ssh_failed_login` - Başarısız SSH girişi

### Webhook Payload Örneği

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+00:00",
  "service": "user_activity",
  "server_name": "server-01",
  "server_ip": "192.168.1.100",
  "server_env": "Production",
  "event_type": "ssh_failed_login",
  "user": "root",
  "ip": "1.2.3.4",
  "port": "54321",
  "fail_count_window": 3,
  "ban_triggered": false,
  "raw_log": "Failed password for root from 1.2.3.4 port 54321 ssh2"
}
```

## 🔧 Sorun Giderme

### Linux

**Servis başlamıyor:**
```bash
# Logları kontrol et
sudo journalctl -u user_activity_monitor -n 50

# Python path kontrolü
which python3

# .env dosyası kontrolü
sudo cat /opt/user_activity_monitor.env
```

**Event'ler yakalanmıyor:**
```bash
# auth.log kontrolü
sudo tail -f /var/log/auth.log

# SSH servisi kontrolü
sudo systemctl status ssh
```

### Windows

**Servis başlamıyor:**
```powershell
# Logları kontrol et
Get-Content C:\ProgramData\user_activity_monitor\logs\service_stderr.log

# Python kontrolü
python --version

# .env dosyası kontrolü
Get-Content C:\ProgramData\user_activity_monitor\user_activity_monitor.env
```

**Event'ler yakalanmıyor:**
```powershell
# Event Log kontrolü
Get-WinEvent -LogName "Security" -MaxEvents 10
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 10
```

## 📁 Dosya Yapısı

### Linux:
```
/opt/
├── user_activity_monitor.py          # Ana script
└── user_activity_monitor.env        # Yapılandırma

/var/log/user_activity_monitor/
├── activity_monitor.log              # Ana log
└── webhook_errors.log                # Webhook hataları

/etc/systemd/system/
└── user_activity_monitor.service     # Systemd servisi
```

### Windows:
```
C:\ProgramData\user_activity_monitor\
├── user_activity_monitor.py          # Ana script
├── user_activity_monitor.env         # Yapılandırma
├── nssm.exe                          # NSSM
└── logs\
    ├── activity_monitor.log          # Ana log
    ├── webhook_errors.log            # Webhook hataları
    ├── service_stdout.log            # Servis stdout
    └── service_stderr.log            # Servis stderr
```

## 🔄 Güncelleme

### Linux:
```bash
# Yeni scripti kopyala
sudo cp user_activity_monitor.py /opt/
sudo systemctl restart user_activity_monitor.service
```

### Windows:
```powershell
# Yeni scripti kopyala
Copy-Item user_activity_monitor.py C:\ProgramData\user_activity_monitor\
Restart-Service UserActivityMonitor
```

## 🆘 Destek

Sorun yaşarsanız:
1. Log dosyalarını kontrol edin
2. Servis durumunu kontrol edin
3. .env dosyasındaki ayarları doğrulayın
4. Python ve bağımlılıkları kontrol edin

## 📝 Notlar

- Servisler root/SYSTEM hesabıyla çalışır
- IP banlama otomatik yapılır (iptables/Windows Firewall)
- Loglar UTF-8 encoding ile yazılır
- Webhook gönderimi retry mekanizması ile yapılır
- Komut geçmişi izleme periyodik olarak kontrol edilir (30 saniye)

## 🔐 Güvenlik

- .env dosyası sadece root/yönetici tarafından okunabilir
- Log dosyaları güvenli klasörlerde saklanır
- Whitelist ile kendi IP'leriniz banlanmaz
- Tüm aktiviteler loglanır ve n8n'e gönderilir

# Hostname'i görüntüle
hostname

# Eğer boşsa, ayarla
sudo hostnamectl set-hostname "my-server-name"
sudo systemctl restart user_activity_monitor.service