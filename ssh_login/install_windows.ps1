# Kullanıcı Aktivite İzleme Sistemi - Windows Server
# Tek Komutla Otomatik Kurulum
# Kullanım: PowerShell'i Yönetici olarak açın ve çalıştırın:
#   .\install_windows.ps1
# Veya: Invoke-WebRequest -Uri "https://your-domain.com/install_windows.ps1" -OutFile install.ps1; .\install.ps1

# UTF-8 encoding ayarları (Türkçe karakterler için)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Kullanıcı Aktivite İzleme Sistemi" -ForegroundColor Cyan
Write-Host "Windows - Otomatik Kurulum" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Yönetici kontrolü
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[HATA] Bu script YÖNETİCİ olarak çalıştırılmalıdır!" -ForegroundColor Red
    Write-Host "PowerShell'i 'Yönetici olarak çalıştır' ile açın." -ForegroundColor Yellow
    exit 1
}

# Yapılandırma
$InstallDir = "C:\ProgramData\user_activity_monitor"
$ScriptPath = "$InstallDir\user_activity_monitor.py"
$EnvPath = "$InstallDir\user_activity_monitor.env"
$ServiceName = "UserActivityMonitor"
$NSSMPath = "$InstallDir\nssm.exe"
$LogDir = "$InstallDir\logs"

Write-Host "[1/8] Python kontrol ediliyor..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python bulunamadı"
    }
    Write-Host "       Python bulundu: $pythonVersion" -ForegroundColor Green
    $pythonPath = (Get-Command python).Source
    Write-Host "       Python yolu: $pythonPath" -ForegroundColor Gray
} catch {
    Write-Host "[HATA] Python bulunamadı!" -ForegroundColor Red
    Write-Host "       Lütfen Python 3.x kurun: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "       Kurulum sırasında 'Add Python to PATH' seçeneğini işaretleyin." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[2/8] Python paketleri kontrol ediliyor..." -ForegroundColor Yellow
try {
    $null = python -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "       ✓ requests yüklü" -ForegroundColor Green
    } else {
        Write-Host "       requests kuruluyor..." -ForegroundColor Yellow
        python -m pip install requests --quiet
        Write-Host "       ✓ requests kuruldu" -ForegroundColor Green
    }
} catch {
    Write-Host "[HATA] Paket kurulumu başarısız!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[3/8] Kurulum klasörü oluşturuluyor..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "       Klasör oluşturuldu: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "       Klasör zaten var: $InstallDir" -ForegroundColor Gray
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Host ""
Write-Host "[4/8] Python scripti oluşturuluyor..." -ForegroundColor Yellow

# Python script'i GitHub'dan indir (base64 embed sorunlarını önlemek için)
Write-Host "       Python script indiriliyor..." -ForegroundColor Gray
$pythonScriptUrl = "https://raw.githubusercontent.com/Coosef/serverlogin/main/ssh_login/windows_server/user_activity_monitor.py"
try {
    Invoke-WebRequest -Uri $pythonScriptUrl -OutFile $ScriptPath -UseBasicParsing -TimeoutSec 30
    Write-Host "       ✓ Python script indirildi" -ForegroundColor Green
} catch {
    Write-Host "[HATA] Python script indirilemedi: $_" -ForegroundColor Red
    Write-Host "URL: $pythonScriptUrl" -ForegroundColor Yellow
    exit 1
}

Write-Host "       Script oluşturuldu: $ScriptPath" -ForegroundColor Green

Write-Host ""
Write-Host "[5/8] .env dosyası oluşturuluyor..." -ForegroundColor Yellow
if (-not (Test-Path $EnvPath)) {
    $envContent = @"
# Kullanıcı Aktivite İzleme Sistemi - Yapılandırma Dosyası (Windows)
# Değişiklik yaptıktan sonra: Restart-Service UserActivityMonitor

# ============================================
#  ZORUNLU AYARLAR
# ============================================

# n8n webhook URL (zorunlu) - BURAYI DÜZENLEYİN!
WEBHOOK_URL="https://n8vp.yeb.one/webhook/useractivity"

# ============================================
#  GÜVENLİK AYARLARI
# ============================================

# Kaç başarısız denemeden sonra IP banlansın?
MAX_ATTEMPTS=5

# Kaç saniyelik zaman penceresi içinde sayılacak? (örn: 120 = 2 dakika)
TIME_WINDOW_SEC=120

# Ban süresi (saniye) - şimdilik sadece bilgi amaçlı
BAN_DURATION=3600

# Banlanmayacak IP'ler (virgülle ayrılmış)
# Örnek: WHITELIST_IPS="1.2.3.4,5.6.7.8"
WHITELIST_IPS=""

# ============================================
#  SUNUCU BİLGİLERİ
# ============================================

# Sunucu adı (boş bırakırsan hostname kullanılır)
SERVER_NAME=""

# Sunucu IP (boş bırakırsan otomatik tespit edilir)
SERVER_IP=""

# Ortam bilgisi (Production, Staging, Development vb.)
SERVER_ENV="Production"

# ============================================
#  İZLEME AYARLARI
# ============================================

# Başarılı girişler için de bildirim gönderilsin mi? (1 = evet, 0 = hayır)
ALERT_ON_SUCCESS=1

# PowerShell komut geçmişini izle? (1 = evet, 0 = hayır)
MONITOR_COMMANDS=1

# Process oluşturma olaylarını izle? (1 = evet, 0 = hayır)
MONITOR_PROCESSES=1

# Login/logout olaylarını izle? (1 = evet, 0 = hayır)
MONITOR_LOGINS=1

# Dosya erişimlerini izle? (1 = evet, 0 = hayır) - File System Audit gerekir
MONITOR_FILE_ACCESS=0
"@
    $envContent | Out-File -FilePath $EnvPath -Encoding UTF8
    Write-Host "       .env dosyası oluşturuldu: $EnvPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "       ⚠️  ÖNEMLİ: WEBHOOK_URL'i düzenlemeniz gerekiyor!" -ForegroundColor Yellow
    Write-Host "       Dosya: $EnvPath" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "       .env dosyası zaten var, üzerine yazılmadı." -ForegroundColor Gray
}

Write-Host ""
Write-Host "[6/8] NSSM kontrol ediliyor..." -ForegroundColor Yellow
if (-not (Test-Path $NSSMPath)) {
    Write-Host "       NSSM bulunamadı." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       NSSM'i otomatik indirmeyi deniyoruz..." -ForegroundColor Cyan
    
    # NSSM'i otomatik indirmeyi dene
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$InstallDir\nssm.zip"
    $nssmExtract = "$InstallDir\nssm_extract"
    
    try {
        Write-Host "       NSSM indiriliyor..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        $nssmExe = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" | Select-Object -First 1
        if ($nssmExe) {
            Copy-Item $nssmExe.FullName -Destination $NSSMPath -Force
            Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
            Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "       ✓ NSSM otomatik indirildi ve kuruldu" -ForegroundColor Green
        } else {
            throw "nssm.exe bulunamadı"
        }
    } catch {
        Write-Host "       ⚠️  Otomatik indirme başarısız, manuel kurulum gerekli" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "       Manuel kurulum:" -ForegroundColor Cyan
        Write-Host "       1. https://nssm.cc/download adresinden indirin" -ForegroundColor White
        Write-Host "       2. nssm.exe dosyasını şuraya kopyalayın:" -ForegroundColor White
        Write-Host "          $NSSMPath" -ForegroundColor White
        Write-Host ""
        Write-Host "       Alternatif: Chocolatey ile kurulum:" -ForegroundColor Cyan
        Write-Host "       choco install nssm" -ForegroundColor White
        Write-Host ""
        
        $continue = Read-Host "       NSSM'i manuel olarak indirdiniz mi? (E/H)"
        if ($continue -ne "E" -and $continue -ne "e") {
            Write-Host "[HATA] NSSM gerekli, kurulum iptal edildi." -ForegroundColor Red
            exit 1
        }
        
        if (-not (Test-Path $NSSMPath)) {
            Write-Host "[HATA] NSSM hala bulunamadı: $NSSMPath" -ForegroundColor Red
            exit 1
        }
    }
} else {
    Write-Host "       ✓ NSSM bulundu" -ForegroundColor Green
}

Write-Host ""
Write-Host "[7/8] Windows Service kuruluyor..." -ForegroundColor Yellow

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "       Mevcut servis durduruluyor..." -ForegroundColor Gray
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "       Mevcut servis kaldırılıyor..." -ForegroundColor Gray
    & $NSSMPath remove $ServiceName confirm
}

Write-Host "       Servis yükleniyor..." -ForegroundColor Gray
& $NSSMPath install $ServiceName $pythonPath $ScriptPath

if ($LASTEXITCODE -ne 0) {
    Write-Host "[HATA] Servis kurulumu başarısız!" -ForegroundColor Red
    exit 1
}

Write-Host "       Servis ayarları yapılandırılıyor..." -ForegroundColor Gray
& $NSSMPath set $ServiceName AppDirectory $InstallDir
& $NSSMPath set $ServiceName DisplayName "User Activity Monitor"
& $NSSMPath set $ServiceName Description "Comprehensive User Activity Monitor with n8n webhook and auto-ban for Windows"
& $NSSMPath set $ServiceName Start SERVICE_AUTO_START
& $NSSMPath set $ServiceName AppStdout "$LogDir\service_stdout.log"
& $NSSMPath set $ServiceName AppStderr "$LogDir\service_stderr.log"

Write-Host ""
Write-Host "[8/8] Servis başlatılıyor..." -ForegroundColor Yellow
Start-Service -Name $ServiceName

Start-Sleep -Seconds 2

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ Kurulum başarıyla tamamlandı!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Servis Bilgileri:" -ForegroundColor Cyan
    Write-Host "  Adı: $ServiceName" -ForegroundColor White
    Write-Host "  Durum: $($service.Status)" -ForegroundColor White
    Write-Host "  Script: $ScriptPath" -ForegroundColor White
    Write-Host "  Config: $EnvPath" -ForegroundColor White
    Write-Host "  Loglar: $LogDir" -ForegroundColor White
    Write-Host ""
    Write-Host "Yararlı Komutlar:" -ForegroundColor Cyan
    Write-Host "  Servis durumu:     Get-Service $ServiceName" -ForegroundColor White
    Write-Host "  Servis durdur:     Stop-Service $ServiceName" -ForegroundColor White
    Write-Host "  Servis başlat:     Start-Service $ServiceName" -ForegroundColor White
    Write-Host "  Servis yeniden:    Restart-Service $ServiceName" -ForegroundColor White
    Write-Host "  Logları görüntüle: Get-Content $LogDir\activity_monitor.log -Tail 50" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  ÖNEMLİ: .env dosyasında WEBHOOK_URL'i düzenleyin!" -ForegroundColor Yellow
    Write-Host "   Dosya: $EnvPath" -ForegroundColor Yellow
    Write-Host "   Düzenleme sonrası: Restart-Service $ServiceName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📝 Örnek:" -ForegroundColor Cyan
    Write-Host "   notepad $EnvPath" -ForegroundColor White
    Write-Host "   # WEBHOOK_URL=`"https://your-n8n-url.com/webhook/...`" satırını düzenleyin" -ForegroundColor White
    Write-Host "   Restart-Service $ServiceName" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "[UYARI] Servis kuruldu ancak başlatılamadı!" -ForegroundColor Yellow
    Write-Host "        Lütfen manuel olarak kontrol edin:" -ForegroundColor Yellow
    Write-Host "        Get-Service $ServiceName" -ForegroundColor White
    Write-Host "        Get-Content $LogDir\service_stderr.log" -ForegroundColor White
}

