# Kullanıcı Aktivite İzleme Sistemi - Windows Server Kurulum Scripti
# Yönetici olarak çalıştırılmalıdır!
# Kullanım: .\user_activity_install.ps1

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Kullanıcı Aktivite İzleme Sistemi" -ForegroundColor Cyan
Write-Host "Windows Kurulum" -ForegroundColor Cyan
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

Write-Host "[1/7] Python kontrol ediliyor..." -ForegroundColor Yellow
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
    exit 1
}

Write-Host ""
Write-Host "[2/7] Python paketleri kontrol ediliyor..." -ForegroundColor Yellow
$requiredPackages = @("requests")
$missingPackages = @()

foreach ($package in $requiredPackages) {
    try {
        $null = python -c "import $package" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "       ✓ $package yüklü" -ForegroundColor Green
        } else {
            $missingPackages += $package
        }
    } catch {
        $missingPackages += $package
    }
}

if ($missingPackages.Count -gt 0) {
    Write-Host "       Eksik paketler kuruluyor: $($missingPackages -join ', ')" -ForegroundColor Yellow
    python -m pip install $missingPackages --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[HATA] Paket kurulumu başarısız!" -ForegroundColor Red
        exit 1
    }
    Write-Host "       ✓ Paketler kuruldu" -ForegroundColor Green
}

Write-Host ""
Write-Host "[3/7] Kurulum klasörü oluşturuluyor..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "       Klasör oluşturuldu: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "       Klasör zaten var: $InstallDir" -ForegroundColor Gray
}

$LogDir = "$InstallDir\logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Host ""
Write-Host "[4/7] Python scripti kopyalanıyor..." -ForegroundColor Yellow
$scriptSource = Join-Path $PSScriptRoot "user_activity_monitor.py"
if (Test-Path $scriptSource) {
    Copy-Item -Path $scriptSource -Destination $ScriptPath -Force
    Write-Host "       Script kopyalandı: $ScriptPath" -ForegroundColor Green
} else {
    Write-Host "[HATA] user_activity_monitor.py bulunamadı!" -ForegroundColor Red
    Write-Host "       Script ile aynı klasörde olmalı." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[5/7] .env dosyası kontrol ediliyor..." -ForegroundColor Yellow
$envTemplate = Join-Path $PSScriptRoot "user_activity_monitor.env.template"

if (-not (Test-Path $EnvPath)) {
    if (Test-Path $envTemplate) {
        Copy-Item -Path $envTemplate -Destination $EnvPath
        Write-Host "       .env dosyası oluşturuldu: $EnvPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "       ⚠️  ÖNEMLİ: WEBHOOK_URL'i düzenlemeniz gerekiyor!" -ForegroundColor Yellow
        Write-Host "       Dosya: $EnvPath" -ForegroundColor Yellow
        Write-Host ""
        
        $open = Read-Host "       .env dosyasını şimdi açmak ister misiniz? (E/H)"
        if ($open -eq "E" -or $open -eq "e") {
            notepad $EnvPath
        }
    } else {
        Write-Host "[HATA] .env template bulunamadı!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "       .env dosyası zaten var, üzerine yazılmadı." -ForegroundColor Gray
    Write-Host "       Mevcut dosya: $EnvPath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[6/7] NSSM kontrol ediliyor..." -ForegroundColor Yellow
if (-not (Test-Path $NSSMPath)) {
    Write-Host "       NSSM bulunamadı, indiriliyor..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       ⚠️  NSSM manuel olarak indirilmelidir:" -ForegroundColor Yellow
    Write-Host "       1. https://nssm.cc/download adresinden indirin" -ForegroundColor Cyan
    Write-Host "       2. nssm.exe dosyasını şuraya kopyalayın:" -ForegroundColor Cyan
    Write-Host "          $NSSMPath" -ForegroundColor White
    Write-Host ""
    Write-Host "       Alternatif: Chocolatey ile kurulum:" -ForegroundColor Cyan
    Write-Host "       choco install nssm" -ForegroundColor White
    Write-Host ""
    
    $continue = Read-Host "       NSSM'i indirdiniz mi? (E/H)"
    if ($continue -ne "E" -and $continue -ne "e") {
        Write-Host "[HATA] NSSM gerekli, kurulum iptal edildi." -ForegroundColor Red
        exit 1
    }
    
    if (-not (Test-Path $NSSMPath)) {
        Write-Host "[HATA] NSSM hala bulunamadı: $NSSMPath" -ForegroundColor Red
        exit 1
    }
}

Write-Host "       ✓ NSSM bulundu" -ForegroundColor Green

Write-Host ""
Write-Host "[7/7] Windows Service kuruluyor..." -ForegroundColor Yellow

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

Write-Host "       Servis başlatılıyor..." -ForegroundColor Gray
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
} else {
    Write-Host ""
    Write-Host "[UYARI] Servis kuruldu ancak başlatılamadı!" -ForegroundColor Yellow
    Write-Host "        Lütfen manuel olarak kontrol edin:" -ForegroundColor Yellow
    Write-Host "        Get-Service $ServiceName" -ForegroundColor White
    Write-Host "        Get-Content $LogDir\service_stderr.log" -ForegroundColor White
}

