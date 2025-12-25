# User Activity Monitoring System - Windows Server
# One-Command Automatic Installation
# Usage: Open PowerShell as Administrator and run:
#   .\install_windows.ps1
# Or: Invoke-WebRequest -Uri "https://your-domain.com/install_windows.ps1" -OutFile install.ps1; .\install.ps1

# UTF-8 encoding settings
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ErrorActionPreference = "Stop"

# Fix BOM issue if script was downloaded with BOM
$scriptContent = Get-Content $PSCommandPath -Raw -Encoding UTF8
if ($scriptContent -match '^\xEF\xBB\xBF') {
    $scriptContent = $scriptContent.Substring(3)
    Set-Content -Path $PSCommandPath -Value $scriptContent -Encoding UTF8 -NoNewline
    & $PSCommandPath
    exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "User Activity Monitoring System" -ForegroundColor Cyan
Write-Host "Windows - Automatic Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Administrator check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as ADMINISTRATOR!" -ForegroundColor Red
    Write-Host "Please open PowerShell with 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# Configuration
$InstallDir = "C:\ProgramData\user_activity_monitor"
$ScriptPath = "$InstallDir\user_activity_monitor.py"
$EnvPath = "$InstallDir\user_activity_monitor.env"
$ServiceName = "UserActivityMonitor"
$NSSMPath = "$InstallDir\nssm.exe"
$LogDir = "$InstallDir\logs"

Write-Host "[1/8] Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-Host "       Python found: $pythonVersion" -ForegroundColor Green
    $pythonPath = (Get-Command python).Source
    Write-Host "       Python path: $pythonPath" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Python not found!" -ForegroundColor Red
    Write-Host "       Please install Python 3.x: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "       Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[2/8] Checking Python packages..." -ForegroundColor Yellow
try {
    $null = python -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "       ✓ requests installed" -ForegroundColor Green
    } else {
        Write-Host "       Installing requests..." -ForegroundColor Yellow
        python -m pip install requests --quiet
        Write-Host "       ✓ requests installed" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Package installation failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[3/8] Creating installation directory..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "       Directory created: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "       Directory already exists: $InstallDir" -ForegroundColor Gray
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Host ""
Write-Host "[4/8] Creating Python script..." -ForegroundColor Yellow

# Download Python script from GitHub (to avoid base64 embed issues)
Write-Host "       Downloading Python script..." -ForegroundColor Gray
$pythonScriptUrl = "https://raw.githubusercontent.com/Coosef/serverlogin/main/ssh_login/windows_server/user_activity_monitor.py"
try {
    Invoke-WebRequest -Uri $pythonScriptUrl -OutFile $ScriptPath -UseBasicParsing -TimeoutSec 30
    Write-Host "       ✓ Python script downloaded" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to download Python script: $_" -ForegroundColor Red
    Write-Host "URL: $pythonScriptUrl" -ForegroundColor Yellow
    exit 1
}

Write-Host "       Script created: $ScriptPath" -ForegroundColor Green

Write-Host ""
Write-Host "[5/8] Creating .env file..." -ForegroundColor Yellow
if (-not (Test-Path $EnvPath)) {
    $envContent = @"
# User Activity Monitoring System - Configuration File (Windows)
# After making changes: Restart-Service UserActivityMonitor

# ============================================
#  REQUIRED SETTINGS
# ============================================

# n8n webhook URL (required) - EDIT THIS!
WEBHOOK_URL="https://n8vp.yeb.one/webhook/useractivity"

# ============================================
#  SECURITY SETTINGS
# ============================================

# How many failed attempts before IP is banned?
MAX_ATTEMPTS=5

# Time window in seconds for counting attempts (e.g., 120 = 2 minutes)
TIME_WINDOW_SEC=120

# Ban duration (seconds) - currently informational only
BAN_DURATION=3600

# IPs that should not be banned (comma-separated)
# Example: WHITELIST_IPS="1.2.3.4,5.6.7.8"
WHITELIST_IPS=""

# ============================================
#  SERVER INFORMATION
# ============================================

# Server name (leave empty to use hostname)
SERVER_NAME=""

# Server IP (leave empty for automatic detection)
SERVER_IP=""

# Environment information (Production, Staging, Development, etc.)
SERVER_ENV="Production"

# ============================================
#  MONITORING SETTINGS
# ============================================

# Send notifications for successful logins? (1 = yes, 0 = no)
ALERT_ON_SUCCESS=1

# Monitor PowerShell command history? (1 = yes, 0 = no)
MONITOR_COMMANDS=1

# Monitor process creation events? (1 = yes, 0 = no)
MONITOR_PROCESSES=1

# Monitor login/logout events? (1 = yes, 0 = no)
MONITOR_LOGINS=1

# Monitor file access? (1 = yes, 0 = no) - Requires File System Audit
MONITOR_FILE_ACCESS=0
"@
    $envContent | Out-File -FilePath $EnvPath -Encoding UTF8
    Write-Host "       .env file created: $EnvPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "       ⚠️  IMPORTANT: You need to edit WEBHOOK_URL!" -ForegroundColor Yellow
    Write-Host "       File: $EnvPath" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "       .env file already exists, not overwritten." -ForegroundColor Gray
}

Write-Host ""
Write-Host "[6/8] Checking NSSM..." -ForegroundColor Yellow
if (-not (Test-Path $NSSMPath)) {
    Write-Host "       NSSM not found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       Attempting to download NSSM automatically..." -ForegroundColor Cyan
    
    # Try to download NSSM automatically
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$InstallDir\nssm.zip"
    $nssmExtract = "$InstallDir\nssm_extract"
    
    try {
        Write-Host "       Downloading NSSM..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        $nssmExe = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" | Select-Object -First 1
        if ($nssmExe) {
            Copy-Item $nssmExe.FullName -Destination $NSSMPath -Force
            Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
            Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "       ✓ NSSM downloaded and installed automatically" -ForegroundColor Green
        } else {
            throw "nssm.exe not found"
        }
    } catch {
        Write-Host "       ⚠️  Automatic download failed, manual installation required" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "       Manual installation:" -ForegroundColor Cyan
        Write-Host "       1. Download from https://nssm.cc/download" -ForegroundColor White
        Write-Host "       2. Copy nssm.exe to:" -ForegroundColor White
        Write-Host "          $NSSMPath" -ForegroundColor White
        Write-Host ""
        Write-Host "       Alternative: Install with Chocolatey:" -ForegroundColor Cyan
        Write-Host "       choco install nssm" -ForegroundColor White
        Write-Host ""
        
        $continue = Read-Host "       Have you manually downloaded NSSM? (Y/N)"
        if ($continue -ne "Y" -and $continue -ne "y") {
            Write-Host "[ERROR] NSSM is required, installation cancelled." -ForegroundColor Red
            exit 1
        }
        
        if (-not (Test-Path $NSSMPath)) {
            Write-Host "[ERROR] NSSM still not found: $NSSMPath" -ForegroundColor Red
            exit 1
        }
    }
} else {
    Write-Host "       ✓ NSSM found" -ForegroundColor Green
}

Write-Host ""
Write-Host "[7/8] Installing Windows Service..." -ForegroundColor Yellow

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "       Stopping existing service..." -ForegroundColor Gray
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "       Removing existing service..." -ForegroundColor Gray
    & $NSSMPath remove $ServiceName confirm
}

Write-Host "       Installing service..." -ForegroundColor Gray
& $NSSMPath install $ServiceName $pythonPath $ScriptPath

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Service installation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "       Configuring service settings..." -ForegroundColor Gray
& $NSSMPath set $ServiceName AppDirectory $InstallDir
& $NSSMPath set $ServiceName DisplayName "User Activity Monitor"
& $NSSMPath set $ServiceName Description "Comprehensive User Activity Monitor with n8n webhook and auto-ban for Windows"
& $NSSMPath set $ServiceName Start SERVICE_AUTO_START
& $NSSMPath set $ServiceName AppStdout "$LogDir\service_stdout.log"
& $NSSMPath set $ServiceName AppStderr "$LogDir\service_stderr.log"

Write-Host ""
Write-Host "[8/8] Starting service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 2
} catch {
    Write-Host "       ⚠️  Service start failed: $_" -ForegroundColor Yellow
    Write-Host "       Checking error logs..." -ForegroundColor Gray
    if (Test-Path "$LogDir\service_stderr.log") {
        Write-Host "       Error log content:" -ForegroundColor Yellow
        Get-Content "$LogDir\service_stderr.log" -Tail 10 | ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
    }
}

Start-Sleep -Seconds 2

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ Installation completed successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service Information:" -ForegroundColor Cyan
    Write-Host "  Name: $ServiceName" -ForegroundColor White
    Write-Host "  Status: $($service.Status)" -ForegroundColor White
    Write-Host "  Script: $ScriptPath" -ForegroundColor White
    Write-Host "  Config: $EnvPath" -ForegroundColor White
    Write-Host "  Logs: $LogDir" -ForegroundColor White
    Write-Host ""
    Write-Host "Useful Commands:" -ForegroundColor Cyan
    Write-Host "  Service status:     Get-Service $ServiceName" -ForegroundColor White
    Write-Host "  Stop service:       Stop-Service $ServiceName" -ForegroundColor White
    Write-Host "  Start service:      Start-Service $ServiceName" -ForegroundColor White
    Write-Host "  Restart service:    Restart-Service $ServiceName" -ForegroundColor White
    Write-Host "  View logs:          Get-Content $LogDir\activity_monitor.log -Tail 50" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  IMPORTANT: Edit WEBHOOK_URL in .env file!" -ForegroundColor Yellow
    Write-Host "   File: $EnvPath" -ForegroundColor Yellow
    Write-Host "   After editing: Restart-Service $ServiceName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📝 Example:" -ForegroundColor Cyan
    Write-Host "   notepad $EnvPath" -ForegroundColor White
    Write-Host "   # Edit the line: WEBHOOK_URL=`"https://your-n8n-url.com/webhook/...`"" -ForegroundColor White
    Write-Host "   Restart-Service $ServiceName" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "[WARNING] Service installed but could not be started!" -ForegroundColor Yellow
    Write-Host "         Please check manually:" -ForegroundColor Yellow
    Write-Host "         Get-Service $ServiceName" -ForegroundColor White
    Write-Host "         Get-Content $LogDir\service_stderr.log" -ForegroundColor White
    Write-Host ""
    Write-Host "         Testing Python script manually..." -ForegroundColor Cyan
    Write-Host "         Running: python $ScriptPath" -ForegroundColor Gray
    try {
        $testOutput = python $ScriptPath 2>&1 | Select-Object -First 10
        if ($testOutput) {
            Write-Host "         Script output:" -ForegroundColor Yellow
            $testOutput | ForEach-Object { Write-Host "           $_" -ForegroundColor Red }
        }
    } catch {
        Write-Host "         Could not test script: $_" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "         Common issues:" -ForegroundColor Cyan
    Write-Host "         1. WEBHOOK_URL not set in .env file" -ForegroundColor White
    Write-Host "         2. Python script has errors" -ForegroundColor White
    Write-Host "         3. Missing Python packages" -ForegroundColor White
    Write-Host ""
    Write-Host "         To fix:" -ForegroundColor Cyan
    Write-Host "         1. Edit: notepad $EnvPath" -ForegroundColor White
    Write-Host "         2. Set WEBHOOK_URL to your n8n webhook URL" -ForegroundColor White
    Write-Host "         3. Test: python $ScriptPath" -ForegroundColor White
    Write-Host "         4. Start: Start-Service $ServiceName" -ForegroundColor White
}
