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

# Check if .env exists and validate WEBHOOK_URL
$webhookConfigured = $false
if (Test-Path $EnvPath) {
    $envContent = Get-Content $EnvPath -ErrorAction SilentlyContinue
    $webhookLine = $envContent | Select-String "WEBHOOK_URL"
    if ($webhookLine) {
        if ($webhookLine -match 'WEBHOOK_URL="(.*)"') {
            $webhookUrl = $matches[1]
            if ($webhookUrl -and $webhookUrl -ne "https://n8vp.yeb.one/webhook/useractivity" -and $webhookUrl -ne "") {
                $webhookConfigured = $true
                Write-Host "       WEBHOOK_URL is configured" -ForegroundColor Green
            } else {
                Write-Host "       ⚠️  WEBHOOK_URL needs to be configured!" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "       ⚠️  WEBHOOK_URL not found in .env file!" -ForegroundColor Yellow
    }
}

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
    if (-not $webhookConfigured) {
        Write-Host ""
        Write-Host "       ⚠️  IMPORTANT: WEBHOOK_URL must be configured before starting the service!" -ForegroundColor Yellow
        Write-Host "       Edit: notepad $EnvPath" -ForegroundColor White
    }
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

# Check if python3.13 exists and use it if available (for better compatibility)
$python313Path = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WindowsApps\python3.13.exe"
if (Test-Path $python313Path) {
    Write-Host "       Python 3.13 found, checking requests package..." -ForegroundColor Cyan
    # Check if requests is installed for Python 3.13
    $testResult = & $python313Path -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        # Try to get the actual Python executable path (WindowsApps may be a stub)
        $actualPython = & $python313Path -c "import sys; print(sys.executable)" 2>&1
        if ($actualPython -and $actualPython -ne $python313Path -and (Test-Path $actualPython)) {
            Write-Host "       Using actual Python 3.13 path: $actualPython" -ForegroundColor Green
            $pythonPath = $actualPython.Trim()
        } else {
            Write-Host "       Python 3.13 with requests - using it for service" -ForegroundColor Green
            $pythonPath = $python313Path
        }
    } else {
        Write-Host "       Installing requests for Python 3.13..." -ForegroundColor Yellow
        & $python313Path -m pip install requests --quiet
        if ($LASTEXITCODE -eq 0) {
            # Try to get the actual Python executable path
            $actualPython = & $python313Path -c "import sys; print(sys.executable)" 2>&1
            if ($actualPython -and $actualPython -ne $python313Path -and (Test-Path $actualPython)) {
                Write-Host "       Using actual Python 3.13 path: $actualPython" -ForegroundColor Green
                $pythonPath = $actualPython.Trim()
            } else {
                Write-Host "       Python 3.13 with requests - using it for service" -ForegroundColor Green
                $pythonPath = $python313Path
            }
        } else {
            Write-Host "       Failed to install requests for Python 3.13, using default Python" -ForegroundColor Yellow
        }
    }
}

Write-Host "       Using Python: $pythonPath" -ForegroundColor Gray

# Test Python script before installing service (only if WEBHOOK_URL is configured)
if ($webhookConfigured) {
    Write-Host "       Testing Python script..." -ForegroundColor Gray
    $testProcess = Start-Process -FilePath $pythonPath -ArgumentList $ScriptPath -NoNewWindow -PassThru -RedirectStandardOutput "$LogDir\test_stdout.log" -RedirectStandardError "$LogDir\test_stderr.log"
    Start-Sleep -Seconds 3
    if (-not $testProcess.HasExited) {
        Stop-Process -Id $testProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "       Script test passed" -ForegroundColor Green
    } else {
        Write-Host "       Script test failed - checking errors..." -ForegroundColor Yellow
        if (Test-Path "$LogDir\test_stderr.log") {
            $errorContent = Get-Content "$LogDir\test_stderr.log" -Tail 5
            if ($errorContent) {
                Write-Host "       Error output:" -ForegroundColor Red
                $errorContent | ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
            }
        }
        Write-Host "       Continuing with service installation..." -ForegroundColor Yellow
    }
} else {
    Write-Host "       ⚠️  Skipping script test - WEBHOOK_URL not configured" -ForegroundColor Yellow
    Write-Host "       Service will be installed but may not start until WEBHOOK_URL is set" -ForegroundColor Yellow
}

# Install service using batch file wrapper (Windows Store Python requires this)
# Create wrapper batch file for reliable service execution
$wrapperBatch = Join-Path $InstallDir "start_monitor.bat"
$batchContent = "@echo off`r`ncd /d `"$InstallDir`"`r`n`"$pythonPath`" -u `"$ScriptPath`"`r`n"
[System.IO.File]::WriteAllText($wrapperBatch, $batchContent, [System.Text.Encoding]::ASCII)
Write-Host "       Created wrapper batch file: $wrapperBatch" -ForegroundColor Gray

# NSSM can execute batch files directly - use the batch file as the application
# NSSM will automatically use cmd.exe to run .bat files
& $NSSMPath install $ServiceName $wrapperBatch

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
& $NSSMPath set $ServiceName AppRestartDelay 5000
& $NSSMPath set $ServiceName AppThrottle 1500
& $NSSMPath set $ServiceName AppStopMethodSkip 0
& $NSSMPath set $ServiceName AppStopMethodConsole 1500
& $NSSMPath set $ServiceName AppStopMethodWindow 1500
& $NSSMPath set $ServiceName AppStopMethodThreads 1500

# Set environment variables for Python
$pythonDir = Split-Path $pythonPath -Parent
$pythonPathEnv = "$pythonDir;" + $env:PATH
& $NSSMPath set $ServiceName AppEnvironmentExtra "PATH=$pythonPathEnv"

# Parameters are set via wrapper batch file, no need to set here

Write-Host ""
Write-Host "[8/8] Starting service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 3
} catch {
    Write-Host "       Service start failed, attempting to fix..." -ForegroundColor Yellow
    
    # Try to fix common issues
    Write-Host "       Verifying service configuration..." -ForegroundColor Gray
    
    # Verify and fix all service settings
    $wrapperBatch = Join-Path $InstallDir "start_monitor.bat"
    
    $currentApp = & $NSSMPath get $ServiceName Application 2>&1
    if ($currentApp -ne $wrapperBatch) {
        Write-Host "       Updating application to batch file..." -ForegroundColor Gray
        & $NSSMPath set $ServiceName Application "$wrapperBatch"
    }
    
    # Ensure batch file exists and is up to date
    if (-not (Test-Path $wrapperBatch)) {
        Write-Host "       Recreating wrapper batch file..." -ForegroundColor Gray
        $batchContent = "@echo off`r`ncd /d `"$InstallDir`"`r`n`"$pythonPath`" -u `"$ScriptPath`"`r`n"
        [System.IO.File]::WriteAllText($wrapperBatch, $batchContent, [System.Text.Encoding]::ASCII)
    } else {
        # Update batch file content to ensure it's current
        Write-Host "       Updating wrapper batch file content..." -ForegroundColor Gray
        $batchContent = "@echo off`r`ncd /d `"$InstallDir`"`r`n`"$pythonPath`" -u `"$ScriptPath`"`r`n"
        [System.IO.File]::WriteAllText($wrapperBatch, $batchContent, [System.Text.Encoding]::ASCII)
    }
    
    # Ensure working directory is set
    $currentDir = & $NSSMPath get $ServiceName AppDirectory 2>&1
    if ($currentDir -ne $InstallDir) {
        Write-Host "       Updating working directory..." -ForegroundColor Gray
        & $NSSMPath set $ServiceName AppDirectory "$InstallDir"
    }
    
    # Check Windows Event Viewer for service errors
    Write-Host "       Checking Windows Event Viewer for errors..." -ForegroundColor Gray
    try {
        $events = Get-WinEvent -LogName System -MaxEvents 5 -ErrorAction SilentlyContinue | Where-Object {
            $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and
            ($_.Message -like "*UserActivityMonitor*" -or $_.Message -like "*python*")
        }
        if ($events) {
            Write-Host "       Recent service-related events found:" -ForegroundColor Yellow
            $events | ForEach-Object {
                Write-Host "         [$($_.TimeCreated)] $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))" -ForegroundColor Red
            }
        }
    } catch {
        # Ignore event viewer errors
    }
    
    # Try starting again
    Write-Host "       Retrying service start..." -ForegroundColor Gray
    Start-Sleep -Seconds 2
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
    } catch {
        Write-Host "       Service still failed to start" -ForegroundColor Yellow
        
        # Check NSSM service status
        Write-Host "       Checking NSSM service status..." -ForegroundColor Gray
        $nssmStatus = & $NSSMPath status $ServiceName 2>&1
        Write-Host "       NSSM status: $nssmStatus" -ForegroundColor Gray
        
        # Get all NSSM service settings for debugging
        Write-Host "       Current service settings:" -ForegroundColor Gray
        $currentApp = & $NSSMPath get $ServiceName Application 2>&1
        $currentParams = & $NSSMPath get $ServiceName AppParameters 2>&1
        $currentDir = & $NSSMPath get $ServiceName AppDirectory 2>&1
        Write-Host "         Application: $currentApp" -ForegroundColor White
        Write-Host "         Parameters: $currentParams" -ForegroundColor White
        Write-Host "         Directory: $currentDir" -ForegroundColor White
        
        Write-Host "       Checking error logs..." -ForegroundColor Gray
        if (Test-Path "$LogDir\service_stderr.log") {
            $errorLog = Get-Content "$LogDir\service_stderr.log" -Tail 10 -ErrorAction SilentlyContinue
            if ($errorLog) {
                Write-Host "       Error log content:" -ForegroundColor Yellow
                $errorLog | ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
            } else {
                Write-Host "       Error log is empty - service may not be starting at all" -ForegroundColor Yellow
            }
        } else {
            Write-Host "       Error log file does not exist yet" -ForegroundColor Yellow
        }
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
    Write-Host ""
    Write-Host "         Diagnosing issue..." -ForegroundColor Cyan
    
    # Check error logs
    $stderrLog = Join-Path $LogDir "service_stderr.log"
    $stdoutLog = Join-Path $LogDir "service_stdout.log"
    
    if (Test-Path $stderrLog) {
        Write-Host "         Error log content:" -ForegroundColor Yellow
        $errorContent = Get-Content $stderrLog -Tail 20 -ErrorAction SilentlyContinue
        if ($errorContent) {
            $errorContent | ForEach-Object { Write-Host "           $_" -ForegroundColor Red }
        } else {
            Write-Host "           (log file is empty)" -ForegroundColor Gray
        }
    } else {
        Write-Host "         Error log file not found" -ForegroundColor Gray
    }
    
    if (Test-Path $stdoutLog) {
        Write-Host "         Output log content:" -ForegroundColor Yellow
        $outputContent = Get-Content $stdoutLog -Tail 10 -ErrorAction SilentlyContinue
        if ($outputContent) {
            $outputContent | ForEach-Object { Write-Host "           $_" -ForegroundColor White }
        }
    }
    
    # Check .env file for WEBHOOK_URL
    Write-Host ""
    Write-Host "         Checking .env file..." -ForegroundColor Cyan
    if (Test-Path $EnvPath) {
        $envContent = Get-Content $EnvPath -ErrorAction SilentlyContinue
        $webhookLine = $envContent | Select-String "WEBHOOK_URL"
        if ($webhookLine) {
            if ($webhookLine -match 'WEBHOOK_URL="(.*)"') {
                $webhookUrl = $matches[1]
                if ($webhookUrl -and $webhookUrl -ne "https://n8vp.yeb.one/webhook/useractivity") {
                    Write-Host "         WEBHOOK_URL is set" -ForegroundColor Green
                } else {
                    Write-Host "         WEBHOOK_URL needs to be configured!" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "         WEBHOOK_URL not found in .env file!" -ForegroundColor Red
        }
    }
    
    # Try to start service with more verbose output
    Write-Host ""
    Write-Host "         Attempting manual service start..." -ForegroundColor Cyan
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "         Current service status: $($service.Status)" -ForegroundColor White
            if ($service.Status -eq "Stopped") {
                Start-Service -Name $ServiceName -ErrorAction Stop
                Start-Sleep -Seconds 3
                $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($service.Status -eq "Running") {
                    Write-Host "         Service started successfully!" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "========================================" -ForegroundColor Green
                    Write-Host "✓ Service is now running!" -ForegroundColor Green
                    Write-Host "========================================" -ForegroundColor Green
                    exit 0
                }
            }
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Host "         Manual start failed: $errorMsg" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "         Manual troubleshooting:" -ForegroundColor Cyan
    Write-Host "         1. Check service: Get-Service $ServiceName" -ForegroundColor White
    Write-Host "         2. Check logs: Get-Content $stderrLog" -ForegroundColor White
    Write-Host "         3. Edit .env: notepad $EnvPath" -ForegroundColor White
    Write-Host "         4. Test script: $pythonPath $ScriptPath" -ForegroundColor White
    Write-Host "         5. Start service: Start-Service $ServiceName" -ForegroundColor White
}
