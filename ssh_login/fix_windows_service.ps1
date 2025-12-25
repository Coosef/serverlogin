# Fix Windows Service - User Activity Monitor
# This script fixes common service startup issues

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Fixing User Activity Monitor Service" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ServiceName = "UserActivityMonitor"
$InstallDir = "C:\ProgramData\user_activity_monitor"
$NSSMPath = "$InstallDir\nssm.exe"
$ScriptPath = "$InstallDir\user_activity_monitor.py"
$LogDir = "$InstallDir\logs"

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as ADMINISTRATOR!" -ForegroundColor Red
    Write-Host "Please open PowerShell with 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# Step 1: Check if service exists
Write-Host "[1/6] Checking service..." -ForegroundColor Yellow
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "       Service not found. Please run install_windows.ps1 first." -ForegroundColor Red
    exit 1
}
Write-Host "       Service found: $($service.Status)" -ForegroundColor Green

# Step 2: Stop service if running
Write-Host ""
Write-Host "[2/6] Stopping service..." -ForegroundColor Yellow
if ($service.Status -eq "Running") {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "       Service stopped" -ForegroundColor Green
} else {
    Write-Host "       Service already stopped" -ForegroundColor Gray
}

# Step 3: Find correct Python path
Write-Host ""
Write-Host "[3/6] Finding Python..." -ForegroundColor Yellow

# Try Python 3.13 first
$python313Path = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WindowsApps\python3.13.exe"
if (Test-Path $python313Path) {
    # Check if requests is installed for Python 3.13
    $testResult = & $python313Path -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $pythonPath = $python313Path
        Write-Host "       Using Python 3.13: $pythonPath" -ForegroundColor Green
    } else {
        Write-Host "       Python 3.13 found but requests not installed" -ForegroundColor Yellow
        Write-Host "       Installing requests for Python 3.13..." -ForegroundColor Gray
        & $python313Path -m pip install requests --quiet
        if ($LASTEXITCODE -eq 0) {
            $pythonPath = $python313Path
            Write-Host "       Using Python 3.13: $pythonPath" -ForegroundColor Green
        } else {
            Write-Host "       Failed to install requests for Python 3.13, using default Python" -ForegroundColor Yellow
            $pythonPath = (Get-Command python).Source
            Write-Host "       Using default Python: $pythonPath" -ForegroundColor Green
        }
    }
} else {
    $pythonPath = (Get-Command python).Source
    Write-Host "       Using default Python: $pythonPath" -ForegroundColor Green
}

# Step 4: Verify Python script exists
Write-Host ""
Write-Host "[4/6] Verifying files..." -ForegroundColor Yellow
if (-not (Test-Path $ScriptPath)) {
    Write-Host "       [ERROR] Python script not found: $ScriptPath" -ForegroundColor Red
    exit 1
}
Write-Host "       Python script found" -ForegroundColor Green

if (-not (Test-Path $NSSMPath)) {
    Write-Host "       [ERROR] NSSM not found: $NSSMPath" -ForegroundColor Red
    exit 1
}
Write-Host "       NSSM found" -ForegroundColor Green

# Step 5: Create logs directory if it doesn't exist
Write-Host ""
Write-Host "[5/6] Creating logs directory..." -ForegroundColor Yellow
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    Write-Host "       Logs directory created" -ForegroundColor Green
} else {
    Write-Host "       Logs directory exists" -ForegroundColor Gray
}

# Step 6: Update service settings
Write-Host ""
Write-Host "[6/6] Updating service settings..." -ForegroundColor Yellow

# Update Python path
& $NSSMPath set $ServiceName Application "$pythonPath"
if ($LASTEXITCODE -eq 0) {
    Write-Host "       Python path updated" -ForegroundColor Green
} else {
    Write-Host "       [WARNING] Failed to update Python path" -ForegroundColor Yellow
}

# Update script parameters
& $NSSMPath set $ServiceName AppParameters "$ScriptPath"
if ($LASTEXITCODE -eq 0) {
    Write-Host "       Script parameters updated" -ForegroundColor Green
} else {
    Write-Host "       [WARNING] Failed to update script parameters" -ForegroundColor Yellow
}

# Update working directory
& $NSSMPath set $ServiceName AppDirectory "$InstallDir"
if ($LASTEXITCODE -eq 0) {
    Write-Host "       Working directory updated" -ForegroundColor Green
} else {
    Write-Host "       [WARNING] Failed to update working directory" -ForegroundColor Yellow
}

# Update log files
& $NSSMPath set $ServiceName AppStdout "$LogDir\service_stdout.log"
& $NSSMPath set $ServiceName AppStderr "$LogDir\service_stderr.log"
if ($LASTEXITCODE -eq 0) {
    Write-Host "       Log files updated" -ForegroundColor Green
} else {
    Write-Host "       [WARNING] Failed to update log files" -ForegroundColor Yellow
}

# Step 7: Test Python script manually
Write-Host ""
Write-Host "[7/7] Testing Python script..." -ForegroundColor Yellow
Write-Host "       Running: $pythonPath $ScriptPath" -ForegroundColor Gray
$testProcess = Start-Process -FilePath $pythonPath -ArgumentList $ScriptPath -NoNewWindow -PassThru -RedirectStandardOutput "$LogDir\test_stdout.log" -RedirectStandardError "$LogDir\test_stderr.log"
Start-Sleep -Seconds 3
if (-not $testProcess.HasExited) {
    Stop-Process -Id $testProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "       Script started successfully (stopped after test)" -ForegroundColor Green
} else {
    Write-Host "       [WARNING] Script exited immediately" -ForegroundColor Yellow
    if (Test-Path "$LogDir\test_stderr.log") {
        $errorContent = Get-Content "$LogDir\test_stderr.log" -Tail 5
        if ($errorContent) {
            Write-Host "       Error output:" -ForegroundColor Red
            $errorContent | ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
        }
    }
}

# Step 8: Start service
Write-Host ""
Write-Host "[8/8] Starting service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 3
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service.Status -eq "Running") {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "✓ Service started successfully!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Service Information:" -ForegroundColor Cyan
        Write-Host "  Name: $ServiceName" -ForegroundColor White
        Write-Host "  Status: $($service.Status)" -ForegroundColor White
        Write-Host "  Python: $pythonPath" -ForegroundColor White
        Write-Host "  Script: $ScriptPath" -ForegroundColor White
        Write-Host "  Logs: $LogDir" -ForegroundColor White
        Write-Host ""
        Write-Host "Useful Commands:" -ForegroundColor Cyan
        Write-Host "  Service status:  Get-Service $ServiceName" -ForegroundColor White
        $stderrLog = Join-Path $LogDir "service_stderr.log"
        $activityLog = Join-Path $LogDir "activity_monitor.log"
        Write-Host ("  View logs:       Get-Content " + $stderrLog + " -Tail 20") -ForegroundColor White
        Write-Host ("  View activity:   Get-Content " + $activityLog + " -Tail 20") -ForegroundColor White
    } else {
        Write-Host ""
        Write-Host "[WARNING] Service did not start" -ForegroundColor Yellow
        Write-Host "         Status: $($service.Status)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "         Check error logs:" -ForegroundColor Cyan
        $stderrLog = Join-Path $LogDir "service_stderr.log"
        Write-Host ("         Get-Content " + $stderrLog) -ForegroundColor White
    }
} catch {
    Write-Host ""
    Write-Host "[ERROR] Failed to start service: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check error logs:" -ForegroundColor Cyan
    $stderrLog = Join-Path $LogDir "service_stderr.log"
    $stdoutLog = Join-Path $LogDir "service_stdout.log"
    Write-Host ("  Get-Content " + $stderrLog) -ForegroundColor White
    Write-Host ("  Get-Content " + $stdoutLog) -ForegroundColor White
}

Write-Host ""

