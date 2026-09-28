# install_task.ps1
# Create a Windows scheduled task that runs the WorkBuddy daily check-in script
# every day at 09:00.
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\install_task.ps1
# (ASCII only on purpose: Windows PowerShell 5.1 mis-parses non-BOM UTF-8.)

$ErrorActionPreference = 'Stop'

$TaskName      = 'WorkBuddyDailyCheckin-SystemTask'
$ScriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$CheckinScript = Join-Path $ScriptDir 'workbuddy_checkin.py'

if (-not (Test-Path $CheckinScript)) {
    Write-Output "[x] check-in script not found: $CheckinScript"
    exit 1
}

function Resolve-Python {
    $managed = Join-Path $env:USERPROFILE '.workbuddy\binaries\python\versions\3.13.12\python.exe'
    if (Test-Path $managed) { return $managed }
    $versRoot = Join-Path $env:USERPROFILE '.workbuddy\binaries\python\versions'
    if (Test-Path $versRoot) {
        $dirs = Get-ChildItem $versRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        foreach ($d in $dirs) {
            $c = Join-Path $d.FullName 'python.exe'
            if (Test-Path $c) { return $c }
        }
    }
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command python3.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$Python = Resolve-Python
if (-not $Python) {
    Write-Output "[x] Python not found. Install Python 3 or make sure WorkBuddy is installed."
    exit 1
}
Write-Output "[+] python : $Python"
Write-Output "[+] script : $CheckinScript"

$action = New-ScheduledTaskAction -Execute $Python -Argument ('"{0}"' -f $CheckinScript) -WorkingDirectory $ScriptDir

$trigger = New-ScheduledTaskTrigger -Daily -At '09:00'

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -WakeToRun `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew

$identity  = "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Write-Output "[+] scheduled task registered: $TaskName (daily 09:00)"

Write-Output "[*] test run now (skip_already_signed is normal when already checked in today)..."
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 10
Get-ScheduledTaskInfo -TaskName $TaskName | Format-List TaskName, LastRunTime, LastTaskResult, NextRunTime
Write-Output "[*] log file: $ScriptDir\checkin.log"
