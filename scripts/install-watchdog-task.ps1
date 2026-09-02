$ErrorActionPreference = "Stop"

param(
  [string]$TaskName = "TelephonyPortal Watchdog",
  [ValidateSet("AtLogon","AtStartup")]
  [string]$Mode = "AtLogon"
)

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Watchdog = Join-Path $RepoRoot "scripts\watchdog.ps1"
if (-not (Test-Path -LiteralPath $Watchdog)) { throw "watchdog.ps1 not found at: $Watchdog" }

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Watchdog`""

if ($Mode -eq "AtStartup") {
  # NOTE: AtStartup typically requires a service account (SYSTEM) and will use SYSTEM's %APPDATA%.
  # Prefer AtLogon unless you intentionally set up a dedicated service account + DB path.
  $Trigger = New-ScheduledTaskTrigger -AtStartup
  $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
  $Trigger = New-ScheduledTaskTrigger -AtLogOn
  $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType InteractiveToken -RunLevel Highest
}

$Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
  -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1)

$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal

try {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
} catch {}

Register-ScheduledTask -TaskName $TaskName -InputObject $Task | Out-Null
Write-Output "Installed scheduled task: $TaskName ($Mode)"
Write-Output "To remove: Unregister-ScheduledTask -TaskName `"$TaskName`" -Confirm:`$false"


