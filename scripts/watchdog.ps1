$ErrorActionPreference = "Stop"

function Write-Log([string]$Message) {
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = "[$ts] $Message"
  Write-Output $line
  try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {}
}

function Load-DotEnv([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  Get-Content -LiteralPath $Path -Encoding UTF8 | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) { return }
    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { return }
    $k = $line.Substring(0, $idx).Trim()
    $v = $line.Substring($idx + 1).Trim()
    if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
      $v = $v.Substring(1, $v.Length - 2)
    }
    if ($k) { [Environment]::SetEnvironmentVariable($k, $v, "Process") }
  }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ProgramDataRoot = Join-Path $env:ProgramData "Telephony-Portal"
$LogsDir = Join-Path $ProgramDataRoot "logs"
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null
$script:LogFile = Join-Path $LogsDir "watchdog.log"

$StopFile = Join-Path $LogsDir "watchdog.stop"

# Load environment variables (optional).
# Prefer a user-local env file if present; otherwise fall back to repo telephony.env.
$UserEnv = Join-Path $ProgramDataRoot "telephony.env"
$RepoEnv = Join-Path $RepoRoot "telephony.env"
if (Test-Path -LiteralPath $UserEnv) {
  Load-DotEnv $UserEnv
  Write-Log "Loaded env: $UserEnv"
} elseif (Test-Path -LiteralPath $RepoEnv) {
  Load-DotEnv $RepoEnv
  Write-Log "Loaded env: $RepoEnv"
}

# Force production server behavior when running from source.
if (-not $env:TELEPHONY_USE_WAITRESS) { $env:TELEPHONY_USE_WAITRESS = "1" }
if (-not $env:TELEPHONY_HOST) { $env:TELEPHONY_HOST = "0.0.0.0" }
if (-not $env:TELEPHONY_PORT) { $env:TELEPHONY_PORT = "5500" }
if (-not $env:TELEPHONY_DB_PATH) { $env:TELEPHONY_DB_PATH = (Join-Path $ProgramDataRoot "instance\telephony.db") }

$ExePath = Join-Path $RepoRoot "dist\TelephonyPortal\TelephonyPortal.exe"
$VenvPython = Join-Path $RepoRoot "venv\Scripts\python.exe"

if (Test-Path -LiteralPath $StopFile) { Remove-Item -Force -LiteralPath $StopFile | Out-Null }

Write-Log "Watchdog starting. RepoRoot=$RepoRoot"
Write-Log "Stop file: $StopFile (create this file to stop the watchdog loop)"

while ($true) {
  if (Test-Path -LiteralPath $StopFile) {
    Write-Log "Stop file detected. Exiting watchdog."
    break
  }

  $StdOut = Join-Path $LogsDir "telephonyportal.stdout.log"
  $StdErr = Join-Path $LogsDir "telephonyportal.stderr.log"

  $p = $null
  try {
    if (Test-Path -LiteralPath $ExePath) {
      Write-Log "Starting EXE: $ExePath"
      $p = Start-Process -FilePath $ExePath -WorkingDirectory (Split-Path $ExePath -Parent) -PassThru -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
    } elseif (Test-Path -LiteralPath $VenvPython) {
      Write-Log "Starting from source (venv): $VenvPython app.py"
      $p = Start-Process -FilePath $VenvPython -ArgumentList @("app.py") -WorkingDirectory $RepoRoot -PassThru -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
    } else {
      Write-Log "Starting from source (python on PATH): python app.py"
      $p = Start-Process -FilePath "python" -ArgumentList @("app.py") -WorkingDirectory $RepoRoot -PassThru -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
    }

    Write-Log "Started PID=$($p.Id). Monitoring health..."

    $HealthUrl = "http://127.0.0.1:$($env:TELEPHONY_PORT)/health"
    $FailCount = 0
    $MaxFails = 5

    while (-not $p.HasExited) {
      if (Test-Path -LiteralPath $StopFile) {
        Write-Log "Stop file detected. Exiting watchdog."
        break
      }

      try {
        $resp = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 5
        if ($resp.StatusCode -eq 200) {
          $FailCount = 0
        } else {
          $FailCount++
          Write-Log "Health check non-200 ($($resp.StatusCode)). FailCount=$FailCount"
        }
      } catch {
        $FailCount++
        Write-Log "Health check failed: $($_.Exception.Message). FailCount=$FailCount"
      }

      if ($FailCount -ge $MaxFails) {
        Write-Log "Health check failed $FailCount times. Killing PID=$($p.Id) for restart."
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        break
      }

      Start-Sleep -Seconds 15
      try { $p.Refresh() } catch {}
    }

    if (-not $p.HasExited) {
      Wait-Process -Id $p.Id
    }

    $exitCode = $p.ExitCode
    Write-Log "Process exited (PID=$($p.Id)) exitCode=$exitCode"
  } catch {
    Write-Log "Failed to start or monitor process: $($_.Exception.Message)"
  }

  if (Test-Path -LiteralPath $StopFile) {
    Write-Log "Stop file detected after exit. Exiting watchdog."
    break
  }

  Write-Log "Restarting in 3 seconds..."
  Start-Sleep -Seconds 3
}


