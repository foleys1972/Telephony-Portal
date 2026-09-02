param(
  [switch]$Clean
)

$ErrorActionPreference = "Stop"

Write-Host "Building Telephony Portal EXE (PyInstaller)..."

# Ensure venv exists
if (-not (Test-Path ".\venv\Scripts\python.exe")) {
  Write-Host "Creating venv..."
  python -m venv venv
}

Write-Host "Activating venv..."
& .\venv\Scripts\Activate.ps1

Write-Host "Installing build deps..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller

# Stop any running EXE that would lock dist files
Get-Process TelephonyPortal -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host "Stopping running TelephonyPortal process (PID $($_.Id))..."
  try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch { }
}
Start-Sleep -Seconds 1

# Always try to clean the active dist target (common cause of PyInstaller exit code 1 on Windows)
$distTarget = ".\dist\TelephonyPortal"
if (Test-Path $distTarget) {
  for ($i = 1; $i -le 5; $i++) {
    try {
      Remove-Item -Recurse -Force -ErrorAction Stop $distTarget
      break
    } catch {
      Write-Host "Retrying delete of $distTarget (attempt $i/5)..."
      Start-Sleep -Seconds 1
    }
  }
}

if ($Clean) {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .\build
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .\dist
  Remove-Item -Force -ErrorAction SilentlyContinue .\TelephonyPortal.spec
}

# Build as one-folder app for reliable file access
pyinstaller --noconfirm --clean --onedir --name TelephonyPortal `
  --add-data "templates;templates" `
  --add-data "utils;utils" `
  --add-data "instance\telephony.db;instance" `
  --add-data "instance\port.txt;instance" `
  run_portal.py

if ($LASTEXITCODE -ne 0) {
  throw "PyInstaller failed with exit code $LASTEXITCODE"
}

# Copy runtime env file beside the EXE so LAN access works out of the box
if (Test-Path ".\\telephony.env") {
  Copy-Item ".\\telephony.env" ".\\dist\\TelephonyPortal\\telephony.env" -Force
  Write-Host "Copied telephony.env to dist\\TelephonyPortal\\telephony.env"
}

Write-Host ""
Write-Host "Build complete:"
Write-Host "  dist\TelephonyPortal\TelephonyPortal.exe"
Write-Host ""
Write-Host "Note: On first run, the bundled DB is copied to:"
Write-Host "  %ProgramData%\Telephony-Portal\instance\telephony.db"

