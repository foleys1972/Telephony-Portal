# Telephony Portal

Flask web application for managing DDI numbers, private wires, servers, incidents, changes, and dealerboard turrets.

## Requirements

- Python 3.10 or newer
- A web browser

## Run from source

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item telephony.env.example telephony.env
```

Edit `telephony.env` and set a strong `SECRET_KEY`. The application reads environment variables from the shell; load the file before starting:

```powershell
Get-Content .\telephony.env | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
    $name, $value = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), 'Process')
}
python run_portal.py
```

Open <http://127.0.0.1:5500>. The SQLite database is created and migrated automatically in the platform's application-data directory. Set `TELEPHONY_DB_PATH` when a specific database location is required.

For a simpler local run, the environment file is optional:

```powershell
python run_portal.py
```

Do not commit `telephony.env`, database files, uploaded CSVs, backups, or the virtual environment.

## Configuration

Available settings are documented in `telephony.env.example`, including host, port, Waitress worker count, and import batch size. For shared use, keep `TELEPHONY_USE_WAITRESS=1` and do not expose the application directly to the public internet without appropriate network controls.

## Windows executable

To build the bundled Windows application, install Python and run:

```powershell
.\build-exe.ps1
```

The executable is written to `dist\TelephonyPortal\TelephonyPortal.exe`. See `README-EXE.md` for watchdog and service deployment details.