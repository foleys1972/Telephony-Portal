## Build Windows EXE (includes starter database)

This project can be packaged as a Windows EXE using PyInstaller. The build bundles:
- `templates/`
- `utils/`
- `instance/telephony.db` (starter DB)

On first run, the EXE will copy the bundled DB to a writable location:
- `%APPDATA%\Telephony-Portal\instance\telephony.db`

### Build

From the project root in PowerShell:

```powershell
.\build-exe.ps1
```

Output:
- `dist\TelephonyPortal\TelephonyPortal.exe`

### Run

Run the EXE and browse to the URL it prints in the console.

## Auto-restart / Watchdog (Windows)

You have two good options:

### Option A (recommended): Windows Task Scheduler + Watchdog script (built-in)

This repo includes a watchdog script that restarts the app if it exits.

- **Watchdog script**: `scripts/watchdog.ps1`
- **Logs**: `%APPDATA%\Telephony-Portal\logs\watchdog.log`

Install a scheduled task (runs on user logon by default):

```powershell
.\scripts\install-watchdog-task.ps1 -Mode AtLogon
```

If you *really* want it at machine startup (runs as SYSTEM by default):

```powershell
.\scripts\install-watchdog-task.ps1 -Mode AtStartup
```

Note: `AtStartup` runs under **SYSTEM**, so `%APPDATA%` is different. Only use this if you intentionally run the app under SYSTEM or have configured the DB/env paths accordingly.

To stop the watchdog loop without uninstalling the task, create this file:
- `%APPDATA%\Telephony-Portal\logs\watchdog.stop`

### Option B: Run as a Windows Service (NSSM)

If you prefer a true Windows Service, use NSSM to wrap either:
- `dist\TelephonyPortal\TelephonyPortal.exe`, or
- `venv\Scripts\python.exe app.py`

NSSM can auto-restart on exit and integrates with the Services UI.

### Notes

- The app runs with `debug=False` when packaged (frozen).
- By default, the EXE **will not** fall back to Flask dev server if Waitress fails to start.
  - If you want to allow fallback temporarily (troubleshooting only), set `TELEPHONY_ALLOW_DEV_FALLBACK=1`.
- If you want to ship an updated starter DB, replace `instance\telephony.db` and rebuild.

