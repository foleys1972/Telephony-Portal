from __future__ import annotations

import os


def _app_data_dir() -> str:
    base = (
        os.environ.get("PROGRAMDATA")
        or os.environ.get("ProgramData")
        or os.environ.get("APPDATA")
        or os.path.expanduser("~")
    )
    return os.path.join(base, "Telephony-Portal")


def _instance_dir() -> str:
    inst = os.path.join(_app_data_dir(), "instance")
    os.makedirs(inst, exist_ok=True)
    return inst


def get_logs_dir() -> str:
    p = os.path.join(_app_data_dir(), "logs")
    os.makedirs(p, exist_ok=True)
    return p


def _db_path_config_file() -> str:
    return os.path.join(_instance_dir(), "db_path.txt")


def _port_config_file() -> str:
    return os.path.join(_instance_dir(), "port.txt")


def get_configured_db_path() -> str | None:
    try:
        p = _db_path_config_file()
        if not os.path.exists(p):
            return None
        val = (open(p, "r", encoding="utf-8").read() or "").strip()
        if not val:
            return None
        val = os.path.abspath(val)
        if not val.lower().endswith(".db"):
            return None
        return val
    except Exception:
        return None


def set_configured_db_path(path: str | None) -> None:
    p = _db_path_config_file()
    if not path:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
        return

    val = os.path.abspath(path)
    if not val.lower().endswith(".db"):
        raise ValueError("Database path must end with .db")
    parent = os.path.dirname(val)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(val)


def resolve_db_path() -> str:
    override = os.environ.get("TELEPHONY_DB_PATH")
    if override:
        return override

    configured = get_configured_db_path()
    if configured:
        return configured

    return os.path.join(_instance_dir(), "telephony.db")


def get_configured_port() -> int | None:
    try:
        p = _port_config_file()
        if not os.path.exists(p):
            return None
        raw = (open(p, "r", encoding="utf-8").read() or "").strip()
        if not raw:
            return None
        port = int(raw)
        if port < 1 or port > 65535:
            return None
        return port
    except Exception:
        return None


def set_configured_port(port: int | str | None) -> None:
    p = _port_config_file()
    if port is None or str(port).strip() == "":
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
        return

    val = int(str(port).strip())
    if val < 1 or val > 65535:
        raise ValueError("Port must be between 1 and 65535")
    with open(p, "w", encoding="utf-8") as f:
        f.write(str(val))


def resolve_port(default: int = 5500) -> int:
    override = os.environ.get("TELEPHONY_PORT")
    if override and str(override).strip() != "":
        try:
            port = int(str(override).strip())
            if 1 <= port <= 65535:
                return port
        except Exception:
            pass

    configured = get_configured_port()
    if configured:
        return configured

    # First-run experience: create a default port.txt so the user has something to edit.
    try:
        set_configured_port(int(default))
    except Exception:
        pass

    return int(default)
