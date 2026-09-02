from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime

from sqlalchemy import text

from portal_app import create_app
from portal_app.db import db
from portal_app.paths import resolve_db_path


def _setting_get(key: str, default: str | None = None) -> str | None:
    try:
        row = db.session.execute(text("SELECT value FROM app_setting WHERE key = :k"), {"k": key}).fetchone()
        if row and row[0] is not None:
            v = str(row[0]).strip()
            return v
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
    return default


def _setting_int(key: str, default: int, *, min_v: int | None = None, max_v: int | None = None) -> int:
    raw = _setting_get(key, None)
    try:
        n = int((raw or "").strip())
    except Exception:
        n = default
    if min_v is not None:
        n = max(min_v, n)
    if max_v is not None:
        n = min(max_v, n)
    return n


def _setting_bool(key: str, default: bool) -> bool:
    raw = (_setting_get(key, "1" if default else "0") or "").strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


def _backup_dir_default() -> str:
    base = os.environ.get("APPDATA") or os.environ.get("ProgramData") or os.getcwd()
    return os.path.join(base, "Telephony-Portal", "backups")


def _get_backup_settings() -> dict:
    return {
        "backup_dir": _setting_get("backup_dir", _backup_dir_default()) or _backup_dir_default(),
        "backup_retention": _setting_int("backup_retention", 30, min_v=1, max_v=365),
        "backup_auto_delete": _setting_bool("backup_auto_delete", True),
    }


def _sqlite_backup(src_path: str, dest_path: str) -> None:
    src = sqlite3.connect(src_path, timeout=60, check_same_thread=False)
    try:
        dest = sqlite3.connect(dest_path, timeout=60, check_same_thread=False)
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()


def _create_backup_copy(db_path: str, backups_dir: str) -> str:
    os.makedirs(backups_dir, exist_ok=True)
    name = f"telephony_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    dest_path = os.path.join(backups_dir, name)

    try:
        db.session.close()
    except Exception:
        pass
    try:
        db.engine.dispose()
    except Exception:
        pass

    _sqlite_backup(db_path, dest_path)
    return dest_path


def _run_retention(backups_dir: str, retention_count: int) -> list[str]:
    deleted: list[str] = []
    try:
        files: list[tuple[float, str]] = []
        for name in os.listdir(backups_dir):
            if not name.lower().endswith(".db"):
                continue
            p = os.path.join(backups_dir, name)
            try:
                st = os.stat(p)
                files.append((st.st_mtime, p))
            except Exception:
                continue
        files.sort(key=lambda x: x[0], reverse=True)
        for _, p in files[retention_count:]:
            try:
                os.remove(p)
                deleted.append(os.path.basename(p))
            except Exception:
                continue
    except Exception:
        return deleted
    return deleted


def run_backup() -> tuple[str, list[str]]:
    settings = _get_backup_settings()
    backups_dir = settings["backup_dir"]
    retention = int(settings["backup_retention"])
    auto_delete = bool(settings["backup_auto_delete"])

    # Must match the app's DB-path resolution (env override + config file + default)
    db_path = resolve_db_path()

    backup_path = _create_backup_copy(db_path, backups_dir)
    deleted = _run_retention(backups_dir, retention) if auto_delete else []
    return backup_path, deleted


def main(argv: list[str] | None = None) -> int:
    _ = argv or sys.argv[1:]
    app = create_app()
    with app.app_context():
        try:
            backup_path, deleted = run_backup()
            sys.stdout.write(
                f"OK backup={os.path.basename(backup_path)} deleted={len(deleted)} dir={os.path.dirname(backup_path)}\n"
            )
            return 0
        except Exception as e:
            sys.stderr.write(f"ERROR {e}\n")
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
