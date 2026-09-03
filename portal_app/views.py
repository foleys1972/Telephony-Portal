from __future__ import annotations

import csv
import io
import base64
import json
import os
import re
import shutil
import sqlite3
import socket
import subprocess
import sys
import tempfile
import ipaddress
from datetime import date, datetime, timedelta

from flask import (
    Blueprint,
    Response,
    abort,
    after_this_request,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import or_, select

from .db import db
from .paths import get_configured_db_path, set_configured_db_path
from .models import (
    ActivityLogEntry,
    AppSetting,
    CeasedRMATurret,
    CeasedServer,
    CeasedPrivateWire,
    CabLock,
    ChangeRecord,
    CustomFieldDef,
    DealerboardTurret,
    DDINumber,
    IncidentRecord,
    LookupOption,
    PrivateWire,
    Server,
    TurretMove,
    TurretMoveGroup,
    TurretMoveHistory,
    User,
)

core_bp = Blueprint("core", __name__)


def _norm_header(s: str) -> str:
    return (s or "").strip().lower().replace(" ", "_")


def _read_upload_text(file_storage) -> str:
    raw = file_storage.stream.read()
    try:
        return raw.decode("utf-8-sig", errors="replace")
    except Exception:
        return raw.decode("utf-8", errors="replace")


def _csv_preview(text: str, max_rows: int = 5) -> tuple[list[str], list[dict]]:
    reader = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []
    rows: list[dict] = []
    for i, r in enumerate(reader):
        if i >= max_rows:
            break
        rows.append(r)
    return headers, rows


def _suggest_mapping(csv_headers: list[str], synonyms_by_field: dict[str, list[str]]) -> dict[str, str]:
    by_norm = {_norm_header(h): h for h in csv_headers}
    suggestions: dict[str, str] = {}
    for field_key, syns in synonyms_by_field.items():
        for syn in syns:
            h = by_norm.get(_norm_header(syn))
            if h:
                suggestions[field_key] = h
                break
    return suggestions


def _csv_text_to_hidden(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _hidden_to_csv_text(val: str) -> str:
    return base64.b64decode((val or "").encode("ascii"), validate=False).decode("utf-8", errors="replace")


def _parse_date(val: str | None) -> datetime | None:
    if not val:
        return None
    v = val.strip()
    if not v:
        return None

    # HTML date input provides YYYY-MM-DD, but accept a few common variants.
    for fmt in (
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(v, fmt)
        except Exception:
            pass
    return None


def _db_path_from_uri() -> str:
    uri = db.engine.url
    if uri.drivername != "sqlite":
        raise RuntimeError("Only SQLite is supported")
    return uri.database


def _setting_get(key: str, default: str | None = None) -> str | None:
    row = db.session.execute(select(AppSetting).where(AppSetting.key == key)).scalar_one_or_none()
    if not row:
        return default
    return row.value if row.value is not None else default


def _setting_set(key: str, value: str | None, username: str | None) -> None:
    row = db.session.execute(select(AppSetting).where(AppSetting.key == key)).scalar_one_or_none()
    if not row:
        row = AppSetting(key=key)
        db.session.add(row)
    row.value = value
    row.updated_at = datetime.utcnow()
    row.updated_by = username


def _log_action(username: str | None, action_type: str, details: str, *, success: bool = True) -> None:
    try:
        db.session.add(
            ActivityLogEntry(
                created_at=datetime.utcnow(),
                username=username,
                action_type=action_type,
                method="app",
                path="-",
                success=bool(success),
                details=(details or "")[:1000],
            )
        )
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def _norm_hostname(v: str | None) -> str | None:
    s = (v or "").strip().rstrip(".")
    return s or None


def _norm_ip(v: str | None) -> str | None:
    s = (v or "").strip()
    return s or None


def _validate_ip(v: str | None) -> tuple[bool, str | None]:
    s = (v or "").strip()
    if not s:
        return True, None
    try:
        ipaddress.ip_address(s)
        return True, None
    except Exception:
        return False, "Invalid IP address format"


def _sqlite_tables_and_cols(path: str) -> tuple[set[str], dict[str, set[str]]]:
    tables: set[str] = set()
    cols: dict[str, set[str]] = {}
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    try:
        conn.row_factory = sqlite3.Row
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            name = (r["name"] or "").strip()
            if not name:
                continue
            tables.add(name)
        for t in list(tables):
            try:
                cols[t] = {r["name"] for r in conn.execute(f"PRAGMA table_info('{t}')").fetchall()}
            except Exception:
                cols[t] = set()
    finally:
        conn.close()
    return tables, cols


def _preflight_db_restore(path: str, *, users_only: bool = False, safe_restore: bool = False) -> list[str]:
    issues: list[str] = []
    try:
        conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        try:
            cur = conn.execute("PRAGMA integrity_check")
            res = (cur.fetchone() or [""])[0]
            if str(res).strip().lower() != "ok":
                issues.append(f"SQLite integrity_check failed: {res}")
        finally:
            conn.close()
    except Exception as e:
        issues.append(f"SQLite integrity_check failed to run: {e}")

    try:
        tables, cols = _sqlite_tables_and_cols(path)

        requirements: dict[str, dict[str, list[str]]] = {"Authentication/Users": {"user": ["username", "password", "role"]}}

        # Safe restore is allowed to skip incompatible/missing tables, so the only hard requirement
        # is that the DB is readable and (optionally) has a user table.
        if (not users_only) and (not safe_restore):
            requirements.update(
                {
                    "Dealerboard Turrets": {
                        "dealerboard_turret": ["id", "mac_address", "last_updated"],
                    },
                    "Ceased/RMA Turrets": {
                        "ceased_rma_turret": ["id", "mac_address", "moved_at"],
                    },
                    "Private Wires": {"private_wire": ["id", "record_no"]},
                    "Ceased Private Wires": {"ceased_private_wire": ["id", "record_no", "cease_date"]},
                    "Changes": {"change_record": ["id"]},
                    "Incidents": {"incident_record": ["id"]},
                }
            )

        for feature, req in requirements.items():
            for table, need_cols in req.items():
                if table not in tables:
                    issues.append(f"Missing table for {feature}: {table}")
                    continue
                present = cols.get(table, set())
                missing = [c for c in need_cols if c not in present]
                if missing:
                    issues.append(f"Missing column(s) for {feature}: {table}.{', '.join(missing)}")
    except Exception as e:
        issues.append(f"Schema inspection failed: {e}")

    return issues


def _setting_bool(key: str, default: bool) -> bool:
    v = (_setting_get(key) or "").strip().lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False
    return default


def _setting_int(key: str, default: int, *, min_v: int | None = None, max_v: int | None = None) -> int:
    try:
        n = int((_setting_get(key) or "").strip())
    except Exception:
        n = default
    if min_v is not None:
        n = max(min_v, n)
    if max_v is not None:
        n = min(max_v, n)
    return n


def _lookup_ensure_option(group: str, value: str | None) -> None:
    v = (value or "").strip()
    if not v:
        return
    try:
        existing = (
            db.session.execute(
                select(LookupOption)
                .where(LookupOption.group == group)
                .where(LookupOption.value == v)
                .limit(1)
            )
            .scalars()
            .first()
        )
        if existing:
            return
        db.session.add(LookupOption(group=group, value=v, is_active=False, sort_order=0))
    except Exception:
        # Best-effort; never break imports/forms.
        pass


def _custom_field_entity_key(entity: str) -> str:
    return (entity or "").strip().lower()


def _custom_fields_for(entity: str) -> list[CustomFieldDef]:
    ek = _custom_field_entity_key(entity)
    return (
        db.session.execute(
            select(CustomFieldDef)
            .where(CustomFieldDef.entity == ek)
            .where(CustomFieldDef.is_active.is_(True))
            .order_by(CustomFieldDef.sort_order.asc(), CustomFieldDef.field_key.asc())
        )
        .scalars()
        .all()
    )


def _custom_values_from_obj(obj) -> dict[int, str]:
    try:
        raw = getattr(obj, "custom_fields_json", None) or ""
        if not raw:
            return {}
        d = json.loads(raw)
        if not isinstance(d, dict):
            return {}
        out: dict[int, str] = {}
        for k, v in d.items():
            try:
                fid = int(k)
            except Exception:
                continue
            out[fid] = "" if v is None else str(v)
        return out
    except Exception:
        return {}


def _save_custom_values(entity: str, obj, form: dict) -> tuple[bool, str | None]:
    fields = _custom_fields_for(entity)
    values: dict[str, str] = {}
    for f in fields:
        key = f"cf_{f.id}"
        val = (form.get(key) or "").strip()
        if f.is_required and not val:
            return False, f"{f.label} is required"
        values[str(f.id)] = val
    try:
        setattr(obj, "custom_fields_json", json.dumps(values))
    except Exception:
        pass
    return True, None


def _human_size(n: int) -> str:
    try:
        n = int(n)
    except Exception:
        return "-"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _backup_dir_default() -> str:
    base = os.environ.get("APPDATA") or os.environ.get("ProgramData") or os.getcwd()
    return os.path.join(base, "Telephony-Portal", "backups")


def _get_backup_settings() -> dict:
    return {
        "backup_dir": _setting_get("backup_dir", _backup_dir_default()) or _backup_dir_default(),
        "backup_retention": _setting_int("backup_retention", 30, min_v=1, max_v=365),
        "backup_auto_delete": _setting_bool("backup_auto_delete", True),
        "backup_allow_manual_delete": _setting_bool("backup_allow_manual_delete", True),
        "backup_schedule_time": _setting_get("backup_schedule_time", "02:00") or "02:00",
        "task_name": _setting_get("backup_task_name", "TelephonyPortal Nightly Backup") or "TelephonyPortal Nightly Backup",
    }


def _safe_backup_filename(filename: str) -> str:
    name = os.path.basename((filename or "").strip())
    if not name.lower().endswith(".db"):
        return ""
    return name


def _sqlite_backup(src_path: str, dest_path: str) -> None:
    src = sqlite3.connect(src_path, timeout=30, check_same_thread=False)
    try:
        dest = sqlite3.connect(dest_path, timeout=30, check_same_thread=False)
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

    db.session.close()
    try:
        db.engine.dispose()
    except Exception:
        pass
    _sqlite_backup(db_path, dest_path)
    return dest_path


def _run_retention(backups_dir: str, retention_count: int) -> list[str]:
    deleted: list[str] = []
    try:
        files = []
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


def _sqlite_list_tables() -> list[str]:
    db_path = _db_path_from_uri()
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def _sqlite_table_info(table: str) -> list[dict]:
    db_path = _db_path_from_uri()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _sqlite_pk_column(table: str) -> str | None:
    info = _sqlite_table_info(table)
    for r in info:
        if r.get("pk"):
            return r.get("name")
    return None


def _safe_identifier(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""))


def _dbadmin_allowed_tables() -> list[str]:
    return _sqlite_list_tables()


def _sqlite_conn():
    db_path = _db_path_from_uri()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ddi_form_options():
    locations = _lookup_values("ddi_location") or []
    bt_systems = _lookup_values("ddi_bt_system") or []
    cisco_clusters = _lookup_values("ddi_cisco_cluster") or []
    tpo_options = _lookup_values("ddi_tpo") or []

    return {
        "locations": locations,
        "bt_systems": bt_systems,
        "cisco_clusters": cisco_clusters,
        "tpo_options": tpo_options,
    }


def _parse_any_date(val: str | None) -> datetime | None:
    if not val:
        return None
    v = val.strip()
    if not v:
        return None

    # Try a few common formats.
    for fmt in (
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(v, fmt)
        except Exception:
            pass
    return None


def _parse_yes_no_na(val: str | None) -> bool | None:
    if not val:
        return None
    v = val.strip().lower()
    if v == "yes":
        return True
    if v == "no":
        return False
    if v in {"n/a", "na", "n\\a"}:
        return None
    return None


def _lookup_values(group: str) -> list[str]:
    try:
        rows = (
            db.session.execute(
                select(LookupOption)
                .where(LookupOption.group == group)
                .where(LookupOption.is_active.is_(True))
                .order_by(LookupOption.sort_order.asc(), LookupOption.value.asc())
            )
            .scalars()
            .all()
        )
        return [r.value for r in rows if r.value]
    except Exception:
        return []


def _cab_mondays(count: int = 30) -> list[datetime]:
    today = date.today()
    # Monday is 0
    days_to_next_monday = (7 - today.weekday()) % 7
    first = today + timedelta(days=days_to_next_monday)
    return [datetime.combine(first + timedelta(days=7 * i), datetime.min.time()) for i in range(count)]


def _cab_monday_options(count: int = 30) -> list[datetime]:
    opts = {d.date(): d for d in _cab_mondays(count=count)}
    try:
        rows = db.session.execute(
            select(db.func.date(ChangeRecord.cab_date)).where(ChangeRecord.cab_date.is_not(None)).distinct()
        ).all()
        for r in rows:
            v = r[0]
            if not v:
                continue
            if isinstance(v, date):
                dt = datetime.combine(v, datetime.min.time())
            else:
                dt = _parse_any_date(str(v))
                if not dt:
                    continue
                dt = datetime.combine(dt.date(), datetime.min.time())
            opts[dt.date()] = dt
    except Exception:
        pass

    try:
        lock_dates = db.session.execute(
            select(CabLock.cab_monday).where(CabLock.cab_monday.is_not(None)).distinct()
        ).all()
        for r in lock_dates:
            v = r[0]
            if not v:
                continue
            if isinstance(v, date):
                dt = datetime.combine(v, datetime.min.time())
            else:
                dt = _parse_any_date(str(v))
                if not dt:
                    continue
                dt = datetime.combine(dt.date(), datetime.min.time())
            opts[dt.date()] = dt
    except Exception:
        pass

    return [opts[k] for k in sorted(opts.keys())]


def _changes_form_options():
    yes_no = _lookup_values("yes_no") or ["Yes", "No"]
    yes_no_na = list(dict.fromkeys([*yes_no, "N/A"]))

    approved_statuses = _lookup_values("approved_status")
    if not approved_statuses:
        approved_statuses = ["No", "On Hold", "Yes"]

    regions = _lookup_values("region") or []
    technologies = _lookup_values("technology") or []
    change_categories = _lookup_values("change_category") or []
    global_service_approvals = _lookup_values("global_service_approval") or []

    change_statuses = _lookup_values("change_status")
    if not change_statuses:
        change_statuses = ["Planned", "In Progress", "Completed"]

    return {
        "yes_no": yes_no,
        "yes_no_na": yes_no_na,
        "approved_statuses": approved_statuses,
        "regions": regions,
        "technologies": technologies,
        "change_categories": change_categories,
        "global_service_approvals": global_service_approvals,
        "change_statuses": change_statuses,
        "cab_mondays": _cab_monday_options(),
    }


def _servers_form_options() -> dict:
    return {
        "applications": _lookup_values("server_application") or [],
        "sites": _lookup_values("server_site") or [],
        "prod_devs": _lookup_values("server_prod_dev") or ["Prod", "Dev"],
        "roles": _lookup_values("server_role") or [],
        "db_servers": _lookup_values("server_db_server") or [],
        "services": _lookup_values("server_service") or [],
        "oses": _lookup_values("server_os") or [],
        "hardwares": _lookup_values("server_hardware") or [],
        "statuses": _lookup_values("server_status") or [],
        "server_types": _lookup_values("server_type") or [],
        "countries": _lookup_values("country") or [],
    }


def _current_username() -> str:
    return (getattr(current_user, "name", None) or getattr(current_user, "username", None) or "").strip() or "Unknown"


def _log_activity(action_type: str, details: str, success: bool = True) -> None:
    try:
        db.session.add(
            ActivityLogEntry(
                created_at=datetime.utcnow(),
                username=getattr(current_user, "username", None),
                action_type=action_type,
                method=request.method,
                path=request.path,
                success=success,
                details=details,
            )
        )
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        try:
            current_app.logger.exception("Failed to write activity log entry")
        except Exception:
            pass


def _incidents_form_options():
    regions = _lookup_values("region") or []
    technologies = _lookup_values("technology") or []
    locations = _lookup_values("incident_location") or []
    severities = _lookup_values("incident_severity") or []
    years = [
        str(r[0])
        for r in db.session.execute(
            select(db.func.strftime("%Y", IncidentRecord.incident_date)).distinct().order_by(db.func.strftime("%Y", IncidentRecord.incident_date).desc())
        ).all()
        if r[0]
    ]

    return {
        "regions": regions,
        "technologies": technologies,
        "locations": locations,
        "severities": severities,
        "years": years,
    }


def _parse_int(val: str | None) -> int | None:
    if val is None:
        return None
    v = str(val).strip()
    if not v:
        return None
    try:
        return int(v)
    except Exception:
        return None


@core_bp.route("/")
@login_required
def index():
    ddi_count = 0
    spare_count = 0
    pw_count = 0
    turret_count = 0

    changes_pending_approval = 0
    changes_pending_regional = 0
    incidents_by_severity_30d: list = []
    changes_by_region: list = []
    recent_changes: list = []
    recent_incidents: list = []
    upcoming_cabs: list = []

    servers_by_os: list = []
    servers_by_application: list = []
    servers_eol_18m: int = 0
    servers_count: int = 0

    now = datetime.utcnow()

    try:
        ddi_count = db.session.execute(select(db.func.count()).select_from(DDINumber)).scalar_one()
    except Exception:
        ddi_count = 0

    try:
        spare_count = (
            db.session.execute(
                select(db.func.count()).select_from(DDINumber).where(DDINumber.status == "Spare")
            ).scalar_one()
        )
    except Exception:
        spare_count = 0

    try:
        pw_count = db.session.execute(select(db.func.count()).select_from(PrivateWire)).scalar_one()
    except Exception:
        pw_count = 0

    try:
        turret_count = db.session.execute(select(db.func.count()).select_from(DealerboardTurret)).scalar_one()
    except Exception:
        turret_count = 0

    try:
        changes_pending_approval = (
            db.session.execute(
                select(db.func.count())
                .select_from(ChangeRecord)
                .where((ChangeRecord.approved_status == "No") | (ChangeRecord.approved_status.is_(None)))
            ).scalar_one()
        )
    except Exception:
        changes_pending_approval = 0

    try:
        changes_pending_regional = (
            db.session.execute(
                select(db.func.count())
                .select_from(ChangeRecord)
                .where(
                    (ChangeRecord.regional_approval_status == "No")
                    | (ChangeRecord.regional_approval_status.is_(None))
                )
            ).scalar_one()
        )
    except Exception:
        changes_pending_regional = 0

    try:
        cutoff = now - timedelta(days=30)
        incidents_by_severity_30d = (
            db.session.execute(
                select(
                    IncidentRecord.severity.label("severity"),
                    db.func.count().label("count"),
                )
                .where(IncidentRecord.incident_date >= cutoff)
                .group_by(IncidentRecord.severity)
                .order_by(IncidentRecord.severity.asc())
            )
            .mappings()
            .all()
        )
    except Exception:
        incidents_by_severity_30d = []

    try:
        changes_by_region = (
            db.session.execute(
                select(
                    ChangeRecord.region.label("region"),
                    db.func.count().label("count"),
                )
                .group_by(ChangeRecord.region)
                .order_by(db.func.count().desc())
            )
            .mappings()
            .all()
        )
    except Exception:
        changes_by_region = []

    try:
        recent_changes = (
            db.session.execute(
                select(ChangeRecord)
                .order_by(ChangeRecord.last_updated.desc().nullslast(), ChangeRecord.id.desc())
                .limit(8)
            )
            .scalars()
            .all()
        )
    except Exception:
        recent_changes = []

    try:
        recent_incidents = (
            db.session.execute(
                select(IncidentRecord)
                .order_by(IncidentRecord.last_updated.desc().nullslast(), IncidentRecord.id.desc())
                .limit(8)
            )
            .scalars()
            .all()
        )
    except Exception:
        recent_incidents = []

    try:
        servers_count = db.session.execute(select(db.func.count()).select_from(Server)).scalar_one()
    except Exception:
        servers_count = 0

    try:
        servers_by_os = (
            db.session.execute(
                select(
                    Server.os.label("os"),
                    db.func.count().label("count"),
                )
                .group_by(Server.os)
                .order_by(db.func.count().desc())
            )
            .mappings()
            .all()
        )
    except Exception:
        servers_by_os = []

    try:
        servers_by_application = (
            db.session.execute(
                select(
                    Server.application.label("application"),
                    db.func.count().label("count"),
                )
                .group_by(Server.application)
                .order_by(db.func.count().desc())
            )
            .mappings()
            .all()
        )
    except Exception:
        servers_by_application = []

    try:
        eol_cutoff = now + timedelta(days=30 * 18)
        servers_eol_18m = (
            db.session.execute(
                select(db.func.count())
                .select_from(Server)
                .where(Server.eol_date.is_not(None))
                .where(Server.eol_date >= now)
                .where(Server.eol_date <= eol_cutoff)
            ).scalar_one()
        )
    except Exception:
        servers_eol_18m = 0

    try:
        mondays = _cab_mondays(count=12)
        if mondays:
            start = mondays[0]
            end = mondays[-1] + timedelta(days=1)
            rows = (
                db.session.execute(
                    select(
                        db.func.date(ChangeRecord.cab_date).label("cab_date"),
                        db.func.count().label("count"),
                    )
                    .where(ChangeRecord.cab_date.is_not(None))
                    .where(ChangeRecord.cab_date >= start)
                    .where(ChangeRecord.cab_date < end)
                    .group_by(db.func.date(ChangeRecord.cab_date))
                )
                .mappings()
                .all()
            )

            counts = {str(r["cab_date"]): int(r["count"] or 0) for r in rows if r.get("cab_date")}
            upcoming_cabs = [
                {"cab_date": d.strftime("%Y-%m-%d"), "count": counts.get(d.strftime("%Y-%m-%d"), 0)}
                for d in mondays
            ]
            upcoming_cabs = [r for r in upcoming_cabs if int(r.get("count") or 0) > 0]
    except Exception:
        upcoming_cabs = []

    return render_template(
        "index.html",
        ddi_count=ddi_count,
        spare_count=spare_count,
        pw_count=pw_count,
        turret_count=turret_count,
        changes_pending_approval=changes_pending_approval,
        changes_pending_regional=changes_pending_regional,
        incidents_by_severity_30d=incidents_by_severity_30d,
        changes_by_region=changes_by_region,
        recent_changes=recent_changes,
        recent_incidents=recent_incidents,
        upcoming_cabs=upcoming_cabs,
        servers_by_os=servers_by_os,
        servers_by_application=servers_by_application,
        servers_eol_18m=servers_eol_18m,
        servers_count=servers_count,
        saved_filters=[],
        users=[],
        now=now,
    )


@core_bp.route("/servers")
@login_required
def servers_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    country = (request.args.get("country") or "").strip()
    application = (request.args.get("application") or "").strip()
    os_name = (request.args.get("os") or "").strip()
    sort = (request.args.get("sort") or "hostname").strip()
    order = (request.args.get("order") or "asc").strip().lower()

    stmt = select(Server)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            or_(
                Server.hostname.ilike(like),
                Server.ip_address.ilike(like),
                Server.verint_id.ilike(like),
                Server.esxi_host.ilike(like),
            )
        )
    if country:
        stmt = stmt.where(Server.country == country)
    if application:
        stmt = stmt.where(Server.application == application)
    if os_name:
        stmt = stmt.where(Server.os == os_name)

    sort_map = {
        "hostname": Server.hostname,
        "ip_address": Server.ip_address,
        "application": Server.application,
        "os": Server.os,
        "country": Server.country,
        "site": Server.site,
        "eol_date": Server.eol_date,
        "status": Server.status,
        "last_updated": Server.last_updated,
    }
    sort_col = sort_map.get(sort, Server.hostname)
    if order == "desc":
        stmt = stmt.order_by(sort_col.desc().nullslast(), Server.id.desc())
    else:
        stmt = stmt.order_by(sort_col.asc().nullslast(), Server.id.asc())

    servers = db.paginate(stmt, page=page, per_page=25, error_out=False)
    opts = _servers_form_options()
    return render_template(
        "servers/list.html",
        servers=servers,
        search=search,
        country=country,
        application=application,
        os=os_name,
        sort=sort,
        order=order,
        **opts,
    )


@core_bp.route("/servers/view/<int:id>")
@login_required
def servers_view(id: int):
    s = db.session.get(Server, id)
    if not s:
        abort(404)
    next_url = request.args.get("next") or request.referrer or url_for("servers_list")
    return render_template("servers/view.html", server=s, next_url=next_url)


@core_bp.route("/servers/add", methods=["GET", "POST"])
@login_required
def servers_add():
    next_url = request.args.get("next") or url_for("servers_list")
    opts = _servers_form_options()
    if request.method == "POST":
        form = request.form.to_dict(flat=True)
        hostname = (form.get("hostname") or "").strip()
        if not hostname:
            flash("Hostname is required", "danger")
            return render_template("servers/add.html", next_url=next_url, form=form, **opts), 400
        if db.session.execute(select(Server.id).where(Server.hostname == hostname).limit(1)).first():
            flash("Hostname already exists", "danger")
            return render_template("servers/add.html", next_url=next_url, form=form, **opts), 400

        now = datetime.utcnow()
        s = Server(
            hostname=hostname,
            ip_address=(form.get("ip_address") or "").strip() or None,
            application=(form.get("application") or "").strip() or None,
            role=(form.get("role") or "").strip() or None,
            service=(form.get("service") or "").strip() or None,
            db_server=(form.get("db_server") or "").strip() or None,
            prod_dev=(form.get("prod_dev") or "").strip() or None,
            country=(form.get("country") or "").strip() or None,
            site=(form.get("site") or "").strip() or None,
            verint_id=(form.get("verint_id") or "").strip() or None,
            os=(form.get("os") or "").strip() or None,
            status=(form.get("status") or "").strip() or None,
            hardware=(form.get("hardware") or "").strip() or None,
            esxi_host=(form.get("esxi_host") or "").strip() or None,
            server_type=(form.get("server_type") or "").strip() or None,
            eol_date=_parse_date(form.get("eol_date")),
            date_created=now,
            last_updated=now,
            last_updated_by=_current_username(),
        )
        db.session.add(s)
        db.session.commit()
        flash("Server created", "success")
        return redirect(url_for("servers_view", id=s.id, next=next_url))

    return render_template("servers/add.html", next_url=next_url, form={}, **opts)


@core_bp.route("/servers/edit/<int:id>", methods=["GET", "POST"])
@login_required
def servers_edit(id: int):
    s = db.session.get(Server, id)
    if not s:
        abort(404)
    next_url = request.args.get("next") or request.referrer or url_for("servers_list")
    opts = _servers_form_options()

    if request.method == "POST":
        form = request.form.to_dict(flat=True)
        hostname = (form.get("hostname") or "").strip()
        if not hostname:
            flash("Hostname is required", "danger")
            return render_template("servers/edit.html", server=s, next_url=next_url, form=form, **opts), 400
        existing = (
            db.session.execute(
                select(Server.id)
                .where(Server.hostname == hostname)
                .where(Server.id != s.id)
                .limit(1)
            ).first()
        )
        if existing:
            flash("Hostname already exists", "danger")
            return render_template("servers/edit.html", server=s, next_url=next_url, form=form, **opts), 400

        s.hostname = hostname
        s.ip_address = (form.get("ip_address") or "").strip() or None
        s.application = (form.get("application") or "").strip() or None
        s.role = (form.get("role") or "").strip() or None
        s.service = (form.get("service") or "").strip() or None
        s.db_server = (form.get("db_server") or "").strip() or None
        s.prod_dev = (form.get("prod_dev") or "").strip() or None
        s.country = (form.get("country") or "").strip() or None
        s.site = (form.get("site") or "").strip() or None
        s.verint_id = (form.get("verint_id") or "").strip() or None
        s.os = (form.get("os") or "").strip() or None
        s.status = (form.get("status") or "").strip() or None
        s.hardware = (form.get("hardware") or "").strip() or None
        s.esxi_host = (form.get("esxi_host") or "").strip() or None
        s.server_type = (form.get("server_type") or "").strip() or None
        s.eol_date = _parse_date(form.get("eol_date"))
        s.last_updated = datetime.utcnow()
        s.last_updated_by = _current_username()
        db.session.commit()
        flash("Server updated", "success")
        return redirect(url_for("servers_view", id=s.id, next=next_url))

    form = {
        "hostname": s.hostname or "",
        "ip_address": s.ip_address or "",
        "application": s.application or "",
        "role": s.role or "",
        "service": s.service or "",
        "db_server": s.db_server or "",
        "prod_dev": s.prod_dev or "",
        "country": s.country or "",
        "site": s.site or "",
        "verint_id": s.verint_id or "",
        "os": s.os or "",
        "status": s.status or "",
        "hardware": s.hardware or "",
        "esxi_host": s.esxi_host or "",
        "server_type": s.server_type or "",
        "eol_date": s.eol_date.strftime("%Y-%m-%d") if s.eol_date else "",
    }
    return render_template("servers/edit.html", server=s, next_url=next_url, form=form, **opts)


@core_bp.route("/servers/cease/<int:id>", methods=["POST"])
@login_required
def servers_cease(id: int):
    s = db.session.get(Server, id)
    if not s:
        abort(404)
    reason = (request.form.get("cease_reason") or "").strip() or None
    if not reason:
        flash("Cease reason is required", "danger")
        return redirect(url_for("servers_view", id=id))

    now = datetime.utcnow()
    c = CeasedServer(
        original_server_id=s.id,
        hostname=s.hostname,
        ip_address=s.ip_address,
        application=s.application,
        role=s.role,
        service=s.service,
        db_server=s.db_server,
        prod_dev=s.prod_dev,
        country=s.country,
        site=s.site,
        verint_id=s.verint_id,
        os=s.os,
        status=s.status,
        hardware=s.hardware,
        esxi_host=s.esxi_host,
        server_type=s.server_type,
        eol_date=s.eol_date,
        ceased_date=now,
        ceased_by=_current_username(),
        cease_reason=reason,
    )
    db.session.add(c)
    db.session.delete(s)
    db.session.commit()
    flash("Server ceased", "success")
    return redirect(url_for("ceased_servers_list"))


@core_bp.route("/servers/ceased")
@login_required
def ceased_servers_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    stmt = select(CeasedServer)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            or_(
                CeasedServer.hostname.ilike(like),
                CeasedServer.ip_address.ilike(like),
                CeasedServer.verint_id.ilike(like),
            )
        )
    stmt = stmt.order_by(CeasedServer.ceased_date.desc().nullslast(), CeasedServer.id.desc())
    servers = db.paginate(stmt, page=page, per_page=25, error_out=False)
    return render_template("servers/ceased_list.html", servers=servers, search=search)


@core_bp.route("/servers/ceased/view/<int:id>")
@login_required
def ceased_servers_view(id: int):
    s = db.session.get(CeasedServer, id)
    if not s:
        abort(404)
    next_url = request.args.get("next") or request.referrer or url_for("ceased_servers_list")
    return render_template("servers/ceased_view.html", server=s, next_url=next_url)


@core_bp.route("/servers/bulk-os-update", methods=["GET", "POST"])
@login_required
def servers_bulk_os_update():
    if not current_user.is_admin():
        abort(403)
    opts = _servers_form_options()
    if request.method == "POST":
        old_os = (request.form.get("old_os") or "").strip()
        new_os = (request.form.get("new_os") or "").strip()
        new_eol_date = _parse_date(request.form.get("new_eol_date"))

        if not old_os:
            flash("Current OS is required", "danger")
            return render_template("servers/bulk_os_update.html", **opts), 400

        if not new_os and not new_eol_date:
            flash("Provide a new OS and/or a new EOL date", "danger")
            return render_template("servers/bulk_os_update.html", **opts), 400

        if new_os and old_os == new_os and not new_eol_date:
            flash("No changes to apply", "warning")
            return render_template("servers/bulk_os_update.html", **opts), 400

        now = datetime.utcnow()

        updates: dict = {
            Server.last_updated: now,
            Server.last_updated_by: _current_username(),
        }
        if new_os and old_os != new_os:
            updates[Server.os] = new_os
        if new_eol_date:
            updates[Server.eol_date] = new_eol_date

        updated = (
            db.session.query(Server)
            .filter(Server.os == old_os)
            .update(updates, synchronize_session=False)
        )
        db.session.commit()
        flash(f"Updated {updated} server(s)", "success")
        return redirect(url_for("servers_list", os=(new_os or old_os)))
    return render_template("servers/bulk_os_update.html", **opts)


@core_bp.route("/servers/export")
@login_required
def servers_export():
    if not current_user.is_admin():
        abort(403)

    rows = db.session.execute(select(Server).order_by(Server.hostname.asc())).scalars().all()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(
        [
            "hostname",
            "ip_address",
            "application",
            "role",
            "service",
            "db_server",
            "prod_dev",
            "country",
            "site",
            "verint_id",
            "os",
            "status",
            "hardware",
            "esxi_host",
            "server_type",
            "eol_date",
        ]
    )
    for s in rows:
        w.writerow(
            [
                s.hostname or "",
                s.ip_address or "",
                s.application or "",
                s.role or "",
                s.service or "",
                s.db_server or "",
                s.prod_dev or "",
                s.country or "",
                s.site or "",
                s.verint_id or "",
                s.os or "",
                s.status or "",
                s.hardware or "",
                s.esxi_host or "",
                s.server_type or "",
                s.eol_date.strftime("%Y-%m-%d") if s.eol_date else "",
            ]
        )
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=servers.csv"
    return resp


@core_bp.route("/servers/import", methods=["GET", "POST"])
@login_required
def servers_import():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("servers/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            hostname_col = mapping.get("hostname")
            if not hostname_col:
                flash("Hostname must be mapped", "danger")
                return redirect(url_for("servers_import"))

            now = datetime.utcnow()
            created = 0
            updated = 0
            skipped = 0

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            for row in reader:
                hostname = pick(row, "hostname")
                if not hostname:
                    skipped += 1
                    continue

                s = Server.query.filter_by(hostname=hostname).first()
                is_new = s is None
                if is_new:
                    s = Server(hostname=hostname, date_created=now)
                    db.session.add(s)

                s.ip_address = pick(row, "ip_address") or s.ip_address
                s.application = pick(row, "application") or s.application
                s.role = pick(row, "role") or s.role
                s.service = pick(row, "service") or s.service
                s.db_server = pick(row, "db_server") or s.db_server
                s.prod_dev = pick(row, "prod_dev") or s.prod_dev
                s.country = pick(row, "country") or s.country
                s.site = pick(row, "site") or s.site
                s.verint_id = pick(row, "verint_id") or s.verint_id
                s.os = pick(row, "os") or s.os
                s.status = pick(row, "status") or s.status
                s.hardware = pick(row, "hardware") or s.hardware
                s.esxi_host = pick(row, "esxi_host") or s.esxi_host
                s.server_type = pick(row, "server_type") or s.server_type

                eol_raw = pick(row, "eol_date")
                if eol_raw:
                    parsed = _parse_any_date(eol_raw)
                    if parsed:
                        s.eol_date = parsed

                s.last_updated = now
                s.last_updated_by = _current_username()

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete. Created {created}, updated {updated}, skipped {skipped}.", "success")
            return redirect(url_for("servers_list"))

        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return redirect(url_for("servers_import"))

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return redirect(url_for("servers_import"))

        target_fields = [
            {"key": "hostname", "label": "Hostname", "required": True},
            {"key": "ip_address", "label": "IP Address", "required": False},
            {"key": "application", "label": "Application", "required": False},
            {"key": "role", "label": "Role", "required": False},
            {"key": "service", "label": "Service", "required": False},
            {"key": "db_server", "label": "DB Server", "required": False},
            {"key": "prod_dev", "label": "Prod/Dev", "required": False},
            {"key": "country", "label": "Country", "required": False},
            {"key": "site", "label": "Site", "required": False},
            {"key": "verint_id", "label": "Verint ID", "required": False},
            {"key": "os", "label": "OS", "required": False},
            {"key": "status", "label": "Status", "required": False},
            {"key": "hardware", "label": "Hardware", "required": False},
            {"key": "esxi_host", "label": "ESXi Host", "required": False},
            {"key": "server_type", "label": "Server Type", "required": False},
            {"key": "eol_date", "label": "EOL Date", "required": False},
        ]

        synonyms = {
            "hostname": ["hostname", "host", "server", "server_name", "server name", "name"],
            "ip_address": ["ip", "ip_address", "ip address"],
            "application": ["application", "app"],
            "role": ["role"],
            "service": ["service"],
            "db_server": ["db_server", "db server", "database server", "database"],
            "prod_dev": ["prod_dev", "prod/dev", "environment", "env"],
            "country": ["country"],
            "site": ["site", "location"],
            "verint_id": ["verint_id", "verint id", "verint"],
            "os": ["os", "operating system"],
            "status": ["status"],
            "hardware": ["hardware"],
            "esxi_host": ["esxi_host", "esxi host", "vmhost", "vm host", "host"],
            "server_type": ["server_type", "server type", "type"],
            "eol_date": ["eol", "eol_date", "eol date", "end_of_life", "end of life"],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map Servers CSV Fields",
            help_text="Map the columns from your CSV file to the Server fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("servers_list"),
        )

    return render_template("servers/import.html")


@core_bp.route("/ddi")
@login_required
def ddi_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    location = (request.args.get("location") or "").strip()
    bt_system = (request.args.get("bt_system") or "").strip()
    cisco_cluster = (request.args.get("cisco_cluster") or "").strip()
    tpo = (request.args.get("tpo") or "").strip()
    sort = (request.args.get("sort") or "last_updated").strip()
    order = (request.args.get("order") or "desc").strip().lower()

    stmt = select(DDINumber)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if status:
        stmt = stmt.where(DDINumber.status == status)
    if location:
        stmt = stmt.where(DDINumber.location == location)
    if bt_system:
        stmt = stmt.where(DDINumber.bt_system == bt_system)
    if cisco_cluster:
        stmt = stmt.where(DDINumber.cisco_cluster == cisco_cluster)
    if tpo:
        stmt = stmt.where(DDINumber.tpo == tpo)

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(DDINumber.ddi_number, s),
                _contains(DDINumber.username, s),
                _contains(DDINumber.location, s),
                _contains(DDINumber.bt_system, s),
                _contains(DDINumber.cisco_cluster, s),
                _contains(DDINumber.tpo, s),
            )
        )

    sort_map = {
        "ddi_number": DDINumber.ddi_number,
        "username": DDINumber.username,
        "cisco_cluster": DDINumber.cisco_cluster,
        "tpo": DDINumber.tpo,
        "bt_system": DDINumber.bt_system,
        "location": DDINumber.location,
        "status": DDINumber.status,
        "date_spare": DDINumber.date_spare,
        "last_updated": DDINumber.last_updated,
    }
    sort_col = sort_map.get(sort, DDINumber.last_updated)
    if order == "asc":
        stmt = stmt.order_by(sort_col.asc().nullslast(), DDINumber.id.asc())
    else:
        stmt = stmt.order_by(sort_col.desc().nullslast(), DDINumber.id.desc())

    ddi_numbers = db.paginate(stmt, page=page, per_page=25, error_out=False)
    opts = _ddi_form_options()
    return render_template(
        "ddi/list.html",
        ddi_numbers=ddi_numbers,
        search=search,
        status=status,
        location=location,
        bt_system=bt_system,
        cisco_cluster=cisco_cluster,
        tpo=tpo,
        sort=sort,
        order=order,
        locations=opts["locations"],
        bt_systems=opts["bt_systems"],
        cisco_clusters=opts["cisco_clusters"],
        tpo_options=opts["tpo_options"],
    )


@core_bp.route("/ddi/request-spare", methods=["GET", "POST"])
@login_required
def ddi_request_spare():
    if not current_user.is_admin():
        abort(403)

    opts = _ddi_form_options()

    if request.method == "POST":
        location = (request.form.get("location") or "").strip()
        username = (request.form.get("username") or "").strip() or None
        cisco_cluster = (request.form.get("cisco_cluster") or "").strip() or None
        tpo = (request.form.get("tpo") or "").strip() or None

        if not location:
            flash("Location is required", "danger")
            return render_template(
                "ddi/request_spare.html",
                locations=opts["locations"],
                cisco_clusters=opts["cisco_clusters"],
                tpo_options=opts["tpo_options"],
            )

        spare = (
            db.session.execute(
                select(DDINumber)
                .where(DDINumber.status == "Spare", DDINumber.location == location)
                .order_by(DDINumber.date_spare.asc().nullsfirst(), DDINumber.id.asc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if not spare:
            flash("No spare numbers available for that location", "warning")
            return redirect(url_for("ddi_list"))

        now = datetime.utcnow()
        spare.status = "Active"
        spare.username = username
        if cisco_cluster is not None:
            spare.cisco_cluster = cisco_cluster
        if tpo is not None:
            spare.tpo = tpo
        spare.date_spare = None
        spare.last_updated = now
        spare.last_change = f"Assigned from spare by {_current_username()}"

        db.session.commit()
        flash(f"Assigned spare DDI {spare.ddi_number}", "success")
        return redirect(url_for("ddi_list"))

    return render_template(
        "ddi/request_spare.html",
        locations=opts["locations"],
        cisco_clusters=opts["cisco_clusters"],
        tpo_options=opts["tpo_options"],
    )


@core_bp.route("/ddi/import", methods=["GET", "POST"])
@login_required
def ddi_import():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("ddi/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            ddi_col = mapping.get("ddi_number")
            if not ddi_col:
                flash("DDI Number must be mapped", "danger")
                return redirect(url_for("ddi_import"))

            now = datetime.utcnow()
            created = 0
            updated = 0
            skipped = 0

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            for row in reader:
                line_type = pick(row, "line_type")
                if line_type and line_type.upper() != "DDI":
                    skipped += 1
                    continue

                ddi_no = pick(row, "ddi_number")
                if not ddi_no:
                    skipped += 1
                    continue

                rec = DDINumber.query.filter(DDINumber.ddi_number == ddi_no).first()
                is_new = rec is None
                if is_new:
                    rec = DDINumber(ddi_number=ddi_no, date_created=now)
                    db.session.add(rec)

                rec.username = pick(row, "username") or rec.username
                rec.line_type = line_type or rec.line_type
                rec.virtual_slot_start = pick(row, "virtual_slot_start") or rec.virtual_slot_start
                rec.virtual_slot_stop = pick(row, "virtual_slot_stop") or rec.virtual_slot_stop

                rec.last_updated = now
                rec.last_change = f"Imported by {_current_username()}"

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete. Created {created}, updated {updated}, skipped {skipped}.", "success")
            return redirect(url_for("ddi_list"))

        f = request.files.get("file")
        if not f:
            flash("No file uploaded", "danger")
            return render_template("ddi/import.html")

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("ddi/import.html"), 400

        target_fields = [
            {"key": "ddi_number", "label": "DDI Number", "required": True},
            {"key": "username", "label": "Username", "required": False},
            {"key": "line_type", "label": "Line Type", "required": False},
            {"key": "virtual_slot_start", "label": "Virtual Slot Start", "required": False},
            {"key": "virtual_slot_stop", "label": "Virtual Slot Stop", "required": False},
        ]
        synonyms = {
            "ddi_number": [
                "lineExtension",
                "line_extension",
                "ddi_number",
                "ddi",
                "DDI",
                "Line Extension",
            ],
            "username": [
                "LineName",
                "line_name",
                "username",
                "user",
                "UserName",
                "Line Name",
            ],
            "line_type": ["Linetype", "line_type", "LineType", "Line type"],
            "virtual_slot_start": [
                "virtualslotstart",
                "virtual_slot_start",
                "virtual slot start",
            ],
            "virtual_slot_stop": [
                "virtualslotstop",
                "virtual_slot_stop",
                "virtual slot stop",
            ],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map DDI CSV Fields",
            help_text="Map the columns from your CSV file to the DDI fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("ddi_list"),
        )

    return render_template("ddi/import.html")


@core_bp.route("/ddi/export")
@login_required
def ddi_export():
    stmt = select(DDINumber).order_by(DDINumber.id.asc())
    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)
    headers = [
        "id",
        "ddi_number",
        "username",
        "cisco_cluster",
        "tpo",
        "bt_system",
        "location",
        "status",
        "date_spare",
        "date_created",
        "last_updated",
        "last_change",
        "line_type",
        "virtual_slot_start",
        "virtual_slot_stop",
    ]
    w.writerow(headers)

    def fmt_dt(d: datetime | None) -> str:
        return d.strftime("%Y-%m-%d %H:%M:%S") if d else ""

    for r in rows:
        w.writerow(
            [
                r.id,
                r.ddi_number or "",
                r.username or "",
                r.cisco_cluster or "",
                r.tpo or "",
                r.bt_system or "",
                r.location or "",
                r.status or "",
                fmt_dt(r.date_spare),
                fmt_dt(r.date_created),
                fmt_dt(r.last_updated),
                r.last_change or "",
                r.line_type or "",
                r.virtual_slot_start or "",
                r.virtual_slot_stop or "",
            ]
        )

    from flask import Response

    data = output.getvalue()
    filename = f"ddi_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/ddi/add", methods=["GET", "POST"])
@login_required
def ddi_add():
    if not current_user.is_admin():
        abort(403)

    opts = _ddi_form_options()
    if request.method == "POST":
        ddi_number = (request.form.get("ddi_number") or "").strip()
        location = (request.form.get("location") or "").strip()
        status = (request.form.get("status") or "Active").strip() or "Active"

        if not ddi_number or not location:
            flash("DDI number and location are required", "danger")
            return render_template(
                "ddi/add.html",
                locations=opts["locations"],
                bt_systems=opts["bt_systems"],
                cisco_clusters=opts["cisco_clusters"],
                tpo_options=opts["tpo_options"],
            )

        existing = DDINumber.query.filter(DDINumber.ddi_number == ddi_number).first()
        if existing:
            flash("DDI number already exists", "danger")
            return render_template(
                "ddi/add.html",
                locations=opts["locations"],
                bt_systems=opts["bt_systems"],
                cisco_clusters=opts["cisco_clusters"],
                tpo_options=opts["tpo_options"],
            )

        now = datetime.utcnow()
        ddi = DDINumber(
            ddi_number=ddi_number,
            username=(request.form.get("username") or "").strip() or None,
            cisco_cluster=(request.form.get("cisco_cluster") or "").strip() or None,
            tpo=(request.form.get("tpo") or "").strip() or None,
            bt_system=(request.form.get("bt_system") or "").strip() or None,
            location=location,
            status=status,
            date_spare=now if status == "Spare" else None,
            date_created=now,
            last_updated=now,
            last_change=f"Created by {_current_username()}",
        )
        db.session.add(ddi)
        db.session.commit()
        flash("DDI created", "success")
        return redirect(url_for("ddi_list"))

    return render_template(
        "ddi/add.html",
        locations=opts["locations"],
        bt_systems=opts["bt_systems"],
        cisco_clusters=opts["cisco_clusters"],
        tpo_options=opts["tpo_options"],
    )


@core_bp.route("/ddi/edit/<int:id>", methods=["GET", "POST"])
@login_required
def ddi_edit(id: int):
    if not current_user.is_admin():
        abort(403)

    ddi = db.session.get(DDINumber, id)
    if not ddi:
        abort(404)

    opts = _ddi_form_options()
    if request.method == "POST":
        ddi.username = (request.form.get("username") or "").strip() or None
        ddi.cisco_cluster = (request.form.get("cisco_cluster") or "").strip() or None
        ddi.tpo = (request.form.get("tpo") or "").strip() or None
        ddi.bt_system = (request.form.get("bt_system") or "").strip() or None
        ddi.location = (request.form.get("location") or "").strip() or None
        new_status = (request.form.get("status") or "Active").strip() or "Active"

        now = datetime.utcnow()
        if ddi.status != new_status and new_status == "Spare":
            ddi.date_spare = now
        if ddi.status == "Spare" and new_status == "Active":
            ddi.date_spare = None
        ddi.status = new_status
        ddi.last_updated = now
        ddi.last_change = f"Updated by {_current_username()}"
        db.session.commit()
        flash("DDI updated", "success")
        return redirect(url_for("ddi_list"))

    return render_template(
        "ddi/edit.html",
        ddi=ddi,
        locations=opts["locations"],
        bt_systems=opts["bt_systems"],
        cisco_clusters=opts["cisco_clusters"],
        tpo_options=opts["tpo_options"],
    )


@core_bp.route("/private_wire")
@login_required
def pw_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    location_filter = (request.args.get("location") or "").strip()
    vendor_filter = (request.args.get("vendor") or "").strip()
    bearer_filter = (request.args.get("bearer_no") or "").strip()
    sort = (request.args.get("sort") or "last_updated").strip()
    order = (request.args.get("order") or "desc").strip().lower()

    stmt = select(PrivateWire)

    if location_filter:
        stmt = stmt.where(PrivateWire.location == location_filter)
    if vendor_filter:
        stmt = stmt.where(PrivateWire.vendor == vendor_filter)
    if bearer_filter:
        stmt = stmt.where(PrivateWire.bearer_no == bearer_filter)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(PrivateWire.aor, s),
                _contains(PrivateWire.aor_number, s),
                _contains(PrivateWire.location, s),
                _contains(PrivateWire.circuit_no, s),
                _contains(PrivateWire.vendor, s),
                _contains(PrivateWire.bearer_no, s),
                _contains(PrivateWire.hsbc_main_user, s),
                _contains(PrivateWire.company_name, s),
                _contains(PrivateWire.line_label, s),
            )
        )

    sort_map = {
        "aor": PrivateWire.aor,
        "location": PrivateWire.location,
        "circuit_no": PrivateWire.circuit_no,
        "line_label": PrivateWire.line_label,
        "last_updated": PrivateWire.last_updated,
    }
    sort_col = sort_map.get(sort, PrivateWire.last_updated)
    if order == "asc":
        stmt = stmt.order_by(sort_col.asc().nullslast(), PrivateWire.id.asc())
    else:
        stmt = stmt.order_by(sort_col.desc().nullslast(), PrivateWire.id.desc())

    private_wires = db.paginate(stmt, page=page, per_page=25, error_out=False)

    locations = _lookup_values("private_wire_location") or []
    vendors = _lookup_values("private_wire_vendor") or []
    bearers = _lookup_values("private_wire_bearer_no") or []

    return render_template(
        "private_wire/list.html",
        private_wires=private_wires,
        search=search,
        location_filter=location_filter,
        vendor_filter=vendor_filter,
        bearer_filter=bearer_filter,
        locations=locations,
        vendors=vendors,
        bearers=bearers,
        sort=sort,
        order=order,
    )


@core_bp.route("/private_wire/view/<int:id>")
@login_required
def pw_view(id: int):
    pw = db.session.get(PrivateWire, id)
    if not pw:
        abort(404)
    custom_fields = _custom_fields_for("private_wires")
    custom_values = _custom_values_from_obj(pw)
    return render_template(
        "private_wire/view.html",
        pw=pw,
        custom_fields=custom_fields,
        custom_values=custom_values,
    )


@core_bp.route("/private_wire/export")
@login_required
def pw_export():
    if not (current_user.is_admin() or getattr(current_user, "can_export_private_wires", False)):
        abort(403)
    stmt = select(PrivateWire).order_by(PrivateWire.id.asc())
    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)
    headers = [
        "id",
        "record_no",
        "aor",
        "aor_number",
        "port_number",
        "channel_number",
        "location",
        "dc_locale",
        "vega_port",
        "channel",
        "bearer_no",
        "circuit_no",
        "vendor",
        "pw_type",
        "hsbc_main_user",
        "employee_id",
        "private_public",
        "line_label",
        "company_name",
        "company_contact",
        "company_email",
        "snow_ref",
        "last_updated",
        "last_change",
    ]
    w.writerow(headers)

    for pw in rows:
        w.writerow(
            [
                pw.id,
                pw.record_no or "",
                pw.aor or "",
                pw.aor_number or "",
                pw.port_number or "",
                pw.channel_number or "",
                pw.location or "",
                pw.dc_locale or "",
                pw.vega_port or "",
                pw.channel or "",
                pw.bearer_no or "",
                pw.circuit_no or "",
                pw.vendor or "",
                pw.pw_type or "",
                pw.hsbc_main_user or "",
                pw.employee_id or "",
                pw.private_public or "",
                pw.line_label or "",
                pw.company_name or "",
                pw.company_contact or "",
                pw.company_email or "",
                pw.snow_ref or "",
                pw.last_updated.strftime("%Y-%m-%d %H:%M:%S") if pw.last_updated else "",
                pw.last_change or "",
            ]
        )

    from flask import Response

    data = output.getvalue()
    filename = f"private_wires_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/private_wire/add", methods=["GET", "POST"])
@login_required
def pw_add():
    if not current_user.can_edit_inventory():
        abort(403)
    is_admin = current_user.is_admin()
    locations = _lookup_values("private_wire_location") or []
    custom_fields = _custom_fields_for("private_wires")

    if request.method == "POST":
        form = request.form.to_dict(flat=True)

        pw = PrivateWire()

        # Admin-only fields on create
        if is_admin:
            pw.record_no = (form.get("record_no") or "").strip() or None
            pw.location = (form.get("location") or "").strip() or None
            pw.dc_locale = (form.get("dc_locale") or "").strip() or None
            pw.vega_port = (form.get("vega_port") or "").strip() or None
            pw.channel = (form.get("channel") or "").strip() or None
            pw.bearer_no = (form.get("bearer_no") or "").strip() or None
            pw.back_up_bearer = (form.get("back_up_bearer") or "").strip() or None
            pw.cluster_name = (form.get("cluster_name") or "").strip() or None
            pw.tpo_name = (form.get("tpo_name") or "").strip() or None
            pw.vega_hostname = (form.get("vega_hostname") or "").strip() or None
            pw.back_up_vega_gw = (form.get("back_up_vega_gw") or "").strip() or None
            pw.vendor = (form.get("vendor") or "").strip() or None
        else:
            # Allow user to create a record but keep restricted identifiers/connection data blank.
            pw.record_no = f"AUTO-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # User-editable fields
        pw.circuit_no = (form.get("circuit_no") or "").strip() or None
        pw.pw_type = (form.get("pw_type") or "").strip() or None
        pw.btt_slot = (form.get("btt_slot") or "").strip() or None
        pw.aor = (form.get("aor") or "").strip() or None
        pw.a_or_b = (form.get("a_or_b") or "").strip() or None
        pw.dedicated_country = (form.get("dedicated_country") or "").strip() or None
        pw.hsbc_main_user = (form.get("hsbc_main_user") or "").strip() or None
        pw.employee_id = (form.get("employee_id") or "").strip() or None
        pw.private_public = (form.get("private_public") or "").strip() or None
        pw.line_label = (form.get("line_label") or "").strip() or None
        pw.company_name = (form.get("company_name") or "").strip() or None
        pw.company_contact = (form.get("company_contact") or "").strip() or None
        pw.company_email = (form.get("company_email") or "").strip() or None
        pw.vr_yn = (form.get("vr_yn") or "").strip() or None
        pw.snow_ref = (form.get("snow_ref") or "").strip() or None

        now = datetime.utcnow()
        pw.date_created = now
        pw.last_updated = now
        pw.last_change = f"Created by {_current_username()}"

        ok, msg = _save_custom_values("private_wires", pw, form)
        if not ok:
            flash(msg or "Custom fields invalid", "danger")
            return render_template(
                "private_wire/add.html",
                locations=locations,
                is_admin=is_admin,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(pw),
            )

        if not pw.record_no:
            flash("Record No is required", "danger")
            return render_template(
                "private_wire/add.html",
                locations=locations,
                is_admin=is_admin,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(pw),
            )

        if PrivateWire.query.filter_by(record_no=pw.record_no).first():
            flash("Record No already exists", "danger")
            return render_template(
                "private_wire/add.html",
                locations=locations,
                is_admin=is_admin,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(pw),
            )

        db.session.add(pw)
        db.session.commit()
        flash("Private wire created", "success")
        return redirect(url_for("pw_view", id=pw.id))

    return render_template(
        "private_wire/add.html",
        locations=locations,
        is_admin=is_admin,
        custom_fields=custom_fields,
        custom_values={},
    )


@core_bp.route("/private_wire/edit/<int:id>", methods=["GET", "POST"])
@login_required
def pw_edit(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    pw = db.session.get(PrivateWire, id)
    if not pw:
        abort(404)

    is_admin = current_user.is_admin()
    custom_fields = _custom_fields_for("private_wires")
    custom_values = _custom_values_from_obj(pw)

    def _set_attr(obj, name: str, value):
        if hasattr(obj, name):
            setattr(obj, name, value if value != "" else None)

    if request.method == "POST":
        form = request.form.to_dict(flat=True)

        ok, msg = _save_custom_values("private_wires", pw, form)
        if not ok:
            flash(msg or "Custom fields invalid", "danger")
            locations = _lookup_values("private_wire_location") or []
            return render_template(
                "private_wire/edit.html",
                pw=pw,
                is_admin=is_admin,
                locations=locations,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(pw),
            )

        # Always-editable (admin + user)
        for f in (
            "pw_type",
            "circuit_no",
            "a_or_b",
            "dedicated_country",
            "hsbc_main_user",
            "employee_id",
            "private_public",
            "line_label",
            "vr_yn",
            "company_name",
            "company_contact",
            "company_email",
            "snow_ref",
        ):
            if f in form:
                _set_attr(pw, f, form.get(f) or "")

        # Admin-only fields
        if is_admin:
            for f in (
                "record_no",
                "location",
                "dc_locale",
                "vega_port",
                "channel",
                "bearer_no",
                "back_up_bearer",
                "cluster_name",
                "tpo_name",
                "vega_hostname",
                "back_up_vega_gw",
                "vendor",
            ):
                if f in form:
                    _set_attr(pw, f, form.get(f) or "")

        # Timestamps / audit-ish fields
        pw.last_updated = datetime.utcnow()
        pw.last_change = f"Updated by {_current_username()}"

        db.session.commit()
        flash("Private wire updated", "success")
        return redirect(url_for("pw_view", id=pw.id))

    locations = _lookup_values("private_wire_location") or []

    return render_template(
        "private_wire/edit.html",
        pw=pw,
        is_admin=is_admin,
        locations=locations,
        custom_fields=custom_fields,
        custom_values=custom_values,
    )


@core_bp.route("/private_wire/cease/<int:id>", methods=["GET", "POST"])
@login_required
def pw_cease(id: int):
    if not current_user.can_edit_inventory():
        abort(403)
    return "Not implemented", 501


@core_bp.route("/private_wire/import", methods=["GET", "POST"])
@login_required
def pw_import():
    if not (current_user.is_admin() or getattr(current_user, "can_import_private_wires", False)):
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("private_wire/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            if not mapping.get("record_no"):
                flash("Record No must be mapped", "danger")
                return redirect(url_for("pw_import"))

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            created = 0
            updated = 0
            skipped = 0
            now = datetime.utcnow()

            for row in reader:
                record_no = pick(row, "record_no")
                if not record_no:
                    skipped += 1
                    continue

                pw = PrivateWire.query.filter_by(record_no=record_no).first()
                is_new = pw is None
                if is_new:
                    pw = PrivateWire(record_no=record_no)
                    pw.date_created = now
                    db.session.add(pw)

                pw.location = pick(row, "location") or pw.location
                pw.dc_locale = pick(row, "dc_locale") or pw.dc_locale
                pw.vega_port = pick(row, "vega_port") or pw.vega_port
                pw.channel = pick(row, "channel") or pw.channel
                pw.bearer_no = pick(row, "bearer_no") or pw.bearer_no
                pw.circuit_no = pick(row, "circuit_no") or pw.circuit_no
                pw.back_up_bearer = pick(row, "back_up_bearer") or pw.back_up_bearer
                pw.cluster_name = pick(row, "cluster_name") or pw.cluster_name
                pw.tpo_name = pick(row, "tpo_name") or pw.tpo_name
                pw.vega_hostname = pick(row, "vega_hostname") or pw.vega_hostname
                pw.back_up_vega_gw = pick(row, "back_up_vega_gw") or pw.back_up_vega_gw
                pw.vendor = pick(row, "vendor") or pw.vendor
                pw.pw_type = pick(row, "pw_type") or pw.pw_type
                pw.btt_slot = pick(row, "btt_slot") or pw.btt_slot
                pw.aor = pick(row, "aor") or pw.aor
                pw.a_or_b = pick(row, "a_or_b") or pw.a_or_b
                pw.dedicated_country = pick(row, "dedicated_country") or pw.dedicated_country
                pw.hsbc_main_user = pick(row, "hsbc_main_user") or pw.hsbc_main_user
                pw.employee_id = pick(row, "employee_id") or pw.employee_id
                pw.private_public = pick(row, "private_public") or pw.private_public
                pw.line_label = pick(row, "line_label") or pw.line_label
                pw.company_name = pick(row, "company_name") or pw.company_name
                pw.company_contact = pick(row, "company_contact") or pw.company_contact
                pw.company_email = pick(row, "company_email") or pw.company_email
                pw.vr_yn = pick(row, "vr_yn") or pw.vr_yn
                pw.snow_ref = pick(row, "snow_ref") or pw.snow_ref

                pw.aor_number = pick(row, "aor_number") or pw.aor_number
                pw.port_number = pick(row, "port_number") or pw.port_number
                pw.channel_number = pick(row, "channel_number") or pw.channel_number

                pw.last_updated = now
                pw.last_change = f"Imported by {_current_username()}"

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete: {created} created, {updated} updated, {skipped} skipped", "success")
            return redirect(url_for("pw_list"))

        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return render_template("private_wire/import.html"), 400

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("private_wire/import.html"), 400

        target_fields = [
            {"key": "record_no", "label": "Record No", "required": True},
            {"key": "aor_number", "label": "AOR Number", "required": False},
            {"key": "port_number", "label": "Port Number", "required": False},
            {"key": "channel_number", "label": "Channel Number", "required": False},
            {"key": "location", "label": "Location", "required": False},
            {"key": "dc_locale", "label": "DC Locale", "required": False},
            {"key": "vega_port", "label": "Vega Port", "required": False},
            {"key": "channel", "label": "Channel", "required": False},
            {"key": "bearer_no", "label": "Bearer No", "required": False},
            {"key": "circuit_no", "label": "Circuit No", "required": False},
            {"key": "back_up_bearer", "label": "Back up Bearer", "required": False},
            {"key": "cluster_name", "label": "Cluster Name", "required": False},
            {"key": "tpo_name", "label": "TPO Name", "required": False},
            {"key": "vega_hostname", "label": "Vega Hostname", "required": False},
            {"key": "back_up_vega_gw", "label": "Back up Vega GW", "required": False},
            {"key": "vendor", "label": "Vendor", "required": False},
            {"key": "pw_type", "label": "PW type", "required": False},
            {"key": "btt_slot", "label": "BTT slot", "required": False},
            {"key": "aor", "label": "AOR", "required": False},
            {"key": "a_or_b", "label": "A or B", "required": False},
            {"key": "dedicated_country", "label": "Dedicated Country", "required": False},
            {"key": "hsbc_main_user", "label": "HSBC Main User", "required": False},
            {"key": "employee_id", "label": "Employee ID", "required": False},
            {"key": "private_public", "label": "Private / Public", "required": False},
            {"key": "line_label", "label": "Line Label", "required": False},
            {"key": "company_name", "label": "Company name", "required": False},
            {"key": "company_contact", "label": "Company Contact", "required": False},
            {"key": "company_email", "label": "Company email", "required": False},
            {"key": "vr_yn", "label": "VR Y / N", "required": False},
            {"key": "snow_ref", "label": "SNOW Ref", "required": False},
        ]
        synonyms = {
            "record_no": ["record_no", "Record No", "record", "Record"],
            "aor_number": ["aor_number", "AOR Number"],
            "port_number": ["port_number", "Port Number"],
            "channel_number": ["channel_number", "Channel Number"],
            "location": ["location", "Location"],
            "dc_locale": ["dc_locale", "DC Locale"],
            "vega_port": ["vega_port", "Vega Port"],
            "channel": ["channel", "Channel"],
            "bearer_no": ["bearer_no", "Bearer No"],
            "circuit_no": ["circuit_no", "Circuit No"],
            "back_up_bearer": ["back_up_bearer", "Back up Bearer", "Backup Bearer"],
            "cluster_name": ["cluster_name", "Cluster Name"],
            "tpo_name": ["tpo_name", "TPO Name"],
            "vega_hostname": ["vega_hostname", "Vega Hostname"],
            "back_up_vega_gw": ["back_up_vega_gw", "Back up Vega GW", "Backup Vega GW"],
            "vendor": ["vendor", "Vendor"],
            "pw_type": ["pw_type", "PW type"],
            "btt_slot": ["btt_slot", "BTT slot"],
            "aor": ["aor", "AOR"],
            "a_or_b": ["a_or_b", "A or B"],
            "dedicated_country": ["dedicated_country", "Dedicated Country"],
            "hsbc_main_user": ["hsbc_main_user", "HSBC Main User"],
            "employee_id": ["employee_id", "Employee ID"],
            "private_public": ["private_public", "Private / Public", "Private Public"],
            "line_label": ["line_label", "Line Label"],
            "company_name": ["company_name", "Company name"],
            "company_contact": ["company_contact", "Company Contact"],
            "company_email": ["company_email", "Company email"],
            "vr_yn": ["vr_yn", "VR Y / N", "VR"],
            "snow_ref": ["snow_ref", "SNOW Ref", "SNOW"],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map Private Wire CSV Fields",
            help_text="Map the columns from your CSV file to the private wire fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("pw_list"),
        )

    return render_template("private_wire/import.html")


@core_bp.route("/private_wire/ceased")
@login_required
def ceased_wires_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    sort = (request.args.get("sort") or "cease_date").strip()
    order = (request.args.get("order") or "desc").strip().lower()

    stmt = select(CeasedPrivateWire)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(CeasedPrivateWire.record_no, s),
                _contains(CeasedPrivateWire.original_record_no, s),
                _contains(CeasedPrivateWire.location, s),
                _contains(CeasedPrivateWire.circuit_no, s),
                _contains(CeasedPrivateWire.hsbc_main_user, s),
                _contains(CeasedPrivateWire.company_name, s),
                _contains(CeasedPrivateWire.ceased_by, s),
                _contains(CeasedPrivateWire.cease_reason, s),
            )
        )

    sort_map = {
        "record_no": CeasedPrivateWire.record_no,
        "location": CeasedPrivateWire.location,
        "cease_date": CeasedPrivateWire.cease_date,
    }
    sort_col = sort_map.get(sort, CeasedPrivateWire.cease_date)
    if order == "asc":
        stmt = stmt.order_by(sort_col.asc().nullslast(), CeasedPrivateWire.id.asc())
    else:
        stmt = stmt.order_by(sort_col.desc().nullslast(), CeasedPrivateWire.id.desc())

    ceased_wires = db.paginate(stmt, page=page, per_page=25, error_out=False)

    return render_template(
        "private_wire/ceased_list.html",
        ceased_wires=ceased_wires,
        search=search,
        sort=sort,
        order=order,
    )


@core_bp.route("/private_wire/ceased/export")
@login_required
def ceased_wires_export():
    if not (current_user.is_admin() or getattr(current_user, "can_export_private_wires", False)):
        abort(403)
    # CSV export that Excel can open.
    search = (request.args.get("search") or "").strip()
    sort = (request.args.get("sort") or "cease_date").strip()
    order = (request.args.get("order") or "desc").strip().lower()

    stmt = select(CeasedPrivateWire)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(CeasedPrivateWire.record_no, s),
                _contains(CeasedPrivateWire.original_record_no, s),
                _contains(CeasedPrivateWire.location, s),
                _contains(CeasedPrivateWire.circuit_no, s),
                _contains(CeasedPrivateWire.hsbc_main_user, s),
                _contains(CeasedPrivateWire.company_name, s),
                _contains(CeasedPrivateWire.ceased_by, s),
                _contains(CeasedPrivateWire.cease_reason, s),
            )
        )

    sort_map = {
        "record_no": CeasedPrivateWire.record_no,
        "location": CeasedPrivateWire.location,
        "cease_date": CeasedPrivateWire.cease_date,
    }
    sort_col = sort_map.get(sort, CeasedPrivateWire.cease_date)
    if order == "asc":
        stmt = stmt.order_by(sort_col.asc().nullslast(), CeasedPrivateWire.id.asc())
    else:
        stmt = stmt.order_by(sort_col.desc().nullslast(), CeasedPrivateWire.id.desc())

    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)
    headers = [
        "id",
        "record_no",
        "original_record_no",
        "aor_number",
        "port_number",
        "channel_number",
        "location",
        "dc_locale",
        "vega_port",
        "channel",
        "bearer_no",
        "circuit_no",
        "back_up_bearer",
        "cluster_name",
        "tpo_name",
        "vega_hostname",
        "back_up_vega_gw",
        "vendor",
        "pw_type",
        "btt_slot",
        "aor",
        "a_or_b",
        "dedicated_country",
        "hsbc_main_user",
        "employee_id",
        "private_public",
        "line_label",
        "company_name",
        "company_contact",
        "company_email",
        "vr_yn",
        "snow_ref",
        "cease_date",
        "ceased_by",
        "cease_reason",
        "date_created",
        "last_updated",
        "last_change",
    ]
    w.writerow(headers)
    for pw in rows:
        w.writerow(
            [
                pw.id,
                pw.record_no or "",
                pw.original_record_no or "",
                pw.aor_number or "",
                pw.port_number or "",
                pw.channel_number or "",
                pw.location or "",
                pw.dc_locale or "",
                pw.vega_port or "",
                pw.channel or "",
                pw.bearer_no or "",
                pw.circuit_no or "",
                pw.back_up_bearer or "",
                pw.cluster_name or "",
                pw.tpo_name or "",
                pw.vega_hostname or "",
                pw.back_up_vega_gw or "",
                pw.vendor or "",
                pw.pw_type or "",
                pw.btt_slot or "",
                pw.aor or "",
                pw.a_or_b or "",
                pw.dedicated_country or "",
                pw.hsbc_main_user or "",
                pw.employee_id or "",
                pw.private_public or "",
                pw.line_label or "",
                pw.company_name or "",
                pw.company_contact or "",
                pw.company_email or "",
                pw.vr_yn or "",
                pw.snow_ref or "",
                pw.cease_date.strftime("%Y-%m-%d %H:%M:%S") if pw.cease_date else "",
                pw.ceased_by or "",
                pw.cease_reason or "",
                pw.date_created.strftime("%Y-%m-%d %H:%M:%S") if pw.date_created else "",
                pw.last_updated.strftime("%Y-%m-%d %H:%M:%S") if pw.last_updated else "",
                pw.last_change or "",
            ]
        )

    data = output.getvalue()
    filename = f"ceased_private_wires_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/private_wire/ceased/import", methods=["GET", "POST"])
@login_required
def ceased_wires_import():
    if not (current_user.is_admin() or getattr(current_user, "can_import_private_wires", False)):
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("private_wire/ceased_import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            if not mapping.get("record_no"):
                flash("Record No must be mapped", "danger")
                return redirect(url_for("ceased_wires_import"))

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            created = 0
            updated = 0
            skipped = 0
            now = datetime.utcnow()

            for row in reader:
                record_no = pick(row, "record_no")
                if not record_no:
                    skipped += 1
                    continue

                rec = CeasedPrivateWire.query.filter_by(record_no=record_no).first()
                is_new = rec is None
                if is_new:
                    rec = CeasedPrivateWire(record_no=record_no)
                    rec.date_created = now
                    db.session.add(rec)

                rec.original_record_no = pick(row, "original_record_no") or rec.original_record_no or record_no
                rec.location = pick(row, "location") or rec.location
                rec.dc_locale = pick(row, "dc_locale") or rec.dc_locale
                rec.vega_port = pick(row, "vega_port") or rec.vega_port
                rec.channel = pick(row, "channel") or rec.channel
                rec.bearer_no = pick(row, "bearer_no") or rec.bearer_no
                rec.circuit_no = pick(row, "circuit_no") or rec.circuit_no
                rec.back_up_bearer = pick(row, "back_up_bearer") or rec.back_up_bearer
                rec.cluster_name = pick(row, "cluster_name") or rec.cluster_name
                rec.tpo_name = pick(row, "tpo_name") or rec.tpo_name
                rec.vega_hostname = pick(row, "vega_hostname") or rec.vega_hostname
                rec.back_up_vega_gw = pick(row, "back_up_vega_gw") or rec.back_up_vega_gw
                rec.vendor = pick(row, "vendor") or rec.vendor
                rec.pw_type = pick(row, "pw_type") or rec.pw_type
                rec.btt_slot = pick(row, "btt_slot") or rec.btt_slot
                rec.aor = pick(row, "aor") or rec.aor
                rec.a_or_b = pick(row, "a_or_b") or rec.a_or_b
                rec.dedicated_country = pick(row, "dedicated_country") or rec.dedicated_country
                rec.hsbc_main_user = pick(row, "hsbc_main_user") or rec.hsbc_main_user
                rec.employee_id = pick(row, "employee_id") or rec.employee_id
                rec.private_public = pick(row, "private_public") or rec.private_public
                rec.line_label = pick(row, "line_label") or rec.line_label
                rec.company_name = pick(row, "company_name") or rec.company_name
                rec.company_contact = pick(row, "company_contact") or rec.company_contact
                rec.company_email = pick(row, "company_email") or rec.company_email
                rec.vr_yn = pick(row, "vr_yn") or rec.vr_yn
                rec.snow_ref = pick(row, "snow_ref") or rec.snow_ref

                rec.aor_number = pick(row, "aor_number") or rec.aor_number
                rec.port_number = pick(row, "port_number") or rec.port_number
                rec.channel_number = pick(row, "channel_number") or rec.channel_number

                cd = _parse_any_date(pick(row, "cease_date"))
                if cd:
                    rec.cease_date = cd
                rec.ceased_by = pick(row, "ceased_by") or rec.ceased_by
                rec.cease_reason = pick(row, "cease_reason") or rec.cease_reason

                rec.last_updated = now
                rec.last_change = f"Imported by {_current_username()}"

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete: {created} created, {updated} updated, {skipped} skipped", "success")
            return redirect(url_for("ceased_wires_list"))

        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return render_template("private_wire/ceased_import.html"), 400

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("private_wire/ceased_import.html"), 400

        target_fields = [
            {"key": "record_no", "label": "Record No", "required": True},
            {"key": "original_record_no", "label": "Original Record No", "required": False},
            {"key": "aor_number", "label": "AOR Number", "required": False},
            {"key": "port_number", "label": "Port Number", "required": False},
            {"key": "channel_number", "label": "Channel Number", "required": False},
            {"key": "location", "label": "Location", "required": False},
            {"key": "dc_locale", "label": "DC Locale", "required": False},
            {"key": "vega_port", "label": "Vega Port", "required": False},
            {"key": "channel", "label": "Channel", "required": False},
            {"key": "bearer_no", "label": "Bearer No", "required": False},
            {"key": "circuit_no", "label": "Circuit No", "required": False},
            {"key": "back_up_bearer", "label": "Back up Bearer", "required": False},
            {"key": "cluster_name", "label": "Cluster Name", "required": False},
            {"key": "tpo_name", "label": "TPO Name", "required": False},
            {"key": "vega_hostname", "label": "Vega Hostname", "required": False},
            {"key": "back_up_vega_gw", "label": "Back up Vega GW", "required": False},
            {"key": "vendor", "label": "Vendor", "required": False},
            {"key": "pw_type", "label": "PW type", "required": False},
            {"key": "btt_slot", "label": "BTT slot", "required": False},
            {"key": "aor", "label": "AOR", "required": False},
            {"key": "a_or_b", "label": "A or B", "required": False},
            {"key": "dedicated_country", "label": "Dedicated Country", "required": False},
            {"key": "hsbc_main_user", "label": "HSBC Main User", "required": False},
            {"key": "employee_id", "label": "Employee ID", "required": False},
            {"key": "private_public", "label": "Private / Public", "required": False},
            {"key": "line_label", "label": "Line Label", "required": False},
            {"key": "company_name", "label": "Company name", "required": False},
            {"key": "company_contact", "label": "Company Contact", "required": False},
            {"key": "company_email", "label": "Company email", "required": False},
            {"key": "vr_yn", "label": "VR Y / N", "required": False},
            {"key": "snow_ref", "label": "SNOW Ref", "required": False},
            {"key": "cease_date", "label": "Cease Date", "required": False},
            {"key": "ceased_by", "label": "Ceased By", "required": False},
            {"key": "cease_reason", "label": "Cease Reason", "required": False},
        ]
        synonyms = {
            "record_no": ["record_no", "Record No", "record", "Record"],
            "original_record_no": ["original_record_no", "Original Record No"],
            "aor_number": ["aor_number", "AOR Number"],
            "port_number": ["port_number", "Port Number"],
            "channel_number": ["channel_number", "Channel Number"],
            "location": ["location", "Location"],
            "dc_locale": ["dc_locale", "DC Locale"],
            "vega_port": ["vega_port", "Vega Port"],
            "channel": ["channel", "Channel"],
            "bearer_no": ["bearer_no", "Bearer No"],
            "circuit_no": ["circuit_no", "Circuit No"],
            "back_up_bearer": ["back_up_bearer", "Back up Bearer", "Backup Bearer"],
            "cluster_name": ["cluster_name", "Cluster Name"],
            "tpo_name": ["tpo_name", "TPO Name"],
            "vega_hostname": ["vega_hostname", "Vega Hostname"],
            "back_up_vega_gw": ["back_up_vega_gw", "Back up Vega GW", "Backup Vega GW"],
            "vendor": ["vendor", "Vendor"],
            "pw_type": ["pw_type", "PW type"],
            "btt_slot": ["btt_slot", "BTT slot"],
            "aor": ["aor", "AOR"],
            "a_or_b": ["a_or_b", "A or B"],
            "dedicated_country": ["dedicated_country", "Dedicated Country"],
            "hsbc_main_user": ["hsbc_main_user", "HSBC Main User"],
            "employee_id": ["employee_id", "Employee ID"],
            "private_public": ["private_public", "Private / Public", "Private Public"],
            "line_label": ["line_label", "Line Label"],
            "company_name": ["company_name", "Company name"],
            "company_contact": ["company_contact", "Company Contact"],
            "company_email": ["company_email", "Company email"],
            "vr_yn": ["vr_yn", "VR Y / N", "VR"],
            "snow_ref": ["snow_ref", "SNOW Ref", "SNOW"],
            "cease_date": ["cease_date", "Cease Date"],
            "ceased_by": ["ceased_by", "Ceased By"],
            "cease_reason": ["cease_reason", "Cease Reason"],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map Ceased Private Wire CSV Fields",
            help_text="Map the columns from your CSV file to the ceased private wire fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("ceased_wires_list"),
        )

    return render_template("private_wire/ceased_import.html")


@core_bp.route("/private_wire/ceased/view/<int:id>")
@login_required
def ceased_wire_view(id: int):
    pw = db.session.get(CeasedPrivateWire, id)
    if not pw:
        abort(404)
    return render_template("private_wire/ceased_view.html", pw=pw)


@core_bp.route("/turret")
@login_required
def turret_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    country = (request.args.get("country") or "").strip()
    sort = (request.args.get("sort") or "last_updated").strip()
    order = (request.args.get("order") or "desc").strip().lower()

    stmt = select(DealerboardTurret)

    if country:
        stmt = stmt.where(DealerboardTurret.country == country)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(DealerboardTurret.mac_address, s),
                _contains(DealerboardTurret.mac_address_2, s),
                _contains(DealerboardTurret.mac_address_3, s),
                _contains(DealerboardTurret.mac_address_4, s),
                _contains(DealerboardTurret.mac_address_5, s),
                _contains(DealerboardTurret.serial_number, s),
                _contains(DealerboardTurret.ip_address, s),
                _contains(DealerboardTurret.dns_hostname, s),
                _contains(DealerboardTurret.zone, s),
                _contains(DealerboardTurret.desk_location, s),
                _contains(DealerboardTurret.office, s),
                _contains(DealerboardTurret.country, s),
            )
        )

    sort_map = {
        "mac_address": DealerboardTurret.mac_address,
        "ip_address": DealerboardTurret.ip_address,
        "country": DealerboardTurret.country,
        "last_updated": DealerboardTurret.last_updated,
    }
    sort_col = sort_map.get(sort, DealerboardTurret.last_updated)

    if order == "asc":
        stmt = stmt.order_by(sort_col.asc().nullslast(), DealerboardTurret.id.asc())
    else:
        stmt = stmt.order_by(sort_col.desc().nullslast(), DealerboardTurret.id.desc())

    turrets = db.paginate(stmt, page=page, per_page=25, error_out=False)
    countries = _lookup_values("country") or []

    return render_template(
        "turret/list.html",
        turrets=turrets,
        search=search,
        country=country,
        countries=countries,
        sort=sort,
        order=order,
    )


@core_bp.route("/turret/import", methods=["GET", "POST"])
@login_required
def turret_import():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("turret/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            if not mapping.get("mac_address"):
                flash("MAC Address 1 must be mapped", "danger")
                return redirect(url_for("turret_import"))

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            created = 0
            updated = 0
            skipped = 0
            now = datetime.utcnow()

            for row in reader:
                mac = pick(row, "mac_address")
                if not mac:
                    skipped += 1
                    continue

                turret = DealerboardTurret.query.filter_by(mac_address=mac).first()
                is_new = turret is None
                if is_new:
                    turret = DealerboardTurret(mac_address=mac)
                    turret.date_created = now
                    turret.created_by = _current_username()
                    db.session.add(turret)

                turret.mac_address_2 = pick(row, "mac_address_2") or turret.mac_address_2
                turret.mac_address_3 = pick(row, "mac_address_3") or turret.mac_address_3
                turret.mac_address_4 = pick(row, "mac_address_4") or turret.mac_address_4
                turret.mac_address_5 = pick(row, "mac_address_5") or turret.mac_address_5
                turret.serial_number = pick(row, "serial_number") or turret.serial_number
                turret.ip_address = pick(row, "ip_address") or turret.ip_address
                turret.dns_hostname = pick(row, "dns_hostname") or turret.dns_hostname
                turret.desk_location = pick(row, "desk_location") or turret.desk_location
                turret.switchport_1 = pick(row, "switchport_1") or turret.switchport_1
                turret.switchport_2 = pick(row, "switchport_2") or turret.switchport_2
                turret.zone = pick(row, "zone") or turret.zone
                turret.model = pick(row, "model") or turret.model
                turret.firmware_version = pick(row, "firmware_version") or turret.firmware_version
                turret.country = pick(row, "country") or turret.country
                turret.office = pick(row, "office") or turret.office
                turret.status = pick(row, "status") or turret.status
                turret.installed_by = pick(row, "installed_by") or turret.installed_by
                turret.installation_snow_ref = pick(row, "installation_snow_ref") or turret.installation_snow_ref

                idt = _parse_any_date(pick(row, "installation_date"))
                if idt:
                    turret.installation_date = idt

                turret.last_updated = now
                turret.last_updated_by = _current_username()
                turret.last_change = f"Imported by {_current_username()}"

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete. Created {created}, updated {updated}, skipped {skipped}.", "success")
            return redirect(url_for("turret_list"))

        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return render_template("turret/import.html"), 400

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("turret/import.html"), 400

        target_fields = [
            {"key": "mac_address", "label": "MAC Address 1", "required": True},
            {"key": "mac_address_2", "label": "MAC Address 2", "required": False},
            {"key": "mac_address_3", "label": "MAC Address 3", "required": False},
            {"key": "mac_address_4", "label": "MAC Address 4", "required": False},
            {"key": "mac_address_5", "label": "MAC Address 5", "required": False},
            {"key": "serial_number", "label": "Serial Number", "required": False},
            {"key": "ip_address", "label": "IP Address", "required": False},
            {"key": "dns_hostname", "label": "DNS/Hostname", "required": False},
            {"key": "desk_location", "label": "Desk Location", "required": False},
            {"key": "switchport_1", "label": "Switchport 1", "required": False},
            {"key": "switchport_2", "label": "Switchport 2", "required": False},
            {"key": "zone", "label": "Zone", "required": False},
            {"key": "model", "label": "Model", "required": False},
            {"key": "firmware_version", "label": "Firmware Version", "required": False},
            {"key": "country", "label": "Country", "required": False},
            {"key": "office", "label": "Office", "required": False},
            {"key": "status", "label": "Status", "required": False},
            {"key": "installed_by", "label": "Installed By", "required": False},
            {"key": "installation_date", "label": "Installation Date", "required": False},
            {"key": "installation_snow_ref", "label": "Installation SNOW Ref", "required": False},
        ]
        synonyms = {
            "mac_address": ["mac_address", "MAC Address", "MAC Address 1", "MAC1", "MAC"],
            "mac_address_2": ["mac_address_2", "MAC Address 2", "MAC2"],
            "mac_address_3": ["mac_address_3", "MAC Address 3", "MAC3"],
            "mac_address_4": ["mac_address_4", "MAC Address 4", "MAC4"],
            "mac_address_5": ["mac_address_5", "MAC Address 5", "MAC5"],
            "serial_number": ["serial_number", "Serial Number", "Serial", "S/N", "SN"],
            "ip_address": ["ip_address", "IP Address", "IP"],
            "dns_hostname": ["dns_hostname", "DNS", "Hostname", "DNS/Hostname"],
            "desk_location": ["desk_location", "Desk Location", "Desk"],
            "switchport_1": ["switchport_1", "Switchport 1", "Switch Port 1"],
            "switchport_2": ["switchport_2", "Switchport 2", "Switch Port 2"],
            "zone": ["zone", "Zone"],
            "model": ["model", "Model"],
            "firmware_version": ["firmware_version", "Firmware", "Firmware Version"],
            "country": ["country", "Country"],
            "office": ["office", "Office"],
            "status": ["status", "Status"],
            "installed_by": ["installed_by", "Installed By", "Installer"],
            "installation_date": ["installation_date", "Installation Date", "Installed Date"],
            "installation_snow_ref": ["installation_snow_ref", "Installation SNOW Ref", "SNOW Ref", "SNOW"],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map Turret CSV Fields",
            help_text="Map the columns from your CSV file to the turret fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("turret_list"),
        )

    return render_template("turret/import.html")


@core_bp.route("/turret/export")
@login_required
def turret_export():
    stmt = select(DealerboardTurret).order_by(DealerboardTurret.id.asc())
    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)

    w.writerow(
        [
            "id",
            "mac_address",
            "mac_address_2",
            "mac_address_3",
            "mac_address_4",
            "mac_address_5",
            "serial_number",
            "ip_address",
            "dns_hostname",
            "desk_location",
            "switchport_1",
            "switchport_2",
            "zone",
            "model",
            "firmware_version",
            "country",
            "office",
            "status",
            "installed_by",
            "installation_date",
            "installation_snow_ref",
            "last_updated",
        ]
    )

    for t in rows:
        w.writerow(
            [
                t.id,
                t.mac_address or "",
                t.mac_address_2 or "",
                t.mac_address_3 or "",
                t.mac_address_4 or "",
                t.mac_address_5 or "",
                t.serial_number or "",
                t.ip_address or "",
                t.dns_hostname or "",
                t.desk_location or "",
                t.switchport_1 or "",
                t.switchport_2 or "",
                t.zone or "",
                t.model or "",
                t.firmware_version or "",
                t.country or "",
                t.office or "",
                t.status or "",
                t.installed_by or "",
                t.installation_date.strftime("%Y-%m-%d %H:%M:%S") if t.installation_date else "",
                t.installation_snow_ref or "",
                t.last_updated.strftime("%Y-%m-%d %H:%M:%S") if t.last_updated else "",
            ]
        )

    from flask import Response

    data = output.getvalue()
    filename = f"turrets_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/turret/add", methods=["GET", "POST"])
@login_required
def turret_add():
    if not current_user.is_admin():
        abort(403)

    countries = _lookup_values("country") or []
    custom_fields = _custom_fields_for("turrets")

    if request.method == "POST":
        form = request.form.to_dict(flat=True)
        mac = (form.get("mac_address") or "").strip()
        if not mac:
            flash("MAC Address 1 is required", "danger")
            return render_template(
                "turret/add.html",
                countries=countries,
                custom_fields=custom_fields,
                custom_values={},
            )

        ip_ok, ip_err = _validate_ip(form.get("ip_address"))
        if not ip_ok:
            flash(ip_err or "Invalid IP address", "danger")
            return render_template(
                "turret/add.html",
                countries=countries,
                custom_fields=custom_fields,
                custom_values={},
            )

        if DealerboardTurret.query.filter_by(mac_address=mac).first():
            flash("MAC Address already exists", "danger")
            return render_template(
                "turret/add.html",
                countries=countries,
                custom_fields=custom_fields,
                custom_values={},
            )

        t = DealerboardTurret(
            mac_address=mac,
            mac_address_2=(form.get("mac_address_2") or "").strip() or None,
            mac_address_3=(form.get("mac_address_3") or "").strip() or None,
            mac_address_4=(form.get("mac_address_4") or "").strip() or None,
            mac_address_5=(form.get("mac_address_5") or "").strip() or None,
            serial_number=(form.get("serial_number") or "").strip() or None,
            ip_address=_norm_ip(form.get("ip_address")),
            dns_hostname=_norm_hostname(form.get("dns_hostname")),
            zone=(form.get("zone") or "").strip() or None,
            firmware_version=(form.get("firmware_version") or "").strip() or None,
            model=(form.get("model") or "").strip() or None,
            country=(form.get("country") or "").strip() or None,
            office=(form.get("office") or "").strip() or None,
            desk_location=(form.get("desk_location") or "").strip() or None,
            switchport_1=(form.get("switchport_1") or "").strip() or None,
            switchport_2=(form.get("switchport_2") or "").strip() or None,
            status="Active",
            created_by=_current_username(),
            last_updated_by=_current_username(),
        )

        now = datetime.utcnow()
        t.date_created = now
        t.last_updated = now
        t.last_change = f"Created by {_current_username()}"

        ok, msg = _save_custom_values("turrets", t, form)
        if not ok:
            flash(msg or "Custom fields invalid", "danger")
            return render_template(
                "turret/add.html",
                countries=countries,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(t),
            )

        db.session.add(t)
        db.session.commit()
        flash("Turret created", "success")
        return redirect(url_for("turret_list"))

    return render_template(
        "turret/add.html",
        countries=countries,
        custom_fields=custom_fields,
        custom_values={},
    )


@core_bp.route("/turret/edit/<int:id>", methods=["GET", "POST"])
@login_required
def turret_edit(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    turret = db.session.get(DealerboardTurret, id)
    if not turret:
        abort(404)

    countries = _lookup_values("country") or []
    custom_fields = _custom_fields_for("turrets")
    custom_values = _custom_values_from_obj(turret)

    if request.method == "POST":
        form = request.form.to_dict(flat=True)

        ok, msg = _save_custom_values("turrets", turret, form)
        if not ok:
            flash(msg or "Custom fields invalid", "danger")
            return render_template(
                "turret/edit.html",
                turret=turret,
                countries=countries,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(turret),
            )

        ip_ok, ip_err = _validate_ip(form.get("ip_address"))
        if not ip_ok:
            flash(ip_err or "Invalid IP address", "danger")
            return render_template(
                "turret/edit.html",
                turret=turret,
                countries=countries,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(turret),
            )

        mac = (form.get("mac_address") or "").strip()
        if not mac:
            flash("MAC Address 1 is required", "danger")
            return render_template(
                "turret/edit.html",
                turret=turret,
                countries=countries,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(turret),
            )

        existing = DealerboardTurret.query.filter(
            DealerboardTurret.mac_address == mac,
            DealerboardTurret.id != turret.id,
        ).first()
        if existing:
            flash("MAC Address already exists", "danger")
            return render_template(
                "turret/edit.html",
                turret=turret,
                countries=countries,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(turret),
            )

        turret.mac_address = mac
        turret.mac_address_2 = (form.get("mac_address_2") or "").strip() or None
        turret.mac_address_3 = (form.get("mac_address_3") or "").strip() or None
        turret.mac_address_4 = (form.get("mac_address_4") or "").strip() or None
        turret.mac_address_5 = (form.get("mac_address_5") or "").strip() or None
        turret.serial_number = (form.get("serial_number") or "").strip() or None
        turret.ip_address = _norm_ip(form.get("ip_address"))
        turret.dns_hostname = _norm_hostname(form.get("dns_hostname"))
        turret.zone = (form.get("zone") or "").strip() or None
        turret.firmware_version = (form.get("firmware_version") or "").strip() or None
        turret.model = (form.get("model") or "").strip() or None
        turret.country = (form.get("country") or "").strip() or None
        turret.office = (form.get("office") or "").strip() or None
        turret.desk_location = (form.get("desk_location") or "").strip() or None
        turret.switchport_1 = (form.get("switchport_1") or "").strip() or None
        turret.switchport_2 = (form.get("switchport_2") or "").strip() or None

        turret.last_updated = datetime.utcnow()
        turret.last_updated_by = _current_username()
        turret.last_change = f"Updated by {_current_username()}"

        db.session.commit()
        flash("Turret updated", "success")
        return redirect(url_for("turret_list"))

    return render_template(
        "turret/edit.html",
        turret=turret,
        countries=countries,
        custom_fields=custom_fields,
        custom_values=custom_values,
    )


@core_bp.route("/turret/rma")
@login_required
def turret_rma_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    country = (request.args.get("country") or "").strip()

    stmt = select(CeasedRMATurret)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(CeasedRMATurret.mac_address, s),
                _contains(CeasedRMATurret.mac_address_2, s),
                _contains(CeasedRMATurret.mac_address_3, s),
                _contains(CeasedRMATurret.mac_address_4, s),
                _contains(CeasedRMATurret.mac_address_5, s),
                _contains(CeasedRMATurret.ip_address, s),
                _contains(CeasedRMATurret.dns_hostname, s),
                _contains(CeasedRMATurret.zone, s),
                _contains(CeasedRMATurret.office, s),
                _contains(CeasedRMATurret.desk_location, s),
                _contains(CeasedRMATurret.moved_by, s),
                _contains(CeasedRMATurret.dealerboard_issue, s),
                _contains(CeasedRMATurret.summary, s),
            )
        )

    if country:
        stmt = stmt.where(CeasedRMATurret.country == country)

    stmt = stmt.order_by(CeasedRMATurret.moved_at.desc().nullslast(), CeasedRMATurret.id.desc())
    turrets = db.paginate(stmt, page=page, per_page=20, error_out=False)
    countries = _lookup_values("country") or []
    return render_template(
        "turret_rma/list.html",
        turrets=turrets,
        search=search,
        country=country,
        countries=countries,
    )


@core_bp.route("/turret/rma/export")
@login_required
def turret_rma_export():
    search = (request.args.get("search") or "").strip()
    country = (request.args.get("country") or "").strip()

    stmt = select(CeasedRMATurret)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(CeasedRMATurret.mac_address, s),
                _contains(CeasedRMATurret.mac_address_2, s),
                _contains(CeasedRMATurret.mac_address_3, s),
                _contains(CeasedRMATurret.mac_address_4, s),
                _contains(CeasedRMATurret.mac_address_5, s),
                _contains(CeasedRMATurret.ip_address, s),
                _contains(CeasedRMATurret.dns_hostname, s),
                _contains(CeasedRMATurret.zone, s),
                _contains(CeasedRMATurret.office, s),
                _contains(CeasedRMATurret.desk_location, s),
                _contains(CeasedRMATurret.moved_by, s),
                _contains(CeasedRMATurret.dealerboard_issue, s),
                _contains(CeasedRMATurret.summary, s),
            )
        )
    if country:
        stmt = stmt.where(CeasedRMATurret.country == country)

    stmt = stmt.order_by(CeasedRMATurret.moved_at.desc().nullslast(), CeasedRMATurret.id.desc())
    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)
    headers = [
        "id",
        "original_turret_id",
        "moved_at",
        "moved_by",
        "move_reason",
        "rma_date_sent",
        "rma_date_received",
        "dealerboard_issue",
        "summary",
        "mac_address",
        "mac_address_2",
        "mac_address_3",
        "mac_address_4",
        "mac_address_5",
        "serial_number",
        "ip_address",
        "dns_hostname",
        "zone",
        "firmware_version",
        "model",
        "country",
        "office",
        "desk_location",
        "date_created",
        "last_updated",
        "last_change",
    ]
    w.writerow(headers)
    for t in rows:
        w.writerow(
            [
                t.id,
                t.original_turret_id or "",
                t.moved_at.strftime("%Y-%m-%d %H:%M:%S") if t.moved_at else "",
                t.moved_by or "",
                t.move_reason or "",
                t.rma_date_sent.strftime("%Y-%m-%d") if t.rma_date_sent else "",
                t.rma_date_received.strftime("%Y-%m-%d") if t.rma_date_received else "",
                t.dealerboard_issue or "",
                t.summary or "",
                t.mac_address or "",
                t.mac_address_2 or "",
                t.mac_address_3 or "",
                t.mac_address_4 or "",
                t.mac_address_5 or "",
                t.serial_number or "",
                t.ip_address or "",
                t.dns_hostname or "",
                t.zone or "",
                t.firmware_version or "",
                t.model or "",
                t.country or "",
                t.office or "",
                t.desk_location or "",
                t.date_created.strftime("%Y-%m-%d %H:%M:%S") if t.date_created else "",
                t.last_updated.strftime("%Y-%m-%d %H:%M:%S") if t.last_updated else "",
                t.last_change or "",
            ]
        )

    data = output.getvalue()
    filename = f"ceased_turrets_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/turret/rma/import", methods=["GET", "POST"])
@login_required
def turret_rma_import():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("turret_rma/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            if not mapping.get("mac_address"):
                flash("MAC Address must be mapped", "danger")
                return redirect(url_for("turret_rma_import"))

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            created = 0
            updated = 0
            skipped = 0
            now = datetime.utcnow()

            for row in reader:
                mac = pick(row, "mac_address")
                if not mac:
                    skipped += 1
                    continue

                rec = (
                    CeasedRMATurret.query.filter_by(mac_address=mac)
                    .order_by(CeasedRMATurret.id.desc())
                    .first()
                )
                is_new = rec is None
                if is_new:
                    rec = CeasedRMATurret(mac_address=mac)
                    rec.date_created = now
                    db.session.add(rec)

                rec.mac_address_2 = pick(row, "mac_address_2") or rec.mac_address_2
                rec.mac_address_3 = pick(row, "mac_address_3") or rec.mac_address_3
                rec.mac_address_4 = pick(row, "mac_address_4") or rec.mac_address_4
                rec.mac_address_5 = pick(row, "mac_address_5") or rec.mac_address_5
                rec.ip_address = pick(row, "ip_address") or rec.ip_address
                rec.dns_hostname = pick(row, "dns_hostname") or rec.dns_hostname
                rec.zone = pick(row, "zone") or rec.zone
                rec.firmware_version = pick(row, "firmware_version") or rec.firmware_version
                rec.model = pick(row, "model") or rec.model
                rec.country = pick(row, "country") or rec.country
                rec.office = pick(row, "office") or rec.office
                rec.desk_location = pick(row, "desk_location") or rec.desk_location

                moved_at = _parse_any_date(pick(row, "moved_at"))
                if moved_at:
                    rec.moved_at = moved_at
                rec.moved_by = pick(row, "moved_by") or rec.moved_by
                rec.move_reason = pick(row, "move_reason") or rec.move_reason

                rec.rma_date_sent = _parse_any_date(pick(row, "rma_date_sent")) or rec.rma_date_sent
                rec.rma_date_received = _parse_any_date(pick(row, "rma_date_received")) or rec.rma_date_received
                rec.dealerboard_issue = pick(row, "dealerboard_issue") or rec.dealerboard_issue
                rec.summary = pick(row, "summary") or rec.summary

                rec.last_updated = now
                rec.last_change = f"Imported by {_current_username()}"

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete: {created} created, {updated} updated, {skipped} skipped", "success")
            return redirect(url_for("turret_rma_list"))

        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return render_template("turret_rma/import.html"), 400

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("turret_rma/import.html"), 400

        target_fields = [
            {"key": "mac_address", "label": "MAC Address", "required": True},
            {"key": "mac_address_2", "label": "MAC 2", "required": False},
            {"key": "mac_address_3", "label": "MAC 3", "required": False},
            {"key": "mac_address_4", "label": "MAC 4", "required": False},
            {"key": "mac_address_5", "label": "MAC 5", "required": False},
            {"key": "ip_address", "label": "IP Address", "required": False},
            {"key": "dns_hostname", "label": "DNS/Hostname", "required": False},
            {"key": "zone", "label": "Zone", "required": False},
            {"key": "firmware_version", "label": "Firmware", "required": False},
            {"key": "model", "label": "Model", "required": False},
            {"key": "country", "label": "Country", "required": False},
            {"key": "office", "label": "Office", "required": False},
            {"key": "desk_location", "label": "Desk Location", "required": False},
            {"key": "moved_at", "label": "Moved At", "required": False},
            {"key": "moved_by", "label": "Moved By", "required": False},
            {"key": "move_reason", "label": "Move Reason", "required": False},
            {"key": "rma_date_sent", "label": "RMA Date Sent", "required": False},
            {"key": "rma_date_received", "label": "RMA Date Received", "required": False},
            {"key": "dealerboard_issue", "label": "Issue", "required": False},
            {"key": "summary", "label": "Summary", "required": False},
        ]

        synonyms = {
            "mac_address": ["mac_address", "MAC Address", "MAC"],
            "mac_address_2": ["mac_address_2", "MAC 2"],
            "mac_address_3": ["mac_address_3", "MAC 3"],
            "mac_address_4": ["mac_address_4", "MAC 4"],
            "mac_address_5": ["mac_address_5", "MAC 5"],
            "ip_address": ["ip_address", "IP Address", "IP"],
            "dns_hostname": ["dns_hostname", "DNS/Hostname", "DNS"],
            "zone": ["zone", "Zone"],
            "firmware_version": ["firmware_version", "Firmware"],
            "model": ["model", "Model"],
            "country": ["country", "Country"],
            "office": ["office", "Office"],
            "desk_location": ["desk_location", "Desk Location"],
            "moved_at": ["moved_at", "Moved At"],
            "moved_by": ["moved_by", "Moved By"],
            "move_reason": ["move_reason", "Move Reason"],
            "rma_date_sent": ["rma_date_sent", "RMA Sent", "RMA Date Sent"],
            "rma_date_received": ["rma_date_received", "RMA Received", "RMA Date Received"],
            "dealerboard_issue": ["dealerboard_issue", "Issue"],
            "summary": ["summary", "Summary"],
        }

        suggestions = _suggest_mapping(csv_headers, synonyms)
        return render_template(
            "import_map.html",
            title="Map Ceased/RMA Turret CSV Fields",
            help_text="Map the columns from your CSV file to the ceased/RMA turret fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("turret_rma_list"),
        )

    return render_template("turret_rma/import.html")


@core_bp.route("/turret/rma/<int:id>", methods=["POST"])
@login_required
def turret_rma(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    turret = db.session.get(DealerboardTurret, id)
    if not turret:
        abort(404)

    form = request.form.to_dict(flat=True)
    now = datetime.utcnow()

    ceased = CeasedRMATurret(
        original_turret_id=turret.id,
        moved_at=now,
        moved_by=_current_username(),
        move_reason=(form.get("move_reason") or "").strip() or None,
        mac_address=turret.mac_address,
        mac_address_2=turret.mac_address_2,
        mac_address_3=turret.mac_address_3,
        mac_address_4=turret.mac_address_4,
        mac_address_5=turret.mac_address_5,
        serial_number=turret.serial_number,
        ip_address=turret.ip_address,
        dns_hostname=turret.dns_hostname,
        zone=turret.zone,
        firmware_version=turret.firmware_version,
        model=turret.model,
        country=turret.country,
        office=turret.office,
        desk_location=turret.desk_location,
        date_created=turret.date_created,
        last_updated=turret.last_updated,
        last_change=turret.last_change,
        custom_fields_json=turret.custom_fields_json,
        rma_date_sent=_parse_any_date((form.get("rma_date_sent") or "").strip()),
        rma_date_received=_parse_any_date((form.get("rma_date_received") or "").strip()),
        dealerboard_issue=(form.get("dealerboard_issue") or "").strip() or None,
        summary=(form.get("summary") or "").strip() or None,
    )

    db.session.add(ceased)
    db.session.delete(turret)
    db.session.commit()
    flash("Turret moved to Ceased/RMA", "success")
    return redirect(url_for("turret_rma_list"))


def _dns_norm(v: str | None) -> str:
    return (v or "").strip().rstrip(".").lower()


def _resolve_hostname_from_ip(ip: str) -> str | None:
    ip = (ip or "").strip()
    if not ip:
        return None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return (host or "").strip() or None
    except Exception:
        return None


def _resolve_ip_from_hostname(hostname: str) -> str | None:
    hostname = (hostname or "").strip()
    if not hostname:
        return None
    try:
        ip = socket.gethostbyname(hostname)
        return (ip or "").strip() or None
    except Exception:
        return None


@core_bp.route("/turret/<int:id>/nslookup/ip", methods=["POST"])
@login_required
def turret_nslookup_by_ip(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    turret = db.session.get(DealerboardTurret, id)
    if not turret:
        abort(404)

    ip = _norm_ip(turret.ip_address)
    if not ip:
        flash("No IP address set on this turret", "warning")
        return redirect(url_for("turret_edit", id=id))

    ip_ok, ip_err = _validate_ip(ip)
    if not ip_ok:
        flash(ip_err or "Invalid IP address", "danger")
        return redirect(url_for("turret_edit", id=id))

    resolved = _resolve_hostname_from_ip(ip)
    if not resolved:
        flash(f"NSLookup by IP failed. Stored IP={ip}", "danger")
        _log_action(_current_username(), "turret_nslookup_ip", f"turret_id={id} ip={ip} resolved=None", success=False)
        return redirect(url_for("turret_edit", id=id))

    prev = turret.dns_hostname
    if _dns_norm(resolved) != _dns_norm(prev):
        turret.dns_hostname = _norm_hostname(resolved)
        turret.last_updated = datetime.utcnow()
        turret.last_updated_by = _current_username()
        turret.last_change = f"Hostname updated from IP lookup by {_current_username()}"
        db.session.commit()
        flash(f"Hostname updated. Stored={prev or '-'} Resolved={resolved}", "success")
        _log_action(
            _current_username(),
            "turret_nslookup_ip_update",
            f"turret_id={id} ip={ip} dns_hostname_prev={prev or ''} dns_hostname_new={resolved}",
        )
    else:
        flash(f"Hostname already matches DNS. Stored={prev or '-'} Resolved={resolved}", "info")
        _log_action(
            _current_username(),
            "turret_nslookup_ip_nochange",
            f"turret_id={id} ip={ip} dns_hostname={prev or ''} resolved={resolved}",
        )

    return redirect(url_for("turret_edit", id=id))


@core_bp.route("/turret/<int:id>/nslookup/hostname", methods=["POST"])
@login_required
def turret_nslookup_by_hostname(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    turret = db.session.get(DealerboardTurret, id)
    if not turret:
        abort(404)

    hostname = _norm_hostname(turret.dns_hostname)
    if not hostname:
        flash("No hostname set on this turret", "warning")
        return redirect(url_for("turret_edit", id=id))

    resolved = _resolve_ip_from_hostname(hostname)
    if not resolved:
        flash(f"NSLookup by hostname failed. Stored hostname={hostname}", "danger")
        _log_action(
            _current_username(),
            "turret_nslookup_hostname",
            f"turret_id={id} hostname={hostname} resolved=None",
            success=False,
        )
        return redirect(url_for("turret_edit", id=id))

    prev = turret.ip_address
    if (resolved or "") != (prev or ""):
        turret.ip_address = _norm_ip(resolved)
        turret.last_updated = datetime.utcnow()
        turret.last_updated_by = _current_username()
        turret.last_change = f"IP updated from hostname lookup by {_current_username()}"
        db.session.commit()
        flash(f"IP updated. Stored={prev or '-'} Resolved={resolved}", "success")
        _log_action(
            _current_username(),
            "turret_nslookup_hostname_update",
            f"turret_id={id} hostname={hostname} ip_prev={prev or ''} ip_new={resolved}",
        )
    else:
        flash(f"IP already matches DNS. Stored={prev or '-'} Resolved={resolved}", "info")
        _log_action(
            _current_username(),
            "turret_nslookup_hostname_nochange",
            f"turret_id={id} hostname={hostname} ip={prev or ''} resolved={resolved}",
        )

    return redirect(url_for("turret_edit", id=id))


@core_bp.route("/turret/<int:id>/open-web", methods=["GET"])
@login_required
def turret_open_web(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    turret = db.session.get(DealerboardTurret, id)
    if not turret:
        abort(404)

    hostname = _norm_hostname(turret.dns_hostname)
    if not hostname:
        flash("No hostname set on this turret", "warning")
        return redirect(url_for("turret_edit", id=id))

    scheme = "http"
    try:
        with socket.create_connection((hostname, 443), timeout=2):
            scheme = "https"
    except Exception:
        scheme = "http"

    return redirect(f"{scheme}://{hostname}/")


@core_bp.route("/turret/moves")
@login_required
def turret_moves_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    priority = (request.args.get("priority") or "").strip()

    stmt = select(TurretMoveGroup)
    if status:
        stmt = stmt.where(TurretMoveGroup.status == status)
    if search:
        s = f"%{search}%"
        stmt = stmt.where(or_(TurretMoveGroup.move_name.ilike(s), TurretMoveGroup.description.ilike(s)))

    stmt = stmt.order_by(TurretMoveGroup.created_date.desc().nullslast(), TurretMoveGroup.id.desc())
    move_groups = db.paginate(stmt, page=page, per_page=12, error_out=False)

    # Annotate each group with counts expected by template
    group_ids = [g.id for g in move_groups.items]
    counts = {}
    completed = {}
    if group_ids:
        all_moves = (
            db.session.execute(select(TurretMove).where(TurretMove.move_group_id.in_(group_ids))).scalars().all()
        )
        for m in all_moves:
            counts[m.move_group_id] = counts.get(m.move_group_id, 0) + 1
            if (m.status or "") == "Completed":
                completed[m.move_group_id] = completed.get(m.move_group_id, 0) + 1

        if priority:
            # When a priority filter is applied, only keep groups that contain a move of that priority.
            wanted = {m.move_group_id for m in all_moves if (m.priority or "") == priority}
            move_groups.items = [g for g in move_groups.items if g.id in wanted]

    for g in move_groups.items:
        g.turret_count = counts.get(g.id, 0)
        g.completed_moves = completed.get(g.id, 0)

    return render_template(
        "turret/moves_list.html",
        move_groups=move_groups,
        search=search,
        status=status,
        priority=priority,
    )


@core_bp.route("/turret/moves/export")
@login_required
def turret_moves_export():
    if not (current_user.is_admin() or getattr(current_user, "can_export_turret_moves", False)):
        abort(403)

    groups = db.session.execute(select(TurretMoveGroup).order_by(TurretMoveGroup.id.asc())).scalars().all()
    group_ids = [g.id for g in groups]
    moves_by_group: dict[int, list[TurretMove]] = {}
    if group_ids:
        moves = (
            db.session.execute(select(TurretMove).where(TurretMove.move_group_id.in_(group_ids)).order_by(TurretMove.id.asc()))
            .scalars()
            .all()
        )
        for m in moves:
            moves_by_group.setdefault(m.move_group_id, []).append(m)

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(
        [
            "move_group_id",
            "move_name",
            "description",
            "planned_execution_date",
            "status",
            "turret_id",
            "turret_mac",
            "from_desk",
            "to_desk",
            "from_office",
            "to_office",
            "from_country",
            "to_country",
            "move_reason",
            "priority",
            "requires_network_config",
            "requires_phone_config",
            "snow_reference",
        ]
    )

    for g in groups:
        planned = g.planned_execution_date.strftime("%Y-%m-%d %H:%M:%S") if g.planned_execution_date else ""
        for m in moves_by_group.get(g.id, []):
            turret = db.session.get(DealerboardTurret, m.turret_id)
            w.writerow(
                [
                    g.id,
                    g.move_name or "",
                    g.description or "",
                    planned,
                    g.status or "",
                    m.turret_id,
                    turret.mac_address if turret else "",
                    m.from_desk or "",
                    m.to_desk or "",
                    m.from_office or "",
                    m.to_office or "",
                    m.from_country or "",
                    m.to_country or "",
                    m.move_reason or "",
                    m.priority or "",
                    "Yes" if m.requires_network_config else "No",
                    "Yes" if m.requires_phone_config else "No",
                    m.snow_reference or "",
                ]
            )

    from flask import Response

    data = output.getvalue()
    filename = f"turret_moves_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/turret/moves/import", methods=["GET", "POST"])
@login_required
def turret_moves_import():
    if not (current_user.is_admin() or getattr(current_user, "can_import_turret_moves", False)):
        abort(403)

    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return render_template("turret/moves_import.html"), 400

        text = _read_upload_text(f)
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            flash("CSV has no header row", "danger")
            return render_template("turret/moves_import.html"), 400

        required_cols = {"move_name", "turret_mac", "to_desk"}
        missing = [c for c in sorted(required_cols) if c not in set(reader.fieldnames or [])]
        if missing:
            flash(f"Missing required columns: {', '.join(missing)}", "danger")
            return render_template("turret/moves_import.html"), 400

        now = datetime.utcnow()
        groups_by_name: dict[str, TurretMoveGroup] = {}
        created_groups = 0
        created_moves = 0
        skipped = 0

        def _yn(v: str | None) -> bool:
            return (v or "").strip().lower() in {"1", "true", "yes", "y"}

        for row in reader:
            move_name = (row.get("move_name") or "").strip()
            turret_mac = (row.get("turret_mac") or "").strip()
            to_desk = (row.get("to_desk") or "").strip()
            if not move_name or not turret_mac or not to_desk:
                skipped += 1
                continue

            turret = DealerboardTurret.query.filter_by(mac_address=turret_mac).first()
            if not turret:
                skipped += 1
                continue

            group = groups_by_name.get(move_name)
            if not group:
                planned = _parse_any_date((row.get("planned_execution_date") or "").strip())
                group = TurretMoveGroup(
                    move_name=move_name,
                    description=(row.get("description") or "").strip() or None,
                    created_by=_current_username(),
                    created_date=now,
                    planned_execution_date=planned,
                    status="Planning",
                    last_updated=now,
                    last_updated_by=_current_username(),
                )
                db.session.add(group)
                db.session.flush()
                groups_by_name[move_name] = group
                created_groups += 1

            db.session.add(
                TurretMove(
                    move_group_id=group.id,
                    turret_id=turret.id,
                    from_desk=turret.desk_location,
                    to_desk=to_desk,
                    from_office=turret.office,
                    to_office=(row.get("to_office") or "").strip() or None,
                    from_country=turret.country,
                    to_country=(row.get("to_country") or "").strip() or None,
                    move_reason=(row.get("move_reason") or "").strip() or None,
                    priority=(row.get("priority") or "Normal").strip() or "Normal",
                    snow_reference=(row.get("snow_reference") or "").strip() or None,
                    requires_network_config=_yn(row.get("requires_network_config")),
                    requires_phone_config=_yn(row.get("requires_phone_config")),
                    status="Planned",
                    created_date=now,
                )
            )
            created_moves += 1

        db.session.commit()
        flash(
            f"Import complete. Groups created={created_groups} Moves created={created_moves} Skipped={skipped}",
            "success",
        )
        return redirect(url_for("turret_moves_list"))

    return render_template("turret/moves_import.html")


@core_bp.route("/turret/moves/history")
@login_required
def turret_move_history():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()

    stmt = select(TurretMoveHistory)
    if search:
        s = f"%{search}%"
        stmt = stmt.join(DealerboardTurret, TurretMoveHistory.turret_id == DealerboardTurret.id).where(
            or_(
                DealerboardTurret.mac_address.ilike(s),
                TurretMoveHistory.from_desk.ilike(s),
                TurretMoveHistory.to_desk.ilike(s),
                TurretMoveHistory.moved_by.ilike(s),
            )
        )

    stmt = stmt.order_by(TurretMoveHistory.move_date.desc(), TurretMoveHistory.id.desc())
    move_history = db.paginate(stmt, page=page, per_page=25, error_out=False)
    return render_template(
        "turret/move_history.html",
        move_history=move_history,
        search=search,
    )


@core_bp.route("/turret/moves/group/<int:id>")
@login_required
def turret_view_move_group(id: int):
    move_group = db.session.get(TurretMoveGroup, id)
    if not move_group:
        abort(404)

    moves = (
        db.session.execute(
            select(TurretMove)
            .where(TurretMove.move_group_id == id)
            .order_by(TurretMove.priority.desc().nullslast(), TurretMove.id.asc())
        )
        .scalars()
        .all()
    )
    return render_template("turret/view_move_group.html", move_group=move_group, moves=moves)


@core_bp.route("/turret/moves/turret/<int:id>")
@login_required
def turret_individual_history(id: int):
    turret = db.session.get(DealerboardTurret, id)
    if not turret:
        abort(404)

    history = (
        db.session.execute(
            select(TurretMoveHistory)
            .where(TurretMoveHistory.turret_id == id)
            .order_by(TurretMoveHistory.move_date.desc(), TurretMoveHistory.id.desc())
        )
        .scalars()
        .all()
    )
    return render_template("turret/turret_history.html", turret=turret, history=history)


@core_bp.route("/turret/moves/plan", methods=["GET", "POST"])
@login_required
def turret_plan_move():
    if not current_user.can_edit_inventory():
        abort(403)

    countries = _lookup_values("country") or []
    turrets = (
        db.session.execute(
            select(DealerboardTurret)
            .where(or_(DealerboardTurret.status.is_(None), DealerboardTurret.status == "Active"))
            .order_by(DealerboardTurret.mac_address.asc().nullslast(), DealerboardTurret.id.asc())
        )
        .scalars()
        .all()
    )

    if request.method == "POST":
        move_name = (request.form.get("move_name") or "").strip()
        description = (request.form.get("description") or "").strip() or None
        planned_execution_raw = (request.form.get("planned_execution_date") or "").strip() or None

        if not move_name:
            flash("Move name is required", "danger")
            return render_template("turret/plan_move.html", turrets=turrets, countries=countries)

        planned_execution_date = None
        if planned_execution_raw:
            try:
                planned_execution_date = datetime.fromisoformat(planned_execution_raw)
            except ValueError:
                planned_execution_date = None

        selected = request.form.getlist("selected_turrets")
        turret_ids = []
        for v in selected:
            try:
                turret_ids.append(int(v))
            except ValueError:
                continue

        if not turret_ids:
            flash("Select at least one turret", "danger")
            return render_template("turret/plan_move.html", turrets=turrets, countries=countries)

        now = datetime.utcnow()
        group = TurretMoveGroup(
            move_name=move_name,
            description=description,
            created_by=_current_username(),
            created_date=now,
            planned_execution_date=planned_execution_date,
            status="Planning",
            last_updated=now,
            last_updated_by=_current_username(),
        )
        db.session.add(group)
        db.session.flush()

        # Create moves
        for tid in turret_ids:
            turret = db.session.get(DealerboardTurret, tid)
            if not turret:
                continue

            to_desk = (request.form.get(f"to_desk_{tid}") or "").strip()
            if not to_desk:
                continue

            move = TurretMove(
                move_group_id=group.id,
                turret_id=tid,
                from_desk=turret.desk_location,
                to_desk=to_desk,
                from_office=turret.office,
                to_office=(request.form.get(f"to_office_{tid}") or "").strip() or None,
                from_country=turret.country,
                to_country=(request.form.get(f"to_country_{tid}") or "").strip() or None,
                move_reason=(request.form.get(f"move_reason_{tid}") or "").strip() or None,
                priority=(request.form.get(f"priority_{tid}") or "Normal").strip() or "Normal",
                status="Planned",
                requires_network_config=bool(request.form.get(f"network_config_{tid}")),
                requires_phone_config=bool(request.form.get(f"phone_config_{tid}")),
                created_date=now,
            )
            db.session.add(move)

        db.session.commit()
        flash("Move group created", "success")
        return redirect(url_for("turret_view_move_group", id=group.id))

    return render_template("turret/plan_move.html", turrets=turrets, countries=countries)


@core_bp.route("/turret/moves/group/<int:id>/edit", methods=["GET", "POST"])
@login_required
def turret_edit_move_group(id: int):
    if not current_user.can_edit_inventory():
        abort(403)

    move_group = db.session.get(TurretMoveGroup, id)
    if not move_group:
        abort(404)

    if move_group.status not in {"Planning", "Approved"}:
        flash("This move group can no longer be edited", "warning")
        return redirect(url_for("turret_view_move_group", id=id))

    countries = _lookup_values("country") or []

    if request.method == "POST":
        is_admin = current_user.is_admin()

        # User-editable fields
        move_group.move_name = (request.form.get("move_name") or "").strip() or move_group.move_name
        move_group.description = (request.form.get("description") or "").strip() or None

        planned_execution_raw = (request.form.get("planned_execution_date") or "").strip() or None
        if planned_execution_raw:
            try:
                move_group.planned_execution_date = datetime.fromisoformat(planned_execution_raw)
            except ValueError:
                pass
        else:
            move_group.planned_execution_date = None

        # Admin-only fields should not be set via this form for non-admins.
        if not is_admin:
            move_group.status = move_group.status
            move_group.executed_by = move_group.executed_by
            move_group.executed_date = move_group.executed_date

        now = datetime.utcnow()
        move_group.last_updated = now
        move_group.last_updated_by = _current_username()

        # Update individual moves
        moves = db.session.execute(select(TurretMove).where(TurretMove.move_group_id == id)).scalars().all()
        for m in moves:
            to_desk = (request.form.get(f"to_desk_{m.id}") or "").strip()
            if to_desk:
                m.to_desk = to_desk
            m.to_office = (request.form.get(f"to_office_{m.id}") or "").strip() or None
            m.to_country = (request.form.get(f"to_country_{m.id}") or "").strip() or None
            m.move_reason = (request.form.get(f"move_reason_{m.id}") or "").strip() or None
            m.priority = (request.form.get(f"priority_{m.id}") or m.priority or "Normal").strip() or "Normal"
            m.requires_network_config = bool(request.form.get(f"network_config_{m.id}"))
            m.requires_phone_config = bool(request.form.get(f"phone_config_{m.id}"))

        db.session.commit()
        flash("Move group updated", "success")
        return redirect(url_for("turret_view_move_group", id=id))

    return render_template("turret/edit_move_group.html", move_group=move_group, countries=countries)


@core_bp.route("/turret/moves/execute", methods=["POST"])
@login_required
def turret_execute_move():
    if not (current_user.is_admin() or getattr(current_user, "can_execute_turret_moves", False)):
        abort(403)

    try:
        group_id = int(request.form.get("move_group_id") or 0)
    except ValueError:
        group_id = 0
    if not group_id:
        abort(400)

    execution_notes = (request.form.get("execution_notes") or "").strip() or None

    group = db.session.get(TurretMoveGroup, group_id)
    if not group:
        abort(404)

    if group.status not in {"Approved", "In Progress"}:
        flash("Move group must be Approved before execution", "warning")
        return redirect(url_for("turret_view_move_group", id=group_id))

    now = datetime.utcnow()
    group.status = "In Progress"
    group.executed_date = now
    group.executed_by = _current_username()
    group.last_updated = now
    group.last_updated_by = _current_username()
    if execution_notes:
        group.notes = (group.notes or "") + ("\n" if group.notes else "") + execution_notes

    moves = db.session.execute(select(TurretMove).where(TurretMove.move_group_id == group_id)).scalars().all()
    for m in moves:
        turret = db.session.get(DealerboardTurret, m.turret_id)
        if not turret:
            continue

        # Record history BEFORE changing
        h = TurretMoveHistory(
            turret_id=turret.id,
            move_id=m.id,
            move_group_id=group_id,
            from_desk=turret.desk_location,
            to_desk=m.to_desk,
            from_office=turret.office,
            to_office=m.to_office,
            from_country=turret.country,
            to_country=m.to_country,
            move_date=now,
            moved_by=_current_username(),
            move_reason=m.move_reason,
            snow_reference=m.snow_reference,
            actual_downtime_minutes=m.actual_downtime_minutes,
            notes=execution_notes,
        )
        db.session.add(h)

        # Apply new location
        turret.desk_location = m.to_desk
        if m.to_office is not None:
            turret.office = m.to_office
        if m.to_country is not None:
            turret.country = m.to_country
        turret.last_updated = now
        turret.last_updated_by = _current_username()
        turret.last_change = f"Moved by {_current_username()}"

        m.status = "Completed"
        m.executed_date = now
        m.execution_notes = execution_notes

    group.status = "Completed"
    db.session.commit()
    flash("Move group executed", "success")
    return redirect(url_for("turret_view_move_group", id=group_id))


@core_bp.route("/turret/moves/group/<int:id>/approve", methods=["POST"])
@login_required
def turret_approve_move_group(id: int):
    if not (current_user.is_admin() or getattr(current_user, "can_approve_turret_moves", False)):
        abort(403)

    group = db.session.get(TurretMoveGroup, id)
    if not group:
        abort(404)

    if group.status != "Planning":
        flash("Only Planning move groups can be approved", "warning")
        return redirect(url_for("turret_view_move_group", id=id))

    group.status = "Approved"
    group.last_updated = datetime.utcnow()
    group.last_updated_by = _current_username()
    db.session.commit()
    flash("Move group approved", "success")
    return redirect(url_for("turret_view_move_group", id=id))


@core_bp.route("/turret/moves/group/<int:id>/history")
@login_required
def turret_history(id: int):
    # Backwards-compat alias; redirect to individual history.
    return redirect(url_for("turret_individual_history", id=id))


@core_bp.route("/changes")
@login_required
def changes_list():
    page = request.args.get("page", 1, type=int)

    search = (request.args.get("search") or "").strip()
    field_filter = (request.args.get("field_filter") or "all").strip()
    criteria = (request.args.get("criteria") or "").strip()
    status = (request.args.get("status") or "").strip()
    region = (request.args.get("region") or "").strip()
    cab_date = (request.args.get("cab_date") or "").strip()
    regional_approval_not_blank = (request.args.get("regional_approval_not_blank") or "").strip()
    global_approval_not_blank = (request.args.get("global_approval_not_blank") or "").strip()
    rtc_cab = (request.args.get("rtc_cab") or "").strip()

    stmt = select(ChangeRecord)

    if status:
        stmt = stmt.where(ChangeRecord.status == status)
    if region:
        stmt = stmt.where(ChangeRecord.region == region)
    if cab_date:
        # Stored as datetime; compare by date string prefix.
        stmt = stmt.where(db.func.date(ChangeRecord.cab_date) == cab_date)

    if regional_approval_not_blank:
        stmt = stmt.where(
            and_(
                ChangeRecord.regional_approval_status.is_not(None),
                ChangeRecord.regional_approval_status != "",
            )
        )
    if global_approval_not_blank:
        stmt = stmt.where(
            and_(
                ChangeRecord.global_service_approval.is_not(None),
                ChangeRecord.global_service_approval != "",
            )
        )

    if rtc_cab == "Yes":
        stmt = stmt.where(ChangeRecord.rtc_cab.is_(True))
    elif rtc_cab == "No":
        stmt = stmt.where(or_(ChangeRecord.rtc_cab.is_(False), ChangeRecord.rtc_cab.is_(None)))

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if search:
        s = search
        if field_filter == "region":
            stmt = stmt.where(_contains(ChangeRecord.region, s))
        elif field_filter == "cr_number":
            stmt = stmt.where(_contains(ChangeRecord.cr_number, s))
        elif field_filter == "title":
            stmt = stmt.where(_contains(ChangeRecord.title, s))
        elif field_filter == "technology":
            stmt = stmt.where(_contains(ChangeRecord.technology, s))
        elif field_filter == "status":
            stmt = stmt.where(_contains(ChangeRecord.status, s))
        elif field_filter == "snow_link":
            stmt = stmt.where(_contains(ChangeRecord.snow_link, s))
        elif field_filter == "raised_by":
            stmt = stmt.where(_contains(ChangeRecord.raised_by, s))
        elif field_filter == "tech_lead":
            stmt = stmt.where(_contains(ChangeRecord.tech_lead, s))
        elif field_filter == "change_category":
            stmt = stmt.where(_contains(ChangeRecord.change_category, s))
        elif field_filter == "change_risk_level":
            stmt = stmt.where(_contains(ChangeRecord.change_risk_level, s))
        elif field_filter == "global_service_approval":
            stmt = stmt.where(_contains(ChangeRecord.global_service_approval, s))
        elif field_filter == "regional_approval_status":
            stmt = stmt.where(_contains(ChangeRecord.regional_approval_status, s))
        elif field_filter == "regional_approver_name":
            stmt = stmt.where(_contains(ChangeRecord.regional_approver_name, s))
        elif field_filter == "approved_status":
            stmt = stmt.where(_contains(ChangeRecord.approved_status, s))
        elif field_filter == "approved_by":
            stmt = stmt.where(_contains(ChangeRecord.approved_by, s))
        elif field_filter == "comments":
            stmt = stmt.where(_contains(ChangeRecord.comments, s))
        elif field_filter == "risk_mitigation":
            stmt = stmt.where(_contains(ChangeRecord.risk_mitigation, s))
        else:
            stmt = stmt.where(
                or_(
                    _contains(ChangeRecord.title, s),
                    _contains(ChangeRecord.cr_number, s),
                    _contains(ChangeRecord.snow_link, s),
                    _contains(ChangeRecord.technology, s),
                    _contains(ChangeRecord.raised_by, s),
                )
            )

    if criteria:
        # Criteria is treated as an additional substring filter against title/cr/snow by default.
        c = criteria
        stmt = stmt.where(or_(_contains(ChangeRecord.title, c), _contains(ChangeRecord.cr_number, c), _contains(ChangeRecord.snow_link, c)))

    # Sort newest first (best-effort)
    stmt = stmt.order_by(ChangeRecord.last_updated.desc().nullslast(), ChangeRecord.id.desc())

    changes = db.paginate(stmt, page=page, per_page=25, error_out=False)

    opts = _changes_form_options()
    custom_fields = _custom_fields_for("changes")
    statuses = opts.get("change_statuses") or []
    regions = opts.get("regions") or []
    technologies = opts.get("technologies") or []
    change_categories = opts.get("change_categories") or []
    global_service_approvals = opts.get("global_service_approvals") or []
    yes_no = opts.get("yes_no") or ["Yes", "No"]
    yes_no_na = opts.get("yes_no_na") or ["Yes", "No", "N/A"]
    cab_mondays = [d.strftime("%Y-%m-%d") for d in (opts.get("cab_mondays") or _cab_monday_options())]

    return render_template(
        "changes/list.html",
        changes=changes,
        search=search,
        field_filter=field_filter,
        criteria=criteria,
        cab_date=cab_date,
        cab_mondays=cab_mondays,
        status=status,
        statuses=statuses,
        region=region,
        regions=regions,
        regional_approval_not_blank=regional_approval_not_blank,
        global_approval_not_blank=global_approval_not_blank,
        rtc_cab=rtc_cab,
        cr_number=request.args.get("cr_number", ""),
        title=request.args.get("title", ""),
        technology=request.args.get("technology", ""),
        technologies=technologies,
        change_category=request.args.get("change_category", ""),
        change_categories=change_categories,
        global_service_approval=request.args.get("global_service_approval", ""),
        global_service_approvals=global_service_approvals,
        change_risk_level=request.args.get("change_risk_level", ""),
        snow_link=request.args.get("snow_link", ""),
        bau_project=request.args.get("bau_project", ""),
        coo_update=request.args.get("coo_update", ""),
        ice_sent=request.args.get("ice_sent", ""),
        ice_approved=request.args.get("ice_approved", ""),
        raised_by=request.args.get("raised_by", ""),
        tech_lead=request.args.get("tech_lead", ""),
        approved_status=request.args.get("approved_status", ""),
        regional_approval_status=request.args.get("regional_approval_status", ""),
        yes_no=yes_no,
        yes_no_na=yes_no_na,
        saved_filters=[],
    )


@core_bp.route("/changes/view/<int:id>")
@login_required
def changes_view(id: int):
    change = db.session.get(ChangeRecord, id)
    if not change:
        abort(404)

    next_url = request.args.get("next") or request.referrer or "/changes"

    custom_fields = _custom_fields_for("changes")
    custom_values = _custom_values_from_obj(change)

    return render_template(
        "changes/view.html",
        change=change,
        next_url=next_url,
        custom_fields=custom_fields,
        custom_values=custom_values,
        audit_entries=[],
    )


@core_bp.route("/changes/add", methods=["GET", "POST"])
@login_required
def changes_add():
    if not current_user.can_edit_changes():
        abort(403)

    next_url = request.args.get("next") or url_for("changes_list")

    opts = _changes_form_options()
    custom_fields = _custom_fields_for("changes")

    if request.method == "POST":
        form = request.form.to_dict(flat=True)

        ch = ChangeRecord()
        ch.region = form.get("region") or None
        ch.cr_number = form.get("cr_number") or None
        ch.start_date = _parse_date(form.get("start_date"))
        ch.title = form.get("title") or None
        ch.status = form.get("status") or None
        ch.change_category = form.get("change_category") or None
        ch.change_risk_level = form.get("change_risk_level") or None
        ch.technology = form.get("technology") or None
        ch.bau_project = form.get("bau_project") or None
        ch.snow_link = form.get("snow_link") or None
        ch.raised_by = form.get("raised_by") or None
        ch.tech_lead = form.get("tech_lead") or None
        ch.coo_update = form.get("coo_update") or None

        if current_user.can_provide_regional_approval:
            ch.regional_approval_status = form.get("regional_approval_status") or None
            ch.regional_approver_name = form.get("regional_approver_name") or None
        else:
            # Keep default behavior: allow the form to display but do not accept changes.
            ch.regional_approval_status = "No"
            ch.regional_approver_name = None

        if current_user.can_approve_global_service:
            ch.global_service_approval = form.get("global_service_approval") or None

        ch.cab_date = _parse_date(form.get("cab_date"))
        ch.ice_sent = _parse_yes_no_na(form.get("ice_sent"))
        ch.ice_approved = _parse_yes_no_na(form.get("ice_approved"))

        if current_user.can_approve_changes:
            ch.approved_status = form.get("approved_status") or "No"
            ch.approved_by = form.get("approved_by") or None
            ch.approved = (ch.approved_status or "").lower() == "yes"
        else:
            ch.approved_status = "No"
            ch.approved_by = None
            ch.approved = False

        ch.regular_change = bool(form.get("regular_change"))
        ch.rtc_cab = bool(form.get("rtc_cab"))
        ch.risk_mitigation = form.get("risk_mitigation") or None
        ch.comments = form.get("comments") or None

        now = datetime.utcnow()
        ch.raised_datetime = now
        ch.date_created = now
        ch.last_updated = now
        ch.last_updated_by = _current_username()

        ok, msg = _save_custom_values("changes", ch, form)
        if not ok:
            flash(msg or "Custom fields invalid", "danger")
            return render_template(
                "changes/add.html",
                next_url=next_url,
                form=form,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(ch),
                **opts,
            )

        db.session.add(ch)
        try:
            db.session.commit()
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            try:
                current_app.logger.exception("Failed to create change record")
            except Exception:
                pass
            flash(f"Failed to create change record: {e}", "danger")
            return render_template(
                "changes/add.html",
                next_url=next_url,
                form=form,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(ch),
                **opts,
            )

        flash("Change created", "success")
        return redirect(url_for("changes_view", id=ch.id, next=next_url))

    return render_template(
        "changes/add.html",
        next_url=next_url,
        form={},
        custom_fields=custom_fields,
        custom_values={},
        **opts,
    )


@core_bp.route("/changes/edit/<int:id>", methods=["GET", "POST"])
@login_required
def changes_edit(id: int):
    if not current_user.can_edit_changes():
        abort(403)

    change = db.session.get(ChangeRecord, id)
    if not change:
        abort(404)

    next_url = (
        (request.args.get("next") or "").strip()
        or (request.form.get("next") or "").strip()
        or request.referrer
        or url_for("changes_list")
    )
    if not (isinstance(next_url, str) and next_url.startswith("/")):
        next_url = url_for("changes_list")
    opts = _changes_form_options()
    custom_fields = _custom_fields_for("changes")
    custom_values = _custom_values_from_obj(change)

    if request.method == "POST":
        form = request.form.to_dict(flat=True)

        loaded_last_updated_raw = (form.get("loaded_last_updated") or "").strip()
        if loaded_last_updated_raw:
            try:
                loaded_last_updated = datetime.fromisoformat(loaded_last_updated_raw)
                current_last_updated = db.session.execute(
                    select(ChangeRecord.last_updated).where(ChangeRecord.id == change.id)
                ).scalar_one_or_none()
                if current_last_updated and loaded_last_updated:
                    if current_last_updated.replace(microsecond=0) != loaded_last_updated.replace(microsecond=0):
                        flash(
                            "This record was updated after you opened the edit page. Please refresh and re-apply your changes.",
                            "warning",
                        )
                        return redirect(url_for("changes_edit", id=change.id, next=next_url))
            except Exception:
                # If we cannot parse the timestamp, do not block the update.
                pass

        change.region = form.get("region") or None
        change.cr_number = form.get("cr_number") or None
        change.start_date = _parse_date(form.get("start_date"))
        change.title = form.get("title") or None
        change.status = form.get("status") or None
        change.change_category = form.get("change_category") or None
        change.change_risk_level = form.get("change_risk_level") or None
        change.technology = form.get("technology") or None
        change.bau_project = form.get("bau_project") or None
        change.snow_link = form.get("snow_link") or None
        change.raised_by = form.get("raised_by") or None
        change.tech_lead = form.get("tech_lead") or None
        change.coo_update = form.get("coo_update") or None

        if current_user.can_provide_regional_approval:
            change.regional_approval_status = form.get("regional_approval_status") or None
            change.regional_approver_name = form.get("regional_approver_name") or None

        if current_user.can_approve_global_service:
            change.global_service_approval = form.get("global_service_approval") or None

        change.cab_date = _parse_date(form.get("cab_date"))
        change.ice_sent = _parse_yes_no_na(form.get("ice_sent"))
        change.ice_approved = _parse_yes_no_na(form.get("ice_approved"))

        if current_user.can_approve_changes:
            change.approved_status = form.get("approved_status") or None
            change.approved_by = form.get("approved_by") or None
            change.approved = (change.approved_status or "").lower() == "yes"

        change.regular_change = bool(form.get("regular_change"))
        change.rtc_cab = bool(form.get("rtc_cab"))
        change.risk_mitigation = form.get("risk_mitigation") or None
        change.comments = form.get("comments") or None

        change.last_updated = datetime.utcnow()
        change.last_updated_by = _current_username()

        ok, msg = _save_custom_values("changes", change, form)
        if not ok:
            flash(msg or "Custom fields invalid", "danger")
            return render_template(
                "changes/edit.html",
                change=change,
                next_url=next_url,
                custom_fields=custom_fields,
                custom_values=_custom_values_from_obj(change),
                audit_entries=[],
                **opts,
            )

        db.session.commit()
        flash("Change updated", "success")
        return redirect(next_url)

    return render_template(
        "changes/edit.html",
        change=change,
        next_url=next_url,
        custom_fields=custom_fields,
        custom_values=custom_values,
        audit_entries=[],
        **opts,
    )


@core_bp.route("/changes/delete/<int:id>", methods=["POST"])
@login_required
def changes_delete(id: int):
    if not current_user.can_edit_changes():
        abort(403)

    change = db.session.get(ChangeRecord, id)
    if not change:
        abort(404)

    next_url = request.args.get("next") or url_for("changes_list")
    db.session.delete(change)
    db.session.commit()
    flash("Change deleted", "success")
    return redirect(next_url)


@core_bp.route("/changes/import", methods=["GET", "POST"])
@login_required
def changes_import():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("changes/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            cr_col = mapping.get("cr_number")
            if not cr_col:
                flash("CR Number must be mapped", "danger")
                return redirect(url_for("changes_import"))

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            created = 0
            updated = 0
            skipped = 0
            now = datetime.utcnow()

            for row in reader:
                cr = pick(row, "cr_number")
                if not cr:
                    skipped += 1
                    continue

                ch = ChangeRecord.query.filter_by(cr_number=cr).first()
                is_new = ch is None
                if is_new:
                    ch = ChangeRecord(cr_number=cr)
                    ch.date_created = now
                    ch.raised_datetime = ch.raised_datetime or now
                    db.session.add(ch)

                ch.region = pick(row, "region") or ch.region
                ch.title = pick(row, "title") or ch.title
                ch.technology = pick(row, "technology") or ch.technology
                ch.status = pick(row, "status") or ch.status
                ch.snow_link = pick(row, "snow_link") or ch.snow_link
                ch.raised_by = pick(row, "raised_by") or ch.raised_by
                ch.tech_lead = pick(row, "tech_lead") or ch.tech_lead
                ch.change_category = pick(row, "change_category") or ch.change_category
                ch.change_risk_level = pick(row, "change_risk_level") or ch.change_risk_level
                ch.bau_project = pick(row, "bau_project") or ch.bau_project
                ch.coo_update = pick(row, "coo_update") or ch.coo_update
                ch.global_service_approval = pick(row, "global_service_approval") or ch.global_service_approval
                ch.regional_approval_status = pick(row, "regional_approval_status") or ch.regional_approval_status
                ch.regional_approver_name = pick(row, "regional_approver_name") or ch.regional_approver_name
                ch.approved_status = pick(row, "approved_status") or ch.approved_status
                ch.approved_by = pick(row, "approved_by") or ch.approved_by
                ch.risk_mitigation = pick(row, "risk_mitigation") or ch.risk_mitigation
                ch.comments = pick(row, "comments") or ch.comments

                sd = _parse_any_date(pick(row, "start_date"))
                if sd:
                    ch.start_date = sd
                cd = _parse_any_date(pick(row, "cab_date"))
                if cd:
                    ch.cab_date = cd

                ice_sent_val = pick(row, "ice_sent")
                if ice_sent_val is not None:
                    ch.ice_sent = _parse_yes_no_na(ice_sent_val)
                ice_approved_val = pick(row, "ice_approved")
                if ice_approved_val is not None:
                    ch.ice_approved = _parse_yes_no_na(ice_approved_val)

                reg = pick(row, "regular_change")
                if reg is not None:
                    ch.regular_change = reg.strip().lower() in {"1", "true", "yes", "y"}

                ch.last_updated = now
                ch.last_updated_by = _current_username()
                ch.last_change = f"Imported by {_current_username()}"

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete. Created {created}, updated {updated}, skipped {skipped}.", "success")
            return redirect(url_for("changes_list"))

        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please select a CSV file to upload", "danger")
            return render_template("changes/import.html"), 400

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("changes/import.html"), 400

        target_fields = [
            {"key": "cr_number", "label": "CR Number", "required": True},
            {"key": "region", "label": "Region", "required": False},
            {"key": "title", "label": "Title", "required": False},
            {"key": "technology", "label": "Technology", "required": False},
            {"key": "status", "label": "Status", "required": False},
            {"key": "snow_link", "label": "SNOW Link", "required": False},
            {"key": "raised_by", "label": "Raised By", "required": False},
            {"key": "tech_lead", "label": "Tech Lead", "required": False},
            {"key": "change_category", "label": "Change Category", "required": False},
            {"key": "change_risk_level", "label": "Risk Level", "required": False},
            {"key": "bau_project", "label": "BAU/Project", "required": False},
            {"key": "coo_update", "label": "COO Update", "required": False},
            {"key": "global_service_approval", "label": "Global Service Approval", "required": False},
            {"key": "regional_approval_status", "label": "Regional Approval Status", "required": False},
            {"key": "regional_approver_name", "label": "Regional Approver Name", "required": False},
            {"key": "approved_status", "label": "Approved Status", "required": False},
            {"key": "approved_by", "label": "Approved By", "required": False},
            {"key": "risk_mitigation", "label": "Risk Mitigation", "required": False},
            {"key": "comments", "label": "Comments", "required": False},
            {"key": "start_date", "label": "Start Date", "required": False},
            {"key": "cab_date", "label": "CAB Date", "required": False},
            {"key": "ice_sent", "label": "ICE Sent", "required": False},
            {"key": "ice_approved", "label": "ICE Approved", "required": False},
            {"key": "regular_change", "label": "Regular Change", "required": False},
        ]
        synonyms = {
            "cr_number": ["cr_number", "cr", "CR#", "CR"],
            "region": ["region"],
            "title": ["title"],
            "technology": ["technology"],
            "status": ["status"],
            "snow_link": ["snow_link", "snow", "snowref", "SNOW"],
            "raised_by": ["raised_by", "raisedby"],
            "tech_lead": ["tech_lead", "techlead"],
            "change_category": ["change_category", "category"],
            "change_risk_level": ["change_risk_level", "risk"],
            "bau_project": ["bau_project", "bau"],
            "coo_update": ["coo_update"],
            "global_service_approval": ["global_service_approval"],
            "regional_approval_status": ["regional_approval_status"],
            "regional_approver_name": ["regional_approver_name"],
            "approved_status": ["approved_status"],
            "approved_by": ["approved_by"],
            "risk_mitigation": ["risk_mitigation"],
            "comments": ["comments"],
            "start_date": ["start_date", "start"],
            "cab_date": ["cab_date", "cab"],
            "ice_sent": ["ice_sent"],
            "ice_approved": ["ice_approved"],
            "regular_change": ["regular_change", "regular"],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map Changes CSV Fields",
            help_text="Map the columns from your CSV file to the change fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("changes_list"),
        )

    return render_template("changes/import.html")


@core_bp.route("/changes/export")
@login_required
def changes_export():
    # CSV export that Excel can open.
    stmt = select(ChangeRecord).order_by(ChangeRecord.id.asc())
    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)

    headers = [
        "id",
        "region",
        "cr_number",
        "title",
        "technology",
        "status",
        "change_category",
        "change_risk_level",
        "start_date",
        "cab_date",
        "snow_link",
        "bau_project",
        "raised_by",
        "tech_lead",
        "coo_update",
        "global_service_approval",
        "regional_approval_status",
        "regional_approver_name",
        "approved_status",
        "approved_by",
        "ice_sent",
        "ice_approved",
        "regular_change",
        "risk_mitigation",
        "comments",
        "raised_datetime",
        "date_created",
        "last_updated",
        "last_updated_by",
    ]
    w.writerow(headers)

    def fmt_dt(d: datetime | None) -> str:
        return d.strftime("%Y-%m-%d %H:%M:%S") if d else ""

    for ch in rows:
        w.writerow(
            [
                ch.id,
                ch.region or "",
                ch.cr_number or "",
                ch.title or "",
                ch.technology or "",
                ch.status or "",
                ch.change_category or "",
                ch.change_risk_level or "",
                ch.start_date.strftime("%Y-%m-%d") if ch.start_date else "",
                ch.cab_date.strftime("%Y-%m-%d") if ch.cab_date else "",
                ch.snow_link or "",
                ch.bau_project or "",
                ch.raised_by or "",
                ch.tech_lead or "",
                ch.coo_update or "",
                ch.global_service_approval or "",
                ch.regional_approval_status or "",
                ch.regional_approver_name or "",
                ch.approved_status or "",
                ch.approved_by or "",
                "" if ch.ice_sent is None else ("Yes" if ch.ice_sent else "No"),
                "" if ch.ice_approved is None else ("Yes" if ch.ice_approved else "No"),
                "Yes" if ch.regular_change else "No",
                ch.risk_mitigation or "",
                ch.comments or "",
                fmt_dt(ch.raised_datetime),
                fmt_dt(ch.date_created),
                fmt_dt(ch.last_updated),
                ch.last_updated_by or "",
            ]
        )

    from flask import Response

    data = output.getvalue()
    filename = f"changes_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/changes/bulk-update", methods=["POST"])
@login_required
def changes_bulk_update():
    return "Not implemented", 501


@core_bp.route("/saved-filters/save", methods=["POST"])
@login_required
def saved_filters_save():
    return "Not implemented", 501


@core_bp.route("/saved-filters/delete/<int:id>", methods=["POST"])
@login_required
def saved_filters_delete(id: int):
    return "Not implemented", 501


@core_bp.route("/saved-filters/apply/<int:id>")
@login_required
def saved_filters_apply(id: int):
    # Placeholder until we port saved-filter storage. Keep endpoint so templates render.
    return redirect(url_for("changes_list"))


@core_bp.route("/incidents")
@login_required
def incidents_list():
    page = request.args.get("page", 1, type=int)
    search = (request.args.get("search") or "").strip()
    field_filter = (request.args.get("field_filter") or "all").strip()
    criteria = (request.args.get("criteria") or "").strip()
    region = (request.args.get("region") or "").strip()
    year = (request.args.get("year") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    technology = (request.args.get("technology") or "").strip()
    location = (request.args.get("location") or "").strip()
    severity = (request.args.get("severity") or "").strip()

    # Advanced
    incident_number = (request.args.get("incident_number") or "").strip()
    zendesk_number = (request.args.get("zendesk_number") or "").strip()
    verint_number = (request.args.get("verint_number") or "").strip()
    overview = (request.args.get("overview") or "").strip()
    calls_lost_min = request.args.get("calls_lost_min")
    calls_lost_max = request.args.get("calls_lost_max")

    stmt = select(IncidentRecord)

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    if region:
        stmt = stmt.where(IncidentRecord.region == region)
    if technology:
        stmt = stmt.where(IncidentRecord.technology == technology)
    if location:
        stmt = stmt.where(IncidentRecord.location == location)
    if severity:
        stmt = stmt.where(IncidentRecord.severity == severity)

    if year:
        stmt = stmt.where(db.func.strftime("%Y", IncidentRecord.incident_date) == year)

    df = _parse_date(date_from)
    if df:
        stmt = stmt.where(IncidentRecord.incident_date >= df)
    dt = _parse_date(date_to)
    if dt:
        stmt = stmt.where(IncidentRecord.incident_date <= dt + timedelta(days=1) - timedelta(seconds=1))

    min_calls = _parse_int(calls_lost_min)
    max_calls = _parse_int(calls_lost_max)
    if min_calls is not None:
        stmt = stmt.where(IncidentRecord.calls_lost >= min_calls)
    if max_calls is not None:
        stmt = stmt.where(IncidentRecord.calls_lost <= max_calls)

    if incident_number:
        stmt = stmt.where(_contains(IncidentRecord.incident_number, incident_number))
    if zendesk_number:
        stmt = stmt.where(_contains(IncidentRecord.zendesk_number, zendesk_number))
    if verint_number:
        stmt = stmt.where(_contains(IncidentRecord.verint_number, verint_number))
    if overview:
        stmt = stmt.where(_contains(IncidentRecord.overview, overview))

    if search:
        s = search
        stmt = stmt.where(
            or_(
                _contains(IncidentRecord.incident_number, s),
                _contains(IncidentRecord.zendesk_number, s),
                _contains(IncidentRecord.verint_number, s),
                _contains(IncidentRecord.small_title, s),
                _contains(IncidentRecord.overview, s),
                _contains(IncidentRecord.incident_summary, s),
                _contains(IncidentRecord.region, s),
                _contains(IncidentRecord.technology, s),
                _contains(IncidentRecord.location, s),
                _contains(IncidentRecord.severity, s),
            )
        )

    if criteria:
        c = criteria
        if field_filter == "incident_number":
            stmt = stmt.where(_contains(IncidentRecord.incident_number, c))
        elif field_filter == "zendesk_number":
            stmt = stmt.where(_contains(IncidentRecord.zendesk_number, c))
        elif field_filter == "verint_number":
            stmt = stmt.where(_contains(IncidentRecord.verint_number, c))
        elif field_filter == "small_title":
            stmt = stmt.where(_contains(IncidentRecord.small_title, c))
        elif field_filter == "region":
            stmt = stmt.where(_contains(IncidentRecord.region, c))
        elif field_filter == "technology":
            stmt = stmt.where(_contains(IncidentRecord.technology, c))
        elif field_filter == "location":
            stmt = stmt.where(_contains(IncidentRecord.location, c))
        elif field_filter == "severity":
            stmt = stmt.where(_contains(IncidentRecord.severity, c))
        elif field_filter == "overview":
            stmt = stmt.where(_contains(IncidentRecord.overview, c))
        elif field_filter == "incident_summary":
            stmt = stmt.where(_contains(IncidentRecord.incident_summary, c))
        elif field_filter == "rca_link":
            stmt = stmt.where(_contains(IncidentRecord.rca_link, c))
        else:
            stmt = stmt.where(
                or_(
                    _contains(IncidentRecord.incident_number, c),
                    _contains(IncidentRecord.zendesk_number, c),
                    _contains(IncidentRecord.verint_number, c),
                    _contains(IncidentRecord.small_title, c),
                    _contains(IncidentRecord.region, c),
                    _contains(IncidentRecord.technology, c),
                    _contains(IncidentRecord.location, c),
                    _contains(IncidentRecord.severity, c),
                    _contains(IncidentRecord.overview, c),
                    _contains(IncidentRecord.incident_summary, c),
                    _contains(IncidentRecord.rca_link, c),
                )
            )

    stmt = stmt.order_by(IncidentRecord.incident_date.desc().nullslast(), IncidentRecord.id.desc())
    incidents = db.paginate(stmt, page=page, per_page=25, error_out=False)

    opts = _incidents_form_options()
    return render_template(
        "incidents/list.html",
        incidents=incidents,
        search=search,
        field_filter=field_filter,
        criteria=criteria,
        region=region,
        year=year,
        date_from=date_from,
        date_to=date_to,
        technology=technology,
        location=location,
        severity=severity,
        incident_number=incident_number,
        zendesk_number=zendesk_number,
        verint_number=verint_number,
        overview=overview,
        calls_lost_min=calls_lost_min,
        calls_lost_max=calls_lost_max,
        regions=opts["regions"],
        technologies=opts["technologies"],
        locations=opts["locations"],
        severities=opts["severities"],
        years=opts["years"],
        saved_filters=[],
    )


@core_bp.route("/incidents/view/<int:id>")
@login_required
def incidents_view(id: int):
    inc = db.session.get(IncidentRecord, id)
    if not inc:
        abort(404)

    next_url = (request.args.get("next") or "").strip() or url_for("incidents_list")
    return render_template(
        "incidents/view.html",
        inc=inc,
        next_url=next_url,
        custom_fields=[],
        custom_values={},
        audit_entries=[],
    )


@core_bp.route("/incidents/add", methods=["GET", "POST"])
@login_required
def incidents_add():
    if not current_user.can_edit_incidents():
        abort(403)

    next_url = (request.args.get("next") or "").strip() or url_for("incidents_list")
    opts = _incidents_form_options()

    if request.method == "POST":
        form = request.form.to_dict(flat=True)
        incident_number = (form.get("incident_number") or "").strip().upper() or None

        inc = IncidentRecord(
            incident_number=incident_number,
            zendesk_number=(form.get("zendesk_number") or "").strip() or None,
            verint_number=(form.get("verint_number") or "").strip() or None,
            small_title=(form.get("small_title") or "").strip() or None,
            region=(form.get("region") or "").strip() or None,
            incident_date=_parse_date((form.get("incident_date") or "").strip() or None),
            incident_time=(form.get("incident_time") or "").strip() or None,
            technology=(form.get("technology") or "").strip() or None,
            location=(form.get("location") or "").strip() or None,
            severity=(form.get("severity") or "").strip() or None,
            calls_lost=_parse_int(form.get("calls_lost")),
            overview=(form.get("overview") or "").strip() or None,
            incident_summary=(form.get("incident_summary") or "").strip() or None,
            rca_link=(form.get("rca_link") or "").strip() or None,
            date_created=datetime.utcnow(),
            last_updated=datetime.utcnow(),
            last_updated_by=_current_username(),
        )
        db.session.add(inc)
        db.session.commit()
        flash("Incident created", "success")
        return redirect(url_for("incidents_view", id=inc.id, next=next_url))

    return render_template(
        "incidents/add.html",
        next_url=next_url,
        regions=opts["regions"],
        technologies=opts["technologies"],
        locations=opts["locations"],
        severities=opts["severities"],
        custom_fields=[],
        custom_values={},
    )


@core_bp.route("/incidents/edit/<int:id>", methods=["GET", "POST"])
@login_required
def incidents_edit(id: int):
    if not current_user.can_edit_incidents():
        abort(403)

    inc = db.session.get(IncidentRecord, id)
    if not inc:
        abort(404)

    next_url = (request.args.get("next") or "").strip() or url_for("incidents_view", id=id)
    opts = _incidents_form_options()

    if request.method == "POST":
        form = request.form.to_dict(flat=True)
        inc.incident_number = (form.get("incident_number") or "").strip().upper() or None
        inc.zendesk_number = (form.get("zendesk_number") or "").strip() or None
        inc.verint_number = (form.get("verint_number") or "").strip() or None
        inc.small_title = (form.get("small_title") or "").strip() or None
        inc.region = (form.get("region") or "").strip() or None
        inc.incident_date = _parse_date((form.get("incident_date") or "").strip() or None)
        inc.incident_time = (form.get("incident_time") or "").strip() or None
        inc.technology = (form.get("technology") or "").strip() or None
        inc.location = (form.get("location") or "").strip() or None
        inc.severity = (form.get("severity") or "").strip() or None
        inc.calls_lost = _parse_int(form.get("calls_lost"))
        inc.overview = (form.get("overview") or "").strip() or None
        inc.incident_summary = (form.get("incident_summary") or "").strip() or None
        inc.rca_link = (form.get("rca_link") or "").strip() or None

        inc.last_updated = datetime.utcnow()
        inc.last_updated_by = _current_username()
        db.session.commit()
        flash("Incident updated", "success")
        return redirect(next_url)

    return render_template(
        "incidents/edit.html",
        inc=inc,
        next_url=next_url,
        regions=opts["regions"],
        technologies=opts["technologies"],
        locations=opts["locations"],
        severities=opts["severities"],
        custom_fields=[],
        custom_values={},
        audit_entries=[],
    )


@core_bp.route("/incidents/import", methods=["GET", "POST"])
@login_required
def incidents_import():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        if request.form.get("mapping_confirmed") == "1":
            text = _hidden_to_csv_text(request.form.get("csv_data") or "")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                flash("CSV has no header row", "danger")
                return render_template("incidents/import.html"), 400

            mapping: dict[str, str] = {}
            for k, v in request.form.items():
                if k.startswith("map__"):
                    field_key = k[len("map__") :]
                    if v:
                        mapping[field_key] = v

            inc_col = mapping.get("incident_number")
            if not inc_col:
                flash("Incident Number must be mapped", "danger")
                return redirect(url_for("incidents_import"))

            def pick(row: dict, key: str) -> str | None:
                col = mapping.get(key)
                if not col:
                    return None
                val = row.get(col)
                if val is None:
                    return None
                s = str(val).strip()
                return s if s != "" else None

            now = datetime.utcnow()
            updated = 0
            created = 0

            for row in reader:
                inc_no = (pick(row, "incident_number") or "").strip().upper()
                if not inc_no:
                    continue

                rec = IncidentRecord.query.filter(IncidentRecord.incident_number == inc_no).first()
                is_new = rec is None
                if is_new:
                    rec = IncidentRecord(incident_number=inc_no, date_created=now)
                    db.session.add(rec)

                rec.zendesk_number = pick(row, "zendesk_number") or rec.zendesk_number
                rec.verint_number = pick(row, "verint_number") or rec.verint_number
                rec.small_title = pick(row, "small_title") or rec.small_title
                rec.region = pick(row, "region") or rec.region
                rec.technology = pick(row, "technology") or rec.technology
                rec.location = pick(row, "location") or rec.location
                rec.severity = pick(row, "severity") or rec.severity
                rec.overview = pick(row, "overview") or rec.overview
                rec.incident_summary = pick(row, "incident_summary") or rec.incident_summary
                rec.rca_link = pick(row, "rca_link") or rec.rca_link
                rec.incident_time = pick(row, "incident_time") or rec.incident_time

                d_raw = pick(row, "incident_date")
                if d_raw:
                    rec.incident_date = _parse_any_date(d_raw)

                calls_raw = pick(row, "calls_lost")
                if calls_raw is not None:
                    rec.calls_lost = _parse_int(calls_raw)

                rec.last_updated = now
                rec.last_updated_by = _current_username()

                if is_new:
                    created += 1
                else:
                    updated += 1

            db.session.commit()
            flash(f"Import complete. Created {created}, updated {updated}.", "success")
            return redirect(url_for("incidents_list"))

        f = request.files.get("file")
        if not f:
            flash("No file uploaded", "danger")
            return render_template("incidents/import.html")

        text = _read_upload_text(f)
        csv_headers, preview_rows = _csv_preview(text)
        if not csv_headers:
            flash("CSV has no header row", "danger")
            return render_template("incidents/import.html"), 400

        target_fields = [
            {"key": "incident_number", "label": "Incident Number", "required": True},
            {"key": "zendesk_number", "label": "Zendesk Number", "required": False},
            {"key": "verint_number", "label": "Verint Number", "required": False},
            {"key": "small_title", "label": "Small Title", "required": False},
            {"key": "region", "label": "Region", "required": False},
            {"key": "incident_date", "label": "Incident Date", "required": False},
            {"key": "incident_time", "label": "Incident Time", "required": False},
            {"key": "technology", "label": "Technology", "required": False},
            {"key": "location", "label": "Location", "required": False},
            {"key": "severity", "label": "Severity", "required": False},
            {"key": "calls_lost", "label": "Calls Lost", "required": False},
            {"key": "overview", "label": "Overview", "required": False},
            {"key": "incident_summary", "label": "Incident Summary", "required": False},
            {"key": "rca_link", "label": "RCA Link", "required": False},
        ]
        synonyms = {
            "incident_number": ["incident_number", "Incident#", "Incident", "inc"],
            "zendesk_number": ["zendesk_number", "ZenDesk#", "zendesk"],
            "verint_number": ["verint_number", "Verint", "verint"],
            "small_title": ["small_title", "Small Title", "title"],
            "region": ["region", "Region"],
            "incident_date": ["incident_date", "Date"],
            "incident_time": ["incident_time", "Time"],
            "technology": ["technology", "Technology"],
            "location": ["location", "Location"],
            "severity": ["severity", "Severity"],
            "calls_lost": ["calls_lost", "Calls Lost", "CallsLost"],
            "overview": ["overview", "Overview"],
            "incident_summary": ["incident_summary", "Incident Summary", "Summary"],
            "rca_link": ["rca_link", "RCA Link"],
        }
        suggestions = _suggest_mapping(csv_headers, synonyms)

        return render_template(
            "import_map.html",
            title="Map Incidents CSV Fields",
            help_text="Map the columns from your CSV file to the incident fields.",
            csv_data=_csv_text_to_hidden(text),
            csv_headers=csv_headers,
            target_fields=target_fields,
            suggestions=suggestions,
            preview_headers=csv_headers,
            preview_rows=preview_rows,
            cancel_url=url_for("incidents_list"),
        )

    return render_template("incidents/import.html")


@core_bp.route("/incidents/export")
@login_required
def incidents_export():
    stmt = select(IncidentRecord).order_by(IncidentRecord.id.asc())
    rows = db.session.execute(stmt).scalars().all()

    output = io.StringIO()
    w = csv.writer(output)
    headers = [
        "id",
        "incident_number",
        "zendesk_number",
        "verint_number",
        "small_title",
        "region",
        "incident_date",
        "incident_time",
        "technology",
        "location",
        "severity",
        "calls_lost",
        "overview",
        "incident_summary",
        "rca_link",
        "date_created",
        "last_updated",
        "last_updated_by",
    ]
    w.writerow(headers)

    def fmt_dt(d: datetime | None) -> str:
        return d.strftime("%Y-%m-%d %H:%M:%S") if d else ""

    for r in rows:
        w.writerow(
            [
                r.id,
                r.incident_number or "",
                r.zendesk_number or "",
                r.verint_number or "",
                r.small_title or "",
                r.region or "",
                r.incident_date.strftime("%Y-%m-%d") if r.incident_date else "",
                r.incident_time or "",
                r.technology or "",
                r.location or "",
                r.severity or "",
                "" if r.calls_lost is None else r.calls_lost,
                r.overview or "",
                r.incident_summary or "",
                r.rca_link or "",
                fmt_dt(r.date_created),
                fmt_dt(r.last_updated),
                r.last_updated_by or "",
            ]
        )

    from flask import Response

    data = output.getvalue()
    filename = f"incidents_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/incidents/bulk-update", methods=["POST"])
@login_required
def incidents_bulk_update():
    if not current_user.is_admin():
        abort(403)

    ids = request.form.getlist("ids")
    bulk_field = (request.form.get("bulk_field") or "").strip()
    bulk_value = (request.form.get("bulk_value") or "").strip()
    next_url = (request.form.get("next") or "").strip() or url_for("incidents_list")

    allowed = {"region", "technology", "severity", "location"}
    if bulk_field not in allowed:
        abort(400)

    now = datetime.utcnow()
    updated = 0
    for v in ids:
        try:
            rid = int(v)
        except ValueError:
            continue
        rec = db.session.get(IncidentRecord, rid)
        if not rec:
            continue
        setattr(rec, bulk_field, bulk_value)
        rec.last_updated = now
        rec.last_updated_by = _current_username()
        updated += 1

    db.session.commit()
    flash(f"Updated {updated} incident(s)", "success")
    return redirect(next_url)


@core_bp.route("/calendar")
@login_required
def calendar_view():
    regions = _lookup_values("region")
    if not regions:
        regions = ["Global", "EMEA", "APAC", "Americas"]

    return render_template("calendar.html", regions=regions, saved_filters=[])


@core_bp.route("/calendar/events")
@login_required
def calendar_events():
    start = (request.args.get("start") or "").strip() or None
    end = (request.args.get("end") or "").strip() or None
    sources = request.args.getlist("source") or ["changes", "incidents"]
    regions = request.args.getlist("region")
    field_filter = (request.args.get("field_filter") or "all").strip()
    criteria = (request.args.get("criteria") or "").strip()
    return_to = (request.args.get("return_to") or "").strip() or url_for("calendar_view")

    start_dt = _parse_any_date(start) if start else None
    end_dt = _parse_any_date(end) if end else None

    def _contains(col, val: str):
        return col.ilike(f"%{val}%")

    events: list[dict] = []

    if "changes" in sources:
        stmt = select(ChangeRecord)
        if regions:
            stmt = stmt.where(ChangeRecord.region.in_(regions))
        if start_dt:
            stmt = stmt.where(or_(ChangeRecord.start_date.is_(None), ChangeRecord.start_date >= start_dt))
        if end_dt:
            stmt = stmt.where(or_(ChangeRecord.start_date.is_(None), ChangeRecord.start_date <= end_dt))

        if criteria:
            if field_filter == "chg:title":
                stmt = stmt.where(_contains(ChangeRecord.title, criteria))
            elif field_filter == "chg:cr_number":
                stmt = stmt.where(_contains(ChangeRecord.cr_number, criteria))
            elif field_filter == "chg:technology":
                stmt = stmt.where(_contains(ChangeRecord.technology, criteria))
            elif field_filter == "chg:snow_link":
                stmt = stmt.where(_contains(ChangeRecord.snow_link, criteria))
            elif field_filter == "chg:raised_by":
                stmt = stmt.where(_contains(ChangeRecord.raised_by, criteria))
            elif field_filter == "chg:tech_lead":
                stmt = stmt.where(_contains(ChangeRecord.tech_lead, criteria))
            elif field_filter == "chg:comments":
                stmt = stmt.where(_contains(ChangeRecord.comments, criteria))

        rows = db.session.execute(stmt.order_by(ChangeRecord.start_date.desc().nullslast(), ChangeRecord.id.desc())).scalars().all()
        for ch in rows:
            d = ch.start_date or ch.cab_date or ch.raised_datetime
            if not d:
                continue
            events.append(
                {
                    "id": f"chg-{ch.id}",
                    "title": f"{(ch.cr_number or '').strip()} {((ch.title or '').strip())}".strip() or f"Change {ch.id}",
                    "start": d.date().isoformat(),
                    "url": url_for("changes_view", id=ch.id, next=return_to),
                    "backgroundColor": "#0d6efd",
                    "borderColor": "#0d6efd",
                    "extendedProps": {
                        "type": "changes",
                        "region": ch.region,
                        "technology": ch.technology,
                    },
                }
            )

    if "incidents" in sources:
        stmt = select(IncidentRecord)
        if regions:
            stmt = stmt.where(IncidentRecord.region.in_(regions))
        if start_dt:
            stmt = stmt.where(or_(IncidentRecord.incident_date.is_(None), IncidentRecord.incident_date >= start_dt))
        if end_dt:
            stmt = stmt.where(or_(IncidentRecord.incident_date.is_(None), IncidentRecord.incident_date <= end_dt))

        if criteria:
            if field_filter == "inc:incident_number":
                stmt = stmt.where(_contains(IncidentRecord.incident_number, criteria))
            elif field_filter == "inc:zendesk_number":
                stmt = stmt.where(_contains(IncidentRecord.zendesk_number, criteria))
            elif field_filter == "inc:verint_number":
                stmt = stmt.where(_contains(IncidentRecord.verint_number, criteria))
            elif field_filter == "inc:small_title":
                stmt = stmt.where(_contains(IncidentRecord.small_title, criteria))
            elif field_filter == "inc:technology":
                stmt = stmt.where(_contains(IncidentRecord.technology, criteria))
            elif field_filter == "inc:location":
                stmt = stmt.where(_contains(IncidentRecord.location, criteria))
            elif field_filter == "inc:overview":
                stmt = stmt.where(_contains(IncidentRecord.overview, criteria))

        rows = db.session.execute(stmt.order_by(IncidentRecord.incident_date.desc().nullslast(), IncidentRecord.id.desc())).scalars().all()
        for inc in rows:
            if not inc.incident_date:
                continue
            events.append(
                {
                    "id": f"inc-{inc.id}",
                    "title": f"{(inc.incident_number or '').strip()} {((inc.small_title or '').strip())}".strip() or f"Incident {inc.id}",
                    "start": inc.incident_date.date().isoformat(),
                    "url": url_for("incidents_view", id=inc.id, next=return_to),
                    "backgroundColor": "#dc3545",
                    "borderColor": "#dc3545",
                    "extendedProps": {
                        "type": "incidents",
                        "region": inc.region,
                        "technology": inc.technology,
                    },
                }
            )

    return jsonify(events)


@core_bp.route("/admin/users")
@login_required
def manage_users():
    if not current_user.is_admin():
        abort(403)

    users = db.session.execute(select(User).order_by(User.username.asc(), User.id.asc())).scalars().all()
    return render_template("admin/users.html", users=users)


@core_bp.route("/admin/users/<int:user_id>/toggle-turret-move-approver", methods=["POST"])
@login_required
def toggle_turret_move_approver(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_approve_turret_moves = not bool(getattr(u, "can_approve_turret_moves", False))
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-turret-move-executor", methods=["POST"])
@login_required
def toggle_turret_move_executor(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_execute_turret_moves = not bool(getattr(u, "can_execute_turret_moves", False))
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-turret-move-import", methods=["POST"])
@login_required
def toggle_turret_move_import(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_import_turret_moves = not bool(getattr(u, "can_import_turret_moves", False))
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-turret-move-export", methods=["POST"])
@login_required
def toggle_turret_move_export(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_export_turret_moves = not bool(getattr(u, "can_export_turret_moves", False))
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-private-wire-import", methods=["POST"])
@login_required
def toggle_private_wire_import(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_import_private_wires = not bool(getattr(u, "can_import_private_wires", False))
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-private-wire-export", methods=["POST"])
@login_required
def toggle_private_wire_export(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_export_private_wires = not bool(getattr(u, "can_export_private_wires", False))
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/add", methods=["GET", "POST"])
@login_required
def add_user():
    if not current_user.is_admin():
        abort(403)

    if request.method == "POST":
        from werkzeug.security import generate_password_hash

        username = (request.form.get("username") or "").strip()
        name = (request.form.get("name") or "").strip() or None
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "user").strip() or "user"
        role = role.lower()
        if role == "editor":
            role = "change_user"
        allowed_roles = {"user", "change_user", "admin"}
        if role not in allowed_roles:
            flash("Invalid role.", "danger")
            return redirect(url_for("add_user"))
        must_change_password = bool(request.form.get("must_change_password"))

        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template("admin/add_user.html")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return render_template("admin/add_user.html")

        u = User(
            username=username,
            name=name,
            password=generate_password_hash(password),
            role=role,
            is_active=True,
            must_change_password=must_change_password,
            last_activity=datetime.utcnow(),
        )
        db.session.add(u)
        db.session.commit()
        flash("User created", "success")
        return redirect(url_for("manage_users"))

    return render_template("admin/add_user.html")


@core_bp.route("/admin/users/<int:user_id>/toggle-change-approver", methods=["POST"])
@login_required
def toggle_change_approver(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_approve_changes = not bool(u.can_approve_changes)
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-regional-approver", methods=["POST"])
@login_required
def toggle_regional_approver(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_provide_regional_approval = not bool(u.can_provide_regional_approval)
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/toggle-global-service-approver", methods=["POST"])
@login_required
def toggle_global_service_approver(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.can_approve_global_service = not bool(u.can_approve_global_service)
    db.session.commit()
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/update", methods=["POST"])
@login_required
def update_user(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.name = (request.form.get("name") or "").strip() or None
    db.session.commit()
    flash("User updated", "success")
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
def reset_user_password(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)

    new_password = (request.form.get("new_password") or "").strip()
    confirm_password = (request.form.get("confirm_password") or "").strip()
    if not new_password or new_password != confirm_password:
        flash("Passwords do not match", "danger")
        return redirect(url_for("manage_users"))

    from werkzeug.security import generate_password_hash

    u.password = generate_password_hash(new_password)
    u.must_change_password = True
    db.session.commit()
    flash("Password reset", "success")
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@login_required
def disable_user(user_id: int):
    if not current_user.is_admin():
        abort(403)
    if current_user.id == user_id:
        flash("You cannot disable yourself", "warning")
        return redirect(url_for("manage_users"))

    u = db.session.get(User, user_id)
    if not u:
        abort(404)

    u.is_active = False
    u.disabled_date = datetime.utcnow()
    u.disabled_by = _current_username()
    u.disable_reason = (request.form.get("disable_reason") or "").strip() or None
    db.session.commit()
    flash("User disabled", "success")
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/enable", methods=["POST"])
@login_required
def enable_user(user_id: int):
    if not current_user.is_admin():
        abort(403)
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    u.is_active = True
    u.disabled_date = None
    u.disabled_by = None
    u.disable_reason = None
    db.session.commit()
    flash("User enabled", "success")
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id: int):
    if not current_user.is_admin():
        abort(403)
    if current_user.id == user_id:
        flash("You cannot delete yourself", "warning")
        return redirect(url_for("manage_users"))

    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    db.session.delete(u)
    db.session.commit()
    flash("User deleted", "success")
    return redirect(url_for("manage_users"))


@core_bp.route("/admin/backups")
@login_required
def admin_backups():
    if not current_user.is_admin():
        abort(403)

    settings = _get_backup_settings()
    settings["live_db_path"] = get_configured_db_path() or ""
    settings["active_db_path"] = _db_path_from_uri()
    settings["env_db_path"] = os.environ.get("TELEPHONY_DB_PATH") or ""
    backups_dir = settings["backup_dir"]
    os.makedirs(backups_dir, exist_ok=True)

    backups = []
    try:
        for name in os.listdir(backups_dir):
            if not name.lower().endswith(".db"):
                continue
            path = os.path.join(backups_dir, name)
            try:
                st = os.stat(path)
                backups.append(
                    {
                        "name": name,
                        "path": path,
                        "size": st.st_size,
                        "size_human": _human_size(st.st_size),
                        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "mtime_ts": st.st_mtime,
                    }
                )
            except Exception:
                continue
        backups.sort(key=lambda x: x["mtime_ts"], reverse=True)
    except Exception:
        pass

    return render_template("admin/backups.html", settings=settings, backups=backups)


@core_bp.route("/admin/backup")
@login_required
def backup_database():
    if not current_user.is_admin():
        abort(403)

    db_path = _db_path_from_uri()
    backup_filename = f"telephony_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"

    try:
        tmp = tempfile.NamedTemporaryFile(prefix="telephony_backup_", suffix=".db", delete=False)
        tmp_path = tmp.name
        tmp.close()

        _sqlite_backup(db_path, tmp_path)

        @after_this_request
        def _cleanup(resp):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return resp

        return send_file(
            tmp_path,
            as_attachment=True,
            download_name=backup_filename,
            mimetype="application/octet-stream",
        )
    except Exception as e:
        flash(f"Error creating database backup: {str(e)}", "danger")
        return redirect(url_for("admin_backups"))


@core_bp.route("/admin/backups/db-test", methods=["POST"])
@login_required
def admin_backups_db_test():
    if not current_user.is_admin():
        abort(403)

    raw = (request.form.get("live_db_path") or "").strip()
    if not raw:
        raw = get_configured_db_path() or ""
    if not raw:
        flash("No live database path configured.", "warning")
        return redirect(url_for("admin_backups"))

    try:
        path = os.path.abspath(raw)
        if not path.lower().endswith(".db"):
            raise ValueError("Path must end with .db")

        if not os.path.exists(path):
            flash("Database file does not exist at that path.", "warning")
            return redirect(url_for("admin_backups"))

        conn = sqlite3.connect(path, timeout=5, check_same_thread=False)
        try:
            conn.execute("PRAGMA schema_version")
        finally:
            conn.close()

        flash("Database path test succeeded.", "success")
    except Exception as e:
        flash(f"Database path test failed: {str(e)}", "danger")
    return redirect(url_for("admin_backups"))


@core_bp.route("/admin/restore", methods=["GET", "POST"])
@login_required
def restore_database():
    if not current_user.is_admin():
        abort(403)

    if request.method == "GET":
        return render_template("admin/restore_database.html")

    try:
        users_only = (request.form.get("users_only") or "").strip() in {"1", "true", "yes", "on"}
        safe_restore = (request.form.get("safe_restore") or "").strip() in {"1", "true", "yes", "on"}
        force_restore = (request.form.get("force_restore") or "").strip() in {"1", "true", "yes", "on"}
        if "file" not in request.files:
            flash("No file provided.", "danger")
            return redirect(url_for("restore_database"))

        f = request.files["file"]
        if not f or not f.filename:
            flash("No file selected.", "danger")
            return redirect(url_for("restore_database"))

        filename = (f.filename or "").strip()
        if not filename.lower().endswith(".db"):
            flash("Please upload a .db SQLite backup file.", "danger")
            return redirect(url_for("restore_database"))

        tmp = tempfile.NamedTemporaryFile(prefix="telephony_restore_", suffix=".db", delete=False)
        tmp_path = tmp.name
        tmp.close()
        f.save(tmp_path)

        issues: list[str] = []
        if not force_restore:
            issues = _preflight_db_restore(tmp_path, users_only=users_only, safe_restore=safe_restore)
            if issues:
                try:
                    current_app.logger.warning(
                        "Restore preflight failed users_only=%s safe_restore=%s file=%s issues=%s",
                        users_only,
                        safe_restore,
                        filename,
                        " | ".join(issues),
                    )
                except Exception:
                    pass

                # Users-only restore must have a compatible user table.
                if users_only:
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                    flash("Restore blocked: uploaded DB failed validation.", "danger")
                    for msg in issues[:8]:
                        flash(msg, "warning")
                    return redirect(url_for("restore_database"))

                # Full overwrite restore must pass validation (unless forced).
                if not safe_restore:
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                    flash("Restore blocked: uploaded DB failed validation.", "danger")
                    for msg in issues[:8]:
                        flash(msg, "warning")
                    return redirect(url_for("restore_database"))

                # Safe restore can proceed even with missing tables/columns (it will skip them),
                # but integrity_check issues are still shown.
                flash("Safe restore warning: uploaded DB reported validation issues. Incompatible tables will be skipped.", "warning")
                for msg in issues[:5]:
                    flash(msg, "warning")
            else:
                try:
                    current_app.logger.info(
                        "Restore preflight passed users_only=%s safe_restore=%s file=%s",
                        users_only,
                        safe_restore,
                        filename,
                    )
                except Exception:
                    pass

        if safe_restore and (not users_only):
            live_path = _db_path_from_uri()
            from .migrate import ensure_schema

            ensure_schema(db.engine)

            restored: list[str] = []
            skipped: list[str] = []

            # Some older backups used different table names. Map destination table -> possible source table names.
            legacy_src_tables: dict[str, list[str]] = {
                "lookup_option": ["lookup_options", "lookup", "dropdown_option", "drop_down_option"],
            }

            # Only restore these known tables. Anything else is ignored by design.
            allow_tables = [
                "user",
                "lookup_option",
                "app_setting",
                "custom_field_def",
                "custom_field_value",
                "import_mapping_template",
                "cab_lock",
                "ddi_number",
                "server",
                "ceased_server",
                "private_wire",
                "ceased_private_wire",
                "dealerboard_turret",
                "ceased_rma_turret",
                "change_record",
                "incident_record",
                "turret_move_group",
                "turret_move",
                "turret_move_history",
            ]

            dest = sqlite3.connect(live_path, timeout=60, check_same_thread=False)
            try:
                dest.row_factory = sqlite3.Row
                dest.execute("PRAGMA foreign_keys=OFF")
                dest.execute("PRAGMA journal_mode=WAL")

                # ATTACH does not reliably support parameter binding in all SQLite builds.
                attach_path = os.path.abspath(tmp_path).replace("'", "''")
                dest.execute(f"ATTACH DATABASE '{attach_path}' AS srcdb")
                try:
                    src_tables = {
                        r["name"]
                        for r in dest.execute("SELECT name FROM srcdb.sqlite_master WHERE type='table'").fetchall()
                    }
                    dest_tables = {
                        r["name"]
                        for r in dest.execute("SELECT name FROM main.sqlite_master WHERE type='table'").fetchall()
                    }

                    for t in allow_tables:
                        if t not in dest_tables:
                            skipped.append(f"{t} (not in live DB)")
                            continue

                        src_t = t
                        if t not in src_tables:
                            # Try legacy source table names if present.
                            candidates = legacy_src_tables.get(t, [])
                            found = next((c for c in candidates if c in src_tables), None)
                            if not found:
                                skipped.append(f"{t} (not in backup DB)")
                                continue
                            src_t = found

                        try:
                            src_cols = {r["name"] for r in dest.execute(f"PRAGMA srcdb.table_info('{src_t}')").fetchall()}
                            dst_cols = {r["name"] for r in dest.execute(f"PRAGMA main.table_info('{t}')").fetchall()}
                            common = [c for c in src_cols.intersection(dst_cols) if c != "id"]

                            # Keep id if both sides have it (helps preserve references). We delete table first.
                            if "id" in src_cols and "id" in dst_cols:
                                common = ["id"] + sorted(common)
                            else:
                                common = sorted(common)

                            if not common:
                                skipped.append(f"{t} (no common columns)")
                                continue

                            cols_sql = ", ".join([f"'{c}'" for c in common])
                            select_sql = ", ".join([f"{c}" for c in common])

                            dest.execute("BEGIN")
                            try:
                                dest.execute(f"DELETE FROM main.'{t}'")
                                dest.execute(
                                    f"INSERT INTO main.'{t}' ({cols_sql}) SELECT {select_sql} FROM srcdb.'{src_t}'"
                                )
                                dest.execute("COMMIT")
                                restored.append(t if src_t == t else f"{t}(from {src_t})")
                            except Exception as e:
                                try:
                                    dest.execute("ROLLBACK")
                                except Exception:
                                    pass
                                skipped.append(f"{t} ({e})")
                        except Exception as e:
                            skipped.append(f"{t} ({e})")

                    # Legacy compatibility: old DBs stored definitions in custom_field_definition.
                    if "custom_field_def" in dest_tables and "custom_field_definition" in src_tables:
                        try:
                            src_cols = {
                                r["name"]
                                for r in dest.execute("PRAGMA srcdb.table_info('custom_field_definition')").fetchall()
                            }
                            dst_cols = {r["name"] for r in dest.execute("PRAGMA main.table_info('custom_field_def')").fetchall()}
                            common = sorted([c for c in src_cols.intersection(dst_cols)])
                            if common:
                                cols_sql = ", ".join([f"'{c}'" for c in common])
                                select_sql = ", ".join([f"{c}" for c in common])
                                dest.execute("BEGIN")
                                try:
                                    dest.execute("DELETE FROM main.'custom_field_def'")
                                    dest.execute(
                                        f"INSERT INTO main.'custom_field_def' ({cols_sql}) SELECT {select_sql} FROM srcdb.'custom_field_definition'"
                                    )
                                    dest.execute("COMMIT")
                                    restored.append("custom_field_def(from custom_field_definition)")
                                except Exception as e:
                                    try:
                                        dest.execute("ROLLBACK")
                                    except Exception:
                                        pass
                                    skipped.append(f"custom_field_definition->custom_field_def ({e})")
                        except Exception as e:
                            skipped.append(f"custom_field_definition->custom_field_def ({e})")
                finally:
                    try:
                        dest.execute("DETACH DATABASE srcdb")
                    except Exception:
                        pass
            finally:
                try:
                    dest.execute("PRAGMA foreign_keys=ON")
                except Exception:
                    pass
                dest.close()
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

            try:
                db.session.close()
            except Exception:
                pass
            try:
                db.engine.dispose()
            except Exception:
                pass

            try:
                current_app.logger.info(
                    "Safe restore complete restored=%s skipped=%s file=%s",
                    ",".join(restored),
                    " | ".join(skipped[:30]),
                    filename,
                )
            except Exception:
                pass

            flash(f"Safe restore complete. Restored {len(restored)} table(s); skipped {len(skipped)}.", "success")
            if skipped:
                for msg in skipped[:8]:
                    flash(f"Skipped: {msg}", "warning")
            return redirect(url_for("admin_database"))

        if users_only:
            live_path = _db_path_from_uri()
            src = sqlite3.connect(tmp_path, timeout=30, check_same_thread=False)
            try:
                src.row_factory = sqlite3.Row
                src_cols = {r["name"] for r in src.execute("PRAGMA table_info(user)").fetchall()}
                if "username" not in src_cols or "password" not in src_cols:
                    raise ValueError("Uploaded DB does not contain a compatible user table")

                rows = src.execute("SELECT * FROM user").fetchall()
            finally:
                src.close()
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

            from .migrate import ensure_schema

            ensure_schema(db.engine)

            dest = sqlite3.connect(live_path, timeout=30, check_same_thread=False)
            try:
                dest.row_factory = sqlite3.Row
                dest_cols = {r["name"] for r in dest.execute("PRAGMA table_info(user)").fetchall()}

                common_cols = [c for c in rows[0].keys()] if rows else []
                common_cols = [c for c in common_cols if c in dest_cols and c != "id"]
                if not common_cols:
                    flash("No compatible user columns found to restore.", "warning")
                    return redirect(url_for("admin_database"))

                restored_users = 0
                for r in rows:
                    username = (r["username"] or "").strip() if "username" in r.keys() else ""
                    if not username:
                        continue

                    vals = {c: r[c] for c in common_cols}
                    existing = dest.execute("SELECT id FROM user WHERE username = ? LIMIT 1", (username,)).fetchone()
                    if existing:
                        set_clause = ", ".join([f"{c} = ?" for c in common_cols if c != "username"])
                        params = [vals[c] for c in common_cols if c != "username"] + [username]
                        if set_clause:
                            dest.execute(f"UPDATE user SET {set_clause} WHERE username = ?", params)
                        restored_users += 1
                    else:
                        cols = ", ".join(common_cols)
                        placeholders = ", ".join(["?"] * len(common_cols))
                        params = [vals[c] for c in common_cols]
                        dest.execute(f"INSERT INTO user ({cols}) VALUES ({placeholders})", params)
                        restored_users += 1

                dest.commit()
            finally:
                dest.close()

            try:
                db.session.close()
            except Exception:
                pass
            try:
                db.engine.dispose()
            except Exception:
                pass

            flash(f"Users restored successfully. Updated/created {restored_users} user(s).", "success")
            return redirect(url_for("admin_database"))

        db.session.close()
        try:
            db.engine.dispose()
        except Exception:
            pass

        live_path = _db_path_from_uri()
        src = sqlite3.connect(tmp_path, timeout=30, check_same_thread=False)
        try:
            dest = sqlite3.connect(live_path, timeout=30, check_same_thread=False)
            try:
                src.backup(dest)
            finally:
                dest.close()
        finally:
            src.close()
            try:
                os.remove(tmp_path)
            except Exception:
                pass

        try:
            from .migrate import ensure_schema

            ensure_schema(db.engine)
        except Exception:
            pass

        try:
            db.session.close()
        except Exception:
            pass
        try:
            db.engine.dispose()
        except Exception:
            pass

        flash("Database restored successfully.", "success")
        return redirect(url_for("admin_database"))
    except Exception as e:
        flash(f"Error restoring database: {str(e)}", "danger")
        return redirect(url_for("restore_database"))


@core_bp.route("/admin/database")
@login_required
def admin_database():
    if not current_user.is_admin():
        abort(403)

    tables = _dbadmin_allowed_tables()
    table_meta = []
    db_path = _db_path_from_uri()
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        for t in tables:
            try:
                cur.execute(f"SELECT COUNT(*) FROM '{t}'")
                c = cur.fetchone()[0]
            except Exception:
                c = None
            table_meta.append({"name": t, "count": c})
    finally:
        conn.close()

    return render_template("admin/database.html", tables=table_meta)


@core_bp.route("/admin/database/<table>")
@login_required
def admin_table_view(table: str):
    if not current_user.is_admin():
        abort(403)
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = max(10, min(per_page, 200))
    search = request.args.get("search", "")

    info = _sqlite_table_info(table)
    columns = [r["name"] for r in info]
    pk = _sqlite_pk_column(table)

    where = ""
    params: list = []
    if search:
        text_cols = [
            r["name"]
            for r in info
            if (r.get("type") or "").upper().startswith(("CHAR", "TEXT", "VARCHAR"))
        ]
        if text_cols:
            where = " WHERE " + " OR ".join([f"{c} LIKE ?" for c in text_cols])
            params = [f"%{search}%"] * len(text_cols)

    offset = (page - 1) * per_page
    with _sqlite_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM {table}{where}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT rowid AS _rowid_, * FROM {table}{where} ORDER BY rowid DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

    pages = (total + per_page - 1) // per_page
    return render_template(
        "admin/table_view.html",
        table=table,
        columns=columns,
        pk=pk,
        rows=rows,
        page=page,
        pages=pages,
        per_page=per_page,
        total=total,
        search=search,
    )


@core_bp.route("/admin/database/<table>/spreadsheet")
@login_required
def admin_table_spreadsheet(table: str):
    if not current_user.is_admin():
        abort(403)
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    per_page = max(10, min(per_page, 500))
    search = request.args.get("search", "")

    info = _sqlite_table_info(table)
    columns = [r["name"] for r in info]
    pk = _sqlite_pk_column(table)

    where = ""
    params: list = []
    if search:
        text_cols = [
            r["name"]
            for r in info
            if (r.get("type") or "").upper().startswith(("CHAR", "TEXT", "VARCHAR"))
        ]
        if text_cols:
            where = " WHERE " + " OR ".join([f"{c} LIKE ?" for c in text_cols])
            params = [f"%{search}%"] * len(text_cols)

    offset = (page - 1) * per_page
    with _sqlite_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM {table}{where}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT rowid AS _rowid_, * FROM {table}{where} ORDER BY rowid DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

    pages = (total + per_page - 1) // per_page
    return render_template(
        "admin/table_spreadsheet.html",
        table=table,
        columns=columns,
        pk=pk,
        rows=rows,
        page=page,
        pages=pages,
        per_page=per_page,
        total=total,
        search=search,
        column_info=info,
    )


@core_bp.route("/admin/database/<table>/edit/<int:rowid>", methods=["GET", "POST"])
@login_required
def admin_edit_record(table: str, rowid: int):
    if not current_user.is_admin():
        abort(403)
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))

    info = _sqlite_table_info(table)
    columns = [r["name"] for r in info]

    with _sqlite_conn() as conn:
        row = conn.execute(f"SELECT rowid AS _rowid_, * FROM {table} WHERE rowid = ?", (rowid,)).fetchone()
        if not row:
            flash("Record not found.", "danger")
            return redirect(url_for("admin_table_view", table=table))

        if request.method == "POST":
            updates = []
            params = []
            for c in columns:
                v = request.form.get(c, "")
                if v == "":
                    updates.append(f"{c} = NULL")
                else:
                    updates.append(f"{c} = ?")
                    params.append(v)
            sql = f"UPDATE {table} SET {', '.join(updates)} WHERE rowid = ?"
            conn.execute(sql, params + [rowid])
            conn.commit()
            flash("Record updated.", "success")
            return redirect(url_for("admin_table_view", table=table))

    return render_template("admin/edit_record.html", table=table, columns=columns, row=row)


@core_bp.route("/admin/database/<table>/delete/<int:rowid>", methods=["POST"])
@login_required
def admin_delete_record(table: str, rowid: int):
    if not current_user.is_admin():
        abort(403)
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))
    with _sqlite_conn() as conn:
        conn.execute(f"DELETE FROM {table} WHERE rowid = ?", (rowid,))
        conn.commit()
    flash("Record deleted.", "success")
    return redirect(url_for("admin_table_view", table=table))


@core_bp.route("/admin/database/<table>/delete-all", methods=["POST"])
@login_required
def admin_delete_all_records(table: str):
    if not current_user.is_admin():
        abort(403)
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))

    confirm = (request.form.get("confirm") or "").strip()
    expected = f"DELETE {table}"
    if confirm != expected:
        flash(f'Type "{expected}" to confirm deleting all rows in {table}.', "danger")
        return redirect(url_for("admin_table_view", table=table))

    try:
        with _sqlite_conn() as conn:
            conn.execute(f'DELETE FROM "{table}"')
            conn.commit()
        flash(f"All rows deleted from {table}.", "success")
    except Exception as e:
        flash(f"Error deleting rows from {table}: {str(e)}", "danger")

    return redirect(url_for("admin_table_view", table=table))


@core_bp.route("/admin/database/<table>/update-cell", methods=["POST"])
@login_required
def admin_update_cell(table: str):
    if not current_user.is_admin():
        abort(403)
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        return jsonify({"success": False, "error": "Invalid table"}), 400

    data = request.get_json(silent=True) or {}
    rowid = data.get("rowid")
    column = data.get("column")
    value = data.get("value")

    if not rowid or not column:
        return jsonify({"success": False, "error": "Missing rowid or column"}), 400
    if not _safe_identifier(column):
        return jsonify({"success": False, "error": "Invalid column name"}), 400

    try:
        with _sqlite_conn() as conn:
            info = _sqlite_table_info(table)
            if column not in [r["name"] for r in info]:
                return jsonify({"success": False, "error": "Column not found"}), 400

            if value is None or value == "":
                conn.execute(f"UPDATE {table} SET {column} = NULL WHERE rowid = ?", (rowid,))
            else:
                conn.execute(f"UPDATE {table} SET {column} = ? WHERE rowid = ?", (value, rowid))
            conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@core_bp.route("/admin/reports")
@login_required
def admin_reports():
    if not current_user.is_admin():
        abort(403)
    tables = _sqlite_list_tables()
    return render_template(
        "admin/reports.html",
        tables=tables,
        report_presets=[],
        error=None,
        selected_table=request.args.get("table") or "",
        columns=[],
        sort_col="",
        sort_dir="desc",
        limit=1000,
        selected_columns=[],
        filters=[],
        ops=[("=", "="), ("!=", "!="), ("contains", "contains"), ("not_contains", "not contains")],
        rows=[],
    )


@core_bp.route("/admin/lookups")
@login_required
def admin_lookups():
    if not current_user.is_admin():
        abort(403)

    known_groups = {
        "approved_status",
        "change_category",
        "change_status",
        "country",
        "ddi_bt_system",
        "ddi_cisco_cluster",
        "ddi_location",
        "ddi_tpo",
        "global_service_approval",
        "incident_location",
        "incident_severity",
        "private_wire_bearer_no",
        "private_wire_location",
        "private_wire_vendor",
        "region",
        "server_application",
        "server_site",
        "server_prod_dev",
        "server_role",
        "server_db_server",
        "server_service",
        "server_os",
        "server_hardware",
        "server_status",
        "server_type",
        "technology",
        "yes_no",
    }

    groups = {
        r[0]
        for r in db.session.execute(
            select(LookupOption.group).distinct().order_by(LookupOption.group)
        ).all()
        if r[0]
    }
    groups = sorted(groups.union(known_groups))
    counts = {}
    for g in groups:
        counts[g] = db.session.execute(
            select(db.func.count()).select_from(LookupOption).where(LookupOption.group == g)
        ).scalar_one()
    return render_template("admin/lookups.html", groups=groups, counts=counts)


@core_bp.route("/admin/cab-locks")
@login_required
def admin_cab_locks():
    if not current_user.is_admin():
        abort(403)

    locks = {l.cab_monday: l for l in db.session.execute(select(CabLock)).scalars().all() if l.cab_monday}

    cab_mondays = {d.date() for d in _cab_monday_options()}
    cab_mondays.update({d for d in locks.keys() if isinstance(d, date)})
    cab_mondays = sorted(cab_mondays)

    rows = []
    for m in cab_mondays:
        lock = locks.get(m)
        is_locked = bool(lock.is_locked) if lock else False
        change_count = db.session.execute(
            select(db.func.count()).select_from(ChangeRecord).where(db.func.date(ChangeRecord.cab_date) == m)
        ).scalar_one()
        rows.append(
            {
                "cab_monday": m.strftime("%Y-%m-%d"),
                "is_locked": is_locked,
                "locked_by": lock.locked_by if lock else None,
                "locked_at": lock.locked_at if lock else None,
                "change_count": change_count,
            }
        )
    cab_monday_options = [d.strftime("%Y-%m-%d") for d in cab_mondays]
    return render_template("admin/cab_locks.html", rows=rows, cab_monday_options=cab_monday_options)


@core_bp.route("/admin/cab-locks/add", methods=["POST"])
@login_required
def admin_cab_locks_add():
    if not current_user.is_admin():
        abort(403)

    cab_monday_str = (request.form.get("cab_monday") or "").strip()
    if not cab_monday_str:
        cab_monday_str = (request.form.get("cab_monday_date") or "").strip()
    try:
        cab_monday = datetime.strptime(cab_monday_str, "%Y-%m-%d").date()
    except Exception:
        flash("Invalid CAB Monday.", "danger")
        return redirect(url_for("admin_cab_locks"))

    if cab_monday.weekday() != 0:
        flash("CAB date must be a Monday.", "warning")
        return redirect(url_for("admin_cab_locks"))

    lock = db.session.execute(select(CabLock).where(CabLock.cab_monday == cab_monday)).scalar_one_or_none()
    if lock:
        flash("CAB Monday already exists.", "info")
        return redirect(url_for("admin_cab_locks"))

    db.session.add(CabLock(cab_monday=cab_monday, is_locked=False))
    db.session.commit()
    _log_activity("cab_lock_add", f"Added CAB Monday {cab_monday.strftime('%Y-%m-%d')}")
    flash("CAB Monday added.", "success")
    return redirect(url_for("admin_cab_locks"))


@core_bp.route("/admin/custom-fields")
@login_required
def admin_custom_fields():
    if not current_user.is_admin():
        abort(403)

    entities = [
        ("changes", "Changes"),
        ("incidents", "Incidents"),
        ("turrets", "Turrets"),
        ("private_wires", "Private Wires"),
    ]
    counts = {}
    for key, _ in entities:
        counts[key] = db.session.execute(
            select(db.func.count()).select_from(CustomFieldDef).where(CustomFieldDef.entity == key)
        ).scalar_one()
    return render_template("admin/custom_fields.html", entities=entities, counts=counts)


@core_bp.route("/admin/activity-log")
@login_required
def admin_activity_log():
    if not current_user.is_admin():
        abort(403)

    page = request.args.get("page", 1, type=int)
    username = (request.args.get("username") or "").strip() or None
    action_type = (request.args.get("action_type") or "").strip() or None
    date_from = (request.args.get("date_from") or "").strip() or None
    date_to = (request.args.get("date_to") or "").strip() or None

    stmt = select(ActivityLogEntry)
    if username:
        stmt = stmt.where(ActivityLogEntry.username == username)
    if action_type:
        stmt = stmt.where(ActivityLogEntry.action_type == action_type)

    df = _parse_any_date(date_from) if date_from else None
    dt = _parse_any_date(date_to) if date_to else None
    if df:
        stmt = stmt.where(ActivityLogEntry.created_at >= df)
    if dt:
        stmt = stmt.where(ActivityLogEntry.created_at <= (dt + timedelta(days=1)))

    stmt = stmt.order_by(ActivityLogEntry.created_at.desc().nullslast(), ActivityLogEntry.id.desc())
    logs = db.paginate(stmt, page=page, per_page=50, error_out=False)

    users = [
        r[0]
        for r in db.session.execute(select(ActivityLogEntry.username).distinct().order_by(ActivityLogEntry.username)).all()
        if r[0]
    ]
    action_types = [
        r[0]
        for r in db.session.execute(
            select(ActivityLogEntry.action_type).distinct().order_by(ActivityLogEntry.action_type)
        ).all()
        if r[0]
    ]

    return render_template(
        "admin/activity_log.html",
        logs=logs,
        users=users,
        action_types=action_types,
        username=username,
        action_type=action_type,
        date_from=date_from or "",
        date_to=date_to or "",
    )


@core_bp.route("/admin/backups/settings", methods=["POST"])
@login_required
def admin_backups_settings():
    if not current_user.is_admin():
        abort(403)

    backup_dir = (request.form.get("backup_dir") or "").strip() or _backup_dir_default()
    live_db_path = (request.form.get("live_db_path") or "").strip()
    retention = request.form.get("backup_retention") or "30"
    schedule_time = (request.form.get("backup_schedule_time") or "02:00").strip() or "02:00"

    try:
        datetime.strptime(schedule_time, "%H:%M")
    except Exception:
        schedule_time = "02:00"

    auto_delete = "backup_auto_delete" in request.form
    allow_manual_delete = "backup_allow_manual_delete" in request.form

    try:
        backup_dir = os.path.abspath(backup_dir)
        os.makedirs(backup_dir, exist_ok=True)
    except Exception:
        flash("Backup folder is invalid or not writable.", "danger")
        return redirect(url_for("admin_backups"))

    try:
        if live_db_path:
            live_db_path = os.path.abspath(live_db_path)
            if not live_db_path.lower().endswith(".db"):
                raise ValueError("Database path must end with .db")
            set_configured_db_path(live_db_path)
        else:
            set_configured_db_path(None)
    except Exception:
        flash("Live database path is invalid.", "danger")
        return redirect(url_for("admin_backups"))

    try:
        r = int(retention)
    except Exception:
        r = 30
    r = max(1, min(365, r))

    try:
        _setting_set("backup_dir", backup_dir, _current_username())
        _setting_set("backup_retention", str(r), _current_username())
        _setting_set("backup_schedule_time", schedule_time, _current_username())
        _setting_set("backup_auto_delete", "1" if auto_delete else "0", _current_username())
        _setting_set("backup_allow_manual_delete", "1" if allow_manual_delete else "0", _current_username())
        db.session.commit()
        flash("Backup settings saved.", "success")
    except Exception:
        db.session.rollback()
        flash("Failed to save settings.", "danger")
    return redirect(url_for("admin_backups"))


@core_bp.route("/admin/backups/run", methods=["POST"])
@login_required
def admin_backups_run_now():
    if not current_user.is_admin():
        abort(403)
    settings = _get_backup_settings()
    backups_dir = settings["backup_dir"]
    retention = settings["backup_retention"]
    auto_delete = settings["backup_auto_delete"]

    try:
        db_path = _db_path_from_uri()
        backup_path = _create_backup_copy(db_path, backups_dir)
        deleted = _run_retention(backups_dir, retention) if auto_delete else []
        flash(
            f"Backup created: {os.path.basename(backup_path)} (auto-deleted {len(deleted)})",
            "success",
        )
    except Exception as e:
        flash(f"Backup failed: {str(e)}", "danger")
    return redirect(url_for("admin_backups"))


@core_bp.route("/admin/backups/download/<path:filename>")
@login_required
def admin_backups_download(filename: str):
    if not current_user.is_admin():
        abort(403)
    settings = _get_backup_settings()
    name = _safe_backup_filename(filename)
    if not name:
        flash("Invalid filename.", "danger")
        return redirect(url_for("admin_backups"))
    path = os.path.join(settings["backup_dir"], name)
    if not os.path.exists(path):
        flash("Backup file not found.", "danger")
        return redirect(url_for("admin_backups"))
    return send_file(path, as_attachment=True, download_name=name)


@core_bp.route("/admin/backups/delete/<path:filename>", methods=["POST"])
@login_required
def admin_backups_delete(filename: str):
    if not current_user.is_admin():
        abort(403)
    settings = _get_backup_settings()
    if not settings["backup_allow_manual_delete"]:
        flash("Manual delete is disabled in settings.", "danger")
        return redirect(url_for("admin_backups"))
    name = _safe_backup_filename(filename)
    if not name:
        flash("Invalid filename.", "danger")
        return redirect(url_for("admin_backups"))
    path = os.path.join(settings["backup_dir"], name)
    try:
        os.remove(path)
        flash("Backup deleted.", "success")
    except Exception:
        flash("Failed to delete backup.", "danger")
    return redirect(url_for("admin_backups"))


@core_bp.route("/admin/backups/schedule/install", methods=["GET", "POST"])
@login_required
def admin_backups_schedule_install():
    if not current_user.is_admin():
        abort(403)
    if request.method == "GET":
        flash("Use the button on the Backups page to install/update the scheduled task.", "info")
        return redirect(url_for("admin_backups"))

    settings = _get_backup_settings()
    task_name = settings.get("task_name") or "TelephonyPortal Nightly Backup"
    schedule_time = settings.get("backup_schedule_time") or "02:00"
    try:
        datetime.strptime(schedule_time, "%H:%M")
    except Exception:
        schedule_time = "02:00"

    python_exe = sys.executable
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Use a module invocation to avoid relying on absolute file paths.
    # Ensure the task runs from the project root so imports resolve.
    task_cmd = f'cmd.exe /c "cd /d {project_root} && \"{python_exe}\" -m portal_app.backup_job"'

    # /F overwrites; try /RL HIGHEST first, then fall back to a non-elevated task.
    args = [
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        task_name,
        "/SC",
        "DAILY",
        "/ST",
        schedule_time,
        "/RL",
        "HIGHEST",
        "/TR",
        task_cmd,
    ]

    try:
        res = subprocess.run(args, capture_output=True, text=True)
        if res.returncode != 0:
            msg = (res.stderr or res.stdout or "").strip() or f"schtasks failed (code {res.returncode})"

            # Common: Access is denied when trying to create a highest-privilege task.
            if "access is denied" in msg.lower():
                args_fallback = [
                    "schtasks",
                    "/Create",
                    "/F",
                    "/TN",
                    task_name,
                    "/SC",
                    "DAILY",
                    "/ST",
                    schedule_time,
                    "/TR",
                    task_cmd,
                ]
                res2 = subprocess.run(args_fallback, capture_output=True, text=True)
                if res2.returncode == 0:
                    flash(
                        f"Scheduled task installed (non-elevated): {task_name} at {schedule_time}. "
                        "If it needs admin access, run the app as Administrator and install again.",
                        "success",
                    )
                    _log_activity(
                        "backup_schedule_install",
                        f"task={task_name} time={schedule_time} rl=limited (fallback)",
                    )
                    return redirect(url_for("admin_backups"))

                msg2 = (res2.stderr or res2.stdout or "").strip() or f"schtasks failed (code {res2.returncode})"
                flash(
                    "Failed to install scheduled task (even without elevation). "
                    f"Error: {msg2}. Try running the app as Administrator once and re-install.",
                    "danger",
                )
                _log_activity("backup_schedule_install", f"elevated_failed={msg} fallback_failed={msg2}", success=False)
                return redirect(url_for("admin_backups"))

            flash(
                "Failed to install scheduled task. "
                f"Error: {msg}. Try running the app as Administrator once and re-install.",
                "danger",
            )
            _log_activity("backup_schedule_install", msg, success=False)
            return redirect(url_for("admin_backups"))

        flash(f"Scheduled task installed/updated: {task_name} at {schedule_time}", "success")
        _log_activity("backup_schedule_install", f"task={task_name} time={schedule_time}")
    except Exception as e:
        flash(f"Failed to install scheduled task: {str(e)}", "danger")
        _log_activity("backup_schedule_install", str(e), success=False)
    return redirect(url_for("admin_backups"))


@core_bp.route("/admin/backups/schedule/run", methods=["GET", "POST"])
@login_required
def admin_backups_schedule_run():
    if not current_user.is_admin():
        abort(403)
    if request.method == "GET":
        flash("Use the button on the Backups page to run the scheduled task.", "info")
        return redirect(url_for("admin_backups"))

    settings = _get_backup_settings()
    task_name = settings.get("task_name") or "TelephonyPortal Nightly Backup"

    try:
        res = subprocess.run(
            ["schtasks", "/Run", "/TN", task_name],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            msg = (res.stderr or res.stdout or "").strip() or f"schtasks failed (code {res.returncode})"
            flash(f"Failed to start scheduled task: {msg}", "danger")
            _log_activity("backup_schedule_run", msg, success=False)
            return redirect(url_for("admin_backups"))

        flash(f"Scheduled task started: {task_name}", "success")
        _log_activity("backup_schedule_run", f"task={task_name}")
    except Exception as e:
        flash(f"Failed to start scheduled task: {str(e)}", "danger")
        _log_activity("backup_schedule_run", str(e), success=False)
    return redirect(url_for("admin_backups"))


@core_bp.route("/admin/cab-locks/toggle", methods=["POST"])
@login_required
def admin_cab_locks_toggle():
    if not current_user.is_admin():
        abort(403)

    cab_monday_str = (request.form.get("cab_monday") or "").strip()
    action = (request.form.get("action") or "").strip().lower()
    try:
        cab_monday = datetime.strptime(cab_monday_str, "%Y-%m-%d").date()
    except Exception:
        flash("Invalid CAB Monday.", "danger")
        return redirect(url_for("admin_cab_locks"))

    lock = db.session.execute(select(CabLock).where(CabLock.cab_monday == cab_monday)).scalar_one_or_none()
    if not lock:
        lock = CabLock(cab_monday=cab_monday)
        db.session.add(lock)

    if action == "lock":
        lock.is_locked = True
        lock.locked_by = _current_username()
        lock.locked_at = datetime.utcnow()
    elif action == "unlock":
        lock.is_locked = False
        lock.locked_by = _current_username()
        lock.locked_at = datetime.utcnow()
    else:
        flash("Invalid action.", "danger")
        return redirect(url_for("admin_cab_locks"))

    db.session.commit()
    _log_activity(
        "cab_lock_toggle",
        f"{action.title()} CAB Monday {cab_monday.strftime('%Y-%m-%d')}",
    )
    return redirect(url_for("admin_cab_locks"))


@core_bp.route("/admin/lookups/<group>")
@login_required
def admin_lookup_group(group: str):
    if not current_user.is_admin():
        abort(403)
    options = (
        db.session.execute(
            select(LookupOption)
            .where(LookupOption.group == group)
            .order_by(LookupOption.sort_order.asc(), LookupOption.value.asc())
        )
        .scalars()
        .all()
    )
    return render_template("admin/lookup_group.html", group=group, options=options)


@core_bp.route("/admin/lookups/<group>/add", methods=["POST"])
@login_required
def admin_lookup_add(group: str):
    if not current_user.is_admin():
        abort(403)
    value = (request.form.get("value") or "").strip()
    sort_order = request.form.get("sort_order") or "0"
    is_active = "is_active" in request.form
    if not value:
        flash("Value is required", "danger")
        return redirect(url_for("admin_lookup_group", group=group))
    try:
        so = int(sort_order)
    except Exception:
        so = 0
    o = LookupOption(group=group, value=value, sort_order=so, is_active=is_active)
    db.session.add(o)
    db.session.commit()
    return redirect(url_for("admin_lookup_group", group=group))


@core_bp.route("/admin/lookups/<group>/edit/<int:id>", methods=["GET", "POST"])
@login_required
def admin_lookup_edit(group: str, id: int):
    if not current_user.is_admin():
        abort(403)
    option = db.session.get(LookupOption, id)
    if not option or option.group != group:
        abort(404)
    if request.method == "POST":
        option.value = (request.form.get("value") or "").strip()
        try:
            option.sort_order = int(request.form.get("sort_order") or "0")
        except Exception:
            option.sort_order = 0
        option.is_active = "is_active" in request.form
        db.session.commit()
        flash("Updated", "success")
        return redirect(url_for("admin_lookup_group", group=group))
    return render_template("admin/edit_lookup_option.html", group=group, option=option)


@core_bp.route("/admin/lookups/<group>/delete/<int:id>", methods=["POST"])
@login_required
def admin_lookup_delete(group: str, id: int):
    if not current_user.is_admin():
        abort(403)
    option = db.session.get(LookupOption, id)
    if not option or option.group != group:
        abort(404)
    db.session.delete(option)
    db.session.commit()
    return redirect(url_for("admin_lookup_group", group=group))


@core_bp.route("/admin/custom-fields/<entity>")
@login_required
def admin_custom_fields_entity(entity: str):
    if not current_user.is_admin():
        abort(403)
    fields = (
        db.session.execute(
            select(CustomFieldDef)
            .where(CustomFieldDef.entity == entity)
            .order_by(CustomFieldDef.sort_order.asc(), CustomFieldDef.field_key.asc())
        )
        .scalars()
        .all()
    )
    return render_template("admin/custom_fields_entity.html", entity=entity, fields=fields)


@core_bp.route("/admin/custom-fields/<entity>/add", methods=["POST"])
@login_required
def admin_custom_fields_add(entity: str):
    if not current_user.is_admin():
        abort(403)
    field_key = (request.form.get("field_key") or "").strip()
    label = (request.form.get("label") or "").strip()
    field_type = (request.form.get("field_type") or "text").strip() or "text"
    options_text = (request.form.get("options") or "").strip() or None
    is_required = "is_required" in request.form
    try:
        sort_order = int(request.form.get("sort_order") or "0")
    except Exception:
        sort_order = 0
    if not re.fullmatch(r"[a-z0-9_]+", field_key):
        flash("Field Key must be lowercase letters/numbers/underscore only", "danger")
        return redirect(url_for("admin_custom_fields_entity", entity=entity))
    if not label:
        flash("Label is required", "danger")
        return redirect(url_for("admin_custom_fields_entity", entity=entity))

    f = CustomFieldDef(
        entity=entity,
        field_key=field_key,
        label=label,
        field_type=field_type,
        sort_order=sort_order,
        is_required=is_required,
        is_active=True,
        options_text=options_text,
    )
    db.session.add(f)
    db.session.commit()
    return redirect(url_for("admin_custom_fields_entity", entity=entity))


@core_bp.route("/admin/custom-fields/<entity>/toggle/<int:id>", methods=["POST"])
@login_required
def admin_custom_fields_toggle(entity: str, id: int):
    if not current_user.is_admin():
        abort(403)
    f = db.session.get(CustomFieldDef, id)
    if not f or f.entity != entity:
        abort(404)
    f.is_active = not bool(f.is_active)
    db.session.commit()
    return redirect(url_for("admin_custom_fields_entity", entity=entity))
