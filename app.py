# app.py - Complete Enhanced Telephony DDI Management Portal

from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify, session, send_file, after_this_request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from datetime import timedelta
import os
import csv
import io
import shutil
import json
import tempfile
from utils.field_mapper import FieldMapper
import sqlite3
import re
from urllib.parse import urlparse
import sys
import logging
import ctypes
import sqlite3
from sqlalchemy import event, text
from sqlalchemy.dialects import sqlite as _sqlite_dialect
import time

try:
    from portal_app import create_app as _tp_create_app

    app = _tp_create_app()

    if __name__ == "__main__":
        port = int(os.environ.get("TELEPHONY_PORT", "5500"))
        host = os.environ.get("TELEPHONY_HOST", "0.0.0.0")
        if host.strip() in {"*", "0", "0.0.0.0"}:
            host = "0.0.0.0"

        from waitress import serve

        serve(app, host=host, port=port, threads=max(1, int(os.environ.get("TELEPHONY_WAITRESS_THREADS", "8"))))

    raise SystemExit(0)
except Exception as _e:
    # In the frozen build and current rewrite, this file should not fall through into the legacy
    # code below if the new app import fails. Doing so can leave `app` undefined and crash.
    raise SystemExit(f"Failed to start portal_app application: {_e}")

def _find_recovered_pyc():
    candidates = []

    try:
        candidates.append(os.path.join(os.path.dirname(__file__), "app_valid2.pyc"))
    except Exception:
        pass

    try:
        candidates.append(os.path.join(os.path.dirname(sys.executable), "app_valid2.pyc"))
    except Exception:
        pass

    try:
        mei = getattr(sys, "_MEIPASS", None)
        if mei:
            candidates.append(os.path.join(mei, "app_valid2.pyc"))
            candidates.append(os.path.join(mei, "_internal", "app_valid2.pyc"))
    except Exception:
        pass

    try:
        candidates.append(os.path.abspath(os.path.join(os.getcwd(), "app_valid2.pyc")))
    except Exception:
        pass

    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None

def _load_recovered_module():
    import importlib.util
    import importlib.machinery

    recovered_pyc = _find_recovered_pyc()
    if not recovered_pyc:
        raise FileNotFoundError("app_valid2.pyc")

    loader = importlib.machinery.SourcelessFileLoader("telephonyportal_recovered", recovered_pyc)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

def _patch_health(mod):
    try:
        flask_app = getattr(mod, "app", None)
        db = getattr(mod, "db", None)
        if flask_app is None or db is None:
            return
        if "health" in getattr(flask_app, "view_functions", {}):
            return

        from sqlalchemy import text as _sql_text

        @flask_app.route("/health")
        def health():
            try:
                db.session.execute(_sql_text("SELECT 1"))
                return jsonify({"ok": True}), 200
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500
    except Exception:
        # Best-effort patching only; avoid breaking startup.
        pass

def _patch_templates(mod):
    try:
        flask_app = getattr(mod, "app", None)
        if flask_app is None:
            return

        import jinja2

        candidates = []
        try:
            candidates.append(os.path.join(os.path.dirname(sys.executable), "templates"))
        except Exception:
            pass
        try:
            mei = getattr(sys, "_MEIPASS", None)
            if mei:
                candidates.append(os.path.join(mei, "templates"))
                candidates.append(os.path.join(mei, "_internal", "templates"))
        except Exception:
            pass
        try:
            candidates.append(os.path.abspath(os.path.join(os.getcwd(), "templates")))
        except Exception:
            pass

        template_dirs = [p for p in candidates if p and os.path.isdir(p)]
        if not template_dirs:
            return

        existing = []
        try:
            if isinstance(flask_app.jinja_loader, jinja2.FileSystemLoader):
                existing = list(flask_app.jinja_loader.searchpath or [])
        except Exception:
            existing = []

        merged = []
        for p in existing + template_dirs:
            ap = os.path.abspath(p)
            if ap not in merged:
                merged.append(ap)

        flask_app.jinja_loader = jinja2.FileSystemLoader(merged)
    except Exception:
        pass

def _patch_permissions(mod):
    try:
        flask_app = getattr(mod, "app", None)
        if flask_app is None:
            return

        from functools import wraps
        from flask import abort
        from flask_login import current_user

        def _is_admin() -> bool:
            try:
                fn = getattr(current_user, "is_admin", None)
                if callable(fn):
                    return bool(fn())
            except Exception:
                pass
            try:
                return str(getattr(current_user, "role", "")).strip().lower() == "admin"
            except Exception:
                return False

        def _admin_write_required(fn):
            @wraps(fn)
            def _wrapped(*args, **kwargs):
                if not _is_admin():
                    abort(403)
                return fn(*args, **kwargs)

            return _wrapped

        # Endpoints that mutate data and must remain admin-only.
        # Editors/users can still view/list/export.
        admin_only_write_endpoints = {
            # Turrets
            "turret_add",
            "turret_edit",
            "turret_import",
            "turret_import_execute",
            "turret_plan_move",
            "turret_edit_move_group",
            "turret_execute_move",
            "turret_approve_move_group",
            "turret_rma",
            # Private wires
            "pw_add",
            "pw_edit",
            "pw_import",
            "pw_cease",
            # DDI
            "ddi_add",
            "ddi_edit",
            "ddi_import",
            "ddi_request_spare",
        }

        for endpoint in admin_only_write_endpoints:
            try:
                vf = flask_app.view_functions.get(endpoint)
                if vf and getattr(vf, "_tp_admin_wrapped", False) is False:
                    wrapped = _admin_write_required(vf)
                    setattr(wrapped, "_tp_admin_wrapped", True)
                    flask_app.view_functions[endpoint] = wrapped
            except Exception:
                continue
    except Exception:
        pass

def _init_db(mod):
    flask_app = getattr(mod, "app", None)
    db = getattr(mod, "db", None)
    if flask_app is None or db is None:
        return

    with flask_app.app_context():
        try:
            cfg = getattr(mod, "_configure_sqlite_engine", None)
            if callable(cfg):
                cfg(db.engine)
        except Exception:
            pass

        try:
            db.create_all()
        except Exception:
            pass

        try:
            ensure = getattr(mod, "ensure_sqlite_schema", None)
            if callable(ensure):
                ensure()
        except Exception:
            pass

        # Fallback: ensure older DBs have columns expected by the ORM.
        try:
            rows = db.session.execute(text("PRAGMA table_info('user')")).fetchall()
            cols = {r[1] for r in rows if r and len(r) > 1}
            if "name" not in cols:
                db.session.execute(text("ALTER TABLE user ADD COLUMN name TEXT"))
                db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

        try:
            seed = getattr(mod, "seed_lookup_defaults", None)
            if callable(seed):
                seed()
        except Exception:
            pass

def _patch_cab_locks(mod):
    try:
        flask_app = getattr(mod, "app", None)
        db = getattr(mod, "db", None)
        ChangeRecord = getattr(mod, "ChangeRecord", None)
        CabLock = getattr(mod, "CabLock", None)
        get_cab_mondays = getattr(mod, "get_cab_mondays", None)
        render_template_fn = getattr(mod, "render_template", None)

        if not all([flask_app, db, ChangeRecord, CabLock, get_cab_mondays, render_template_fn]):
            return

        if "admin_cab_locks" not in getattr(flask_app, "view_functions", {}):
            return

        def _admin_cab_locks_patched():
            existing_change_dates = [
                row[0] for row in db.session.query(db.func.date(ChangeRecord.cab_date)).distinct()
                .filter(ChangeRecord.cab_date.isnot(None)).all()
                if row[0]
            ]

            locks = CabLock.query.all()
            lock_dates = [l.cab_monday for l in locks if l and l.cab_monday]
            cab_values = get_cab_mondays(as_strings=False) or []

            mondays = sorted(set(existing_change_dates) | set(lock_dates) | set(cab_values))
            lock_map = {l.cab_monday.isoformat(): l for l in locks}

            cab_counts = dict(
                db.session.query(db.func.date(ChangeRecord.cab_date), db.func.count(ChangeRecord.id))
                .filter(ChangeRecord.cab_date.isnot(None))
                .group_by(db.func.date(ChangeRecord.cab_date))
                .all()
            )

            rows = []
            for d in mondays:
                key = d.isoformat()
                lock = lock_map.get(key)
                rows.append({
                    "cab_monday": key,
                    "is_locked": bool(lock.is_locked) if lock else False,
                    "locked_by": lock.locked_by if lock else None,
                    "locked_at": lock.locked_at if lock else None,
                    "change_count": int(cab_counts.get(key, 0) or 0),
                })

            return render_template_fn("admin/cab_locks.html", rows=rows)

        flask_app.view_functions["admin_cab_locks"] = _admin_cab_locks_patched
    except Exception:
        # Best-effort patching only; avoid breaking startup.
        pass

def _run_server(mod):
    flask_app = getattr(mod, "app", None)
    if flask_app is None:
        raise RuntimeError("Recovered module does not define 'app'.")

    _init_db(mod)

    port = int(os.environ.get("TELEPHONY_PORT", "5500"))
    host = os.environ.get("TELEPHONY_HOST", "0.0.0.0")
    if host.strip() in {"*", "0", "0.0.0.0"}:
        host = "0.0.0.0"

    use_waitress = str(os.environ.get("TELEPHONY_USE_WAITRESS", "1")).strip().lower() in {"1", "true", "yes", "y", "on"}
    if use_waitress:
        from waitress import serve
        serve(flask_app, host=host, port=port, threads=max(1, int(os.environ.get("TELEPHONY_WAITRESS_THREADS", "8"))))
    else:
        flask_app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


# If we have a recovered bytecode payload, load it and avoid executing the corrupted remainder of this file.
if _find_recovered_pyc():
    _mod = _load_recovered_module()
    _patch_health(_mod)
    _patch_templates(_mod)
    _patch_permissions(_mod)
    _patch_cab_locks(_mod)

    # Export commonly used globals (best-effort).
    app = getattr(_mod, "app", None)
    db = getattr(_mod, "db", None)

    if __name__ == "__main__":
        _run_server(_mod)

    raise SystemExit(0)

def normalize_mac(value):
    """Normalize MAC-like input for consistent storage/comparison."""
    if value is None:
        return None

# ... (rest of the code remains the same)

@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ... (rest of the code remains the same)

@app.route('/admin/cab-locks')
@login_required
@admin_required
def admin_cab_locks():
    existing_change_dates = [
        row[0] for row in db.session.query(db.func.date(ChangeRecord.cab_date)).distinct()
        .filter(ChangeRecord.cab_date.isnot(None)).all()
        if row[0]
    ]

    locks = CabLock.query.all()
    lock_dates = [l.cab_monday for l in locks if l and l.cab_monday]

    cab_values = get_cab_mondays(as_strings=False) or []

    mondays = sorted(set(existing_change_dates) | set(lock_dates) | set(cab_values))
    lock_map = {l.cab_monday.isoformat(): l for l in locks}

    # Count changes per cab_date
    cab_counts = dict(
        db.session.query(db.func.date(ChangeRecord.cab_date), db.func.count(ChangeRecord.id))
        .filter(ChangeRecord.cab_date.isnot(None))
    # ... (rest of the code remains the same)
        .group_by(db.func.date(ChangeRecord.cab_date))
        .all()
    )

    rows = []
    for d in mondays:
        key = d.isoformat()
        lock = lock_map.get(key)
        rows.append({
            'cab_monday': key,
            'is_locked': bool(lock.is_locked) if lock else False,
            'locked_by': lock.locked_by if lock else None,
            'locked_at': lock.locked_at if lock else None,
            'change_count': int(cab_counts.get(key, 0) or 0),
        })

    return render_template('admin/cab_locks.html', rows=rows)

@app.route('/admin/cab-locks/toggle', methods=['POST'])
@login_required
@admin_required
def admin_cab_locks_toggle():
    cab_monday_str = request.form.get('cab_monday')
    action = request.form.get('action')  # lock / unlock

    if not cab_monday_str:
        flash('CAB Monday is required.', 'danger')
        return redirect(url_for('admin_cab_locks'))

    try:
        cab_monday = datetime.strptime(cab_monday_str, '%Y-%m-%d').date()
    except Exception:
        flash('Invalid CAB Monday date format.', 'danger')
        return redirect(url_for('admin_cab_locks'))

    lock = CabLock.query.filter_by(cab_monday=cab_monday).first()
    if not lock:
        lock = CabLock(cab_monday=cab_monday, is_locked=False)
        db.session.add(lock)

    if action == 'lock':
        lock.is_locked = True
        lock.locked_by = current_user.username
        lock.locked_at = datetime.utcnow()
        flash(f'CAB {cab_monday_str} locked.', 'success')
    elif action == 'unlock':
        lock.is_locked = False
        flash(f'CAB {cab_monday_str} unlocked.', 'success')
    else:
        flash('Invalid action.', 'danger')

    db.session.commit()
    return redirect(url_for('admin_cab_locks'))

# =====================================================================
# Admin - Custom Fields
# =====================================================================

@app.route('/admin/custom-fields')
@login_required
@admin_required
def admin_custom_fields():
    entities = [
        ('changes', 'Changes'),
        ('incidents', 'Incidents'),
        ('turrets', 'Dealerboards (Turrets)'),
        ('private_wires', 'Private Wires'),
    ]
    counts = {e: CustomFieldDefinition.query.filter_by(entity=e).count() for e, _ in entities}
    return render_template('admin/custom_fields.html', entities=entities, counts=counts)

@app.route('/admin/custom-fields/<entity>')
@login_required
@admin_required
def admin_custom_fields_entity(entity):
    fields = CustomFieldDefinition.query.filter_by(entity=entity).order_by(
        CustomFieldDefinition.sort_order.asc(), CustomFieldDefinition.label.asc()
    ).all()
    return render_template('admin/custom_fields_entity.html', entity=entity, fields=fields)

@app.route('/admin/custom-fields/<entity>/add', methods=['POST'])
@login_required
@admin_required
def admin_custom_fields_add(entity):
    field_key = (request.form.get('field_key') or '').strip().lower()
    label = (request.form.get('label') or '').strip()
    field_type = (request.form.get('field_type') or '').strip()
    is_required = bool(request.form.get('is_required'))
    sort_order = request.form.get('sort_order', 0, type=int)
    options_raw = (request.form.get('options') or '').strip()

    if not field_key or not re.fullmatch(r'[a-z0-9_]+', field_key):
        flash('Field key is required and must be lowercase letters/numbers/underscore only.', 'danger')
        return redirect(url_for('admin_custom_fields_entity', entity=entity))
    if not label:
        flash('Label is required.', 'danger')
        return redirect(url_for('admin_custom_fields_entity', entity=entity))
    if field_type not in ['text', 'textarea', 'number', 'date', 'yesno', 'dropdown', 'url']:
        flash('Invalid field type.', 'danger')
        return redirect(url_for('admin_custom_fields_entity', entity=entity))

    options_json = None
    if field_type == 'dropdown':
        # options = newline separated values
        opts = [o.strip() for o in options_raw.splitlines() if o.strip()]
        options_json = json.dumps(opts)

    if CustomFieldDefinition.query.filter_by(entity=entity, field_key=field_key).first():
        flash('That field key already exists for this entity.', 'danger')
        return redirect(url_for('admin_custom_fields_entity', entity=entity))

    db.session.add(CustomFieldDefinition(
        entity=entity,
        field_key=field_key,
        label=label,
        field_type=field_type,
        is_required=is_required,
        options=options_json,
        is_active=True,
        sort_order=sort_order,
        created_by=current_user.username
    ))
    db.session.commit()
    flash('Custom field created.', 'success')
    return redirect(url_for('admin_custom_fields_entity', entity=entity))

@app.route('/admin/custom-fields/<entity>/toggle/<int:id>', methods=['POST'])
@login_required
@admin_required
def admin_custom_fields_toggle(entity, id):
    f = CustomFieldDefinition.query.get_or_404(id)
    if f.entity != entity:
        flash('Invalid entity.', 'danger')
        return redirect(url_for('admin_custom_fields'))
    f.is_active = not bool(f.is_active)
    db.session.commit()
    flash('Custom field updated.', 'success')
    return redirect(url_for('admin_custom_fields_entity', entity=entity))

# =====================================================================
# Admin - Database viewer/editor
# =====================================================================

@app.route('/admin/database')
@login_required
@admin_required
def admin_database():
    tables = _dbadmin_allowed_tables()
    table_meta = []
    with _sqlite_conn() as conn:
        for t in tables:
            try:
                count = conn.execute(f"SELECT COUNT(*) AS c FROM {t}").fetchone()["c"]
            except Exception:
                count = None
            table_meta.append({"name": t, "count": count})
    return render_template("admin/database.html", tables=table_meta)


# =====================================================================
# Admin - Report Builder (query any table + export)
# =====================================================================

def _report_ops():
    return [
        ("eq", "Equals"),
        ("ne", "Not equals"),
        ("contains", "Contains"),
        ("starts", "Starts with"),
        ("ends", "Ends with"),
        ("gt", "Greater than"),
        ("gte", "Greater or equal"),
        ("lt", "Less than"),
        ("lte", "Less or equal"),
        ("is_null", "Is NULL"),
        ("is_not_null", "Is NOT NULL"),
    ]

def _build_report_where(filters, allowed_cols):
    clauses = []
    params = []
    for f in filters:
        col = (f.get("col") or "").strip()
        op = (f.get("op") or "").strip()
        val = f.get("val")

        if not col or col not in allowed_cols:
            continue
        if op not in {o for o, _ in _report_ops()}:
            continue

        if op == "is_null":
            clauses.append(f'"{col}" IS NULL')
            continue
        if op == "is_not_null":
            clauses.append(f'"{col}" IS NOT NULL')
            continue

        sval = ("" if val is None else str(val)).strip()
        if sval == "":
            continue

        if op == "eq":
            clauses.append(f'"{col}" = ?')
            params.append(sval)
        elif op == "ne":
            clauses.append(f'"{col}" != ?')
            params.append(sval)
        elif op == "contains":
            clauses.append(f'"{col}" LIKE ?')
            params.append(f"%{sval}%")
        elif op == "starts":
            clauses.append(f'"{col}" LIKE ?')
            params.append(f"{sval}%")
        elif op == "ends":
            clauses.append(f'"{col}" LIKE ?')
            params.append(f"%{sval}")
        elif op == "gt":
            clauses.append(f'"{col}" > ?')
            params.append(sval)
        elif op == "gte":
            clauses.append(f'"{col}" >= ?')
            params.append(sval)
        elif op == "lt":
            clauses.append(f'"{col}" < ?')
            params.append(sval)
        elif op == "lte":
            clauses.append(f'"{col}" <= ?')
            params.append(sval)

    if not clauses:
        return "", []
    return " WHERE " + " AND ".join(clauses), params

def _parse_report_request(form_or_args):
    table = (form_or_args.get("table") or "").strip()
    cols = form_or_args.getlist("columns") if hasattr(form_or_args, "getlist") else []

    filters = []
    for i in range(1, 6):
        filters.append(
            {
                "col": (form_or_args.get(f"filter_col_{i}") or "").strip(),
                "op": (form_or_args.get(f"filter_op_{i}") or "").strip(),
                "val": (form_or_args.get(f"filter_val_{i}") or "").strip(),
            }
        )

    sort_col = (form_or_args.get("sort_col") or "").strip()
    sort_dir = (form_or_args.get("sort_dir") or "desc").strip().lower()
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    try:
        limit = int(form_or_args.get("limit") or "500")
    except Exception:
        limit = 500
    limit = max(1, min(limit, 100000))

    return table, cols, filters, sort_col, sort_dir, limit


def _report_preset_defs():
    """
    Opinionated presets for the Report Builder.
    NOTE: Table names are the SQLite table names, not model class names.
    """
    return {
        "changes_open": {
            "label": "Changes: Open",
            "table": "change_record",
            "columns": [
                "id", "region", "cr_number", "title", "technology", "status",
                "cab_date", "start_date", "approved_status", "approved_by",
                "regional_approval_status", "regional_approver_name",
                "global_service_approval", "last_updated", "last_updated_by",
            ],
            "filters": [
                {"col": "status", "op": "ne", "val": "Cancelled"},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
            ],
            "sort_col": "cab_date",
            "sort_dir": "asc",
            "limit": 500,
        },
        "changes_pending_approvals": {
            "label": "Changes: Pending Approvals",
            "table": "change_record",
            "columns": [
                "id", "region", "cr_number", "title", "technology", "status",
                "cab_date", "start_date",
                "approved_status", "approved_by",
                "regional_approval_status", "regional_approver_name",
                "global_service_approval",
                "last_updated", "last_updated_by",
            ],
            "filters": [
                {"col": "approved_status", "op": "ne", "val": "Yes"},
                {"col": "status", "op": "ne", "val": "Cancelled"},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
            ],
            "sort_col": "last_updated",
            "sort_dir": "desc",
            "limit": 500,
        },
        "incidents_last_30d": {
            "label": "Incidents: Last 30 Days",
            "table": "incident_record",
            "columns": [
                "id", "incident_number", "small_title", "region", "incident_date", "incident_time",
                "technology", "location", "severity", "calls_lost", "zendesk_number", "verint_number",
                "last_updated", "last_updated_by",
            ],
            # NOTE: date filtering is string-based (SQLite is loose). User can refine further.
            "filters": [
                {"col": "incident_date", "op": "gte", "val": (datetime.utcnow().date() - timedelta(days=30)).isoformat()},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
            ],
            "sort_col": "incident_date",
            "sort_dir": "desc",
            "limit": 1000,
        },
        "private_wires_all": {
            "label": "Private Wires: All",
            "table": "private_wire",
            "columns": [
                "id", "aor_number", "aor", "location", "vendor", "bearer_no",
                "circuit_no", "line_label", "pw_type", "hsbc_main_user",
                "company_name", "status", "last_updated", "last_change",
            ],
            "filters": [{"col": "", "op": "contains", "val": ""} for _ in range(5)],
            "sort_col": "last_updated",
            "sort_dir": "desc",
            "limit": 5000,
        },
        "turrets_active": {
            "label": "Turrets: Active",
            "table": "dealerboard_turret",
            "columns": [
                "id", "desk_location", "office", "country", "mac_address",
                "mac_address_2", "mac_address_3", "mac_address_4", "mac_address_5",
                "status", "last_updated", "last_change",
            ],
            "filters": [
                {"col": "status", "op": "eq", "val": "Active"},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
                {"col": "", "op": "contains", "val": ""},
            ],
            "sort_col": "last_updated",
            "sort_dir": "desc",
            "limit": 5000,
        },
    }

@app.route("/admin/reports", methods=["GET", "POST"])
@login_required
@admin_required
def admin_reports():
    tables = _sqlite_list_tables()
    presets = _report_preset_defs()
    tables_set = set(tables)
    report_presets = [
        {"key": k, "label": v["label"], "table": v["table"]}
        for k, v in presets.items()
        if v.get("table") in tables_set
    ]
    report_presets.sort(key=lambda x: x["label"].lower())

    selected_table = ""
    columns = []
    selected_columns = []
    filters = [{"col": "", "op": "contains", "val": ""} for _ in range(5)]
    sort_col = ""
    sort_dir = "desc"
    limit = 500
    rows = []
    error = None

    if request.method == "POST":
        selected_table, selected_columns, filters, sort_col, sort_dir, limit = _parse_report_request(request.form)
    else:
        preset_key = (request.args.get("preset") or "").strip()
        if preset_key and preset_key in presets:
            p = presets[preset_key]
            selected_table = (p.get("table") or "").strip()
            selected_columns = list(p.get("columns") or [])
            filters = list(p.get("filters") or [{"col": "", "op": "contains", "val": ""} for _ in range(5)])
            sort_col = (p.get("sort_col") or "").strip()
            sort_dir = (p.get("sort_dir") or "desc").strip().lower()
            try:
                limit = int(p.get("limit") or 500)
            except Exception:
                limit = 500
        else:
            selected_table = (request.args.get("table") or "").strip()

    if selected_table:
        if selected_table not in tables:
            error = "Invalid table."
        else:
            info = _sqlite_table_info(selected_table)
            columns = [r["name"] for r in info]
            allowed_cols = set(columns)

            # Default to all columns if none selected (POST or preset)
            if not selected_columns:
                selected_columns = columns
            selected_columns = [c for c in selected_columns if c in allowed_cols]

            # Sort validation
            if sort_col and sort_col not in allowed_cols:
                sort_col = ""

            if request.method == "POST":
                where, params = _build_report_where(filters, allowed_cols)
                order = f' ORDER BY "{sort_col}" {sort_dir.upper()}' if sort_col else " ORDER BY rowid DESC"
                sel = ", ".join([f'"{c}"' for c in selected_columns]) if selected_columns else "*"

                sql = f'SELECT {sel} FROM "{selected_table}"{where}{order} LIMIT ?'
                try:
                    with _sqlite_conn() as conn:
                        rows = conn.execute(sql, params + [limit]).fetchall()
                except Exception as e:
                    error = str(e)

    return render_template(
        "admin/reports.html",
        tables=tables,
        report_presets=report_presets,
        selected_table=selected_table,
        columns=columns,
        selected_columns=selected_columns,
        filters=filters,
        ops=_report_ops(),
        sort_col=sort_col,
        sort_dir=sort_dir,
        limit=limit,
        rows=rows,
        error=error,
    )


@app.route("/admin/reports/preset/<preset_key>/export")
@login_required
@admin_required
def admin_reports_export_preset(preset_key):
    presets = _report_preset_defs()
    if preset_key not in presets:
        flash("Invalid preset.", "danger")
        return redirect(url_for("admin_reports"))

    p = presets[preset_key]
    table = (p.get("table") or "").strip()
    columns_p = list(p.get("columns") or [])
    filters = list(p.get("filters") or [{"col": "", "op": "contains", "val": ""} for _ in range(5)])
    sort_col = (p.get("sort_col") or "").strip()
    sort_dir = (p.get("sort_dir") or "desc").strip().lower()
    try:
        limit = int(p.get("limit") or 500)
    except Exception:
        limit = 500
    limit = max(1, min(limit, 100000))

    tables = _sqlite_list_tables()
    if table not in tables:
        flash("Preset table not available in this database.", "danger")
        return redirect(url_for("admin_reports"))

    info = _sqlite_table_info(table)
    columns = [r["name"] for r in info]
    allowed_cols = set(columns)
    selected_columns = [c for c in columns_p if c in allowed_cols] or columns

    if sort_col and sort_col not in allowed_cols:
        sort_col = ""

    where, params = _build_report_where(filters, allowed_cols)
    order = f' ORDER BY "{sort_col}" {sort_dir.upper()}' if sort_col else " ORDER BY rowid DESC"
    sel = ", ".join([f'"{c}"' for c in selected_columns])
    sql = f'SELECT {sel} FROM "{table}"{where}{order} LIMIT ?'

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(selected_columns)
    try:
        with _sqlite_conn() as conn:
            rs = conn.execute(sql, params + [limit]).fetchall()
            for r in rs:
                writer.writerow([r[c] for c in selected_columns])
    except Exception as e:
        flash(f"Preset report export failed: {str(e)}", "danger")
        return redirect(url_for("admin_reports", table=table))

    output.seek(0)
    csv_data = output.getvalue()
    filename = f"preset_{preset_key}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


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


def _get_backup_settings():
    return {
        "backup_dir": get_setting("backup_dir", _backup_dir_default()),
        "backup_retention": _setting_int("backup_retention", 30, min_v=1, max_v=365),
        "backup_auto_delete": _setting_bool("backup_auto_delete", True),
        "backup_allow_manual_delete": _setting_bool("backup_allow_manual_delete", True),
        "backup_schedule_time": get_setting("backup_schedule_time", "02:00") or "02:00",
        "task_name": get_setting("backup_task_name", "TelephonyPortal Nightly Backup") or "TelephonyPortal Nightly Backup",
    }


@app.route("/admin/backups")
@login_required
@admin_required
def admin_backups():
    settings = _get_backup_settings()
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
                backups.append({
                    "name": name,
                    "path": path,
                    "size": st.st_size,
                    "size_human": _human_size(st.st_size),
                    "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "mtime_ts": st.st_mtime,
                })
            except Exception:
                continue
        backups.sort(key=lambda x: x["mtime_ts"], reverse=True)
    except Exception:
        pass

    return render_template("admin/backups.html", settings=settings, backups=backups)


@app.route("/admin/backups/settings", methods=["POST"])
@login_required
@admin_required
def admin_backups_settings():
    backup_dir = (request.form.get("backup_dir") or "").strip() or _backup_dir_default()
    retention = request.form.get("backup_retention") or "30"
    schedule_time = (request.form.get("backup_schedule_time") or "02:00").strip() or "02:00"

    # validate time format HH:MM
    try:
        datetime.strptime(schedule_time, "%H:%M")
    except Exception:
        schedule_time = "02:00"

    auto_delete = "backup_auto_delete" in request.form
    allow_manual_delete = "backup_allow_manual_delete" in request.form

    try:
        # Normalize dir
        backup_dir = os.path.abspath(backup_dir)
        os.makedirs(backup_dir, exist_ok=True)
    except Exception:
        flash("Backup folder is invalid or not writable.", "danger")
        return redirect(url_for("admin_backups"))

    try:
        r = int(retention)
    except Exception:
        r = 30
    r = max(1, min(365, r))

    try:
        set_setting("backup_dir", backup_dir, current_user.username)
        set_setting("backup_retention", str(r), current_user.username)
        set_setting("backup_schedule_time", schedule_time, current_user.username)
        set_setting("backup_auto_delete", "1" if auto_delete else "0", current_user.username)
        set_setting("backup_allow_manual_delete", "1" if allow_manual_delete else "0", current_user.username)
        db.session.commit()
        flash("Backup settings saved.", "success")
    except Exception:
        db.session.rollback()
        flash("Failed to save settings.", "danger")

    return redirect(url_for("admin_backups"))


@app.route("/admin/backups/run", methods=["POST"])
@login_required
@admin_required
def admin_backups_run_now():
    settings = _get_backup_settings()
    backups_dir = settings["backup_dir"]
    retention = settings["backup_retention"]
    auto_delete = settings["backup_auto_delete"]

    res = run_backup_job(db_file_path, backups_dir, retention_count=retention, auto_delete=auto_delete)
    if res.get("ok"):
        deleted_n = len(res.get("deleted") or [])
        flash(f"Backup created: {os.path.basename(res.get('backup_path') or '')} (auto-deleted {deleted_n})", "success")
    else:
        flash(f"Backup failed: {res.get('error')}", "danger")
    return redirect(url_for("admin_backups"))


def _safe_backup_filename(filename: str) -> str:
    name = (filename or "").strip()
    # disallow path traversal
    name = os.path.basename(name)
    if not name.lower().endswith(".db"):
        return ""
    return name


@app.route("/admin/backups/download/<path:filename>")
@login_required
@admin_required
def admin_backups_download(filename):
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


@app.route("/admin/backups/delete/<path:filename>", methods=["POST"])
@login_required
@admin_required
def admin_backups_delete(filename):
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


def _schtasks_create_or_update(task_name: str, run_time_hhmm: str, *, exe_path: str, db_path: str, backup_dir: str):
    # Run as SYSTEM so it can run at 2AM without user logon.
    tr = f"\\\"{exe_path}\\\" --backup-job --db-path \\\"{db_path}\\\" --backup-dir \\\"{backup_dir}\\\""
    cmd = [
        "schtasks.exe",
        "/Create",
        "/TN", task_name,
        "/TR", tr,
        "/SC", "DAILY",
        "/ST", run_time_hhmm,
        "/RU", "SYSTEM",
        "/RL", "HIGHEST",
        "/F",
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def _schtasks_run(task_name: str):
    cmd = ["schtasks.exe", "/Run", "/TN", task_name]
    return subprocess.run(cmd, capture_output=True, text=True)


@app.route("/admin/backups/schedule/install", methods=["POST"])
@login_required
@admin_required
def admin_backups_schedule_install():
    settings = _get_backup_settings()
    task_name = settings["task_name"]
    run_time = settings["backup_schedule_time"] or "02:00"

    # Determine runner (EXE preferred; fallback to python app.py)
    if getattr(sys, "frozen", False):
        exe_path = sys.executable
    else:
        exe_path = sys.executable
        # For source run, call python app.py --backup-job ...
        # (works for dev; production EXE will use frozen path above)
        # We handle this by swapping exe_path to "python.exe" and inserting app.py into args in CLI mode below.
    db_path = os.path.abspath(db_file_path)
    backup_dir = settings["backup_dir"]

    # Ensure paths exist
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        os.makedirs(backup_dir, exist_ok=True)
    except Exception:
        pass

    # If not frozen, we still schedule python.exe but need app.py path.
    if not getattr(sys, "frozen", False):
        app_path = os.path.abspath(__file__)
        tr = f"\\\"{exe_path}\\\" \\\"{app_path}\\\" --backup-job --db-path \\\"{db_path}\\\" --backup-dir \\\"{backup_dir}\\\""
        cmd = [
            "schtasks.exe",
            "/Create",
            "/TN", task_name,
            "/TR", tr,
            "/SC", "DAILY",
            "/ST", run_time,
            "/RU", "SYSTEM",
            "/RL", "HIGHEST",
            "/F",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    else:
        proc = _schtasks_create_or_update(task_name, run_time, exe_path=exe_path, db_path=db_path, backup_dir=backup_dir)

    if proc.returncode == 0:
        flash(f"Scheduled task installed/updated: {task_name} at {run_time}", "success")
    else:
        msg = (proc.stderr or proc.stdout or "").strip()
        flash(f"Failed to install scheduled task. {msg}", "danger")
    return redirect(url_for("admin_backups"))


@app.route("/admin/backups/schedule/run", methods=["POST"])
@login_required
@admin_required
def admin_backups_schedule_run():
    settings = _get_backup_settings()
    task_name = settings["task_name"]
    proc = _schtasks_run(task_name)
    if proc.returncode == 0:
        flash("Scheduled task triggered.", "success")
    else:
        msg = (proc.stderr or proc.stdout or "").strip()
        flash(f"Failed to run scheduled task. {msg}", "danger")
    return redirect(url_for("admin_backups"))


@app.route("/admin/reports/export", methods=["POST"])
@login_required
@admin_required
def admin_reports_export():
    tables = _sqlite_list_tables()
    table, selected_columns, filters, sort_col, sort_dir, limit = _parse_report_request(request.form)

    if table not in tables:
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_reports"))

    info = _sqlite_table_info(table)
    columns = [r["name"] for r in info]
    allowed_cols = set(columns)

    if not selected_columns:
        selected_columns = columns
    selected_columns = [c for c in selected_columns if c in allowed_cols]
    if not selected_columns:
        flash("No valid columns selected.", "danger")
        return redirect(url_for("admin_reports", table=table))

    if sort_col and sort_col not in allowed_cols:
        sort_col = ""

    where, params = _build_report_where(filters, allowed_cols)
    order = f' ORDER BY "{sort_col}" {sort_dir.upper()}' if sort_col else " ORDER BY rowid DESC"
    sel = ", ".join([f'"{c}"' for c in selected_columns])
    sql = f'SELECT {sel} FROM "{table}"{where}{order} LIMIT ?'

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(selected_columns)

    try:
        with _sqlite_conn() as conn:
            rs = conn.execute(sql, params + [limit]).fetchall()
            for r in rs:
                writer.writerow([r[c] for c in selected_columns])
    except Exception as e:
        flash(f"Report export failed: {str(e)}", "danger")
        return redirect(url_for("admin_reports", table=table))

    output.seek(0)
    csv_data = output.getvalue()
    filename = f"report_{table}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )

@app.route('/admin/database/<table>')
@login_required
@admin_required
def admin_table_view(table):
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
    params = []
    if search:
        # LIKE across TEXT-like columns only (SQLite types are loose; we use declared type)
        text_cols = [r["name"] for r in info if (r["type"] or "").upper().startswith(("CHAR", "TEXT", "VARCHAR"))]
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

@app.route('/admin/database/<table>/edit/<int:rowid>', methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_record(table, rowid):
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
                # allow setting NULL via empty string for non-string? keep simple: treat empty as NULL
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

@app.route('/admin/database/<table>/delete/<int:rowid>', methods=["POST"])
@login_required
@admin_required
def admin_delete_record(table, rowid):
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))
    with _sqlite_conn() as conn:
        conn.execute(f"DELETE FROM {table} WHERE rowid = ?", (rowid,))
        conn.commit()
    flash("Record deleted.", "success")
    return redirect(url_for("admin_table_view", table=table))

@app.route('/admin/database/<table>/delete-all', methods=["POST"])
@login_required
@admin_required
def admin_delete_all_records(table):
    """
    Delete ALL rows in a table (dangerous).
    Requires an explicit confirmation string to reduce accidents.
    """
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
            # Respect FK constraints if enabled; if blocked, surface error to admin.
            conn.execute(f'DELETE FROM "{table}"')
            conn.commit()
        flash(f"All rows deleted from {table}.", "success")
    except Exception as e:
        flash(f"Error deleting rows from {table}: {str(e)}", "danger")

    return redirect(url_for("admin_table_view", table=table))

@app.route('/admin/database/<table>/spreadsheet')
@login_required
@admin_required
def admin_table_spreadsheet(table):
    """Spreadsheet-style editable view of database table"""
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        flash("Invalid table.", "danger")
        return redirect(url_for("admin_database"))

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    per_page = max(10, min(per_page, 500))  # Allow more rows in spreadsheet view
    search = request.args.get("search", "")

    info = _sqlite_table_info(table)
    columns = [r["name"] for r in info]
    pk = _sqlite_pk_column(table)

    where = ""
    params = []
    if search:
        text_cols = [r["name"] for r in info if (r["type"] or "").upper().startswith(("CHAR", "TEXT", "VARCHAR"))]
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

@app.route('/admin/database/<table>/update-cell', methods=["POST"])
@login_required
@admin_required
def admin_update_cell(table):
    """API endpoint to update a single cell in spreadsheet view"""
    if table not in _dbadmin_allowed_tables() or not _safe_identifier(table):
        return jsonify({"success": False, "error": "Invalid table"}), 400

    data = request.get_json()
    rowid = data.get("rowid")
    column = data.get("column")
    value = data.get("value")

    if not rowid or not column:
        return jsonify({"success": False, "error": "Missing rowid or column"}), 400

    if not _safe_identifier(column):
        return jsonify({"success": False, "error": "Invalid column name"}), 400

    try:
        with _sqlite_conn() as conn:
            # Check if column exists
            info = _sqlite_table_info(table)
            if column not in [r["name"] for r in info]:
                return jsonify({"success": False, "error": "Column not found"}), 400

            # Update the cell
            if value is None or value == "":
                conn.execute(f"UPDATE {table} SET {column} = NULL WHERE rowid = ?", (rowid,))
            else:
                conn.execute(f"UPDATE {table} SET {column} = ? WHERE rowid = ?", (value, rowid))
            conn.commit()

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/turret')
@login_required
def turret_list():
    page = request.args.get('page', 1, type=int)
    query = DealerboardTurret.query
    
    # Enhanced search with partial matching
    search = request.args.get('search', '')
    if search:
        search_filter = db.or_(
            DealerboardTurret.mac_address.like(f'%{search}%'),
            DealerboardTurret.mac_address_2.like(f'%{search}%'),
            DealerboardTurret.mac_address_3.like(f'%{search}%'),
            DealerboardTurret.mac_address_4.like(f'%{search}%'),
            DealerboardTurret.mac_address_5.like(f'%{search}%'),
            DealerboardTurret.ip_address.like(f'%{search}%'),
            DealerboardTurret.dns_hostname.like(f'%{search}%'),
            DealerboardTurret.zone.like(f'%{search}%'),
            DealerboardTurret.office.like(f'%{search}%'),
            DealerboardTurret.desk_location.like(f'%{search}%')
        )
        query = query.filter(search_filter)
    
    # Filter by country
    country = request.args.get('country', '')
    if country:
        query = query.filter_by(country=country)
    
    # Order by
    sort = request.args.get('sort', 'mac_address')
    order = request.args.get('order', 'asc')
    
    if order == 'desc':
        query = query.order_by(getattr(DealerboardTurret, sort).desc())
    else:
        query = query.order_by(getattr(DealerboardTurret, sort))
    
    turrets = query.paginate(page=page, per_page=20, error_out=False)
    
    return render_template('turret/list.html', 
                          turrets=turrets,
                          search=search,
                          country=country,
                          sort=sort,
                          order=order,
                          countries=get_locations())

@app.route('/turret/add', methods=['GET', 'POST'])
@login_required
def turret_add():
    if request.method == 'POST':
        mac_address = normalize_mac(request.form.get('mac_address'))
        mac_address_2 = normalize_mac(request.form.get('mac_address_2'))
        mac_address_3 = normalize_mac(request.form.get('mac_address_3'))
        mac_address_4 = normalize_mac(request.form.get('mac_address_4'))
        mac_address_5 = normalize_mac(request.form.get('mac_address_5'))

        macs = [mac_address, mac_address_2, mac_address_3, mac_address_4, mac_address_5]
        non_empty_macs = [m for m in macs if m]
        if len(set(non_empty_macs)) != len(non_empty_macs):
            flash('MAC addresses must be unique within the same turret record.', 'danger')
            return redirect(url_for('turret_add'))
        
        # Check if MAC address already exists
        for mac in non_empty_macs:
            if find_turret_by_any_mac(mac):
                flash(f'MAC address already exists: {mac}', 'danger')
                return redirect(url_for('turret_add'))
        
        new_turret = DealerboardTurret(
            mac_address=mac_address,
            mac_address_2=mac_address_2,
            mac_address_3=mac_address_3,
            mac_address_4=mac_address_4,
            mac_address_5=mac_address_5,
            ip_address=request.form.get('ip_address'),
            dns_hostname=(request.form.get('dns_hostname') or '').strip() or None,
            zone=request.form.get('zone'),
            firmware_version=request.form.get('firmware_version'),
            model=request.form.get('model'),
            country=request.form.get('country'),
            office=request.form.get('office'),
            desk_location=request.form.get('desk_location'),
            installed_by=request.form.get('installed_by'),
            installation_date=datetime.strptime(request.form.get('installation_date'), '%Y-%m-%d') if request.form.get('installation_date') else None,
            installation_snow_ref=request.form.get('installation_snow_ref'),
            created_by=current_user.username,
            last_change='Initial creation'
        )
        
        db.session.add(new_turret)
        db.session.commit()
        save_custom_field_values('turrets', new_turret.id, request.form, current_user.username)
        db.session.commit()
        
        flash('Dealerboard turret added successfully', 'success')
        return redirect(url_for('turret_list'))
    
    return render_template('turret/add.html', countries=get_locations(), custom_fields=get_custom_fields('turrets'), custom_values={})

@app.route('/turret/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def turret_edit(id):
    turret = DealerboardTurret.query.get_or_404(id)
    
    if request.method == 'POST':
        mac_address = normalize_mac(request.form.get('mac_address'))
        mac_address_2 = normalize_mac(request.form.get('mac_address_2'))
        mac_address_3 = normalize_mac(request.form.get('mac_address_3'))
        mac_address_4 = normalize_mac(request.form.get('mac_address_4'))
        mac_address_5 = normalize_mac(request.form.get('mac_address_5'))

        macs = [mac_address, mac_address_2, mac_address_3, mac_address_4, mac_address_5]
        non_empty_macs = [m for m in macs if m]
        if len(set(non_empty_macs)) != len(non_empty_macs):
            flash('MAC addresses must be unique within the same turret record.', 'danger')
            return redirect(url_for('turret_edit', id=id))

        # Ensure no other turret already uses any of these MACs
        for mac in non_empty_macs:
            existing = find_turret_by_any_mac(mac)
            if existing and existing.id != turret.id:
                flash(f'MAC address already exists on another turret: {mac}', 'danger')
                return redirect(url_for('turret_edit', id=id))

        turret.mac_address = mac_address
        turret.mac_address_2 = mac_address_2
        turret.mac_address_3 = mac_address_3
        turret.mac_address_4 = mac_address_4
        turret.mac_address_5 = mac_address_5
        turret.ip_address = request.form.get('ip_address')
        turret.dns_hostname = (request.form.get('dns_hostname') or '').strip() or None
        turret.zone = request.form.get('zone')
        turret.firmware_version = request.form.get('firmware_version')
        turret.model = request.form.get('model')
        turret.country = request.form.get('country')
        turret.office = request.form.get('office')
        turret.desk_location = request.form.get('desk_location')
        turret.installed_by = request.form.get('installed_by')
        
        installation_date_str = request.form.get('installation_date')
        if installation_date_str:
            turret.installation_date = datetime.strptime(installation_date_str, '%Y-%m-%d')
        
        turret.installation_snow_ref = request.form.get('installation_snow_ref')
        turret.status = request.form.get('status')
        
        turret.last_updated = datetime.utcnow()
        turret.last_updated_by = current_user.username
        turret.last_change = f'Updated by {current_user.username}'
        
        db.session.commit()
        save_custom_field_values('turrets', turret.id, request.form, current_user.username)
        db.session.commit()
        
        flash('Dealerboard turret updated successfully', 'success')
        return redirect(url_for('turret_list'))
    
    return render_template('turret/edit.html', 
                          turret=turret,
                          countries=get_locations(),
                          custom_fields=get_custom_fields('turrets'),
                          custom_values=get_custom_field_values('turrets', turret.id))


@app.route('/turret/rma')
@login_required
def turret_rma_list():
    page = request.args.get('page', 1, type=int)
    query = CeasedRMATurret.query

    search = request.args.get('search', '')
    if search:
        search_filter = db.or_(
            CeasedRMATurret.mac_address.like(f'%{search}%'),
            CeasedRMATurret.mac_address_2.like(f'%{search}%'),
            CeasedRMATurret.mac_address_3.like(f'%{search}%'),
            CeasedRMATurret.mac_address_4.like(f'%{search}%'),
            CeasedRMATurret.mac_address_5.like(f'%{search}%'),
            CeasedRMATurret.ip_address.like(f'%{search}%'),
            CeasedRMATurret.dns_hostname.like(f'%{search}%'),
            CeasedRMATurret.zone.like(f'%{search}%'),
            CeasedRMATurret.office.like(f'%{search}%'),
            CeasedRMATurret.desk_location.like(f'%{search}%'),
            CeasedRMATurret.dealerboard_issue.like(f'%{search}%'),
            CeasedRMATurret.summary.like(f'%{search}%'),
            CeasedRMATurret.moved_by.like(f'%{search}%'),
        )
        query = query.filter(search_filter)

    country = request.args.get('country', '')
    if country:
        query = query.filter_by(country=country)

    query = query.order_by(CeasedRMATurret.moved_at.desc())
    turrets = query.paginate(page=page, per_page=20, error_out=False)

    return render_template(
        'turret_rma/list.html',
        turrets=turrets,
        search=search,
        country=country,
        countries=get_locations(),
    )


@app.route('/turret/rma/<int:id>', methods=['POST'])
@login_required
@admin_required
def turret_rma(id):
    turret = DealerboardTurret.query.get_or_404(id)

    rma_date_sent = None
    rma_date_received = None
    try:
        v = (request.form.get('rma_date_sent') or '').strip()
        rma_date_sent = datetime.strptime(v, '%Y-%m-%d').date() if v else None
    except Exception:
        rma_date_sent = None
    try:
        v = (request.form.get('rma_date_received') or '').strip()
        rma_date_received = datetime.strptime(v, '%Y-%m-%d').date() if v else None
    except Exception:
        rma_date_received = None

    dealerboard_issue = (request.form.get('dealerboard_issue') or '').strip()[:100] or None
    summary = (request.form.get('rma_summary') or '').strip()[:100] or None

    archived = CeasedRMATurret(
        original_turret_id=turret.id,
        moved_at=datetime.utcnow(),
        moved_by=current_user.username,
        move_reason='RMA',
        mac_address=turret.mac_address,
        mac_address_2=turret.mac_address_2,
        mac_address_3=turret.mac_address_3,
        mac_address_4=turret.mac_address_4,
        mac_address_5=turret.mac_address_5,
        ip_address=turret.ip_address,
        dns_hostname=turret.dns_hostname,
        zone=turret.zone,
        firmware_version=turret.firmware_version,
        model=turret.model,
        country=turret.country,
        office=turret.office,
        desk_location=turret.desk_location,
        installed_by=turret.installed_by,
        installation_date=turret.installation_date,
        installation_snow_ref=turret.installation_snow_ref,
        status=turret.status,
        created_by=turret.created_by,
        last_updated_by=turret.last_updated_by,
        date_created=turret.date_created,
        last_updated=turret.last_updated,
        last_change=turret.last_change,
        custom_fields_json=snapshot_custom_fields_json('turrets', turret.id),
        rma_date_sent=rma_date_sent,
        rma_date_received=rma_date_received,
        dealerboard_issue=dealerboard_issue,
        summary=summary,
    )
    db.session.add(archived)

    # Clean up dependent rows to avoid orphaned references.
    try:
        CustomFieldValue.query.filter_by(entity='turrets', record_id=turret.id).delete(synchronize_session=False)
    except Exception:
        pass
    try:
        TurretMove.query.filter_by(turret_id=turret.id).delete(synchronize_session=False)
    except Exception:
        pass

    db.session.delete(turret)
    db.session.commit()
    flash('Turret moved to Ceased/RMA Turrets and removed from Dealerboard Turrets.', 'success')
    return redirect(url_for('turret_list'))

@app.route('/turret/import', methods=['GET', 'POST'])
@login_required
@admin_required
def turret_import():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file:
            filename = save_uploaded_file(file)
            if filename:
                return redirect(url_for('dynamic_field_mapping', import_type='turret', file=filename))
            else:
                flash('Error saving file', 'danger')
    
    return render_template('turret/import.html')

@app.route('/turret/import/execute')
@login_required
@admin_required
def turret_import_execute():
    """Execute Turret import using stored mappings"""
    mappings = session.get('turret_mappings')
    csv_filename = session.get('turret_csv_file')
    
    if not mappings or not csv_filename:
        flash('Import session expired. Please start over.', 'danger')
        return redirect(url_for('turret_import'))
    
    csv_path = os.path.join(app.config['UPLOAD_FOLDER'], csv_filename)
    
    try:
        counter = {'added': 0, 'updated': 0, 'skipped': 0}
        batch_size = _import_batch_size()
        pending = 0
        importer = current_user.username
        
        with open(csv_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            
            for row in csv_reader:
                # Extract mapped fields
                mapped_data = {}
                for field_name, csv_header in mappings.items():
                    mapped_data[field_name] = row.get(csv_header, '').strip()
                
                mac_address = normalize_mac(mapped_data.get('mac_address', ''))
                
                if not mac_address:
                    counter['skipped'] += 1
                    continue
                
                # Check if this MAC is already present in any MAC field
                existing_turret = find_turret_by_any_mac(mac_address)
                
                if existing_turret:
                    # Update existing record but preserve specific fields
                    for field_name, value in mapped_data.items():
                        if hasattr(existing_turret, field_name) and value and field_name not in ['country', 'office', 'desk_location']:
                            if field_name.startswith('mac_address'):
                                setattr(existing_turret, field_name, normalize_mac(value))
                            else:
                                setattr(existing_turret, field_name, value)
                    
                    existing_turret.last_updated = datetime.utcnow()
                    existing_turret.last_updated_by = current_user.username
                    existing_turret.last_change = f'Updated from import by {importer}'
                    counter['updated'] += 1
                    pending += 1
                else:
                    # Create new record
                    new_turret = DealerboardTurret(
                        **{k: v for k, v in mapped_data.items() if hasattr(DealerboardTurret, k) and v},
                        created_by=current_user.username,
                        last_change=f'Added from import by {importer}'
                    )
                    # Normalize any MAC fields that may have been imported
                    for f in ['mac_address', 'mac_address_2', 'mac_address_3', 'mac_address_4', 'mac_address_5']:
                        if getattr(new_turret, f, None):
                            setattr(new_turret, f, normalize_mac(getattr(new_turret, f)))
                    db.session.add(new_turret)
                    counter['added'] += 1
                    pending += 1

                if pending >= batch_size:
                    db.session.commit()
                    db.session.close()
                    pending = 0
        
        db.session.commit()
        db.session.close()
        flash(f'Import completed: {counter["added"]} added, {counter["updated"]} updated, {counter["skipped"]} skipped', 'success')
        
        # Clean up
        session.pop('turret_mappings', None)
        session.pop('turret_csv_file', None)
        os.remove(csv_path)
        
    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'danger')
    
    return redirect(url_for('turret_list'))

@app.route('/turret/export')
@login_required
def turret_export():
    # Create a CSV file in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'MAC Address', 'MAC Address 2', 'MAC Address 3', 'MAC Address 4', 'MAC Address 5',
        'IP Address', 'DNS/Hostname', 'Zone', 'Firmware Version', 'Model',
        'Country', 'Office', 'Desk Location', 'Installed By', 'Installation Date',
        'Installation SNOW Ref', 'Status', 'Last Updated', 'Last Change'
    ])
    
    # Query all Turrets
    turrets = DealerboardTurret.query.all()
    
    # Write data
    for turret in turrets:
        writer.writerow([
            turret.mac_address,
            turret.mac_address_2,
            turret.mac_address_3,
            turret.mac_address_4,
            turret.mac_address_5,
            turret.ip_address,
            turret.dns_hostname,
            turret.zone,
            turret.firmware_version,
            turret.model,
            turret.country,
            turret.office,
            turret.desk_location,
            turret.installed_by,
            turret.installation_date.strftime('%Y-%m-%d') if turret.installation_date else '',
            turret.installation_snow_ref,
            turret.status,
            turret.last_updated.strftime('%Y-%m-%d %H:%M:%S'),
            turret.last_change
        ])
    
    # Prepare response
    output.seek(0)
    csv_data = output.getvalue()
    
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=dealerboard_turrets.csv"}
    )

# =====================================================================
# Routes - Turret Moves Management
# =====================================================================

@app.route('/turret/moves')
@login_required
def turret_moves_list():
    page = request.args.get('page', 1, type=int)
    
    # Query move groups with additional statistics
    query = db.session.query(
        TurretMoveGroup,
        db.func.count(TurretMove.id).label('turret_count'),
        db.func.sum(db.case((TurretMove.status == 'Completed', 1), else_=0)).label('completed_moves')
    ).outerjoin(TurretMove).group_by(TurretMoveGroup.id)
    
    # Apply filters
    search = request.args.get('search', '')
    if search:
        query = query.filter(
            db.or_(
                TurretMoveGroup.move_name.like(f'%{search}%'),
                TurretMoveGroup.created_by.like(f'%{search}%'),
                TurretMoveGroup.description.like(f'%{search}%')
            )
        )
    
    status = request.args.get('status', '')
    if status:
        query = query.filter(TurretMoveGroup.status == status)
    
    priority = request.args.get('priority', '')
    if priority:
        query = query.having(db.func.max(TurretMove.priority) == priority)
    
    # Order by creation date (newest first)
    query = query.order_by(TurretMoveGroup.created_date.desc())
    
    # Paginate
    move_groups_data = query.paginate(page=page, per_page=12, error_out=False)
    
    # Convert to objects with additional attributes
    move_groups_list = []
    for move_group, turret_count, completed_moves in move_groups_data.items:
        move_group.turret_count = turret_count or 0
        move_group.completed_moves = completed_moves or 0
        # Get the highest priority from moves in this group
        max_priority = db.session.query(db.func.max(TurretMove.priority)).filter_by(move_group_id=move_group.id).scalar()
        move_group.priority = max_priority or 'Normal'
        move_groups_list.append(move_group)
    
    # Create paginated object manually
    class MockPagination:
        def __init__(self, items, page, per_page, total):
            self.items = items
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1 if self.has_prev else None
            self.next_num = page + 1 if self.has_next else None
        
        def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
            last = self.pages
            for num in range(1, last + 1):
                if num <= left_edge or \
                   (self.page - left_current - 1 < num < self.page + right_current) or \
                   num > last - right_edge:
                    yield num
    
    move_groups = MockPagination(move_groups_list, move_groups_data.page, move_groups_data.per_page, move_groups_data.total)
    
    return render_template('turret/moves_list.html',
                          move_groups=move_groups,
                          search=search,
                          status=status,
                          priority=priority)

@app.route('/turret/moves/plan', methods=['GET', 'POST'])
@login_required
def turret_plan_move():
    if request.method == 'POST':
        move_name = request.form.get('move_name')
        description = request.form.get('description')
        planned_execution_date_str = request.form.get('planned_execution_date')
        
        # Create move group
        move_group = TurretMoveGroup(
            move_name=move_name,
            description=description,
            created_by=current_user.username,
            planned_execution_date=datetime.strptime(planned_execution_date_str, '%Y-%m-%dT%H:%M') if planned_execution_date_str else None,
            last_updated_by=current_user.username
        )
        
        db.session.add(move_group)
        db.session.flush()  # Get the ID
        
        # Process selected turrets
        selected_turrets = request.form.getlist('selected_turrets')
        
        for turret_id in selected_turrets:
            turret = DealerboardTurret.query.get(turret_id)
            if turret:
                to_desk = request.form.get(f'to_desk_{turret_id}')
                to_office = request.form.get(f'to_office_{turret_id}')
                to_country = request.form.get(f'to_country_{turret_id}')
                move_reason = request.form.get(f'move_reason_{turret_id}')
                priority = request.form.get(f'priority_{turret_id}', 'Normal')
                
                if to_desk:  # Only create move if destination is specified
                    move = TurretMove(
                        move_group_id=move_group.id,
                        turret_id=turret.id,
                        from_desk=turret.desk_location,
                        to_desk=to_desk,
                        from_office=turret.office,
                        to_office=to_office,
                        from_country=turret.country,
                        to_country=to_country,
                        move_reason=move_reason,
                        priority=priority,
                        requires_network_config=bool(request.form.get(f'network_config_{turret_id}')),
                        requires_phone_config=bool(request.form.get(f'phone_config_{turret_id}'))
                    )
                    db.session.add(move)
        
        db.session.commit()
        flash(f'Move group "{move_name}" created successfully', 'success')
        return redirect(url_for('turret_moves_list'))
    
    # Get all turrets for selection
    turrets = DealerboardTurret.query.filter_by(status='Active').order_by(DealerboardTurret.desk_location).all()
    
    return render_template('turret/plan_move.html',
                          turrets=turrets,
                          countries=get_locations())

@app.route('/turret/moves/view/<int:id>')
@login_required
def turret_view_move_group(id):
    move_group = TurretMoveGroup.query.get_or_404(id)
    moves = TurretMove.query.filter_by(move_group_id=id).join(DealerboardTurret).all()
    
    return render_template('turret/view_move_group.html',
                          move_group=move_group,
                          moves=moves)

@app.route('/turret/moves/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def turret_edit_move_group(id):
    move_group = TurretMoveGroup.query.get_or_404(id)
    
    if move_group.status not in ['Planning', 'Approved']:
        flash('Cannot edit move group in current status', 'danger')
        return redirect(url_for('turret_view_move_group', id=id))
    
    if request.method == 'POST':
        move_group.move_name = request.form.get('move_name')
        move_group.description = request.form.get('description')
        
        planned_execution_date_str = request.form.get('planned_execution_date')
        if planned_execution_date_str:
            move_group.planned_execution_date = datetime.strptime(planned_execution_date_str, '%Y-%m-%dT%H:%M')
        
        move_group.last_updated = datetime.utcnow()
        move_group.last_updated_by = current_user.username
        
        # Update individual moves
        for move in move_group.moves:
            move.to_desk = request.form.get(f'to_desk_{move.id}')
            move.to_office = request.form.get(f'to_office_{move.id}')
            move.to_country = request.form.get(f'to_country_{move.id}')
            move.move_reason = request.form.get(f'move_reason_{move.id}')
            move.priority = request.form.get(f'priority_{move.id}', 'Normal')
            move.requires_network_config = bool(request.form.get(f'network_config_{move.id}'))
            move.requires_phone_config = bool(request.form.get(f'phone_config_{move.id}'))
        
        db.session.commit()
        flash('Move group updated successfully', 'success')
        return redirect(url_for('turret_view_move_group', id=id))
    
    return render_template('turret/edit_move_group.html',
                          move_group=move_group,
                          countries=get_locations())

@app.route('/turret/moves/execute', methods=['POST'])
@login_required
@admin_required
def turret_execute_move():
    move_group_id = request.form.get('move_group_id')
    execution_notes = request.form.get('execution_notes', '')
    
    move_group = TurretMoveGroup.query.get_or_404(move_group_id)
    
    if move_group.status != 'Approved':
        flash('Move group must be approved before execution', 'danger')
        return redirect(url_for('turret_moves_list'))
    
    try:
        # Update move group status
        move_group.status = 'In Progress'
        move_group.executed_date = datetime.utcnow()
        move_group.executed_by = current_user.username
        move_group.notes = execution_notes
        
        # Execute each move
        for move in move_group.moves:
            if move.status == 'Planned':
                # Get the turret
                turret = move.turret
                
                # Create history record
                history = TurretMoveHistory(
                    turret_id=turret.id,
                    move_id=move.id,
                    move_group_id=move_group.id,
                    from_desk=turret.desk_location,
                    to_desk=move.to_desk,
                    from_office=turret.office,
                    to_office=move.to_office,
                    from_country=turret.country,
                    to_country=move.to_country,
                    move_date=datetime.utcnow(),
                    moved_by=current_user.username,
                    move_reason=move.move_reason,
                    snow_reference=move.snow_reference,
                    notes=execution_notes
                )
                db.session.add(history)
                
                # Update turret location
                turret.desk_location = move.to_desk
                if move.to_office:
                    turret.office = move.to_office
                if move.to_country:
                    turret.country = move.to_country
                
                turret.last_updated = datetime.utcnow()
                turret.last_updated_by = current_user.username
                turret.last_change = f'Moved from {move.from_desk} to {move.to_desk} via move group {move_group.move_name}'
                
                # Update move status
                move.status = 'Completed'
                move.executed_date = datetime.utcnow()
        
        # Update move group to completed
        move_group.status = 'Completed'
        
        db.session.commit()
        flash(f'Move group "{move_group.move_name}" executed successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error executing moves: {str(e)}', 'danger')
    
    return redirect(url_for('turret_moves_list'))

@app.route('/turret/moves/approve/<int:id>', methods=['POST'])
@login_required
@admin_required
def turret_approve_move_group(id):
    move_group = TurretMoveGroup.query.get_or_404(id)
    
    if move_group.status != 'Planning':
        flash('Move group is not in planning status', 'danger')
        return redirect(url_for('turret_view_move_group', id=id))
    
    move_group.status = 'Approved'
    move_group.last_updated = datetime.utcnow()
    move_group.last_updated_by = current_user.username
    
    db.session.commit()
    flash(f'Move group "{move_group.move_name}" approved', 'success')
    
    return redirect(url_for('turret_view_move_group', id=id))

@app.route('/turret/move-history')
@login_required
def turret_move_history():
    page = request.args.get('page', 1, type=int)
    query = TurretMoveHistory.query.join(DealerboardTurret)
    
    # Filter by search term
    search = request.args.get('search', '')
    if search:
        search_filter = db.or_(
            DealerboardTurret.mac_address.like(f'%{search}%'),
            TurretMoveHistory.from_desk.like(f'%{search}%'),
            TurretMoveHistory.to_desk.like(f'%{search}%'),
            TurretMoveHistory.moved_by.like(f'%{search}%')
        )
        query = query.filter(search_filter)
    
    # Order by move date (newest first)
    query = query.order_by(TurretMoveHistory.move_date.desc())
    
    move_history = query.paginate(page=page, per_page=20, error_out=False)
    
    return render_template('turret/move_history.html',
                          move_history=move_history,
                          search=search)

@app.route('/turret/<int:id>/history')
@login_required
def turret_individual_history(id):
    turret = DealerboardTurret.query.get_or_404(id)
    history = TurretMoveHistory.query.filter_by(turret_id=id).order_by(TurretMoveHistory.move_date.desc()).all()
    
    return render_template('turret/turret_history.html',
                          turret=turret,
                          history=history)

# =====================================================================
# Database Backup Route
# =====================================================================

@app.route('/admin/backup-database')
@login_required
@admin_required
def backup_database():
    """
    Download a backup of the SQLite database (browser download).
    We do not persist backups on the server; a temporary file is created and removed after the response.
    """
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    backup_filename = f"telephony_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"

    def _sqlite_backup(src_path: str, dest_path: str):
        # Use SQLite online backup API (faster/safer than raw file copy for live DBs)
        src = sqlite3.connect(src_path, timeout=30, check_same_thread=False)
        try:
            dest = sqlite3.connect(dest_path, timeout=30, check_same_thread=False)
            try:
                src.backup(dest)
            finally:
                dest.close()
        finally:
            src.close()

    try:
        # Close sessions and dispose engine to reduce chances of locked DB file on Windows
        db.session.close()
        try:
            db.engine.dispose()
        except Exception:
            pass

        # Create a temp file and delete it after sending.
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
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash(f'Error creating database backup: {str(e)}', 'danger')
        return redirect(url_for('index'))

# =====================================================================
# Database Restore Route
# =====================================================================

@app.route('/admin/restore-database', methods=['GET', 'POST'])
@login_required
@admin_required
def restore_database():
    """
    Restore the SQLite database from a user-provided .db file uploaded via browser.
    """
    if request.method == 'GET':
        return render_template('admin/restore_database.html')

    try:
        if 'file' not in request.files:
            flash('No file provided.', 'danger')
            return redirect(url_for('restore_database'))

        f = request.files['file']
        if not f or not f.filename:
            flash('No file selected.', 'danger')
            return redirect(url_for('restore_database'))

        filename = secure_filename(f.filename)
        if not filename.lower().endswith('.db'):
            flash('Please upload a .db SQLite backup file.', 'danger')
            return redirect(url_for('restore_database'))

        tmp = tempfile.NamedTemporaryFile(prefix="telephony_restore_", suffix=".db", delete=False)
        tmp_path = tmp.name
        tmp.close()
        f.save(tmp_path)

        # Close sessions and dispose engine to reduce chances of locked DB file on Windows
        db.session.close()
        try:
            db.engine.dispose()
        except Exception:
            pass

        # Restore by copying contents from the selected DB into the live DB file
        # (uses SQLite online backup API, so it is safe/fast)
        live_path = db_file_path
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

        # Ensure restored DB is compatible with current app version (backward compatibility)
        try:
            with app.app_context():
                try:
                    _configure_sqlite_engine(db.engine)
                except Exception:
                    pass
                db.create_all()
                ensure_sqlite_schema()
                try:
                    seed_lookup_defaults()
                except Exception:
                    logging.exception("seed_lookup_defaults failed after restore")
        except Exception:
            logging.exception("Post-restore compatibility upgrade failed")

        flash('Database restored successfully. The database was upgraded for compatibility.', 'success')
        return redirect(url_for('admin_database'))
    except Exception as e:
        flash(f'Error restoring database: {str(e)}', 'danger')
        return redirect(url_for('restore_database'))

# =====================================================================
# API Routes for AJAX functionality
# =====================================================================

@app.route('/api/turrets/search')
@login_required
def api_turrets_search():
    """API endpoint for turret search with AJAX"""
    search = request.args.get('q', '')
    
    query = DealerboardTurret.query.filter_by(status='Active')
    
    if search:
        search_filter = db.or_(
            DealerboardTurret.mac_address.like(f'%{search}%'),
            DealerboardTurret.mac_address_2.like(f'%{search}%'),
            DealerboardTurret.mac_address_3.like(f'%{search}%'),
            DealerboardTurret.mac_address_4.like(f'%{search}%'),
            DealerboardTurret.mac_address_5.like(f'%{search}%'),
            DealerboardTurret.desk_location.like(f'%{search}%'),
            DealerboardTurret.office.like(f'%{search}%')
        )
        query = query.filter(search_filter)
    
    turrets = query.limit(20).all()
    
    results = []
    for turret in turrets:
        results.append({
            'id': turret.id,
            'mac_address': turret.mac_address,
            'desk_location': turret.desk_location or '',
            'office': turret.office or '',
            'country': turret.country or ''
        })
    
    return jsonify(results)

# =====================================================================
# Initialize Database Command (for Flask CLI)
# =====================================================================

@app.cli.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    db.drop_all()
    db.create_all()
    
    # Create admin user
    admin_user = User(
        username='admin',
        password=generate_password_hash('admin'),
        role='admin'
    )
    db.session.add(admin_user)
    
    # Create regular user
    regular_user = User(
        username='user',
        password=generate_password_hash('user'),
        role='user'
    )
    db.session.add(regular_user)
    
    db.session.commit()
    logging.info('Initialized the database.')

# =====================================================================
# Global Error Handlers - Prevent Server Crashes
# =====================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors gracefully"""
    try:
        return render_template('errors/404.html'), 404
    except Exception:
        return '<h1>Page Not Found</h1><p>The requested page could not be found.</p>', 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors gracefully and rollback database session"""
    try:
        db.session.rollback()
    except Exception:
        pass
    logging.exception("Internal server error")
    try:
        return render_template('errors/500.html'), 500
    except Exception:
        return '<h1>Internal Server Error</h1><p>An error occurred. Please try again later.</p>', 500

# Note: We don't register a catch-all Exception handler here because Flask handles that
# through the 500 error handler. However, we ensure all database operations are wrapped
# in try-except blocks in individual routes to prevent crashes.

@app.teardown_appcontext
def close_db(error):
    """Ensure database session is closed after each request"""
    try:
        if error:
            # If there was an error, rollback the session
            db.session.rollback()
        db.session.remove()
    except Exception as e:
        # Log but don't crash if session cleanup fails
        logging.warning("Error during database session cleanup: %s", str(e))
        pass

# =====================================================================
# Run the application
# =====================================================================

if __name__ == '__main__':
    try:
        logging.info("Starting TelephonyPortal (%s)", "frozen" if getattr(sys, 'frozen', False) else "source")
        logging.info("DB path: %s", db_file_path)
        port = int(os.environ.get("TELEPHONY_PORT", "5500"))
        host = os.environ.get("TELEPHONY_HOST", "0.0.0.0")
        if host.strip() in {"*", "0", "0.0.0.0"}:
            host = "0.0.0.0"
        logging.info("Port: %s", port)
        logging.info("Host: %s", host)
        # Desktop dialogs (Tkinter, used for backup/restore in "dialog" mode) must be invoked on the main thread on Windows.
        # For shared-server EXE usage, desktop dialogs should be disabled and we can safely run multi-threaded.
        def _env_bool(name: str, default: bool) -> bool:
            v = os.environ.get(name)
            if v is None:
                return default
            return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}

        desktop_dialogs = _env_bool("TELEPHONY_DESKTOP_DIALOGS", default=False)
        default_threaded = True if (getattr(sys, 'frozen', False) and not desktop_dialogs) else (not getattr(sys, 'frozen', False))
        threaded = _env_bool("TELEPHONY_THREADED", default=default_threaded)
        logging.info("Threaded: %s", threaded)
        logging.info("Desktop dialogs enabled: %s", desktop_dialogs)

        # Create all tables if they don't exist
        with app.app_context():
            _configure_sqlite_engine(db.engine)
            db.create_all()
            ensure_sqlite_schema()
            try:
                seed_lookup_defaults()
            except Exception:
                logging.exception("seed_lookup_defaults failed")

            # One-off CLI: scheduled backup job
            if "--backup-job" in sys.argv:
                settings = _get_backup_settings()
                db_path = os.environ.get("TELEPHONY_DB_PATH") or _cli_arg_value("--db-path") or db_file_path
                backups_dir = _cli_arg_value("--backup-dir") or settings["backup_dir"]
                retention = settings["backup_retention"]
                auto_delete = settings["backup_auto_delete"]
                logging.info("Running backup job. db=%s backups_dir=%s retention=%s auto_delete=%s", db_path, backups_dir, retention, auto_delete)
                res = run_backup_job(db_path, backups_dir, retention_count=retention, auto_delete=auto_delete)
                if res.get("ok"):
                    logging.info("Backup job ok. backup=%s deleted=%s", res.get("backup_path"), len(res.get("deleted") or []))
                    raise SystemExit(0)
                logging.error("Backup job failed: %s", res.get("error"))
                raise SystemExit(2)

        # Prefer a production WSGI server (Waitress) when requested.
        # This avoids common "hangs" seen with the Flask dev server under load/long requests.
        use_waitress = _env_bool("TELEPHONY_USE_WAITRESS", default=True if getattr(sys, 'frozen', False) else False)
        waitress_threads = int(os.environ.get("TELEPHONY_WAITRESS_THREADS", "8"))
        # When running as an EXE, we generally do NOT want to silently fall back to the Flask dev server.
        allow_dev_fallback = _env_bool(
            "TELEPHONY_ALLOW_DEV_FALLBACK",
            default=False if getattr(sys, 'frozen', False) else True,
        )
        if use_waitress:
            try:
                from waitress import serve
                logging.info("Serving with Waitress")
                serve(app, host=host, port=port, threads=max(1, waitress_threads))
            except Exception:
                logging.exception("Failed to start Waitress")
                if not allow_dev_fallback:
                    raise
                logging.warning("Falling back to Flask dev server (TELEPHONY_ALLOW_DEV_FALLBACK=1)")
                logging.info("Serving with Flask dev server (fallback)")
                app.run(host=host, port=port, debug=False, use_reloader=False, threaded=threaded)
        else:
            # Run the Flask development server
            logging.info("Serving with Flask dev server")
            app.run(
                host=host,
                port=port,
                debug=not getattr(sys, 'frozen', False),
                use_reloader=False,
                threaded=threaded,
            )
    except Exception as e:
        logging.exception("Fatal startup error")
        if getattr(sys, 'frozen', False):
            log_hint = STARTUP_LOG_PATH or os.path.join(_app_data_dir(), 'logs', 'startup.log')
            _show_fatal_message(f"TelephonyPortal failed to start.\n\nSee log:\n{log_hint}\n\nError:\n{e}")
        raise
