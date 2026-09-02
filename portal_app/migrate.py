from __future__ import annotations

from sqlalchemy import text

from .db import db
from .models import ActivityLogEntry, ChangeRecord, LookupOption, User


def ensure_schema(engine) -> None:
    db.create_all()

    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA foreign_keys=ON"))

        try:
            exists = conn.execute(
                text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='import_mapping_template' LIMIT 1")
            ).fetchone()
            if not exists:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS import_mapping_template (
                            id INTEGER PRIMARY KEY,
                            template_name VARCHAR(100) NOT NULL,
                            import_type VARCHAR(50) NOT NULL,
                            field_mappings TEXT NOT NULL,
                            created_by VARCHAR(100) NOT NULL,
                            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                            last_used_date DATETIME,
                            is_default BOOLEAN DEFAULT 0
                        )
                        """
                    )
                )
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            exists = conn.execute(
                text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='custom_field_value' LIMIT 1")
            ).fetchone()
            if not exists:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS custom_field_value (
                            id INTEGER PRIMARY KEY,
                            entity VARCHAR(50) NOT NULL,
                            record_id INTEGER NOT NULL,
                            field_key VARCHAR(100) NOT NULL,
                            field_value TEXT,
                            last_updated DATETIME,
                            last_updated_by VARCHAR(100)
                        )
                        """
                    )
                )
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            exists = conn.execute(
                text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='activity_log' LIMIT 1")
            ).fetchone()
            if not exists:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS activity_log (
                            id INTEGER PRIMARY KEY,
                            created_at DATETIME,
                            username VARCHAR(100),
                            action_type VARCHAR(100),
                            method VARCHAR(20),
                            path VARCHAR(500),
                            success BOOLEAN DEFAULT 1,
                            details VARCHAR(1000)
                        )
                        """
                    )
                )
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        # Older DBs may have a reduced user table. Ensure required columns exist so auth/login works.
        try:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(user)")).fetchall()}
            for col_name, col_sql in (
                ("is_active", "ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"),
                ("disabled_date", "ALTER TABLE user ADD COLUMN disabled_date DATETIME"),
                ("disabled_by", "ALTER TABLE user ADD COLUMN disabled_by VARCHAR(100)"),
                ("disable_reason", "ALTER TABLE user ADD COLUMN disable_reason VARCHAR(500)"),
                ("must_change_password", "ALTER TABLE user ADD COLUMN must_change_password BOOLEAN DEFAULT 0"),
                ("can_approve_changes", "ALTER TABLE user ADD COLUMN can_approve_changes BOOLEAN DEFAULT 0"),
                ("can_provide_regional_approval", "ALTER TABLE user ADD COLUMN can_provide_regional_approval BOOLEAN DEFAULT 0"),
                ("can_approve_global_service", "ALTER TABLE user ADD COLUMN can_approve_global_service BOOLEAN DEFAULT 0"),
                ("can_approve_turret_moves", "ALTER TABLE user ADD COLUMN can_approve_turret_moves BOOLEAN DEFAULT 0"),
                ("can_execute_turret_moves", "ALTER TABLE user ADD COLUMN can_execute_turret_moves BOOLEAN DEFAULT 0"),
                ("can_import_turret_moves", "ALTER TABLE user ADD COLUMN can_import_turret_moves BOOLEAN DEFAULT 0"),
                ("can_export_turret_moves", "ALTER TABLE user ADD COLUMN can_export_turret_moves BOOLEAN DEFAULT 0"),
                ("can_import_private_wires", "ALTER TABLE user ADD COLUMN can_import_private_wires BOOLEAN DEFAULT 0"),
                ("can_export_private_wires", "ALTER TABLE user ADD COLUMN can_export_private_wires BOOLEAN DEFAULT 0"),
                ("last_activity", "ALTER TABLE user ADD COLUMN last_activity DATETIME"),
                ("name", "ALTER TABLE user ADD COLUMN name VARCHAR(200)"),
            ):
                if col_name not in cols:
                    conn.execute(text(col_sql))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(dealerboard_turret)")).fetchall()}
            if "switchport_1" not in cols:
                conn.execute(text("ALTER TABLE dealerboard_turret ADD COLUMN switchport_1 VARCHAR(100)"))
            if "switchport_2" not in cols:
                conn.execute(text("ALTER TABLE dealerboard_turret ADD COLUMN switchport_2 VARCHAR(100)"))
            if "serial_number" not in cols:
                conn.execute(text("ALTER TABLE dealerboard_turret ADD COLUMN serial_number VARCHAR(100)"))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            exists = conn.execute(
                text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ceased_rma_turret' LIMIT 1")
            ).fetchone()
            if exists:
                cols = {r[1] for r in conn.execute(text("PRAGMA table_info(ceased_rma_turret)")).fetchall()}
                if "serial_number" not in cols:
                    conn.execute(text("ALTER TABLE ceased_rma_turret ADD COLUMN serial_number VARCHAR(100)"))
                if "custom_fields_json" not in cols:
                    conn.execute(text("ALTER TABLE ceased_rma_turret ADD COLUMN custom_fields_json TEXT"))
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            exists = conn.execute(
                text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ceased_private_wire' LIMIT 1")
            ).fetchone()
            if exists:
                cols = {r[1] for r in conn.execute(text("PRAGMA table_info(ceased_private_wire)")).fetchall()}
                for col_name, col_sql in (
                    ("aor_number", "ALTER TABLE ceased_private_wire ADD COLUMN aor_number VARCHAR(50)"),
                    ("port_number", "ALTER TABLE ceased_private_wire ADD COLUMN port_number VARCHAR(50)"),
                    ("channel_number", "ALTER TABLE ceased_private_wire ADD COLUMN channel_number VARCHAR(50)"),
                    ("custom_fields_json", "ALTER TABLE ceased_private_wire ADD COLUMN custom_fields_json TEXT"),
                ):
                    if col_name not in cols:
                        conn.execute(text(col_sql))
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(change_record)")).fetchall()}
            if "custom_fields_json" not in cols:
                conn.execute(text("ALTER TABLE change_record ADD COLUMN custom_fields_json TEXT"))
            if "rtc_cab" not in cols:
                conn.execute(text("ALTER TABLE change_record ADD COLUMN rtc_cab BOOLEAN DEFAULT 0"))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(incident_record)")).fetchall()}
            if "custom_fields_json" not in cols:
                conn.execute(text("ALTER TABLE incident_record ADD COLUMN custom_fields_json TEXT"))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(private_wire)")).fetchall()}
            if "custom_fields_json" not in cols:
                conn.execute(text("ALTER TABLE private_wire ADD COLUMN custom_fields_json TEXT"))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

        try:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(dealerboard_turret)")).fetchall()}
            if "custom_fields_json" not in cols:
                conn.execute(text("ALTER TABLE dealerboard_turret ADD COLUMN custom_fields_json TEXT"))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

    try:
        _seed_admin_user()
        _seed_country_lookups()
    except Exception:
        pass


def _seed_admin_user() -> None:
    from werkzeug.security import generate_password_hash

    if not User.query.filter_by(username="admin").first():
        u = User(username="admin", password=generate_password_hash("admin"), role="admin")
        db.session.add(u)

    if not User.query.filter_by(username="user").first():
        u = User(username="user", password=generate_password_hash("user"), role="user")
        db.session.add(u)

    if not User.query.filter_by(username="change_user").first():
        u = User(username="change_user", password=generate_password_hash("change_user"), role="change_user")
        db.session.add(u)

    db.session.commit()


def _seed_country_lookups() -> None:
    rows = [
        ("UK", 1),
        ("HK", 2),
        ("US", 3),
        ("France", 4),
        ("Singapore", 5),
        ("UAE", 6),
        ("India", 7),
        ("Germany", 8),
        ("Mexico", 9),
        ("Spain", 10),
        ("Italy", 11),
        ("Czech Rep", 12),
        ("Israel", 13),
        ("Japan", 14),
        ("Thailand", 15),
        ("Taiwan", 16),
        ("Philippines", 17),
        ("Indonesia", 18),
        ("Malaysia", 19),
        ("China", 20),
        ("Korea", 21),
        ("Poland", 22),
        ("Brazil", 23),
    ]

    seen: set[str] = set()
    for value, sort_order in rows:
        if value in seen:
            continue
        seen.add(value)

        existing = (
            db.session.query(LookupOption)
            .filter(LookupOption.group == "country")
            .filter(LookupOption.value == value)
            .first()
        )
        if existing:
            changed = False
            if existing.sort_order != sort_order:
                existing.sort_order = sort_order
                changed = True
            if not existing.is_active:
                existing.is_active = True
                changed = True
            if changed:
                db.session.add(existing)
            continue

        db.session.add(
            LookupOption(
                group="country",
                value=value,
                is_active=True,
                sort_order=sort_order,
            )
        )

    db.session.commit()
