from __future__ import annotations

from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os

from flask import Flask, request
from flask_login import current_user
from sqlalchemy import text
from werkzeug.exceptions import HTTPException

from .db import db
from .migrate import ensure_schema
from .auth import login_manager, auth_bp
from .health import health_bp
from .models import ActivityLogEntry
from .views import core_bp


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates")),
        static_folder=None,
    )

    try:
        from .paths import get_logs_dir

        logs_dir = get_logs_dir()
        log_path = os.path.join(logs_dir, "telephony.log")
        handler = RotatingFileHandler(log_path, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

        app.logger.setLevel(logging.INFO)
        if not any(isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == handler.baseFilename for h in app.logger.handlers):
            app.logger.addHandler(handler)

        werk = logging.getLogger("werkzeug")
        werk.setLevel(logging.INFO)
        if not any(isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == handler.baseFilename for h in werk.handlers):
            werk.addHandler(handler)
    except Exception:
        pass

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "dev-secret-key"

    from .paths import resolve_db_path

    db_path = resolve_db_path()
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(core_bp)

    @app.get("/favicon.ico")
    def _favicon():
        return ("", 204)

    @app.errorhandler(Exception)
    def _log_unhandled_exception(e):
        if isinstance(e, HTTPException):
            return e
        try:
            username = None
            try:
                if getattr(current_user, "is_authenticated", False):
                    username = getattr(current_user, "username", None)
            except Exception:
                username = None

            app.logger.exception(
                "Unhandled error user=%s method=%s path=%s endpoint=%s",
                username,
                getattr(request, "method", None),
                getattr(request, "path", None),
                getattr(request, "endpoint", None),
            )
        except Exception:
            pass
        raise e

    @app.after_request
    def _activity_log_after_request(response):
        try:
            p = request.path or ""
            if p.startswith("/static/") or p == "/favicon.ico":
                return response

            username = None
            try:
                if getattr(current_user, "is_authenticated", False):
                    username = getattr(current_user, "username", None)
            except Exception:
                username = None

            full_path = (request.full_path or request.path or "").rstrip("?")
            action_type = (request.endpoint or "request")

            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO activity_log (created_at, username, action_type, method, path, success, details)
                        VALUES (:created_at, :username, :action_type, :method, :path, :success, :details)
                        """
                    ),
                    {
                        "created_at": datetime.utcnow(),
                        "username": username,
                        "action_type": action_type,
                        "method": request.method,
                        "path": full_path,
                        "success": 1 if response.status_code < 400 else 0,
                        "details": f"status={response.status_code}",
                    },
                )
        except Exception:
            pass
        return response

    # Template compatibility: existing templates reference endpoints like `index`, `login`, `logout`.
    # Keep aliases during the rewrite so we can port features incrementally.
    try:
        def _alias(endpoint: str, target: str, rule: str | None = None, methods=None):
            vf = app.view_functions.get(target)
            if not vf:
                return
            r = rule or getattr(vf, "__tp_rule__", None)
            if not r:
                return
            app.add_url_rule(r, endpoint=endpoint, view_func=vf, methods=methods)

        _alias("index", "core.index", rule="/")
        _alias("login", "auth.login", rule="/login", methods=["GET", "POST"])
        _alias("logout", "auth.logout", rule="/logout")

        # Sidebar + templates
        _alias("ddi_list", "core.ddi_list", rule="/ddi")
        _alias("ddi_request_spare", "core.ddi_request_spare", rule="/ddi/request-spare", methods=["GET", "POST"])
        _alias("ddi_import", "core.ddi_import", rule="/ddi/import", methods=["GET", "POST"])
        _alias("ddi_export", "core.ddi_export", rule="/ddi/export")
        _alias("ddi_add", "core.ddi_add", rule="/ddi/add", methods=["GET", "POST"])
        _alias("ddi_edit", "core.ddi_edit", rule="/ddi/edit/<int:id>", methods=["GET", "POST"])
        _alias("pw_list", "core.pw_list", rule="/private_wire")
        _alias("pw_import", "core.pw_import", rule="/private_wire/import", methods=["GET", "POST"])
        _alias("pw_export", "core.pw_export", rule="/private_wire/export")
        _alias("pw_view", "core.pw_view", rule="/private_wire/view/<int:id>")
        _alias("pw_add", "core.pw_add", rule="/private_wire/add", methods=["GET", "POST"])
        _alias("pw_edit", "core.pw_edit", rule="/private_wire/edit/<int:id>", methods=["GET", "POST"])
        _alias("pw_cease", "core.pw_cease", rule="/private_wire/cease/<int:id>", methods=["GET", "POST"])
        _alias("ceased_wires_list", "core.ceased_wires_list", rule="/private_wire/ceased")
        _alias("ceased_wires_import", "core.ceased_wires_import", rule="/private_wire/ceased/import", methods=["GET", "POST"])
        _alias("ceased_wires_export", "core.ceased_wires_export", rule="/private_wire/ceased/export")
        _alias("ceased_wire_view", "core.ceased_wire_view", rule="/private_wire/ceased/view/<int:id>")
        _alias("turret_list", "core.turret_list", rule="/turret")
        _alias("turret_import", "core.turret_import", rule="/turret/import", methods=["GET", "POST"])
        _alias("turret_export", "core.turret_export", rule="/turret/export")
        _alias("turret_add", "core.turret_add", rule="/turret/add", methods=["GET", "POST"])
        _alias("turret_edit", "core.turret_edit", rule="/turret/edit/<int:id>", methods=["GET", "POST"])
        _alias("turret_rma", "core.turret_rma", rule="/turret/rma/<int:id>", methods=["POST"])
        _alias("turret_nslookup_by_ip", "core.turret_nslookup_by_ip", rule="/turret/<int:id>/nslookup/ip", methods=["POST"])
        _alias(
            "turret_nslookup_by_hostname",
            "core.turret_nslookup_by_hostname",
            rule="/turret/<int:id>/nslookup/hostname",
            methods=["POST"],
        )
        _alias("turret_open_web", "core.turret_open_web", rule="/turret/<int:id>/open-web")
        _alias("turret_rma_list", "core.turret_rma_list", rule="/turret/rma")
        _alias("turret_rma_export", "core.turret_rma_export", rule="/turret/rma/export")
        _alias("turret_rma_import", "core.turret_rma_import", rule="/turret/rma/import", methods=["GET", "POST"])
        _alias("turret_moves_list", "core.turret_moves_list", rule="/turret/moves")
        _alias("turret_move_history", "core.turret_move_history", rule="/turret/moves/history")
        _alias("turret_view_move_group", "core.turret_view_move_group", rule="/turret/moves/group/<int:id>")
        _alias("turret_individual_history", "core.turret_individual_history", rule="/turret/moves/turret/<int:id>")
        _alias("turret_moves_import", "core.turret_moves_import", rule="/turret/moves/import", methods=["GET", "POST"])
        _alias("turret_moves_export", "core.turret_moves_export", rule="/turret/moves/export")
        _alias("turret_plan_move", "core.turret_plan_move", rule="/turret/moves/plan", methods=["GET", "POST"])
        _alias("turret_edit_move_group", "core.turret_edit_move_group", rule="/turret/moves/group/<int:id>/edit", methods=["GET", "POST"])
        _alias("turret_execute_move", "core.turret_execute_move", rule="/turret/moves/execute", methods=["POST"])
        _alias("turret_approve_move_group", "core.turret_approve_move_group", rule="/turret/moves/group/<int:id>/approve", methods=["POST"])
        _alias("changes_list", "core.changes_list", rule="/changes")
        _alias("changes_view", "core.changes_view", rule="/changes/view/<int:id>")
        _alias("changes_add", "core.changes_add", rule="/changes/add", methods=["GET", "POST"])
        _alias("changes_edit", "core.changes_edit", rule="/changes/edit/<int:id>", methods=["GET", "POST"])
        _alias("changes_delete", "core.changes_delete", rule="/changes/delete/<int:id>", methods=["POST"])
        _alias("changes_import", "core.changes_import", rule="/changes/import", methods=["GET", "POST"])
        _alias("changes_export", "core.changes_export", rule="/changes/export")
        _alias("changes_bulk_update", "core.changes_bulk_update", rule="/changes/bulk-update", methods=["POST"])
        _alias("saved_filters_save", "core.saved_filters_save", rule="/saved-filters/save", methods=["POST"])
        _alias("saved_filters_delete", "core.saved_filters_delete", rule="/saved-filters/delete/<int:id>", methods=["POST"])
        _alias("saved_filters_apply", "core.saved_filters_apply", rule="/saved-filters/apply/<int:id>")
        _alias("incidents_list", "core.incidents_list", rule="/incidents")
        _alias("incidents_view", "core.incidents_view", rule="/incidents/view/<int:id>")
        _alias("incidents_add", "core.incidents_add", rule="/incidents/add", methods=["GET", "POST"])
        _alias("incidents_edit", "core.incidents_edit", rule="/incidents/edit/<int:id>", methods=["GET", "POST"])
        _alias("incidents_import", "core.incidents_import", rule="/incidents/import", methods=["GET", "POST"])
        _alias("incidents_export", "core.incidents_export", rule="/incidents/export")
        _alias("incidents_bulk_update", "core.incidents_bulk_update", rule="/incidents/bulk-update", methods=["POST"])
        _alias("calendar_view", "core.calendar_view", rule="/calendar")
        _alias("calendar_events", "core.calendar_events", rule="/calendar/events")

        # Servers
        _alias("servers_list", "core.servers_list", rule="/servers")
        _alias("servers_add", "core.servers_add", rule="/servers/add", methods=["GET", "POST"])
        _alias("servers_view", "core.servers_view", rule="/servers/view/<int:id>")
        _alias("servers_edit", "core.servers_edit", rule="/servers/edit/<int:id>", methods=["GET", "POST"])
        _alias("servers_cease", "core.servers_cease", rule="/servers/cease/<int:id>", methods=["POST"])
        _alias("ceased_servers_list", "core.ceased_servers_list", rule="/servers/ceased")
        _alias("ceased_servers_view", "core.ceased_servers_view", rule="/servers/ceased/view/<int:id>")
        _alias("servers_import", "core.servers_import", rule="/servers/import", methods=["GET", "POST"])
        _alias("servers_export", "core.servers_export", rule="/servers/export")
        _alias(
            "servers_bulk_os_update",
            "core.servers_bulk_os_update",
            rule="/servers/bulk-os-update",
            methods=["GET", "POST"],
        )

        # Admin menu
        _alias("manage_users", "core.manage_users", rule="/admin/users")
        _alias("add_user", "core.add_user", rule="/admin/users/add", methods=["GET", "POST"])
        _alias("toggle_change_approver", "core.toggle_change_approver", rule="/admin/users/<int:user_id>/toggle-change-approver", methods=["POST"])
        _alias("toggle_regional_approver", "core.toggle_regional_approver", rule="/admin/users/<int:user_id>/toggle-regional-approver", methods=["POST"])
        _alias("toggle_global_service_approver", "core.toggle_global_service_approver", rule="/admin/users/<int:user_id>/toggle-global-service-approver", methods=["POST"])
        _alias(
            "toggle_turret_move_approver",
            "core.toggle_turret_move_approver",
            rule="/admin/users/<int:user_id>/toggle-turret-move-approver",
            methods=["POST"],
        )
        _alias(
            "toggle_turret_move_executor",
            "core.toggle_turret_move_executor",
            rule="/admin/users/<int:user_id>/toggle-turret-move-executor",
            methods=["POST"],
        )
        _alias(
            "toggle_turret_move_import",
            "core.toggle_turret_move_import",
            rule="/admin/users/<int:user_id>/toggle-turret-move-import",
            methods=["POST"],
        )
        _alias(
            "toggle_turret_move_export",
            "core.toggle_turret_move_export",
            rule="/admin/users/<int:user_id>/toggle-turret-move-export",
            methods=["POST"],
        )
        _alias(
            "toggle_private_wire_import",
            "core.toggle_private_wire_import",
            rule="/admin/users/<int:user_id>/toggle-private-wire-import",
            methods=["POST"],
        )
        _alias(
            "toggle_private_wire_export",
            "core.toggle_private_wire_export",
            rule="/admin/users/<int:user_id>/toggle-private-wire-export",
            methods=["POST"],
        )
        _alias("update_user", "core.update_user", rule="/admin/users/<int:user_id>/update", methods=["POST"])
        _alias("reset_user_password", "core.reset_user_password", rule="/admin/users/<int:user_id>/reset-password", methods=["POST"])
        _alias("disable_user", "core.disable_user", rule="/admin/users/<int:user_id>/disable", methods=["POST"])
        _alias("enable_user", "core.enable_user", rule="/admin/users/<int:user_id>/enable", methods=["POST"])
        _alias("delete_user", "core.delete_user", rule="/admin/users/<int:user_id>/delete", methods=["POST"])
        _alias("admin_backups", "core.admin_backups", rule="/admin/backups")
        _alias("backup_database", "core.backup_database", rule="/admin/backup")
        _alias("restore_database", "core.restore_database", rule="/admin/restore", methods=["GET", "POST"])
        _alias("admin_database", "core.admin_database", rule="/admin/database")
        _alias("admin_table_view", "core.admin_table_view", rule="/admin/database/<table>")
        _alias("admin_table_spreadsheet", "core.admin_table_spreadsheet", rule="/admin/database/<table>/spreadsheet")
        _alias("admin_edit_record", "core.admin_edit_record", rule="/admin/database/<table>/edit/<int:rowid>", methods=["GET", "POST"])
        _alias("admin_delete_record", "core.admin_delete_record", rule="/admin/database/<table>/delete/<int:rowid>", methods=["POST"])
        _alias("admin_delete_all_records", "core.admin_delete_all_records", rule="/admin/database/<table>/delete-all", methods=["POST"])
        _alias("admin_update_cell", "core.admin_update_cell", rule="/admin/database/<table>/update-cell", methods=["POST"])
        _alias("admin_reports", "core.admin_reports", rule="/admin/reports")
        _alias("admin_lookups", "core.admin_lookups", rule="/admin/lookups")
        _alias("admin_lookup_group", "core.admin_lookup_group", rule="/admin/lookups/<group>")
        _alias("admin_lookup_add", "core.admin_lookup_add", rule="/admin/lookups/<group>/add", methods=["POST"])
        _alias("admin_lookup_edit", "core.admin_lookup_edit", rule="/admin/lookups/<group>/edit/<int:id>", methods=["GET", "POST"])
        _alias("admin_lookup_delete", "core.admin_lookup_delete", rule="/admin/lookups/<group>/delete/<int:id>", methods=["POST"])
        _alias("admin_cab_locks", "core.admin_cab_locks", rule="/admin/cab-locks")
        _alias("admin_cab_locks_toggle", "core.admin_cab_locks_toggle", rule="/admin/cab-locks/toggle", methods=["POST"])
        _alias("admin_cab_locks_add", "core.admin_cab_locks_add", rule="/admin/cab-locks/add", methods=["POST"])
        _alias("admin_custom_fields", "core.admin_custom_fields", rule="/admin/custom-fields")
        _alias("admin_custom_fields_entity", "core.admin_custom_fields_entity", rule="/admin/custom-fields/<entity>")
        _alias("admin_custom_fields_add", "core.admin_custom_fields_add", rule="/admin/custom-fields/<entity>/add", methods=["POST"])
        _alias("admin_custom_fields_toggle", "core.admin_custom_fields_toggle", rule="/admin/custom-fields/<entity>/toggle/<int:id>", methods=["POST"])
        _alias("admin_activity_log", "core.admin_activity_log", rule="/admin/activity-log")

        # Backups page actions
        _alias("admin_backups_settings", "core.admin_backups_settings", rule="/admin/backups/settings", methods=["POST"])
        _alias("admin_backups_run_now", "core.admin_backups_run_now", rule="/admin/backups/run", methods=["POST"])
        _alias("admin_backups_db_test", "core.admin_backups_db_test", rule="/admin/backups/db-test", methods=["POST"])
        _alias("admin_backups_download", "core.admin_backups_download", rule="/admin/backups/download/<path:filename>")
        _alias("admin_backups_delete", "core.admin_backups_delete", rule="/admin/backups/delete/<path:filename>", methods=["POST"])
        _alias("admin_backups_schedule_install", "core.admin_backups_schedule_install", rule="/admin/backups/schedule/install", methods=["POST"])
        _alias("admin_backups_schedule_run", "core.admin_backups_schedule_run", rule="/admin/backups/schedule/run", methods=["POST"])
    except Exception:
        pass

    with app.app_context():
        ensure_schema(db.engine)

    return app
