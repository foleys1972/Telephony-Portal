from __future__ import annotations

from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, login_required, login_user, logout_user
from werkzeug.security import check_password_hash

from .db import db
from .models import ActivityLogEntry
from .models import User

login_manager = LoginManager()
login_manager.login_view = "auth.login"

auth_bp = Blueprint("auth", __name__)


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        u = User.query.filter_by(username=username).first()
        if not u or not check_password_hash(u.password, password):
            try:
                db.session.add(
                    ActivityLogEntry(
                        created_at=datetime.utcnow(),
                        username=username or None,
                        action_type="login",
                        method=request.method,
                        path=request.path,
                        success=False,
                        details="Invalid username or password",
                    )
                )
                db.session.commit()
            except Exception:
                db.session.rollback()
                current_app.logger.exception("Failed to write activity log entry (login failure)")
            flash("Invalid username or password", "danger")
            return render_template("login.html"), 401

        login_user(u)
        try:
            u.last_activity = datetime.utcnow()
            db.session.add(
                ActivityLogEntry(
                    created_at=datetime.utcnow(),
                    username=(u.username or None),
                    action_type="login",
                    method=request.method,
                    path=request.path,
                    success=True,
                    details="Login successful",
                )
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to write activity log entry (login success)")
        return redirect(url_for("core.index"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    try:
        from flask_login import current_user

        username = getattr(current_user, "username", None)
    except Exception:
        username = None

    try:
        db.session.add(
            ActivityLogEntry(
                created_at=datetime.utcnow(),
                username=username,
                action_type="logout",
                method=request.method,
                path=request.path,
                success=True,
                details="Logout",
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to write activity log entry (logout)")

    logout_user()
    return redirect(url_for("auth.login"))
