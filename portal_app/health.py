from __future__ import annotations

from flask import Blueprint, jsonify
from sqlalchemy import text

from .db import db

health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
