"""Flask application factory for CAWASMA."""

from __future__ import annotations

from pathlib import Path

from flask import Flask

from config import config_by_name
from app.extensions import db, socketio
from app.tasks import init_celery


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    config_key = config_name or "development"
    app.config.from_object(config_by_name.get(config_key, config_by_name["development"]))

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORT_OUTPUT_DIR"]).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    init_celery(app)

    from app.routes import main_bp
    from app.api import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    return app
