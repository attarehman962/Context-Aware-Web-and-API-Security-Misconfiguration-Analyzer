"""Shared Flask extensions."""

from __future__ import annotations

import os

from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
socketio = SocketIO(async_mode=os.getenv("SOCKETIO_ASYNC_MODE", "threading"), cors_allowed_origins="*")
