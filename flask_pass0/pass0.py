from flask import session, current_app
from datetime import datetime, timedelta, timezone

from .passkey import Passkey
from .magic_link import MagicLink
from .totp import TOTP


class Pass0:
    """Passwordless authentication primitives for Flask."""

    def __init__(self, app=None, storage=None):
        self.storage = storage
        self.app = app
        self.magic_link = MagicLink(storage) if storage else None
        self.passkey = Passkey(storage) if storage else None
        self.totp = TOTP(storage) if storage else None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.config.setdefault("PASS0_TOKEN_EXPIRY", 10)
        app.config.setdefault("PASS0_SESSION_DURATION", 86400)
        app.config.setdefault("PASS0_DEV_MODE", False)
        app.config.setdefault("PASS0_RP_ID", "localhost")
        app.config.setdefault("PASS0_RP_NAME", "Flask-Pass0")
        app.config.setdefault("PASS0_ORIGIN", "http://localhost:5000")
        app.config.setdefault("PASS0_TOTP_ISSUER", "Flask-Pass0")
        app.extensions["pass0"] = self

    def login(self, user_id):
        session["user_id"] = user_id
        session["logged_in_at"] = datetime.now(timezone.utc).isoformat()

    def logout(self):
        session.clear()

    def is_authenticated(self):
        if not session.get("user_id"):
            return False
        if session.get("2fa_pending"):
            return False
        logged_in_at = session.get("logged_in_at")
        if not logged_in_at:
            return False
        try:
            logged_in_dt = datetime.fromisoformat(logged_in_at)
        except (ValueError, TypeError):
            session.clear()
            return False
        duration = current_app.config.get("PASS0_SESSION_DURATION", 86400)
        if datetime.now(timezone.utc) - logged_in_dt > timedelta(seconds=duration):
            session.clear()
            return False
        return True

    def current_user(self):
        if not self.is_authenticated():
            return None
        return self.storage.get_user_by_id(session.get("user_id"))
