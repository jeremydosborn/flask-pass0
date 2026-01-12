"""
Pytest fixtures for Flask-Pass0 tests.

Pytest automatically discovers this file (conftest.py) and uses it to provide
fixtures and optional hooks to tests under this directory tree.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask

# Ensure project root is importable when running tests from /tests
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask_pass0.auth import Pass0
from flask_pass0.storage import InMemoryStorageAdapter
from flask_pass0.magic_link import generate_magic_link


@pytest.fixture
def base_config():
    # Keep config minimal and explicit for test determinism
    return {
        "SECRET_KEY": "test-secret-key",
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,

        # Pass0 config
        "PASS0_DEV_MODE": True,
        "PASS0_TOKEN_EXPIRY": 10,          # minutes
        "PASS0_REDIRECT_URL": "/dashboard",
        "PASS0_LOGIN_URL": "/login",
        "PASS0_SESSION_DURATION": 3600,    # seconds
        "PASS0_PRIMARY_AUTH": "magic_link",

        # Passkey/WebAuthn config
        "PASS0_RP_ID": "localhost",
        "PASS0_RP_NAME": "Test App",
        "PASS0_ORIGIN": "http://localhost:5000",

        # Mail defaults (dev mode suppresses sending anyway)
        "MAIL_SUPPRESS_SEND": True,
        "MAIL_SERVER": "localhost",
        "MAIL_DEFAULT_SENDER": "test@example.com",

        # Helps URL building in non-request contexts if it happens accidentally
        # (we still prefer providing a request context where needed)
        "SERVER_NAME": "example.test",
        "PREFERRED_URL_SCHEME": "http",
    }


@pytest.fixture
def app(base_config):
    """Flask app with Pass0 + in-memory storage and a couple test routes."""
    app = Flask(__name__)
    app.config.update(base_config)

    storage = InMemoryStorageAdapter()
    pass0 = Pass0(app, storage_adapter=storage)

    # ---- Minimal host-app routes used by tests / redirects ----
    @app.route("/public")
    def public():
        return "Public content"

    @app.route("/protected")
    @pass0.login_required
    def protected():
        return "Protected content"

    @app.route("/login")
    def login_page():
        return "Login page"

    @app.route("/dashboard")
    def dashboard():
        return "Dashboard"

    yield app


@pytest.fixture
def app_with_2fa(base_config):
    """Flask app with Pass0 + 2FA enabled."""
    app = Flask(__name__)
    app.config.update(base_config)

    app.config["PASS0_2FA_ENABLED"] = True
    # Pass0 expects this to be an endpoint name to redirect to
    app.config["PASS0_2FA_VERIFY_ROUTE"] = "verify_2fa_page"
    app.config["PASS0_TOTP_ISSUER"] = "Test App"

    storage = InMemoryStorageAdapter()
    pass0 = Pass0(app, storage_adapter=storage)

    @app.route("/protected")
    @pass0.login_required
    def protected():
        return "Protected content"

    @app.route("/verify-2fa")
    def verify_2fa_page():
        return "2FA verification page"

    @app.route("/login")
    def login_page():
        return "Login page"

    @app.route("/dashboard")
    def dashboard():
        return "Dashboard"

    yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def client_2fa(app_with_2fa):
    return app_with_2fa.test_client()


@pytest.fixture
def test_email():
    return "test@example.com"


@pytest.fixture
def test_user(app, test_email):
    """
    Pre-populate Pass0 storage with an existing user.

    In production your app creates users; here we simulate that by inserting directly
    into the in-memory adapter.
    """
    with app.app_context():
        pass0 = app.extensions["pass0"]
        storage = pass0.storage

        user_id = len(getattr(storage, "users", {})) + 1
        user = {
            "id": user_id,
            "email": test_email,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # InMemoryStorageAdapter in your tests uses `storage.users[email] = user`
        storage.users[test_email] = user
        yield user


@pytest.fixture
def authenticated_client(client, test_user):
    with client.session_transaction() as sess:
        sess["user_id"] = test_user["id"]
        sess["logged_in_at"] = datetime.now(timezone.utc).isoformat()
    return client


@pytest.fixture
def expired_session_client(client, test_user):
    with client.session_transaction() as sess:
        sess["user_id"] = test_user["id"]
        expired_time = datetime.now(timezone.utc) - timedelta(hours=2)
        sess["logged_in_at"] = expired_time.isoformat()
    return client


@pytest.fixture
def valid_magic_token(app, test_user):
    """
    Generate a token by calling generate_magic_link() under a request context,
    because generate_magic_link uses url_for(..., _external=True).
    """
    pass0 = app.extensions["pass0"]

    with app.test_request_context("/"):
        link = generate_magic_link(test_user["email"], storage=pass0.storage)
        token = link.split("/verify/")[-1]
        yield token


@pytest.fixture
def expired_magic_token(app, test_user):
    """
    Same as valid_magic_token, but we manually expire the stored token entry.
    """
    pass0 = app.extensions["pass0"]
    storage = pass0.storage

    with app.test_request_context("/"):
        link = generate_magic_link(test_user["email"], storage=storage)
        token = link.split("/verify/")[-1]

    # Expire the token by manipulating storage internals
    token_hash = storage._hash_token(token)
    if token_hash in storage.tokens:
        storage.tokens[token_hash]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)

    yield token
