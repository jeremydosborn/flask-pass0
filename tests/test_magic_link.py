"""
Magic link authentication tests for Flask-Pass0.
"""

import pytest
import secrets


def _token_from_link(link: str) -> str:
    assert "/verify/" in link
    return link.rsplit("/verify/", 1)[-1]


@pytest.mark.unit
class TestMagicLinkGeneration:

    def test_generates_link_for_existing_user(self, app, test_user):
        from flask_pass0.magic_link import generate_magic_link
        pass0 = app.extensions["pass0"]

        # request context required because generate_magic_link uses url_for(..., _external=True)
        with app.test_request_context("/", base_url="http://localhost"):
            link = generate_magic_link(test_user["email"], storage=pass0.storage)

        assert link is not None
        assert "/auth/verify/" in link

    def test_token_is_cryptographically_secure(self, app, test_user):
        from flask_pass0.magic_link import generate_magic_link
        pass0 = app.extensions["pass0"]

        tokens = set()
        with app.test_request_context("/", base_url="http://localhost"):
            for _ in range(10):
                link = generate_magic_link(test_user["email"], storage=pass0.storage)
                tokens.add(_token_from_link(link))

        assert len(tokens) == 10


@pytest.mark.unit
class TestMagicLinkVerification:

    def test_verifies_valid_token(self, app, test_user):
        from flask_pass0.magic_link import generate_magic_link, verify_magic_link
        pass0 = app.extensions["pass0"]

        with app.test_request_context("/", base_url="http://localhost"):
            link = generate_magic_link(test_user["email"], storage=pass0.storage)
        token = _token_from_link(link)

        result = verify_magic_link(token, storage=pass0.storage)
        assert result["success"] is True
        assert result["user"]["email"] == test_user["email"]

    def test_rejects_expired_token(self, app, test_user):
        from datetime import datetime, timedelta, timezone
        from flask_pass0.magic_link import generate_magic_link, verify_magic_link

        pass0 = app.extensions["pass0"]
        storage = pass0.storage

        with app.test_request_context("/", base_url="http://localhost"):
            link = generate_magic_link(test_user["email"], storage=storage)
        token = _token_from_link(link)

        token_hash = storage._hash_token(token)
        storage.tokens[token_hash]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)

        result = verify_magic_link(token, storage=storage)
        assert result["success"] is False
        assert "error" in result

    def test_rejects_invalid_token(self, app):
        from flask_pass0.magic_link import verify_magic_link
        pass0 = app.extensions["pass0"]

        fake_token = secrets.token_urlsafe(32)
        result = verify_magic_link(fake_token, storage=pass0.storage)

        assert result["success"] is False
        assert "error" in result


@pytest.mark.integration
class TestMagicLinkEndToEnd:

    def test_request_and_verify_flow(self, client, test_user):
        response = client.post(
            "/auth/request-magic-link",
            json={"email": test_user["email"]},
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # PASS0_DEV_MODE=True in base_config, so link should always be present
        assert "link" in data

        token = _token_from_link(data["link"])
        response = client.get(f"/auth/verify/{token}", follow_redirects=False)

        assert response.status_code == 302
        assert response.location.endswith("/dashboard")

        with client.session_transaction() as sess:
            assert "user_id" in sess
            assert "logged_in_at" in sess
