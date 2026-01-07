"""
Core authentication tests for Flask-Pass0.
"""

import pytest


def _extract_token_from_link(link: str) -> str:
    """
    Link is generated like: http://localhost/auth/verify/<token>
    We defensively split on the final "/verify/" segment.
    """
    assert isinstance(link, str) and link
    assert "/verify/" in link
    return link.rsplit("/verify/", 1)[-1]


@pytest.mark.unit
class TestAuthentication:
    def test_unauthenticated_user(self, client):
        """Test that is_authenticated returns False without session."""
        pass0 = client.application.extensions["pass0"]

        # Need request context because is_authenticated reads `session`
        with client:
            client.get("/public")
            assert pass0.is_authenticated() is False

    def test_authenticated_user(self, authenticated_client):
        """Test that is_authenticated returns True with valid session."""
        pass0 = authenticated_client.application.extensions["pass0"]

        with authenticated_client:
            authenticated_client.get("/public")
            assert pass0.is_authenticated() is True

    def test_expired_session_fails(self, expired_session_client):
        """Test that is_authenticated returns False with expired session."""
        pass0 = expired_session_client.application.extensions["pass0"]

        with expired_session_client:
            expired_session_client.get("/public")
            assert pass0.is_authenticated() is False


@pytest.mark.unit
class TestLoginRequired:
    def test_blocks_unauthenticated(self, client):
        response = client.get("/protected", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.location

    def test_allows_authenticated(self, authenticated_client):
        response = authenticated_client.get("/protected", follow_redirects=False)
        assert response.status_code == 200
        assert b"Protected content" in response.data

    def test_blocks_expired_session(self, expired_session_client):
        response = expired_session_client.get("/protected", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.location


@pytest.mark.unit
class TestLogout:
    def test_clears_session(self, authenticated_client):
        with authenticated_client.session_transaction() as sess:
            assert "user_id" in sess

        authenticated_client.get("/auth/logout", follow_redirects=False)

        with authenticated_client.session_transaction() as sess:
            assert "user_id" not in sess
            assert "logged_in_at" not in sess

    def test_redirects_to_login(self, authenticated_client):
        response = authenticated_client.get("/auth/logout", follow_redirects=False)
        assert response.status_code == 302
        assert "/login" in response.location


@pytest.mark.integration
class TestAuthFlow:
    def test_complete_login_flow(self, client, test_user):
        """
        End-to-end flow without relying on the valid_magic_token fixture:

        1) Hit /protected -> redirected to /auth/login and session['next'] is set
        2) Request a magic link -> dev mode returns a link with token
        3) Verify token -> redirected back to the stored next URL (safe internal path)
        4) Hit /protected again -> 200
        """
        # 1) Set the "next" target via login_required
        resp = client.get("/protected", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/login" in resp.location

        # 2) Request a magic link (dev mode returns link)
        resp = client.post("/auth/request-magic-link", json={"email": test_user["email"]})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "link" in data  # base_config sets PASS0_DEV_MODE=True

        token = _extract_token_from_link(data["link"])

        # 3) Verify token and expect redirect back to /protected (normalized)
        resp = client.get(f"/auth/verify/{token}", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.location.endswith("/protected")

        # 4) Now protected should succeed
        resp = client.get("/protected", follow_redirects=False)
        assert resp.status_code == 200
        assert b"Protected content" in resp.data