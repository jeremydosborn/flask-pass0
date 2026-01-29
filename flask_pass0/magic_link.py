import secrets
from datetime import datetime, timedelta, timezone
from flask import current_app
from flask_mail import Mail, Message


class MagicLink:
    """Email-based magic link authentication primitives."""

    def __init__(self, storage):
        self.storage = storage

    def generate(self, email, metadata=None, expiry_minutes=None):
        """
        Generate a magic link token.

        Tokens are generated regardless of whether the user exists
        to prevent account enumeration.

        Returns dict with 'token' and 'expires_at'.
        """
        expiry_minutes = expiry_minutes or current_app.config.get("PASS0_TOKEN_EXPIRY", 10)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
        token = secrets.token_urlsafe(32)

        token_data = {"email": email, "expires_at": expires_at.isoformat()}
        if metadata:
            token_data["metadata"] = metadata

        self.storage.store_token(token, token_data)

        return {"token": token, "expires_at": expires_at}

    def verify(self, token):
        """
        Verify a magic link token.

        Returns dict with 'success', 'user', 'metadata', or 'error'.
        Token is consumed on retrieval.
        """
        token_data = self.storage.get_token(token)
        if not token_data:
            return {"success": False, "error": "Invalid or expired token"}

        user = self.storage.get_user_by_email(token_data["email"])
        if not user:
            return {"success": False, "error": "Invalid or expired token"}

        result = {"success": True, "user": user}
        if token_data.get("metadata"):
            result["metadata"] = token_data["metadata"]

        return result

    def send(self, email, token, base_url=None):
        """
        Send magic link email.

        In dev mode (PASS0_DEV_MODE=True), logs the link instead.
        Returns dict with 'success' and optionally 'link' in dev mode.
        """
        base_url = base_url or current_app.config.get("PASS0_BASE_URL", "")
        link = f"{base_url}/auth/verify/{token}"

        if current_app.config.get("PASS0_DEV_MODE"):
            current_app.logger.info(f"Magic link for {email}: {link}")
            return {"success": True, "link": link}

        try:
            self._send_email(email, link)
            return {"success": True}
        except Exception as e:
            current_app.logger.error(f"Failed to send magic link: {e}")
            return {"success": False, "error": str(e)}

    def _send_email(self, email, link):
        app_name = current_app.config.get("PASS0_APP_NAME", "Your Application")
        expiry = current_app.config.get("PASS0_TOKEN_EXPIRY", 10)

        if not hasattr(current_app, "_pass0_mail"):
            current_app._pass0_mail = Mail(current_app)

        msg = Message(
            subject="Your Login Link",
            recipients=[email],
            sender=current_app.config.get("MAIL_DEFAULT_SENDER"),
            body=f"Click to log in to {app_name}: {link}\n\nExpires in {expiry} minutes.",
            html=f"""
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Your Login Link</h2>
                <p>Click below to log in to {app_name}:</p>
                <p><a href="{link}" style="display: inline-block; padding: 12px 24px;
                    background: #4285f4; color: white; text-decoration: none;
                    border-radius: 4px;">Log In</a></p>
                <p style="color: #666; font-size: 14px;">
                    Or copy: {link}<br>Expires in {expiry} minutes.
                </p>
            </div>
            """,
        )
        current_app._pass0_mail.send(msg)
