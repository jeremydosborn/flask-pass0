import secrets
import hashlib
import io
import base64
import pyotp
import qrcode
from flask import current_app


class TOTP:
    """Time-based One-Time Password (TOTP) two-factor authentication primitives."""

    def __init__(self, storage):
        self.storage = storage

    def generate_secret(self):
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

    def get_provisioning_uri(self, identifier, secret, issuer=None):
        """Generate otpauth:// URI for QR code."""
        issuer = issuer or current_app.config.get("PASS0_TOTP_ISSUER", "Flask-Pass0")
        return pyotp.TOTP(secret).provisioning_uri(name=identifier, issuer_name=issuer)

    def generate_qr(self, uri):
        """Generate QR code as base64 data URI."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"

    def verify_code(self, secret, code, window=1):
        """Verify a TOTP code. Returns True if valid."""
        if not secret or not code:
            return False
        return pyotp.TOTP(secret).verify(code, valid_window=window)

    def generate_backup_codes(self, count=8):
        """Generate backup codes. Returns list of formatted codes like 'ABCD-EFGH'."""
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        codes = []
        for _ in range(count):
            code = "".join(secrets.choice(chars) for _ in range(8))
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes

    def hash_code(self, code):
        """Hash a backup code for storage."""
        return hashlib.sha256(code.replace("-", "").upper().encode()).hexdigest()

    def is_enabled(self, user_id):
        """Check if 2FA is enabled for user."""
        return self.storage.is_2fa_enabled(user_id)

    def get_secret(self, user_id):
        """Get stored TOTP secret for user."""
        return self.storage.get_2fa_secret(user_id)

    def enable(self, user_id, secret, backup_codes):
        """
        Enable 2FA for user.

        backup_codes should be plaintext codes; they will be hashed before storage.
        """
        hashed = [self.hash_code(c) for c in backup_codes]
        self.storage.enable_2fa(user_id, secret, hashed)

    def disable(self, user_id):
        """Disable 2FA for user."""
        self.storage.disable_2fa(user_id)

    def verify_backup_code(self, user_id, code):
        """Verify and consume a backup code. Returns True if valid."""
        return self.storage.validate_backup_code(user_id, self.hash_code(code))

    def regenerate_backup_codes(self, user_id, count=8):
        """Generate new backup codes, replacing existing ones. Returns new codes."""
        codes = self.generate_backup_codes(count)
        hashed = [self.hash_code(c) for c in codes]
        self.storage.regenerate_backup_codes(user_id, hashed)
        return codes

    def setup(self, identifier):
        """
        Generate setup data for enabling 2FA.

        Returns dict with 'secret', 'uri', and 'qr_code'.
        """
        secret = self.generate_secret()
        uri = self.get_provisioning_uri(identifier, secret)
        return {"secret": secret, "uri": uri, "qr_code": self.generate_qr(uri)}
