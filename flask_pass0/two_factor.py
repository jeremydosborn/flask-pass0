"""
Flask-Pass0 Two-Factor Authentication Module
=============================================
Supports TOTP (authenticator apps), email-based 2FA, and backup codes.
"""

import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from flask import current_app


class TwoFactorAuth:
    """Handles TOTP, backup codes, and email-based 2FA."""
    
    def __init__(self, storage):
        self.storage = storage
    
    # ==================== TOTP (Authenticator Apps) ====================
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret (base32 encoded)."""
        return pyotp.random_base32()
    
    def get_totp_uri(self, email, secret):
        """Generate provisioning URI for QR code."""
        issuer = current_app.config.get('PASS0_TOTP_ISSUER', 'Flask-Pass0')
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)
    
    def generate_qr_code(self, uri):
        """Generate QR code image as base64 data URI."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_base64}"
    
    def verify_totp_code(self, secret, code):
        """Verify a TOTP code."""
        if not secret or not code:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    
    # ==================== Backup Codes ====================
    
    def generate_backup_codes(self, count=8):
        """Generate backup/recovery codes."""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') 
                          for _ in range(8))
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes
    
    def hash_backup_code(self, code):
        """Hash a backup code for storage."""
        clean_code = code.replace('-', '').upper()
        return hashlib.sha256(clean_code.encode()).hexdigest()
    
    def verify_backup_code(self, user_id, code):
        """Verify and consume a backup code."""
        code_hash = self.hash_backup_code(code)
        return self.storage.validate_backup_code(user_id, code_hash)
    
    # ==================== Email-Based 2FA ====================
    
    def generate_email_2fa_code(self):
        """Generate a 6-digit email verification code."""
        return ''.join(str(secrets.randbelow(10)) for _ in range(6))
    
    def send_email_2fa_code(self, email, code):
        """Send 2FA code via email."""
        from flask_mail import Mail, Message
        
        app_name = current_app.config.get('PASS0_APP_NAME', 'Your Application')
        expiry_minutes = current_app.config.get('PASS0_2FA_CODE_EXPIRY', 300) // 60
        
        subject = "Your Verification Code"
        text = (
            f"Your {app_name} verification code is: {code}\n\n"
            f"This code will expire in {expiry_minutes} minutes.\n\n"
            f"If you didn't request this code, please ignore this email."
        )
        
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #4285f4;">Verification Code</h1>
                    <p>Your {app_name} verification code is:</p>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; 
                                font-size: 32px; font-weight: bold; letter-spacing: 8px; 
                                border-radius: 4px; margin: 20px 0;">
                        {code}
                    </div>
                    <p><em>This code will expire in {expiry_minutes} minutes.</em></p>
                    <p>If you didn't request this code, you can safely ignore this email.</p>
                </div>
            </body>
        </html>
        """
        
        if not hasattr(current_app, '_pass0_mail'):
            current_app._pass0_mail = Mail(current_app)
        
        mail = current_app._pass0_mail
        msg = Message(
            subject=subject,
            recipients=[email],
            body=text,
            html=html,
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        
        mail.send(msg)
    
    def store_email_2fa_code(self, user_id, code):
        """Store email 2FA code in database."""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        expiry_seconds = current_app.config.get('PASS0_2FA_CODE_EXPIRY', 300)
        
        code_data = {
            'user_id': user_id,
            'code_hash': code_hash,
            'created_at': datetime.now(timezone.utc),
            'expires_at': datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds),
            'used': False
        }
        
        self.storage.store_2fa_code(code_data)
    
    def verify_email_2fa_code(self, user_id, code):
        """Verify email 2FA code."""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        return self.storage.verify_2fa_code(user_id, code_hash)
    
    # ==================== 2FA Management ====================
    
    def enable_2fa(self, user_id, secret, backup_codes):
        """Enable 2FA for a user."""
        hashed_codes = [self.hash_backup_code(code) for code in backup_codes]
        self.storage.enable_2fa(user_id, secret, hashed_codes)
    
    def disable_2fa(self, user_id):
        """Disable 2FA for a user."""
        self.storage.disable_2fa(user_id)
    
    def is_2fa_enabled(self, user_id):
        """Check if 2FA is enabled for a user."""
        return self.storage.is_2fa_enabled(user_id)
    
    def get_2fa_secret(self, user_id):
        """Get user's TOTP secret."""
        return self.storage.get_2fa_secret(user_id)
    
    def regenerate_backup_codes(self, user_id):
        """Regenerate backup codes for a user."""
        new_codes = self.generate_backup_codes()
        hashed_codes = [self.hash_backup_code(code) for code in new_codes]
        self.storage.regenerate_backup_codes(user_id, hashed_codes)
        return new_codes