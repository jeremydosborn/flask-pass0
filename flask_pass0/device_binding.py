"""
Flask-Pass0 Device Binding Module
==================================
Device fingerprinting and trusted device management.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import request, current_app
from flask_mail import Mail, Message
from user_agents import parse


class DeviceBinding:
    """Handles device fingerprinting and trusted device management."""
    
    def __init__(self, storage):
        self.storage = storage
    
    # ==================== Device Fingerprinting ====================
    
    def get_device_fingerprint(self, request_obj=None):
        """Generate device fingerprint from request."""
        req = request_obj or request
        
        user_agent_string = req.headers.get('User-Agent', '')
        user_agent = parse(user_agent_string)
        
        ip_address = req.headers.get('X-Forwarded-For', req.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        components = {
            'user_agent': user_agent_string,
            'browser': user_agent.browser.family,
            'browser_version': user_agent.browser.version_string,
            'os': user_agent.os.family,
            'os_version': user_agent.os.version_string,
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'accept_language': req.headers.get('Accept-Language', ''),
            'ip_address': ip_address,
        }
        
        return components
    
    def hash_fingerprint(self, fingerprint):
        """Create a hash from device fingerprint."""
        fp_string = '|'.join([
            fingerprint.get('browser', ''),
            fingerprint.get('browser_version', ''),
            fingerprint.get('os', ''),
            fingerprint.get('os_version', ''),
            str(fingerprint.get('is_mobile', False)),
        ])
        
        return hashlib.sha256(fp_string.encode()).hexdigest()
    
    def get_device_name(self, fingerprint):
        """Generate human-readable device name."""
        browser = fingerprint.get('browser', 'Unknown Browser')
        os = fingerprint.get('os', 'Unknown OS')
        device_type = 'Mobile' if fingerprint.get('is_mobile') else \
                     'Tablet' if fingerprint.get('is_tablet') else \
                     'Computer'
        
        return f"{device_type} - {browser} on {os}"
    
    # ==================== Device Trust Management ====================
    
    def is_device_trusted(self, user_id, fingerprint_hash):
        """Check if device is trusted for this user."""
        return self.storage.is_device_trusted(user_id, fingerprint_hash)
    
    def add_trusted_device(self, user_id, fingerprint, fingerprint_hash, metadata=None):
        """Add device to user's trusted devices."""
        device_name = self.get_device_name(fingerprint)
        ip_address = fingerprint.get('ip_address', '')
        
        device_data = {
            'user_id': user_id,
            'fingerprint_hash': fingerprint_hash,
            'device_name': device_name,
            'ip_address': ip_address,
            'first_seen': datetime.now(timezone.utc),
            'last_seen': datetime.now(timezone.utc),
            'is_trusted': True,
            'user_agent': fingerprint.get('user_agent', ''),
        }
        
        if metadata:
            device_data.update(metadata)
        
        self.storage.add_trusted_device(device_data)
    
    def update_device_last_seen(self, user_id, fingerprint_hash):
        """Update last seen timestamp for device."""
        self.storage.update_device_last_seen(user_id, fingerprint_hash)
    
    def get_trusted_devices(self, user_id):
        """Get all trusted devices for a user."""
        return self.storage.get_trusted_devices(user_id)
    
    def revoke_device(self, user_id, device_id):
        """Revoke trust for a device."""
        self.storage.revoke_device(user_id, device_id)
    
    # ==================== Device Approval Flow ====================
    
    def generate_device_approval_token(self, user_id, fingerprint_hash):
        """Generate token for device approval email."""
        token = secrets.token_urlsafe(32)
        
        expiry_seconds = current_app.config.get('PASS0_DEVICE_CHALLENGE_EXPIRY', 900)
        
        challenge_data = {
            'token': token,
            'user_id': user_id,
            'fingerprint_hash': fingerprint_hash,
            'created_at': datetime.now(timezone.utc),
            'expires_at': datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds),
            'used': False
        }
        
        self.storage.store_device_challenge(challenge_data)
        
        return token
    
    def verify_device_approval_token(self, token):
        """Verify device approval token."""
        return self.storage.verify_device_challenge(token)
    
    def send_device_approval_email(self, email, user_id, fingerprint, approval_url):
        """Send device approval email."""
        app_name = current_app.config.get('PASS0_APP_NAME', 'Your Application')
        device_name = self.get_device_name(fingerprint)
        ip_address = fingerprint.get('ip_address', 'Unknown')
        
        subject = f"New login from {device_name}"
        
        text = (
            f"We detected a new login to your {app_name} account:\n\n"
            f"Device: {device_name}\n"
            f"IP Address: {ip_address}\n"
            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"If this was you, click here to approve this device:\n{approval_url}\n\n"
            f"If this wasn't you, please secure your account immediately."
        )
        
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #d32f2f;">⚠️ New Device Login</h1>
                    <p>We detected a new login to your {app_name} account:</p>
                    
                    <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
                        <strong>Device:</strong> {device_name}<br>
                        <strong>IP Address:</strong> {ip_address}<br>
                        <strong>Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </div>
                    
                    <p><strong>Was this you?</strong></p>
                    <p>
                        <a href="{approval_url}" 
                           style="display: inline-block; padding: 12px 24px; 
                                  background-color: #4285f4; color: white; 
                                  text-decoration: none; border-radius: 4px;">
                            Yes, Approve This Device
                        </a>
                    </p>
                    
                    <p style="margin-top: 30px; color: #666;">
                        <strong>This wasn't you?</strong><br>
                        If you didn't attempt to log in, please secure your account immediately.
                        This link will expire in 15 minutes.
                    </p>
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