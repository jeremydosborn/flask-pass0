import secrets
from datetime import datetime, timedelta, timezone
from flask import url_for, current_app
from flask_mail import Mail, Message

def generate_magic_link(email, next_url=None, storage=None):
    """Generate a magic link for the given email.
    
    Args:
        email (str): The email address to send the link to.
        next_url (str, optional): Optional URL to redirect to after login.
        storage (StorageAdapter, optional): Storage adapter instance.
    
    Returns:
        str: The generated magic link URL.
    """
    # Lookup user
    if storage:
        user = storage.get_user_by_email(email)
    else:
        # Dev-only in-memory lookup (NO creation)
        from .storage import _users
        user = _users.get(email)
    
    # Generate cryptographically secure token (256-bit entropy)
    token = secrets.token_urlsafe(32)
    
    # Store token metadata.
    # Tokens are always stored and emailed to prevent account enumeration.
    # user_id may be None for non-existent accounts; verification requires a bound user.
    token_data = {
    'email': email,
    'next_url': next_url,
    }

    if storage:
        # Storage adapter handles expiry, hashing, and security
        storage.store_token(token, token_data)
    else:
        # Fallback to in-memory storage (dev only)
        # In-memory storage doesn't hash tokens (dev mode only!)
        expiry_minutes = current_app.config.get('PASS0_TOKEN_EXPIRY', 10)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
        token_data['expiry'] = expiry
        
        from .storage import _tokens
        _tokens[token] = token_data
    
    # Generate full URL to the verify endpoint on the pass0 blueprint
    link = url_for('pass0.verify', token=token, _external=True)
    
    # Send the email if not in development mode
    if not current_app.config.get('PASS0_DEV_MODE', False):  # FIXED: Safe default
        send_magic_link_email(email, link)
    else:
        # DEV MODE: log the link instead of sending email
        current_app.logger.info(f"MAGIC LINK for {email}: {link}")
        if next_url:
            current_app.logger.info(f"Will redirect to: {next_url}")
    
    return link


def send_magic_link_email(email, link):
    """Send magic link email via Flask-Mail."""
    app_name = current_app.config.get('PASS0_APP_NAME', 'Your Application')
    expiry_minutes = current_app.config.get('PASS0_TOKEN_EXPIRY', 10)

    subject = "Your Magic Login Link"
    text = (
        f"Click this link to log in to {app_name}: {link}\n\n"
        f"This link will expire in {expiry_minutes} minutes."
    )
    
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #4285f4;">Your Magic Login Link</h1>
                <p>Click the button below to log in to {app_name}:</p>
                <p>
                    <a href="{link}" 
                       style="display: inline-block; padding: 10px 20px; 
                              background-color: #4285f4; color: white; 
                              text-decoration: none; border-radius: 4px;">
                        Log In
                    </a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #666;">{link}</p>
                <p><em>This link will expire in {expiry_minutes} minutes.</em></p>
                <p>If you didn't request this login link, you can safely ignore this email.</p>
            </div>
        </body>
    </html>
    """
    
    # Get or create Mail instance
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
    return {"message": "Email sent successfully"}

def verify_magic_link(token, storage=None):
    if storage:
        token_data = storage.get_token(token)
        
        # Generic error - don't reveal why it failed
        if not token_data:
            return {'success': False, 'error': 'Invalid or expired token'}
        
        email = token_data.get('email')
        
        # Lookup user by email from the verified token
        user = storage.get_user_by_email(email)
        
        # Same generic error - don't reveal if user exists or not
        if not user:
            return {'success': False, 'error': 'Invalid or expired token'}
        
        # Success - token valid AND user exists
        next_url = token_data.get('next_url')
        result = {'success': True, 'user': user}
        if next_url:
            result['next_url'] = next_url
        return result