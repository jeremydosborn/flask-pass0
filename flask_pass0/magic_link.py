import secrets
from datetime import datetime, timedelta
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
    # Get or create user using the storage adapter
    if storage:
        user = storage.get_or_create_user(email)
    else:
        # Fallback to in-memory storage if no adapter provided.
        # NOTE: this is intended for development/testing only.
        user = get_or_create_user(email)
    
    # Generate token
    token = secrets.token_urlsafe(32)
    
    # Set expiration time (use UTC for consistency)
    expiry_minutes = current_app.config.get('PASS0_TOKEN_EXPIRY', 10)
    expiry = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    
    # Store token with expiry and next_url if provided
    token_data = {
        'email': email,
        'expiry': expiry,
        'next_url': next_url,
    }
    
    if storage:
        storage.store_token(token, token_data)
    else:
        # Fallback to in-memory storage (dev only)
        from .storage import _tokens
        _tokens[token] = token_data
    
    # Generate full URL to the verify endpoint on the pass0 blueprint
    link = url_for('pass0.verify', token=token, _external=True)
    
    # Send the email if not in development mode
    if not current_app.config.get('PASS0_DEV_MODE', True):
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
    """Verify a magic link token and return user if valid.
    
    Args:
        token (str): The token to verify.
        storage (StorageAdapter, optional): Storage adapter instance.
    
    Returns:
        dict: Result with:
            - success (bool)
            - user (dict) if successful
            - next_url (str, optional)
            - error (str, optional)
    """
    if storage:
        # Use storage adapter
        token_data = storage.get_token(token)
        if not token_data:
            return {'success': False, 'error': 'Invalid token'}
            
        email = token_data.get('email')
        expiry = token_data.get('expiry')
        next_url = token_data.get('next_url')
    else:
        # Fallback to in-memory storage (dev only)
        from .storage import _tokens
        if token not in _tokens:
            return {'success': False, 'error': 'Invalid token'}
            
        token_data = _tokens[token]
        email = token_data.get('email')
        expiry = token_data.get('expiry')
        next_url = token_data.get('next_url')
    
    # Check if token is expired (use UTC)
    if datetime.utcnow() > expiry:
        return {'success': False, 'error': 'Expired token'}
    
    # Remove token (one-time use)
    if storage:
        storage.delete_token(token)
    else:
        from .storage import _tokens
        del _tokens[token]
    
    # Get user
    if storage:
        user = storage.get_or_create_user(email)
    else:
        user = get_or_create_user(email)
    
    result = {'success': True, 'user': user}
    if next_url:
        result['next_url'] = next_url
        
    return result


# Legacy function for backward compatibility
def get_or_create_user(email):
    """Legacy function for backward compatibility.
    
    Gets user by email or creates a new one using in-memory storage.
    Intended for development/testing without a real storage adapter.
    """
    from .storage import _users
    if email not in _users:
        # In production, you might want to verify the email exists first
        user_id = len(_users) + 1
        _users[email] = {
            'id': user_id,
            'email': email,
            'name': email.split('@')[0],  # Simple name from email
            'created_at': datetime.utcnow().isoformat(),
        }
    return _users[email]
