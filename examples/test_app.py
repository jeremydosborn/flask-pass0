from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, session, request, redirect
from flask_sqlalchemy import SQLAlchemy

from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter
from flask_pass0.utils import login_required, get_current_user

app = Flask(__name__)

# Core Flask configuration
app.config['SECRET_KEY'] = 'change-this-in-production-use-secrets'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Flaskmail config
app.config['MAIL_SUPPRESS_SEND'] = True  # Suppress email sending
app.config['MAIL_SERVER'] = 'localhost'  # Dummy config to prevent errors

# Pass0 configuration
app.config['PASS0_DEV_MODE'] = True
app.config['PASS0_2FA_ENABLED'] = True
app.config['PASS0_2FA_REQUIRED'] = False
app.config['PASS0_TOTP_ISSUER'] = 'Flask-Pass0 Demo'
app.config['PASS0_DEVICE_BINDING_ENABLED'] = False
app.config['PASS0_SKIP_DEVICE_IF_2FA'] = True
app.config['PASS0_LOGIN_REDIRECT'] = '/'
app.config['PASS0_MAGIC_LINK_ENABLED'] = True
app.config['PASS0_PRIMARY_AUTH'] = 'magic_link'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "email": self.email}

# Initialize database and Pass0
with app.app_context():
    db.create_all()
    storage = SQLAlchemyStorageAdapter(
        user_model=User,
        session=db.session,
        secret_key=app.config['SECRET_KEY']
    )
    pass0 = Pass0(app, storage_adapter=storage)

# Security logging
security_logs = []

def log_event(event_type, message, **data):
    """Log security events with IP sanitization"""
    sanitized = {}
    for k, v in data.items():
        if k == 'ip_address':
            parts = str(v).split('.')
            sanitized[k] = f"{parts[0]}.{parts[1]}.x.x" if len(parts) == 4 else 'x.x.x.x'
        else:
            sanitized[k] = v
    
    event = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'type': event_type,
        'message': message,
        'data': sanitized
    }
    security_logs.append(event)
    print(f"[{event_type}] {message}")
    if sanitized:
        for k, v in list(sanitized.items())[:3]:
            print(f"  {k}: {v}")

@app.before_request
def log_request():
    """Log authentication and API requests"""
    if '/auth/' in request.path or '/api/' in request.path:
        log_event(
            'request',
            f'{request.method} {request.path}',
            ip_address=request.remote_addr,
            endpoint=request.endpoint or 'unknown'
        )

# ============================================================================
# Main Routes
# ============================================================================

@app.route('/')
@login_required
def index():
    """Dashboard - requires authentication"""
    user = get_current_user()
    
    # Check 2FA status
    twofa_enabled = False
    if hasattr(pass0, 'two_factor') and pass0.two_factor:
        twofa_enabled = pass0.two_factor.is_2fa_enabled(user['id'])

    return render_template(
        'dashboard.html',
        user=user,
        twofa_enabled=twofa_enabled,
        config=app.config
    )

@app.route('/login')
def login_page():
    """Login page - redirect if already logged in"""
    if get_current_user():
        return redirect('/')
    return render_template('auth.html', config=app.config)

@app.route('/create-user')
def create_user():
    """Create test user for development"""
    email = 'jeremy.osborn@gmail.com'
    existing = User.query.filter_by(email=email).first()
    if existing:
        return f'User already exists: {email}'
    
    user = User(email=email)
    db.session.add(user)
    db.session.commit()
    return f'User created: {email} (id={user.id}). <a href="/login">Login now</a>'

@app.route('/public')
def public():
    """Public page accessible without login"""
    return '<h1>Public Page</h1><p><a href="/login">Login</a> | <a href="/">Dashboard</a></p>'

# ============================================================================
# 2FA Routes
# ============================================================================

@app.route('/2fa-verify', methods=['GET'])  # Different URL
def verify_2fa_page():
    """2FA verification page"""
    if not session.get('2fa_pending'):
        return redirect('/login')
    return render_template('2fa_verify.html')

@app.route('/auth/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA"""
    user = get_current_user()
    pass0.two_factor.disable_2fa(user['id'])
    log_event('2fa_disabled', '2FA disabled', user_id=user['id'])
    return jsonify({'success': True})

# ============================================================================
# Security Logs API
# ============================================================================

@app.route('/api/security-logs')
@login_required
def get_security_logs():
    """Get recent security logs"""
    logs_copy = [dict(event) for event in security_logs[-100:]]
    return jsonify({'events': list(reversed(logs_copy))})

@app.route('/api/security-logs/clear', methods=['POST'])
@login_required
def clear_security_logs():
    """Clear security logs"""
    security_logs.clear()
    user = get_current_user()
    log_event('logs_cleared', 'Security logs cleared', user_id=user['id'])
    return jsonify({'success': True})

# ============================================================================
# Auth Event Logging
# ============================================================================

@app.after_request
def log_auth_events(response):
    """Log authentication events after each request"""
    
    # Magic link request
    if request.endpoint == 'pass0.request_magic_link' and request.method == 'POST':
        try:
            data = request.get_json()
            if data and response.status_code == 200:
                email = data.get('email')
                log_event('step_1_email_entered', 'User entered email address', 
                         email=email, ip_address=request.remote_addr)
                log_event('step_2_token_gen', 'Cryptographic token generated (256-bit)', email=email)
                log_event('step_3_token_hashed', 'Token hashed with SHA-256', email=email)
                log_event('step_4_token_stored', 'Token hash stored in database', email=email)
                
                if app.config.get('PASS0_DEV_MODE'):
                    response_data = response.get_json()
                    if response_data and 'link' in response_data:
                        token = response_data['link'].split('/')[-1]
                        log_event('step_5_link_generated', 'Magic link URL generated (DEV MODE)',
                                email=email, token_preview=token[:12] + '...',
                                full_link=response_data['link'])
                else:
                    log_event('step_5_email_sent', 'Magic link sent via email', email=email)
        except Exception as e:
            print(f"Error logging magic link request: {e}")
    
    # Magic link verification
    if request.endpoint == 'pass0.verify':
        token = request.view_args.get('token', '')
        log_event('step_6_link_clicked', 'User clicked magic link',
                 token_preview=token[:12] + '...' if len(token) > 12 else token,
                 ip_address=request.remote_addr)
        
        if response.status_code == 302:
            # Check if verification was successful (user_id in session means success)
            if 'user_id' in session:
                user = get_current_user()
                if user:
                    log_event('step_7_token_verified', 'Token hash matched in database',
                             user_id=user['id'], email=user['email'])
                    log_event('step_8_user_authenticated', 'User identity verified',
                             user_id=user['id'], email=user['email'])
                    log_event('step_9_session_created', 'Secure session established',
                             user_id=user['id'])
                    
                    # Check if device was recognized
                    if hasattr(pass0, 'device_binding') and pass0.device_binding:
                        try:
                            fingerprint = pass0.device_binding.get_device_fingerprint()
                            fp_hash = pass0.device_binding.hash_fingerprint(fingerprint)
                            is_trusted = pass0.device_binding.is_device_trusted(user['id'], fp_hash)
                            
                            if is_trusted:
                                log_event('step_10_device_recognized', 
                                        'Trusted device detected - skipping additional verification',
                                        user_id=user['id'])
                            else:
                                log_event('step_10_device_new', 
                                        'New device - adding to trusted list',
                                        user_id=user['id'],
                                        device_name=pass0.device_binding.get_device_name(fingerprint))
                        except Exception as e:
                            print(f"Error checking device: {e}")
                    
                    log_event('login_success', '✓ LOGIN SUCCESSFUL - User authenticated via magic link',
                             user_id=user['id'], email=user['email'],
                             ip_address=request.remote_addr)
            else:
                # Token verification failed
                log_event('login_failed', '✗ LOGIN FAILED - Invalid or expired token',
                         ip_address=request.remote_addr)
    
    # 2FA setup GET - Initial setup request
    if request.endpoint == 'pass0.setup_2fa' and request.method == 'GET':
        user = get_current_user()
        if user and response.status_code == 200:
            log_event('2fa_setup_start', '2FA setup initiated by user',
                     user_id=user['id'])
            try:
                response_data = response.get_json()
                if response_data and 'secret' in response_data:
                    log_event('2fa_secret_generated', 'TOTP secret generated (base32)',
                             user_id=user['id'],
                             secret_preview=response_data['secret'][:8] + '...')
                    log_event('2fa_qr_generated', 'QR code generated for authenticator app',
                             user_id=user['id'])
            except Exception as e:
                print(f"Error logging 2FA setup: {e}")
    
    # 2FA setup POST - Verification and enablement
    if request.endpoint == 'pass0.setup_2fa' and request.method == 'POST':
        user = get_current_user()
        if user:
            log_event('2fa_code_submitted', 'User submitted verification code',
                     user_id=user['id'])
            
            if response.status_code == 200:
                try:
                    response_data = response.get_json()
                    if response_data and response_data.get('success'):
                        log_event('2fa_code_verified', 'TOTP code verified successfully',
                                 user_id=user['id'])
                        backup_count = len(response_data.get('backup_codes', []))
                        log_event('2fa_backup_codes_generated', 
                                f'{backup_count} backup codes generated',
                                user_id=user['id'])
                        log_event('2fa_secret_encrypted', 'Secret encrypted and stored in database',
                                 user_id=user['id'])
                        log_event('2fa_enabled', '✓ 2FA ENABLED SUCCESSFULLY',
                                 user_id=user['id'], ip_address=request.remote_addr)
                    else:
                        log_event('2fa_setup_failed', '✗ 2FA setup failed - invalid code',
                                 user_id=user['id'])
                except Exception as e:
                    print(f"Error logging 2FA enable: {e}")
    
    # 2FA verification during login
    if request.endpoint == 'pass0.verify_2fa' and request.method == 'POST':
        if response.status_code == 200:
            try:
                response_data = response.get_json()
                if response_data and response_data.get('success'):
                    user_id = session.get('user_id')
                    log_event('2fa_login_verified', '✓ 2FA verification successful',
                             user_id=user_id, ip_address=request.remote_addr)
                else:
                    log_event('2fa_login_failed', '✗ 2FA verification failed - invalid code',
                             ip_address=request.remote_addr)
            except Exception as e:
                print(f"Error logging 2FA verification: {e}")
    
    # 2FA disable
    if request.endpoint == 'pass0.disable_2fa' and request.method == 'POST':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                log_event('2fa_disabled', '2FA DISABLED by user',
                         user_id=user['id'], ip_address=request.remote_addr)
    
    # Backup codes regeneration
    if request.endpoint == 'pass0.backup_codes' and request.method == 'POST':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                try:
                    response_data = response.get_json()
                    backup_count = len(response_data.get('backup_codes', []))
                    log_event('backup_codes_regenerated', 
                             f'{backup_count} new backup codes generated - old codes invalidated',
                             user_id=user['id'])
                except Exception as e:
                    print(f"Error logging backup codes: {e}")
    
    # Device listing
    if request.endpoint == 'pass0.list_devices' and request.method == 'GET':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                try:
                    response_data = response.get_json()
                    device_count = len(response_data.get('devices', []))
                    log_event('devices_listed', 
                             f'User viewed {device_count} trusted device(s)',
                             user_id=user['id'])
                except Exception as e:
                    print(f"Error logging devices list: {e}")
    
    # Device revocation
    if request.endpoint == 'pass0.revoke_device' and request.method == 'POST':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                device_id = request.view_args.get('device_id')
                log_event('device_revoked', 'Device trust revoked',
                         user_id=user['id'], device_id=device_id)
    
    # Logout
    if request.endpoint == 'pass0.logout':
        user = get_current_user()
        if user:
            log_event('logout', 'User logged out - session cleared',
                     user_id=user['id'], ip_address=request.remote_addr)
    
    return response

if __name__ == '__main__':
    app.run(host="localhost", port=5000, debug=True, use_reloader=True)