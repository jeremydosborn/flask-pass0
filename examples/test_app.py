from datetime import datetime
from flask import Flask, render_template, jsonify, session, request, redirect
from flask_sqlalchemy import SQLAlchemy

from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter
from flask_pass0.utils import login_required, get_current_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Pass0 configuration
app.config['PASS0_DEV_MODE'] = True
app.config['PASS0_2FA_ENABLED'] = True
app.config['PASS0_2FA_REQUIRED'] = False
app.config['PASS0_TOTP_ISSUER'] = 'Flask-Pass0 Demo'
app.config['PASS0_DEVICE_BINDING_ENABLED'] = True
app.config['PASS0_SKIP_DEVICE_IF_2FA'] = True
app.config['PASS0_AUTO_APPROVE_DEVICES'] = True  # TEST APP ONLY - auto-approve new devices
app.config['PASS0_AUTO_APPROVE_DEVICES'] = True  # TEST APP ONLY - auto approve in dev

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

# Initialize Pass0 outside app context
pass0 = Pass0(app, storage_adapter=storage)

# Security logging
security_logs = []

def log_event(event_type, message, **data):
    sanitized = {}
    for k, v in data.items():
        if k == 'ip_address':
            parts = str(v).split('.')
            sanitized[k] = f"{parts[0]}.{parts[1]}.x.x" if len(parts) == 4 else 'x.x.x.x'
        else:
            sanitized[k] = v
    
    event = {
        'timestamp': datetime.utcnow().isoformat(),
        'type': event_type,
        'message': message,
        'data': sanitized
    }
    security_logs.append(event)
    print(f"[{event_type}] {message}")
    if sanitized:
        for k, v in list(sanitized.items())[:3]:  # Print first 3 items
            print(f"  {k}: {v}")

# Request logging
@app.before_request
def log_request():
    if '/auth/' in request.path or '/api/' in request.path:
        log_event('request', f'{request.method} {request.path}', 
                 ip_address=request.remote_addr,
                 endpoint=request.endpoint or 'unknown')

# Routes
@app.route('/')
@login_required
def index():
    user = get_current_user()
    if not user:
        return redirect('/auth/login')
    
    twofa_enabled = False
    if hasattr(pass0, 'two_factor') and pass0.two_factor:
        twofa_enabled = pass0.two_factor.is_2fa_enabled(user['id'])
    
    return render_template(
        'dashboard.html',
        user=user,
        twofa_enabled=twofa_enabled,
        config=app.config
    )

@app.route('/public')
def public():
    return '<h1>Public Page</h1><p><a href="/auth/login">Login</a></p>'

# Security logs API
@app.route('/api/security-logs')
@login_required
def get_security_logs():
    return jsonify({'events': list(reversed(security_logs[-100:]))})

@app.route('/api/security-logs/clear', methods=['POST'])
@login_required
def clear_security_logs():
    security_logs.clear()
    user = get_current_user()
    log_event('logs_cleared', 'Security logs cleared', user_id=user['id'])
    return jsonify({'success': True})

# Auth event logging
@app.after_request
def log_auth_events(response):
    # Magic link request
    if request.endpoint == 'pass0.request_magic_link' and request.method == 'POST':
        try:
            data = request.get_json()
            if data and response.status_code == 200:
                email = data.get('email')
                log_event('step_1_magic_link', 'Magic link requested', 
                         email=email, ip_address=request.remote_addr)
                log_event('step_2_token_gen', 'Token generated and hashed', email=email)
                log_event('step_3_token_stored', 'Token stored in database', email=email)
                
                if app.config.get('PASS0_DEV_MODE'):
                    response_data = response.get_json()
                    if response_data and 'link' in response_data:
                        token = response_data['link'].split('/')[-1]
                        log_event('step_4_link_gen', 'Magic link generated (DEV MODE)',
                                 email=email, token_preview=token[:12]+'...',
                                 full_link=response_data['link'])
        except:
            pass
    
    # Magic link verification
    if request.endpoint == 'pass0.verify':
        token = request.view_args.get('token', '')
        log_event('step_5_link_clicked', 'Magic link clicked',
                 token_preview=token[:12]+'...',
                 ip_address=request.remote_addr)
        
        if response.status_code == 302 and 'user_id' in session:
            user = get_current_user()
            if user:
                log_event('step_6_token_verified', 'Token verified in database',
                         user_id=user['id'], email=user['email'])
                log_event('step_7_session_created', 'User session created',
                         user_id=user['id'])
                
                # Check if device was recognized
                if hasattr(pass0, 'device_binding') and pass0.device_binding:
                    fingerprint = pass0.device_binding.get_device_fingerprint()
                    fp_hash = pass0.device_binding.hash_fingerprint(fingerprint)
                    is_trusted = pass0.device_binding.is_device_trusted(user['id'], fp_hash)
                    
                    if is_trusted:
                        log_event('step_8_device_recognized', 'Existing trusted device detected',
                                 user_id=user['id'])
                    else:
                        log_event('step_8_device_new', 'New device - adding to trusted devices',
                                 user_id=user['id'],
                                 device_name=pass0.device_binding.get_device_name(fingerprint))
                
                log_event('login_success', 'LOGIN SUCCESSFUL',
                         user_id=user['id'],
                         email=user['email'],
                         ip_address=request.remote_addr)
    
    # 2FA setup GET
    if request.endpoint == 'pass0.setup_2fa' and request.method == 'GET':
        user = get_current_user()
        if user and response.status_code == 200:
            log_event('2fa_step_1', '2FA setup initiated', user_id=user['id'])
            try:
                response_data = response.get_json()
                if response_data and 'secret' in response_data:
                    log_event('2fa_step_2', 'TOTP secret generated',
                             user_id=user['id'],
                             secret_preview=response_data['secret'][:8]+'...')
                    log_event('2fa_step_3', 'QR code generated', user_id=user['id'])
            except:
                pass
    
    # 2FA setup POST
    if request.endpoint == 'pass0.setup_2fa' and request.method == 'POST':
        user = get_current_user()
        if user:
            log_event('2fa_step_4', 'Verification code submitted', user_id=user['id'])
            
            if response.status_code == 200:
                try:
                    response_data = response.get_json()
                    if response_data and response_data.get('success'):
                        log_event('2fa_step_5', 'Code verified successfully', user_id=user['id'])
                        backup_count = len(response_data.get('backup_codes', []))
                        log_event('2fa_step_6', f'{backup_count} backup codes generated',
                                 user_id=user['id'])
                        log_event('2fa_step_7', 'Secret encrypted and stored in DB',
                                 user_id=user['id'])
                        log_event('2fa_enabled', '2FA ENABLED SUCCESSFULLY',
                                 user_id=user['id'],
                                 ip_address=request.remote_addr)
                except:
                    pass
            else:
                log_event('2fa_setup_failed', '2FA setup failed - invalid code',
                         user_id=user['id'])
    
    # 2FA disable
    if request.endpoint == 'pass0.disable_2fa' and request.method == 'POST':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                log_event('2fa_disabled', '2FA DISABLED',
                         user_id=user['id'],
                         ip_address=request.remote_addr)
    
    # Backup codes regeneration
    if request.endpoint == 'pass0.backup_codes' and request.method == 'POST':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                try:
                    response_data = response.get_json()
                    backup_count = len(response_data.get('backup_codes', []))
                    log_event('backup_codes_regen', 'Backup codes regenerated',
                             user_id=user['id'],
                             new_count=backup_count)
                except:
                    pass
    
    # Device listing
    if request.endpoint == 'pass0.list_devices' and request.method == 'GET':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                try:
                    response_data = response.get_json()
                    device_count = len(response_data.get('devices', []))
                    log_event('devices_listed', f'Retrieved {device_count} trusted devices',
                             user_id=user['id'])
                except:
                    pass
    
    # Device revocation
    if request.endpoint == 'pass0.revoke_device' and request.method == 'POST':
        if response.status_code == 200:
            user = get_current_user()
            if user:
                device_id = request.view_args.get('device_id')
                log_event('device_revoked', 'Device trust revoked',
                         user_id=user['id'],
                         device_id=device_id)
    
    # Logout
    if request.endpoint == 'pass0.logout':
        user = get_current_user()
        if user:
            log_event('logout', 'User logged out',
                     user_id=user['id'],
                     ip_address=request.remote_addr)
    
    return response

if __name__ == '__main__':
    print("Flask-Pass0 Demo • 2FA + Device Binding + Security Logging • http://127.0.0.1:5000")
    app.run(debug=True)