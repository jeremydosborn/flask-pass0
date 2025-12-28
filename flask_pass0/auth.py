from flask import Blueprint, session, redirect, url_for, request, current_app, jsonify
from datetime import datetime, timedelta, timezone
from .magic_link import generate_magic_link, verify_magic_link
from .storage import InMemoryStorageAdapter
from .two_factor import TwoFactorAuth
from .device_binding import DeviceBinding
from functools import wraps
from urllib.parse import urlparse

class Pass0:
    """Passwordless authentication for Flask with optional 2FA, device binding."""
    
    def __init__(self, app=None, storage_adapter=None, user_model=None):
        self.app = app
        self.blueprint = Blueprint('pass0', __name__, template_folder='templates')

        self.storage = storage_adapter or InMemoryStorageAdapter()
        self.user_model = user_model
        
        self.two_factor = None
        self.device_binding = None
        
        self.auth_methods = {
            'magic_link': {
                'enabled': True,
                'name': 'Magic Link',
                'description': 'Receive a secure login link via email'
            },
        }
        
        if app is not None:
            self.init_app(app)
        else:
            # Register routes even if app is None (will be called again in init_app)
            self._register_routes()
    
    def init_app(self, app):
        """Initialize the extension with Flask app."""
        app.config.setdefault('PASS0_TOKEN_EXPIRY', 10)
        app.config.setdefault('PASS0_REDIRECT_URL', '/')
        # Host app's login UI route (used by login stub + logout redirect)
        app.config.setdefault('PASS0_LOGIN_URL', '/login')
        app.config.setdefault('PASS0_DEV_MODE', False)
        app.config.setdefault('PASS0_SESSION_DURATION', 24 * 60 * 60)
        
        # Primary auth method
        app.config.setdefault('PASS0_PRIMARY_AUTH', 'magic_link')
        
        # 2FA configuration
        app.config.setdefault('PASS0_2FA_ENABLED', False)
        app.config.setdefault('PASS0_2FA_REQUIRED', False)
        app.config.setdefault('PASS0_2FA_CODE_EXPIRY', 300)
        app.config.setdefault('PASS0_TOTP_ISSUER', 'Flask-Pass0')
        
        # Device binding configuration
        app.config.setdefault('PASS0_DEVICE_BINDING_ENABLED', False)
        app.config.setdefault('PASS0_DEVICE_CHALLENGE_EXPIRY', 900)
        app.config.setdefault('PASS0_SKIP_DEVICE_IF_2FA', True)  # Optimization
        
        app.extensions['pass0'] = self
        
        if hasattr(self.storage, 'init_app'):
            self.storage.init_app(app)
        
        if app.config.get('PASS0_2FA_ENABLED'):
            self.two_factor = TwoFactorAuth(self.storage)
        
        if app.config.get('PASS0_DEVICE_BINDING_ENABLED'):
            self.device_binding = DeviceBinding(self.storage)
        
        # Register routes after all initialization is complete
        self._register_routes()
        
        # Register blueprint after routes are added
        app.register_blueprint(self.blueprint, url_prefix='/auth')
    
    def register_auth_method(self, method_id, config):
        """Register a new authentication method."""
        self.auth_methods[method_id] = config
    
    def login_required(self, f):
        """Decorator to require login for a view."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_authenticated():
                # Store internal path only; redirect target will be safely resolved later
                session['next'] = request.full_path
                return redirect(url_for('pass0.login'))
            return f(*args, **kwargs)
        return decorated_function
    
    def is_authenticated(self):
        """Check if the current user is authenticated."""
        if not session.get('user_id'):
            return False
        
        if session.get('2fa_pending'):
            return False
            
        logged_in_at = session.get('logged_in_at')
        if not logged_in_at:
            return False
        
        try:
            logged_in_dt = datetime.fromisoformat(logged_in_at)
        except (ValueError, TypeError):
            session.clear()
            return False
        
        session_duration = current_app.config.get('PASS0_SESSION_DURATION', 24 * 60 * 60)
        if datetime.now(timezone.utc) - logged_in_dt > timedelta(seconds=session_duration):
            session.clear()
            return False
            
        return True
    
    def get_current_user(self):
        """Get the current authenticated user."""
        if not self.is_authenticated():
            return None
            
        user_id = session.get('user_id')
        return self.storage.get_user_by_id(user_id)
    
    def _check_device_and_2fa(self, user):
        """Check device trust and 2FA requirements after authentication."""
        user_id = user.get('id')
        
        # Check if user has 2FA enabled
        has_2fa = self.two_factor and self.two_factor.is_2fa_enabled(user_id)
        
        # Optimization: Skip device binding if user has 2FA enabled
        skip_device = has_2fa and current_app.config.get('PASS0_SKIP_DEVICE_IF_2FA', True)
        
        # Check device binding if enabled and not skipped
        if self.device_binding and current_app.config.get('PASS0_DEVICE_BINDING_ENABLED') and not skip_device:
            fingerprint = self.device_binding.get_device_fingerprint()
            fingerprint_hash = self.device_binding.hash_fingerprint(fingerprint)
            
            if not self.device_binding.is_device_trusted(user_id, fingerprint_hash):
                session['pending_device_fingerprint'] = fingerprint
                session['pending_device_hash'] = fingerprint_hash
                
                approval_token = self.device_binding.generate_device_approval_token(
                    user_id, fingerprint_hash
                )
                approval_url = url_for('pass0.approve_device', token=approval_token, _external=True)
                
                user_email = user.get('email')
                self.device_binding.send_device_approval_email(
                    user_email, user_id, fingerprint, approval_url
                )
                
                return {
                    'allow': False,
                    'redirect': 'pass0.device_approval_required',
                    'reason': 'unrecognized_device'
                }
            else:
                self.device_binding.update_device_last_seen(user_id, fingerprint_hash)
        
        # Check 2FA if enabled
        if has_2fa:
            session['2fa_pending'] = True
            session['2fa_user_id'] = user_id
            
            return {
                'allow': False,
                'redirect': 'pass0.verify_2fa',
                'reason': '2fa_required'
            }
        
        # Check if 2FA is required but not enabled
        if current_app.config.get('PASS0_2FA_REQUIRED') and self.two_factor:
            if not has_2fa:
                return {
                    'allow': False,
                    'redirect': 'pass0.setup_2fa_required',
                    'reason': '2fa_setup_required'
                }
        
        return {'allow': True, 'redirect': None, 'reason': 'authenticated'}
    
    def _resolve_next_url(self, raw_value, default=None):
        """
        Resolve a user-provided or stored redirect target safely.

        - Only allows internal paths like "/dashboard?x=1"
        - Rejects absolute URLs and weird paths
        """
        if default is None:
            default = current_app.config.get('PASS0_REDIRECT_URL', '/')

        if not raw_value:
            return default

        parsed = urlparse(raw_value)

        # Reject absolute URLs: http://evil.com, //evil.com, etc.
        if parsed.scheme or parsed.netloc:
            return default

        # Require a normal internal path
        if not parsed.path.startswith('/'):
            return default

        # Normalize path + query, ignore fragment
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"

        return path

    def _register_routes(self):
        """Register authentication routes on the blueprint."""
        
        @self.blueprint.route('/login')
        def login():
            """
            Redirect to the application's login UI.

            Pass0 does not render templates; the host app is responsible for the UI.
            """
            target = current_app.config.get('PASS0_LOGIN_URL', '/login')
            return redirect(target)
        
        # ==================== Magic Link Routes ====================
        
        @self.blueprint.route('/request-magic-link', methods=['POST'])
        def request_magic_link():
            """Request a magic link for authentication."""
            data = request.get_json()
            email = data.get('email')
            
            if not email:
                return jsonify({'error': 'Email is required'}), 400
            
            try:
                if not self.auth_methods.get('magic_link', {}).get('enabled', False):
                    return jsonify({'error': 'Magic link authentication is not enabled'}), 400
                
                next_url = session.get('next')
                link = generate_magic_link(email, next_url=next_url, storage=self.storage)
                
                if current_app.config.get('PASS0_DEV_MODE', False):
                    return jsonify({'success': True, 'link': link})
                else:
                    return jsonify({'success': True, 'message': 'Magic link sent to your email'})
            except Exception as e:
                current_app.logger.error(f"Error generating magic link: {str(e)}")
                return jsonify({'error': str(e)}), 500
        
        @self.blueprint.route('/verify/<token>')
        def verify(token):
            """Verify a magic link token and proceed with auth flow."""
            result = verify_magic_link(token, storage=self.storage)
            
            if not result['success']:
                return redirect(url_for('pass0.login', error=result['error']))
            
            user = result['user']
            user_id = user.get('id')
            
            session['user_id'] = user_id
            
            check_result = self._check_device_and_2fa(user)
            
            if not check_result['allow']:
                return redirect(url_for(check_result['redirect']))
            
            # Fully authenticated
            session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
            session.pop('2fa_pending', None)
            
            # Add device to trusted list if device binding enabled and not skipped
            if self.device_binding and current_app.config.get('PASS0_DEVICE_BINDING_ENABLED'):
                has_2fa = self.two_factor and self.two_factor.is_2fa_enabled(user_id)
                skip_device = has_2fa and current_app.config.get('PASS0_SKIP_DEVICE_IF_2FA', True)
                
                if not skip_device:
                    fingerprint = self.device_binding.get_device_fingerprint()
                    fingerprint_hash = self.device_binding.hash_fingerprint(fingerprint)
                    
                    if not self.device_binding.is_device_trusted(user_id, fingerprint_hash):
                        self.device_binding.add_trusted_device(user_id, fingerprint, fingerprint_hash)
            
            # Safe redirect target resolution: no request.args['next'], internal paths only
            raw_next = result.get('next_url') or session.pop('next', None)
            next_url = self._resolve_next_url(raw_next)
            return redirect(next_url)
        
        # ==================== 2FA Routes ====================
        
        @self.blueprint.route('/2fa/setup', methods=['GET', 'POST'])
        def setup_2fa():
            """Setup 2FA for the current user."""
            if not self.two_factor:
                return jsonify({'error': '2FA not enabled'}), 400
            
            if not self.is_authenticated() and not session.get('2fa_user_id'):
                return redirect(url_for('pass0.login'))
            
            user_id = session.get('user_id') or session.get('2fa_user_id')
            
            if request.method == 'GET':
                secret = self.two_factor.generate_totp_secret()
                user = self.storage.get_user_by_id(user_id)
                uri = self.two_factor.get_totp_uri(user.get('email'), secret)
                qr_code = self.two_factor.generate_qr_code(uri)
                
                session['temp_totp_secret'] = secret
                
                return jsonify({
                    'qr_code': qr_code,
                    'secret': secret,
                    'uri': uri
                })
            
            data = request.get_json()
            code = data.get('code')
            secret = session.get('temp_totp_secret')
            
            if not secret or not code:
                return jsonify({'error': 'Invalid request'}), 400
            
            if not self.two_factor.verify_totp_code(secret, code):
                return jsonify({'error': 'Invalid verification code'}), 400
            
            backup_codes = self.two_factor.generate_backup_codes()
            self.two_factor.enable_2fa(user_id, secret, backup_codes)
            
            session.pop('temp_totp_secret', None)
            session.pop('2fa_pending', None)
            
            if not session.get('logged_in_at'):
                session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
            
            return jsonify({
                'success': True,
                'backup_codes': backup_codes,
                'message': '2FA enabled successfully'
            })
        
        @self.blueprint.route('/2fa/verify', methods=['GET', 'POST'])
        def verify_2fa():
            """Verify 2FA code during login."""
            if not self.two_factor:
                return jsonify({'error': '2FA not enabled'}), 400
            
            if not session.get('2fa_pending'):
                return redirect(url_for('pass0.login'))
            
            user_id = session.get('2fa_user_id')
            
            if request.method == 'GET':
                # No template rendering in the package; host app provides UI.
                return jsonify({
                    'two_factor_required': True,
                    'user_id': user_id
                })
            
            data = request.get_json()
            code = data.get('code')
            use_backup = data.get('use_backup', False)
            
            if not code:
                return jsonify({'error': 'Code is required'}), 400
            
            verified = False
            
            if use_backup:
                verified = self.two_factor.verify_backup_code(user_id, code)
            else:
                secret = self.two_factor.get_2fa_secret(user_id)
                verified = self.two_factor.verify_totp_code(secret, code)
            
            if not verified:
                return jsonify({'error': 'Invalid code'}), 400
            
            session.pop('2fa_pending', None)
            session.pop('2fa_user_id', None)
            session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
            
            return jsonify({'success': True, 'message': '2FA verification successful'})
        
        @self.blueprint.route('/2fa/disable', methods=['POST'])
        def disable_2fa():
            """Disable 2FA for the current user."""
            if not self.two_factor or not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session.get('user_id')
            self.two_factor.disable_2fa(user_id)
            
            return jsonify({'success': True, 'message': '2FA disabled'})
        
        @self.blueprint.route('/2fa/backup-codes', methods=['GET', 'POST'])
        def backup_codes():
            """View or regenerate backup codes."""
            if not self.two_factor or not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session.get('user_id')
            
            if request.method == 'POST':
                new_codes = self.two_factor.regenerate_backup_codes(user_id)
                return jsonify({'success': True, 'backup_codes': new_codes})
            
            return jsonify({'message': 'Use POST to regenerate backup codes'})
        
        # ==================== Device Binding Routes ====================
        
        @self.blueprint.route('/device-approval-required')
        def device_approval_required():
            """Page shown when device approval is needed."""
            return jsonify({
                'message': 'Device approval required. Please check your email.',
                'status': 'pending_approval'
            })
        
        @self.blueprint.route('/device/approve/<token>')
        def approve_device(token):
            """Approve a new device via email link."""
            if not self.device_binding:
                return jsonify({'error': 'Device binding not enabled'}), 400
            
            challenge = self.device_binding.verify_device_approval_token(token)
            
            if not challenge:
                return jsonify({'error': 'Invalid or expired approval link'}), 400
            
            user_id = challenge['user_id']
            fingerprint_hash = challenge['fingerprint_hash']
            
            device_data = {
                'user_id': user_id,
                'fingerprint_hash': fingerprint_hash,
                'device_name': 'Approved Device',
                'first_seen': datetime.now(timezone.utc),
                'last_seen': datetime.now(timezone.utc),
                'is_trusted': True
            }
            
            self.storage.add_trusted_device(device_data)
            
            return jsonify({
                'success': True,
                'message': 'Device approved successfully. You can now complete your login.'
            })
        
        @self.blueprint.route('/devices', methods=['GET'])
        def list_devices():
            """List all trusted devices for the current user."""
            if not self.device_binding or not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session.get('user_id')
            devices = self.device_binding.get_trusted_devices(user_id)
            
            return jsonify({'devices': devices})
        
        @self.blueprint.route('/devices/<int:device_id>/revoke', methods=['POST'])
        def revoke_device(device_id):
            """Revoke trust for a device."""
            if not self.device_binding or not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session.get('user_id')
            self.device_binding.revoke_device(user_id, device_id)
            
            return jsonify({'success': True, 'message': 'Device revoked'})
        
        @self.blueprint.route('/logout')
        def logout():
            """Log the user out by clearing the session."""
            session.clear()
            return redirect(current_app.config.get('PASS0_LOGIN_URL', '/login'))
    
    def on_user_created(self, user):
        """Called when a new user is created."""
        pass
    
    def on_user_deleted(self, user_id):
        """Called when a user is deleted."""
        pass