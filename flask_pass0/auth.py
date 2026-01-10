from flask import Blueprint, session, redirect, url_for, request, current_app, jsonify
from datetime import datetime, timedelta, timezone
from .magic_link import generate_magic_link, verify_magic_link
from .storage import InMemoryStorageAdapter
from .two_factor import TwoFactorAuth
from functools import wraps
from urllib.parse import urlparse, unquote

class Pass0:
    """Passwordless authentication for Flask with optional 2FA."""
    
    def __init__(self, app=None, storage_adapter=None, user_model=None):
        self.app = app
        self.blueprint = Blueprint('pass0', __name__, template_folder='templates')

        self.storage = storage_adapter or InMemoryStorageAdapter()
        self.user_model = user_model
        
        self.two_factor = None
        
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
        
        app.extensions['pass0'] = self
        
        if hasattr(self.storage, 'init_app'):
            self.storage.init_app(app)
        
        if app.config.get('PASS0_2FA_ENABLED'):
            self.two_factor = TwoFactorAuth(self.storage)
            
            # Require 2FA verify route to be configured
            if not app.config.get('PASS0_2FA_VERIFY_ROUTE'):
                raise ValueError(
                    "Missing required config: PASS0_2FA_VERIFY_ROUTE"
                )
        
        # Register routes after all initialization is complete
        self._register_routes()
        
        # Register blueprint after routes are added
        app.register_blueprint(self.blueprint, url_prefix='/auth')
    
    def _regenerate_session(self):
        """Regenerate session ID to prevent session fixation attacks."""
        # Save current session data
        session_data = dict(session)
        
        # Clear old session
        session.clear()
        
        # Create new session with same data
        for key, value in session_data.items():
            session[key] = value
        
        # Force session to be saved
        session.modified = True

    def _cleanup_temp_session_keys(self):
        """Remove temporary authentication session keys after full login."""
        temp_keys = [
            '2fa_pending',
        ]
        
        for key in temp_keys:
            session.pop(key, None)

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

    def _check_2fa(self, user):
        """Check 2FA requirements after authentication."""
        user_id = user.get('id')
        
        # Check if user has 2FA enabled
        has_2fa = self.two_factor and self.two_factor.is_2fa_enabled(user_id)
        
        if has_2fa:
            session['2fa_pending'] = True
            
            # Use configured route
            verify_route = current_app.config.get('PASS0_2FA_VERIFY_ROUTE')

            return {
                'allow': False,
                'redirect': verify_route,  #configurable
                'reason': '2fa_required'
            }
        
        # Check if 2FA is required but not enabled
        if current_app.config.get('PASS0_2FA_REQUIRED') and self.two_factor:
            if not has_2fa:
                return {
                    'allow': False,
                    'redirect': 'pass0.setup_2fa',
                    'reason': '2fa_setup_required'
                }
        
        return {'allow': True, 'redirect': None, 'reason': 'authenticated'}

    def _resolve_next_url(self, raw_value, default=None):
        """
        Resolve a user-provided or stored redirect target safely.

        - Only allows internal paths like "/dashboard?x=1"
        - Rejects absolute URLs and weird paths (including encoded // and scheme-relative)
        """
        if default is None:
            default = current_app.config.get('PASS0_REDIRECT_URL', '/')

        if not raw_value:
            return default

        raw_value = str(raw_value).strip()
        if not raw_value:
            return default

        # Reject scheme-relative / network-path references early (//evil.com, ///evil.com, etc.)
        if raw_value.startswith("//"):
            return default

        parsed = urlparse(raw_value)

        # Reject absolute URLs: http://evil.com, https://evil.com, etc.
        if parsed.scheme or parsed.netloc:
            return default

        path = parsed.path or ""

        # Decode once to catch encoded bypasses like "/%2f%2fevil.com"
        decoded_path = unquote(path)

        # Require a normal internal path
        if not decoded_path.startswith("/"):
            return default

        # Reject protocol-relative after decoding (//evil.com)
        if decoded_path.startswith("//"):
            return default

        # Reject backslashes (common normalization bypass class)
        if "\\" in decoded_path:
            return default

        # Normalize path + query, ignore fragment
        resolved = path
        if parsed.query:
            resolved = f"{path}?{parsed.query}"

        return resolved


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
        
        # auth.py - Replace lines 266-294 with this:

        @self.blueprint.route('/verify/<token>')
        def verify(token):
            """Verify a magic link token and proceed with auth flow."""
            result = verify_magic_link(token, storage=self.storage)
            
            if not result['success']:
                # Pass both error and hint (if present) to login page
                return redirect(url_for('pass0.login', 
                                        error=result['error'],
                                        hint=result.get('hint', '')))
            
            user = result['user']
            user_id = user.get('id')
            
            session['user_id'] = user_id
            self._regenerate_session() 
            
            check_result = self._check_2fa(user)
            
            if not check_result['allow']:
                return redirect(url_for(check_result['redirect']))
            
            # Fully authenticated
            session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
            session.pop('2fa_pending', None)
            self._cleanup_temp_session_keys() 
            
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
            
            if not self.is_authenticated():
                return redirect(url_for('pass0.login'))
            
            user_id = session.get('user_id')
            
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
            
            user_id = session.get('user_id')
            
            if request.method == 'GET':
                # No template rendering in the package; host app provides UI.
                return jsonify({
                    'two_factor_required': True
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