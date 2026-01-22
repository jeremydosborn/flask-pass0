from flask import Blueprint, session, redirect, url_for, request, current_app, jsonify
from datetime import datetime, timedelta, timezone
from .magic_link import generate_magic_link, verify_magic_link
from .storage import InMemoryStorageAdapter
from .two_factor import TwoFactorAuth
from functools import wraps
from urllib.parse import urlparse
from .passkey import (
    generate_passkey_registration_options,
    verify_passkey_registration,
    generate_passkey_authentication_options,
    verify_passkey_authentication,
)

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
            'passkey': {  
                'enabled': True,
                'name': 'Passkey',
                'description': 'Use biometrics or security key'
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

        app.config.setdefault('PASS0_RP_ID', 'localhost')
        app.config.setdefault('PASS0_RP_NAME', 'Flask-Pass0')
        app.config.setdefault('PASS0_ORIGIN', 'http://localhost:5000')
        
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

    def _cleanup_temp_session_keys(self):
        """Remove temporary authentication session keys after full login."""
        temp_keys = [
            '2fa_pending',
            '2fa_setup_required',
        ]
        
        for key in temp_keys:
            session.pop(key, None)

    def _on_fully_authenticated(self, user_id):
        credential_id = session.pop('passkey_credential_id', None)
        if current_app.config.get('PASS0_PASSKEY_CLEANUP_STALE') and credential_id:
            self._cleanup_stale_passkeys(user_id, credential_id)

    def _cleanup_stale_passkeys(self, user_id, current_credential_id):
        """Remove passkeys older than retention period based on created_at (age-based rotation)."""

        max_age = current_app.config.get('PASS0_PASSKEY_MAX_AGE_DAYS', 90)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age)

        passkeys = self.storage.get_passkey_credentials(user_id) or []

        for pk in passkeys:
            # Don't delete the passkey that was just used to authenticate
            if pk.get('credential_id') == current_credential_id:
                continue

            created = pk.get('created_at')
            if not created:
                continue

            try:
                # InMemory adapter stores isoformat strings; SQLAlchemy returns datetime objects
                created_dt = datetime.fromisoformat(created) if isinstance(created, str) else created

                # Make timezone-aware if naive
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)

                if created_dt < cutoff:
                    self.storage.delete_passkey_credential(pk['id'])
            except (ValueError, TypeError):
                # If parsing fails, skip rather than deleting unpredictably
                continue

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
                session['2fa_setup_required'] = True
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

            check_result = self._check_2fa(user)
            
            if not check_result['allow']:
                return redirect(url_for(check_result['redirect']))
            
            # Fully authenticated
            session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
            self._cleanup_temp_session_keys()
            self._on_fully_authenticated(user_id)
            
            # Safe redirect target resolution: no request.args['next'], internal paths only
            raw_next = result.get('next_url') or session.pop('next', None)
            next_url = self._resolve_next_url(raw_next)
            return redirect(next_url)

        # ==================== Passkey Routes ====================
        
        @self.blueprint.route('/passkey/register/options', methods=['POST'])
        def passkey_register_options():
            """Generate passkey registration options. No email required."""
            try:
                if not self.auth_methods.get('passkey', {}).get('enabled', False):
                    return jsonify({'error': 'Passkey authentication is not enabled'}), 400
                
                # No email needed for passkey registration
                options = generate_passkey_registration_options()
                
                return options, 200, {'Content-Type': 'application/json'}
                
            except Exception as e:
                current_app.logger.error(f"Error generating passkey registration options: {str(e)}")
                return jsonify({'error': str(e)}), 500
                
        @self.blueprint.route('/passkey/register/verify', methods=['POST'])
        def passkey_register_verify():
            """Verify passkey registration and authenticate user."""
            data = request.get_json()
            credential = data.get('credential')
            
            if not credential:
                return jsonify({'error': 'Credential is required'}), 400
            
            try:
                result = verify_passkey_registration(credential, self.storage)
                
                if not result['success']:
                    return jsonify({'error': result['error']}), 401
                
                user = result['user']
                
                # Set session
                session['user_id'] = user['id']
                session['passkey_credential_id'] = credential.get('id')
                
                # Check 2FA
                check_result = self._check_2fa(user)
                
                if not check_result['allow']:
                    redirect_url = url_for(check_result['redirect'])
                    return jsonify({
                        'requires_2fa': True,
                        'redirect': redirect_url
                    }), 200
                
                # No 2FA - complete login
                session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
                self._cleanup_temp_session_keys()
                self._on_fully_authenticated(user['id'])
                
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'email': user['email']
                    }
                }), 200
                
            except Exception as e:
                current_app.logger.error(f"Error verifying passkey registration: {str(e)}")
                return jsonify({'error': str(e)}), 500
        
        @self.blueprint.route('/passkey/login/options', methods=['POST'])
        def passkey_login_options():
            """Generate passkey authentication options. No email required."""
            try:
                if not self.auth_methods.get('passkey', {}).get('enabled', False):
                    return jsonify({'error': 'Passkey authentication is not enabled'}), 400
                
                # No email needed - uses discoverable credentials
                options = generate_passkey_authentication_options(self.storage)
                
                return options, 200, {'Content-Type': 'application/json'}
                
            except Exception as e:
                current_app.logger.error(f"Error generating passkey authentication options: {str(e)}")
                return jsonify({'error': str(e)}), 500
        
        @self.blueprint.route('/passkey/login/verify', methods=['POST'])
        def passkey_login_verify():
            """Verify passkey authentication."""
            data = request.get_json()
            credential = data.get('credential')
            
            if not credential:
                return jsonify({'error': 'Credential is required'}), 400
            
            try:
                result = verify_passkey_authentication(credential, self.storage)
                
                if not result['success']:
                    return jsonify({'error': result['error']}), 401
                
                user = result['user']
                
                # Set session
                session['user_id'] = user['id']
                session['passkey_credential_id'] = credential.get('id')
                
                # Check 2FA
                check_result = self._check_2fa(user)
                
                if not check_result['allow']:
                    redirect_url = url_for(check_result['redirect'])
                    return jsonify({
                        'requires_2fa': True,
                        'redirect': redirect_url
                    }), 200
                
                # No 2FA - complete login
                session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
                self._cleanup_temp_session_keys()
                self._on_fully_authenticated(user['id'])
                
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'email': user['email']
                    }
                }), 200
                
            except Exception as e:
                current_app.logger.error(f"Error verifying passkey authentication: {str(e)}")
                return jsonify({'error': str(e)}), 500


        # ==================== Passkey Management Routes ====================

        @self.blueprint.route('/passkeys', methods=['GET'])
        def list_passkeys():
            """List all passkeys for the current user."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session.get('user_id')
            
            try:
                passkeys = self.storage.get_passkey_credentials(user_id)
                
                return jsonify({
                    'success': True,
                    'passkeys': passkeys
                })
                
            except Exception as e:
                current_app.logger.error(f"Error listing passkeys: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.blueprint.route('/passkeys/<int:passkey_id>', methods=['DELETE'])
        def revoke_passkey(passkey_id):
            """Revoke a specific passkey."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session.get('user_id')
            
            try:
                # Get the passkey to verify ownership
                passkey = None
                passkeys = self.storage.get_passkey_credentials(user_id)
                
                for pk in passkeys:
                    if pk['id'] == passkey_id:
                        passkey = pk
                        break
                
                if not passkey:
                    return jsonify({'error': 'Passkey not found'}), 404
                
                # Verify the passkey belongs to this user
                if passkey['user_id'] != user_id:
                    return jsonify({'error': 'Unauthorized'}), 403
                
                # Delete the passkey
                self.storage.delete_passkey_credential(passkey_id)
                
                return jsonify({
                    'success': True,
                    'message': 'Passkey revoked successfully'
                })
                
            except Exception as e:
                current_app.logger.error(f"Error revoking passkey: {str(e)}")
                return jsonify({'error': str(e)}), 500
        
        # ==================== 2FA Routes ====================
        
        @self.blueprint.route('/2fa/setup', methods=['GET', 'POST'])
        def setup_2fa():
            """Setup 2FA for the current user."""
            if not self.two_factor:
                return jsonify({'error': '2FA not enabled'}), 400
            
            if not self.is_authenticated() and not session.get('2fa_setup_required'):
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
            
            if not session.get('logged_in_at'):
                session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
                self._cleanup_temp_session_keys() 
                self._on_fully_authenticated(user_id)
            
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
            
            session['logged_in_at'] = datetime.now(timezone.utc).isoformat()
            self._cleanup_temp_session_keys()
            self._on_fully_authenticated(user_id)
            
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