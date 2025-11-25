from flask import Blueprint, session, redirect, url_for, render_template, request, current_app, jsonify
import time
from .magic_link import generate_magic_link, verify_magic_link, get_or_create_user
from .storage import get_storage_adapter
from functools import wraps

class Pass0:
    """Passwordless authentication for Flask."""
    
    def __init__(self, app=None, storage_adapter=None, user_model=None):
        self.app = app
        self.blueprint = Blueprint('pass0', __name__, template_folder='templates')
        
        # Initialize storage adapter
        self.storage = storage_adapter or get_storage_adapter()
        
        # Initialize with custom user model if provided
        self.user_model = user_model
        
        # Auth methods registry - can be extended in the future
        self.auth_methods = {
            'magic_link': {
                'enabled': True,
                'name': 'Magic Link',
                'description': 'Receive a secure login link via email'
            }
            # Future: passkey entry would go here
        }
        
        # Register routes on the blueprint
        self._register_routes()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the extension with Flask app."""
        # Set default configuration
        app.config.setdefault('PASS0_TOKEN_EXPIRY', 10)  # minutes
        app.config.setdefault('PASS0_REDIRECT_URL', '/')  # Default redirect after login
        app.config.setdefault('PASS0_LOGIN_URL', '/auth/login')  # Login page URL
        app.config.setdefault('PASS0_DEV_MODE', True)  # Development mode by default
        app.config.setdefault('PASS0_SESSION_DURATION', 24 * 60 * 60)  # Session duration in seconds (24 hours)
        
        # Register the blueprint
        app.register_blueprint(self.blueprint, url_prefix='/auth')
        
        # Store extension on app
        app.extensions['pass0'] = self
        
        # Initialize the storage adapter with the app
        if hasattr(self.storage, 'init_app'):
            self.storage.init_app(app)
    
    def register_auth_method(self, method_id, config):
        """Register a new authentication method."""
        self.auth_methods[method_id] = config
    
    def login_required(self, f):
        """Decorator to require login for a view."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_authenticated():
                # Store the requested URL to redirect after login
                session['next'] = request.url
                return redirect(url_for('pass0.login'))
            return f(*args, **kwargs)
        return decorated_function
    
    def is_authenticated(self):
        """Check if the current user is authenticated."""
        # Check if user_id exists in session
        if not session.get('user_id'):
            return False
            
        # Check if session has expired
        logged_in_at = session.get('logged_in_at', 0)
        session_duration = current_app.config.get('PASS0_SESSION_DURATION', 24 * 60 * 60)
        if int(time.time()) - logged_in_at > session_duration:
            # Session expired, clear it
            session.clear()
            return False
            
        return True
    
    def get_current_user(self):
        """Get the current authenticated user."""
        if not self.is_authenticated():
            return None
            
        user_id = session.get('user_id')
        return self.storage.get_user_by_id(user_id)
    
    def _register_routes(self):
        """Register authentication routes on the blueprint."""
        
        @self.blueprint.route('/login')
        def login():
            """Render the login page."""
            # If user is already logged in, redirect to default redirect URL
            if self.is_authenticated():
                return redirect(current_app.config.get('PASS0_REDIRECT_URL', '/'))
            
            # Get the next URL from query parameters or session
            next_url = request.args.get('next') or session.get('next')
            if next_url:
                session['next'] = next_url
            
            # Pass available auth methods to the template
            return render_template('auth.html', 
                                 auth_methods=self.auth_methods)
        
        @self.blueprint.route('/request-magic-link', methods=['POST'])
        def request_magic_link():
            """Request a magic link for authentication."""
            # Get email from JSON request
            data = request.get_json()
            email = data.get('email')
            
            if not email:
                return jsonify({'error': 'Email is required'}), 400
            
            # Generate and (in production) send magic link
            try:
                # Check if auth method is enabled
                if not self.auth_methods.get('magic_link', {}).get('enabled', False):
                    return jsonify({'error': 'Magic link authentication is not enabled'}), 400
                
                # Get the next URL from the session
                next_url = session.get('next')
                
                # Generate the magic link
                link = generate_magic_link(email, next_url=next_url, storage=self.storage)
                
                # In development mode, return the link in the response
                if current_app.config.get('PASS0_DEV_MODE', True):
                    return jsonify({'success': True, 'link': link})
                else:
                    return jsonify({'success': True, 'message': 'Magic link sent to your email'})
            except Exception as e:
                current_app.logger.error(f"Error generating magic link: {str(e)}")
                return jsonify({'error': str(e)}), 500
        
        @self.blueprint.route('/verify/<token>')
        def verify(token):
            """Verify a magic link token and log the user in."""
            # Validate token and get user
            result = verify_magic_link(token, storage=self.storage)
            
            if not result['success']:
                # If error, redirect to login page with error message
                return redirect(url_for('pass0.login', error=result['error']))
            
            # Set user session
            user = result['user']
            session['user_id'] = user.get('id')
            session['logged_in_at'] = int(time.time())
            
            # Redirect to protected page (or ?next= parameter or stored next URL)
            next_url = result.get('next_url') or session.pop('next', None) or request.args.get('next') or current_app.config.get('PASS0_REDIRECT_URL', '/')
            return redirect(next_url)
        
        @self.blueprint.route('/logout')
        def logout():
            """Log the user out by clearing the session."""
            session.clear()
            return redirect(current_app.config.get('PASS0_LOGIN_URL', '/auth/login'))

    # Hook to be implemented by extensions for user creation/deletion events
    def on_user_created(self, user):
        """Called when a new user is created."""
        pass
    
    def on_user_deleted(self, user_id):
        """Called when a user is deleted."""
        pass