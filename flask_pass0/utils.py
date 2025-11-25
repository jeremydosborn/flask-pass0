from functools import wraps
from flask import current_app, session, redirect, url_for, g, request

def login_required(f):
    """Decorator to require login for a view.
    
    Example:
        @app.route('/profile')
        @login_required
        def profile():
            return 'Protected page'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get Pass0 extension
        pass0 = current_app.extensions.get('pass0')
        
        if not pass0 or not pass0.is_authenticated():
            # Store the requested URL to redirect after login
            session['next'] = request.url
            return redirect(url_for('pass0.login'))
        
        # Add the current user to flask.g for easy access
        g.user = pass0.get_current_user()
        
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get the current authenticated user.
    
    Returns:
        dict or None: The current user if authenticated, None otherwise
    """
    # Get Pass0 extension
    pass0 = current_app.extensions.get('pass0')
    
    if not pass0 or not pass0.is_authenticated():
        return None
    
    return pass0.get_current_user()

def is_authenticated():
    """Check if the current user is authenticated.
    
    Returns:
        bool: True if authenticated, False otherwise
    """
    # Get Pass0 extension
    pass0 = current_app.extensions.get('pass0')
    
    if not pass0:
        return False
    
    return pass0.is_authenticated()

def logout():
    """Log the current user out.
    
    Returns:
        Response: Redirect to login page
    """
    # Get Pass0 extension
    pass0 = current_app.extensions.get('pass0')
    
    if not pass0:
        return redirect('/')
    
    return redirect(url_for('pass0.logout'))