from functools import wraps
from flask import current_app, session, g


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, redirect
        
        pass0 = current_app.extensions.get('pass0')
        
        if not pass0 or not pass0.is_authenticated():
            # API request gets JSON, browser gets redirect
            if request.is_json or request.headers.get('Accept') == 'application/json':
                return {'error': 'Unauthorized'}, 401
            return redirect('/login')
        
        g.user = pass0.get_current_user()
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    pass0 = current_app.extensions.get('pass0')
    
    if not pass0 or not pass0.is_authenticated():
        return None
    
    return pass0.get_current_user()


def is_authenticated():
    pass0 = current_app.extensions.get('pass0')
    
    if not pass0:
        return False
    
    return pass0.is_authenticated()


def logout():
    session.clear()
    return {'success': True}