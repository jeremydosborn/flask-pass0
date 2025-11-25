"""
Flask-Pass0 Basic Test Application

This is a minimal example showing how to use Flask-Pass0
for passwordless authentication with magic links.

Run with: python app.py
Then visit: http://127.0.0.1:5000
"""

from flask import Flask, render_template_string
from flask_pass0 import Pass0, login_required, get_current_user

app = Flask(__name__)

# ==================== CONFIGURATION ====================

# Required: Secret key for session management
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Pass0 Configuration
app.config['PASS0_DEV_MODE'] = True  # Shows magic links in console (no email needed)
app.config['PASS0_TOKEN_EXPIRY'] = 10  # Magic links expire after 10 minutes
app.config['PASS0_SESSION_DURATION'] = 24 * 60 * 60  # Session lasts 24 hours
app.config['PASS0_APP_NAME'] = 'Flask-Pass0 Demo'

# Optional: Email configuration (only needed when PASS0_DEV_MODE = False)
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'your-email@example.com'
# app.config['MAIL_PASSWORD'] = 'your-app-password'
# app.config['MAIL_DEFAULT_SENDER'] = 'no-reply@example.com'

# ==================== INITIALIZE PASS0 ====================

pass0 = Pass0(app)

# ==================== ROUTES ====================

@app.route('/')
def home():
    """Home page - shows login status."""
    if pass0.is_authenticated():
        user = get_current_user()
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Flask-Pass0 Demo</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                        max-width: 800px;
                        margin: 50px auto;
                        padding: 20px;
                        background: #f5f5f5;
                    }
                    .card {
                        background: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }
                    .success { color: #4CAF50; }
                    a {
                        display: inline-block;
                        margin: 10px 10px 0 0;
                        padding: 10px 20px;
                        background: #4285f4;
                        color: white;
                        text-decoration: none;
                        border-radius: 4px;
                    }
                    a:hover { background: #357ae8; }
                    .logout { background: #666; }
                    .logout:hover { background: #444; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>✅ You're Logged In!</h1>
                    <p class="success">Welcome, <strong>{{ user.email }}</strong></p>
                    <p>User ID: {{ user.id }}</p>
                    <p>Name: {{ user.name }}</p>
                    
                    <div>
                        <a href="/dashboard">Go to Dashboard</a>
                        <a href="/protected">Protected Page</a>
                        <a href="/auth/logout" class="logout">Logout</a>
                    </div>
                </div>
            </body>
            </html>
        """, user=user)
    
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Flask-Pass0 Demo</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .card {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                a {
                    display: inline-block;
                    padding: 12px 24px;
                    background: #4285f4;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin-top: 20px;
                }
                a:hover { background: #357ae8; }
                .info {
                    background: #e3f2fd;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                }
                code {
                    background: #f5f5f5;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🔐 Flask-Pass0 Demo</h1>
                <p>Welcome to the Flask-Pass0 passwordless authentication demo!</p>
                
                <div class="info">
                    <strong>📧 DEV MODE is ON</strong><br>
                    Magic links will appear in your terminal console instead of being emailed.
                </div>
                
                <p>Click below to see the login page and test magic link authentication:</p>
                <a href="/auth/login">🚀 Try Magic Link Login</a>
            </div>
        </body>
        </html>
    """)


@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard page."""
    user = get_current_user()
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Flask-Pass0 Demo</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .card {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 20px;
                }
                h1 { color: #333; }
                .user-info {
                    background: #f5f5f5;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                }
                .user-info strong { color: #4285f4; }
                a {
                    display: inline-block;
                    margin: 10px 10px 0 0;
                    padding: 10px 20px;
                    background: #4285f4;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                }
                a:hover { background: #357ae8; }
                .home { background: #666; }
                .home:hover { background: #444; }
                .logout { background: #f44336; }
                .logout:hover { background: #d32f2f; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>📊 Dashboard</h1>
                <p>This is a protected page that requires authentication.</p>
                
                <div class="user-info">
                    <h3>Your Account Info:</h3>
                    <p><strong>Email:</strong> {{ user.email }}</p>
                    <p><strong>User ID:</strong> {{ user.id }}</p>
                    <p><strong>Name:</strong> {{ user.name }}</p>
                    <p><strong>Created:</strong> {{ user.created_at }}</p>
                </div>
                
                <div>
                    <a href="/" class="home">Home</a>
                    <a href="/protected">Another Protected Page</a>
                    <a href="/auth/logout" class="logout">Logout</a>
                </div>
            </div>
        </body>
        </html>
    """, user=user)


@app.route('/protected')
@login_required
def protected():
    """Another protected page to demonstrate routing."""
    user = get_current_user()
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Protected Page - Flask-Pass0 Demo</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .card {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                h1 { color: #333; }
                .success {
                    background: #e8f5e9;
                    color: #2e7d32;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                }
                a {
                    display: inline-block;
                    margin: 10px 10px 0 0;
                    padding: 10px 20px;
                    background: #4285f4;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                }
                a:hover { background: #357ae8; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🔒 Protected Content</h1>
                
                <div class="success">
                    ✅ You successfully accessed this protected page!<br>
                    Only authenticated users can see this.
                </div>
                
                <p>Logged in as: <strong>{{ user.email }}</strong></p>
                
                <div>
                    <a href="/">Home</a>
                    <a href="/dashboard">Dashboard</a>
                    <a href="/auth/logout">Logout</a>
                </div>
            </div>
        </body>
        </html>
    """, user=user)


@app.route('/public')
def public():
    """A public page that doesn't require authentication."""
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Public Page - Flask-Pass0 Demo</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .card {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                h1 { color: #333; }
                .info {
                    background: #fff3e0;
                    color: #e65100;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                }
                a {
                    display: inline-block;
                    margin: 10px 10px 0 0;
                    padding: 10px 20px;
                    background: #4285f4;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                }
                a:hover { background: #357ae8; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🌍 Public Page</h1>
                
                <div class="info">
                    ℹ️ This page is accessible without authentication.<br>
                    No login required!
                </div>
                
                <p>This demonstrates that not all pages need to be protected.</p>
                
                <div>
                    <a href="/">Home</a>
                    <a href="/auth/login">Login</a>
                </div>
            </div>
        </body>
        </html>
    """)


# ==================== RUN APP ====================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Flask-Pass0 Test Application Starting...")
    print("="*60)
    print("\n📋 Configuration:")
    print(f"   DEV_MODE: {app.config['PASS0_DEV_MODE']}")
    print(f"   Token Expiry: {app.config['PASS0_TOKEN_EXPIRY']} minutes")
    print(f"   Session Duration: {app.config['PASS0_SESSION_DURATION'] // 3600} hours")
    print("\n🌐 Visit: http://127.0.0.1:5000")
    print("\n💡 How to test:")
    print("   1. Go to http://127.0.0.1:5000")
    print("   2. Click 'Try Magic Link Login'")
    print("   3. Enter any email address")
    print("   4. Check this terminal for the magic link")
    print("   5. Copy and paste the link into your browser")
    print("   6. You'll be logged in!")
    print("\n📧 Note: In DEV_MODE, magic links appear here instead of being emailed")
    print("="*60 + "\n")
    
    app.run(debug=True, port=5000)