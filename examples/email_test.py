"""
Email Test - Flask-Pass0
DO NOT COMMIT - Contains credentials
"""

from flask import Flask, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter
from flask_pass0.utils import login_required, get_current_user

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = 'test-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///email_test.db'

# Email settings - CHANGE THESE
app.config['PASS0_DEV_MODE'] = False  # FALSE = sends real emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jeremy.osborn@gmail.com'
app.config['MAIL_PASSWORD'] = 'mvqy gvmd xlys rdwq'  # App password
app.config['MAIL_DEFAULT_SENDER'] = 'jeremy.osborn@gmail.com'

# Database
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    
    def to_dict(self):
        return {"id": self.id, "email": self.email}

# Initialize Pass0 BEFORE defining routes
with app.app_context():
    db.create_all()
    storage = SQLAlchemyStorageAdapter(
        user_model=User,
        session=db.session,
        secret_key=app.config['SECRET_KEY']
    )
    pass0 = Pass0(app, storage_adapter=storage)

# Routes
@app.route('/')
def home():
    if pass0.is_authenticated():
        user = get_current_user()
        return f'<h1>Logged in as {user["email"]}</h1><a href="/auth/logout">Logout</a>'
    # Redirect to login instead of showing home page
    return redirect('/auth/login')
    
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    return f'<h1>Dashboard</h1><p>Email: {user["email"]}</p><a href="/">Home</a> | <a href="/auth/logout">Logout</a>'

if __name__ == '__main__':
    print("\nEmail Test App")
    print("=" * 50)
    print(f"DEV_MODE: {app.config['PASS0_DEV_MODE']} (False = sends email)")
    print(f"SMTP: {app.config['MAIL_SERVER']}")
    print(f"From: {app.config['MAIL_USERNAME']}")
    print("\nVisit: http://127.0.0.1:5000")
    print("Check your spam folder if email doesn't arrive")
    print("=" * 50 + "\n")
    
    app.run(debug=True)