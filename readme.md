# Flask-Pass0

A passwordless authentication extension for Flask applications.

## Features

- Magic link authentication - no passwords to remember or manage
- Database agnostic - works with any database through a simple adapter interface
- Secure by design - follows security best practices for authentication
- Easy to integrate - drop-in authentication for Flask applications
- Mobile-friendly - responsive design works on all devices
- Extensible - designed to support additional authentication methods in the future

## Installation

```bash
pip install flask-pass0
```

For SQLAlchemy database support:

```bash
pip install flask-pass0[sqlalchemy]
```

## Quickstart

```python
from flask import Flask, render_template
from flask_pass0 import Pass0
from flask_pass0.utils import login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Required for sessions
app.config['PASS0_DEV_MODE'] = True  # Set to False in production

# For email sending in production
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_DEFAULT_SENDER'] = 'no-reply@example.com'

# Initialize Pass0
pass0 = Pass0(app)

# Create a protected route
@app.route('/')
@login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `PASS0_TOKEN_EXPIRY` | `10` | Magic link token expiry time in minutes |
| `PASS0_REDIRECT_URL` | `/` | Default URL to redirect to after login |
| `PASS0_LOGIN_URL` | `/auth/login` | Login page URL |
| `PASS0_DEV_MODE` | `True` | Development mode - shows magic links instead of sending emails |
| `PASS0_SESSION_DURATION` | `86400` | Session duration in seconds (24 hours) |
| `PASS0_APP_NAME` | `Your Application` | Application name to use in emails |

## Database Integration

Flask-Pass0 comes with built-in memory storage (for development) and SQLAlchemy integration.

### Using SQLAlchemy

```python
from flask import Flask
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Create custom user model (optional)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'is_active': self.is_active
        }

# Initialize storage adapter with custom model
storage = SQLAlchemyStorageAdapter(user_model=User, session=db.session)

# Initialize Pass0 with storage adapter
pass0 = Pass0(app, storage_adapter=storage)
```

### Custom Storage Adapters

You can create your own storage adapter by implementing the `StorageAdapter` interface:

```python
from flask_pass0.storage import StorageAdapter

class MyStorageAdapter(StorageAdapter):
    # Implement required methods
    def get_user_by_email(self, email):
        # ...
    
    def get_user_by_id(self, user_id):
        # ...
    
    # And so on...
```

## Future Roadmap

- Passkey (WebAuthn) support
- Social login integration
- Multi-factor authentication
- Rate limiting and brute force protection
- Email verification flow
- Admin interface

## License

MIT License