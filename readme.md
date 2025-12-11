# Flask-Pass0

Passwordless authentication for Flask with magic links, 2FA, and device binding. Alpha version, still in dev, not production ready.

## Installation

```bash
pip install flask-pass0
```

For all features:
```bash
pip install flask-pass0[all]
```

## Quick Start

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)

with app.app_context():
    db.create_all()
    storage = SQLAlchemyStorageAdapter(
        user_model=User,
        session=db.session,
        secret_key=app.config['SECRET_KEY']
    )
    pass0 = Pass0(app, storage_adapter=storage)

if __name__ == '__main__':
    app.run(debug=True)
```

## Features

- Passwordless authentication via magic links
- Two-factor authentication with TOTP
- Device fingerprinting and trusted device management
- Built-in session management
- SQLAlchemy storage adapter included

## Configuration

### Development Mode

```python
app.config['PASS0_DEV_MODE'] = True  # Print magic links to console
app.config['PASS0_AUTO_APPROVE_DEVICES'] = True  # Skip device approval emails
```

### Production Settings

```python
app.config['PASS0_DEV_MODE'] = False
app.config['PASS0_AUTO_APPROVE_DEVICES'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@yourapp.com'
```

### Two-Factor Authentication

```python
app.config['PASS0_2FA_ENABLED'] = True
app.config['PASS0_2FA_REQUIRED'] = False  # Set True to force all users
app.config['PASS0_TOTP_ISSUER'] = 'YourApp'
```

### Device Binding

```python
app.config['PASS0_DEVICE_BINDING_ENABLED'] = True
app.config['PASS0_SKIP_DEVICE_IF_2FA'] = True  # Skip if user has 2FA enabled
```

## Configuration Reference

| Option | Default | Description |
|--------|---------|-------------|
| `PASS0_DEV_MODE` | `False` | Print magic links to console instead of sending email |
| `PASS0_AUTO_APPROVE_DEVICES` | `False` | Auto-approve new devices without email (dev/testing only) |
| `PASS0_MAGIC_LINK_EXPIRY` | `900` | Magic link expiry in seconds (15 minutes) |
| `PASS0_2FA_ENABLED` | `False` | Enable two-factor authentication |
| `PASS0_2FA_REQUIRED` | `False` | Require all users to enable 2FA |
| `PASS0_TOTP_ISSUER` | `'Flask-Pass0'` | Name shown in authenticator apps |
| `PASS0_DEVICE_BINDING_ENABLED` | `False` | Enable device fingerprinting |
| `PASS0_SKIP_DEVICE_IF_2FA` | `True` | Skip device approval if user has 2FA |
| `PASS0_DEVICE_CHALLENGE_EXPIRY` | `900` | Device approval link expiry in seconds |

Full configuration reference: [CONFIGURATION.md](CONFIGURATION.md)

## Routes

Flask-Pass0 automatically registers these routes:

**Authentication:**
- `GET /auth/login` - Login page
- `POST /auth/request-magic-link` - Request magic link
- `GET /auth/verify/<token>` - Verify magic link
- `GET /auth/logout` - Logout

**Two-Factor Authentication:**
- `GET /auth/2fa/setup` - Setup 2FA
- `POST /auth/2fa/setup` - Verify 2FA setup
- `GET /auth/2fa/verify` - 2FA verification page
- `POST /auth/2fa/verify` - Verify 2FA code
- `POST /auth/2fa/disable` - Disable 2FA
- `GET/POST /auth/2fa/backup-codes` - Manage backup codes

**Device Management:**
- `GET /auth/devices` - List trusted devices
- `POST /auth/devices/<id>/revoke` - Revoke device
- `GET /auth/device/approve/<token>` - Approve device

## Templates

You must provide these templates in your app's `templates/` folder:

- `auth.html` - Login page
- `dashboard.html` - User dashboard (optional)
- `2fa_verify.html` - 2FA verification page (if 2FA enabled)

See `examples/` for reference implementations.

## Usage

### Protect Routes

```python
from flask_pass0 import login_required, get_current_user

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    return f"Hello {user['email']}"
```

### Check Authentication

```python
from flask_pass0 import is_authenticated

@app.route('/profile')
def profile():
    if not is_authenticated():
        return redirect('/auth/login')
    user = get_current_user()
    return render_template('profile.html', user=user)
```

### Logout

```python
from flask_pass0 import logout

@app.route('/signout')
def signout():
    logout()
    return redirect('/')
```

## Dependencies

**Required:**
- Flask >= 2.0.0
- Flask-SQLAlchemy >= 2.5.0

**Optional (install with `flask-pass0[all]`):**
- pyotp - For 2FA
- qrcode[pil] - For QR code generation
- cryptography - For encrypting secrets
- user-agents - For device fingerprinting
- Flask-Mail - For sending emails

## Security

Flask-Pass0 uses cryptographically secure tokens and industry-standard encryption:

- Magic link tokens: secrets.token_urlsafe (256-bit entropy)
- Token storage: HMAC-SHA256 hashing
- 2FA secrets: Fernet encryption (AES-128)
- Backup codes: SHA-256 hashing
- Device fingerprints: SHA-256 hashing
- Sessions: Flask's signed cookies

**Production requirements:**
- HTTPS enabled
- Strong `SECRET_KEY` (use `secrets.token_hex(32)`)
- Secure session cookies:

```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

## Examples

See the `examples/` directory for complete working applications.

## License

MIT License - see LICENSE file

## Contributing

Issues and pull requests welcome at https://github.com/jeremydosborn/flask-pass0