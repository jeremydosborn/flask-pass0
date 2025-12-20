# flask-pass0

Passwordless authentication for Flask with magic links, passkeys (to do), 2FA, and device binding. Alpha version. Not production-ready.

## Installation

```bash
pip install flask-pass0
````

For all optional features:

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

* Passwordless authentication via magic links (Passkeys coming)
* Two-factor authentication (TOTP)
* Device fingerprinting + trusted device management
* Built-in session handling (login, expiration, logout)
* SQLAlchemy storage adapter
* Safe redirect handling (same-site only)

## Configuration

```python
# Magic link (default)
app.config['PASS0_PRIMARY_AUTH'] = 'magic_link'
```

### Development Mode

```python
app.config['PASS0_DEV_MODE'] = True  
# Magic links returned in JSON and full auth flow is logged in test app
```

### Production Email Settings

```python
app.config['PASS0_DEV_MODE'] = False

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
app.config['PASS0_2FA_REQUIRED'] = False
app.config['PASS0_TOTP_ISSUER'] = 'YourApp'
```

### Device Binding

```python
app.config['PASS0_DEVICE_BINDING_ENABLED'] = True
app.config['PASS0_SKIP_DEVICE_IF_2FA'] = True
```

Unknown devices always require email approval. Pass0 never auto-trusts devices.

### Login + Redirect URLs

```python
app.config['PASS0_REDIRECT_URL'] = '/'
app.config['PASS0_LOGIN_URL'] = '/login'

app.config['PASS0_SESSION_DURATION'] = 24 * 60 * 60  # seconds
app.config['PASS0_TOKEN_EXPIRY'] = 10                # minutes
```

---

## Configuration Reference

| Option                            | Default         | Description                                    |
| --------------------------------- | --------------- | ---------------------------------------------- |
| `PASS0_PRIMARY_AUTH`              | `'magic_link'`  | Primary auth method: 'magic_link' or 'passkey' |
| `PASS0_DEV_MODE`                  | `False`         | Magic link returned in JSON instead of email   |
| `PASS0_TOKEN_EXPIRY`              | `10`            | Magic link expiry (minutes)                    |
| `PASS0_REDIRECT_URL`              | `'/'`           | Default redirect after login                   |
| `PASS0_LOGIN_URL`                 | `'/login'`      | Your app's login route                         |
| `PASS0_SESSION_DURATION`          | `86400`         | Max session age (seconds)                      |
| `PASS0_2FA_ENABLED`               | `False`         | Enable 2FA                                     |
| `PASS0_2FA_REQUIRED`              | `False`         | Require all users to enable 2FA                |
| `PASS0_TOTP_ISSUER`               | `'Flask-Pass0'` | Issuer name in authenticator apps              |
| `PASS0_DEVICE_BINDING_ENABLED`    | `False`         | Enable device fingerprinting                   |
| `PASS0_SKIP_DEVICE_IF_2FA`        | `True`          | Skip device checks if user has 2FA             |
| `PASS0_DEVICE_CHALLENGE_EXPIRY`   | `900`           | Device approval expiry (seconds)               |

---

## Routes (Auto-Registered Under `/auth`)

### Authentication

* `GET /auth/login` — Redirects to your app's login UI (`PASS0_LOGIN_URL`)
* `POST /auth/request-magic-link` — Request magic link (JSON)
* `GET /auth/verify/<token>` — Verify link → device check → 2FA → login
* `GET /auth/logout` — Clears session

### 2FA Routes

* `GET /auth/2fa/setup`
* `POST /auth/2fa/setup`
* `GET /auth/2fa/verify`
* `POST /auth/2fa/verify`
* `POST /auth/2fa/disable`
* `GET/POST /auth/2fa/backup-codes`

### Device Binding Routes

* `GET /auth/device-approval-required`
* `GET /auth/device/approve/<token>`
* `GET /auth/devices`
* `POST /auth/devices/<id>/revoke`

---

## Templates / UI

flask-pass0 **does not include templates**. Your app renders the UI.

Example:

```python
@app.route('/login')
def login_page():
    user = get_current_user()
    if user:
        return redirect('/')
    return render_template('auth.html')
```

You typically provide:

* `auth.html` — sends email to `/auth/request-magic-link` or initiates passkey login
* `2fa_verify.html` — calls `/auth/2fa/verify`
* `dashboard.html`

## Usage

### Protect Routes

```python
from flask_pass0.utils import login_required, get_current_user

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    return f"Hello {user['email']}"
```

### Manual Check

```python
from flask_pass0.utils import is_authenticated

@app.route('/profile')
def profile():
    if not is_authenticated():
        return redirect('/auth/login')
    return render_template('profile.html', user=get_current_user())
```

### Logout

```python
from flask_pass0.utils import logout

@app.route('/signout')
def signout():
    return logout()
```

---

## Dependencies

**Required**

* Flask >= 2.0.0
* Flask-SQLAlchemy >= 2.5.0

**Optional (`pip install flask-pass0[all]`)**

* pyotp
* qrcode[pil]
* cryptography
* user-agents
* Flask-Mail

---

## Security

* Token entropy: ~256 bits
* Tokens: HMAC-SHA256 + single-use
* 2FA secrets encrypted
* Backup codes hashed
* Device fingerprints hashed
* Redirects restricted to same-site paths
* Sessions stored in Flask-signed cookies and expire using `PASS0_SESSION_DURATION`

**Production:**

```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

## Security Logging (Test App)

The included test application instruments the full authentication lifecycle for debugging and demos, including:

* Magic link issuance and verification steps
* Token generation, hashing, and storage
* Session creation and login success/failure
* 2FA setup, verification, backup codes, and disable flows
* Device recognition and revocation events

This logging is **for development and demonstration purposes only** and is not persisted by default.

---

## Examples

See the `examples/` directory for working test application including magic links, passkeys, 2FA, device binding, and security logging.

---

## License

MIT License.

## Contributing

PRs welcome at:
[https://github.com/jeremydosborn/flask-pass0](https://github.com/jeremydosborn/flask-pass0)
