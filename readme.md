# Flask-Pass0

Alpha software. Passwordless authentication for Flask.

## What It Does

Handles magic link authentication flow with built-in security:
- Token hashing (HMAC-SHA256)
- Single-use enforcement
- Secure generation (256-bit entropy)
- 10-minute expiry

## What You Add

- HTTPS (required)
- Email sending
- Rate limiting
- CSRF protection

## Install

```bash
pip install flask-pass0
```

## Quick Start

```python
from flask import Flask
from flask_pass0 import Pass0
from flask_pass0.utils import login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['PASS0_DEV_MODE'] = True  # Shows links in console

pass0 = Pass0(app)

@app.route('/')
@login_required
def index():
    return "Protected page"
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| SECRET_KEY | required | For token hashing |
| PASS0_DEV_MODE | False | Show links in console vs email |
| PASS0_TOKEN_EXPIRY | 10 | Token expiry (minutes) |
| PASS0_TOKEN_LENGTH | 32 | Token bytes (32 = 256 bits) |

## Storage

### SQLAlchemy

```python
from flask_sqlalchemy import SQLAlchemy
from flask_pass0.storage import SQLAlchemyStorageAdapter

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    
    def to_dict(self):
        return {"id": self.id, "email": self.email}

storage = SQLAlchemyStorageAdapter(
    user_model=User,
    session=db.session,
    secret_key=app.config['SECRET_KEY']
)
pass0 = Pass0(app, storage_adapter=storage)
```

### Custom

Implement `StorageAdapter` interface for Redis, MongoDB, etc. See `flask_pass0/storage.py`.

## Email Setup

```python
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'user@gmail.com'
app.config['MAIL_PASSWORD'] = 'app-password'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'
app.config['PASS0_DEV_MODE'] = False  # Send real emails
```

## Security

**Built-in:**
- Tokens hashed with HMAC-SHA256
- Single-use enforcement
- 10-minute expiry
- 256-bit entropy

**Your responsibility:**
- HTTPS (tokens in URLs)
- Email security
- Rate limiting (use Flask-Limiter)
- CSRF protection (use Flask-WTF)
- Strong SECRET_KEY

**Attack scenarios:**

Database compromised: Tokens are hashed, can't be reversed without SECRET_KEY.

Token intercepted: Can be used once within 10 minutes. HTTPS required. For banking/healthcare, add 2FA separately.

Brute force: 2^256 space makes guessing impossible.

## Production Checklist

- [ ] PASS0_DEV_MODE = False
- [ ] HTTPS enabled
- [ ] Email configured
- [ ] Rate limiting added
- [ ] Strong SECRET_KEY set
- [ ] CSRF protection added
- [ ] Session cookies secured

## Routes

- `GET /auth/login` - Login page
- `POST /auth/request-magic-link` - Request link (JSON: `{"email": "user@example.com"}`)
- `GET /auth/verify/<token>` - Verify token
- `GET /auth/logout` - Logout

## Limitations

- Alpha software
- No rate limiting (add Flask-Limiter)
- No CSRF protection (add Flask-WTF)
- Email requires external service
- Not suitable alone for high-security (add 2FA)

## Notes

Magic links are bearer tokens. Device/email compromise allows token interception. For sensitive apps, implement 2FA after login.

Power users with password managers may prefer passwords. Consider offering both.

## Examples

See `examples/` directory.

## License

MIT

## Issues

Found a bug? Open an issue on GitHub.
Security issue? Contact maintainer directly.
