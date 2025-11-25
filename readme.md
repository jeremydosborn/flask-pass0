# Flask-Pass0

This is an Alpha project and not production ready as is. Use as a starting point but move it out of dev with caution.

**Passwordless authentication building block for Flask.**

Flask-Pass0 provides the authentication flow for magic link (passwordless) login. It handles token generation, expiration, and session management. All security implementation is your responsibility.

---

## Security Notice

Flask-Pass0 is authentication plumbing, not a security solution.

This extension provides:
- Token generation (`secrets.token_urlsafe`)
- Token expiration checking
- One-time, time-limited token use
- Session management
- Pluggable, overrideable storage interface

**You are responsible for implementing:**
- Token storage security (hashing, encryption, etc.)
- CSRF protection
- Rate limiting
- Session security (SECRET_KEY, secure cookies)
- Database security
- HTTPS/TLS
- Input validation
- Email delivery security
- All other security measures

---

## Installation

```bash
pip install flask-pass0
```

Optional dependencies:
```bash
pip install Flask-Mail        # For email sending
pip install Flask-SQLAlchemy  # For database storage
```

---

## Quick Start

```python
from flask import Flask, render_template
from flask_pass0 import Pass0
from flask_pass0.utils import login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['PASS0_DEV_MODE'] = True  # Dev only - shows links instead of sending email

pass0 = Pass0(app)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
```

---

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `PASS0_TOKEN_EXPIRY` | `10` | Token expiry in minutes |
| `PASS0_REDIRECT_URL` | `/` | Where to redirect after login |
| `PASS0_LOGIN_URL` | `/auth/login` | Login page URL |
| `PASS0_DEV_MODE` | `True` | If True, prints magic links to console instead of sending email |
| `PASS0_SESSION_DURATION` | `86400` | Session lifetime in seconds (24 hours) |
| `PASS0_APP_NAME` | `"Your Application"` | Application name for emails |

---

## Storage Adapters

### In-Memory Storage (Development Only)

```python
from flask_pass0 import Pass0

app = Flask(__name__)
pass0 = Pass0(app)  # Uses in-memory storage by default
```

**Warning:** In-memory storage is cleared when the app restarts. For development only.

### SQLAlchemy Storage

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    
    def to_dict(self):
        return {"id": self.id, "email": self.email}

storage = SQLAlchemyStorageAdapter(user_model=User, session=db.session)
pass0 = Pass0(app, storage_adapter=storage)
```

### Custom Storage

Implement the `StorageAdapter` interface:

```python
from flask_pass0.storage import StorageAdapter

class MyStorage(StorageAdapter):
    def get_user_by_email(self, email):
        """Retrieve user by email address."""
        pass
    
    def get_user_by_id(self, user_id):
        """Retrieve user by ID."""
        pass
    
    def create_user(self, email, **kwargs):
        """Create new user."""
        pass
    
    def get_or_create_user(self, email):
        """Get existing user or create new one."""
        pass
    
    def update_user(self, user_id, **kwargs):
        """Update user data."""
        pass
    
    def delete_user(self, user_id):
        """Delete user."""
        pass
    
    def store_token(self, token, token_data):
        """Store authentication token."""
        pass
    
    def get_token(self, token):
        """Retrieve token data."""
        pass
    
    def delete_token(self, token):
        """Delete token (after use)."""
        pass
```

**Security Note:** Override these methods to implement token hashing, encryption, or other security measures. Tokens are passed to your storage adapter as-is.

---

## Usage

### Protecting Routes

```python
from flask_pass0.utils import login_required

@app.route('/profile')
@login_required
def profile():
    return "Protected page"
```

### Getting Current User

```python
from flask_pass0.utils import get_current_user

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    return f"Welcome {user['email']}"
```

### Checking Authentication

```python
from flask_pass0.utils import is_authenticated

@app.route('/status')
def status():
    if is_authenticated():
        return "Logged in"
    return "Not logged in"
```

### Logout

```python
from flask_pass0.utils import logout

@app.route('/logout')
def logout_route():
    return logout()  # Clears session and redirects to login
```

---

## Email Configuration

Flask-Pass0 uses Flask-Mail for sending magic links. Configure Flask-Mail in your app:

```python
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'
```

Set `PASS0_DEV_MODE = False` to send actual emails instead of printing to console.

---

## API Reference

### Routes

Flask-Pass0 registers these routes under `/auth` (configurable):

- `GET /auth/login` - Login page
- `POST /auth/request-magic-link` - Request magic link (expects JSON: `{"email": "user@example.com"}`)
- `GET /auth/verify/<token>` - Verify magic link token
- `GET /auth/logout` - Logout

### Helper Functions

```python
from flask_pass0.utils import (
    login_required,     # Decorator for protected routes
    get_current_user,   # Returns current user dict or None
    is_authenticated,   # Returns True if user is logged in
    logout             # Logs out and redirects to login
)
```

---

## Production Deployment

### Required Steps

1. **Set a strong SECRET_KEY**
   ```python
   import secrets
   app.config['SECRET_KEY'] = secrets.token_hex(32)
   ```

2. **Disable development mode**
   ```python
   app.config['PASS0_DEV_MODE'] = False
   ```

3. **Configure Flask-Mail** with your email provider (SendGrid, AWS SES, Mailgun, etc.)

4. **Implement security measures** (see Security Checklist below)

### Security Checklist

Before deploying to production:

- [ ] Strong `SECRET_KEY` configured (32+ random bytes)
- [ ] `PASS0_DEV_MODE = False`
- [ ] HTTPS enabled on your server
- [ ] Session cookies secured (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`)
- [ ] CSRF protection added (Flask-WTF recommended)
- [ ] Rate limiting implemented (Flask-Limiter recommended)
- [ ] Token security implemented in storage adapter (hashing/encryption)
- [ ] Database connections secured (TLS, encryption at rest)
- [ ] Email authentication configured (SPF, DKIM, DMARC)
- [ ] Logging and monitoring active
- [ ] Input validation added to your routes
- [ ] Backup procedures in place

### Security Implementation Examples

**These are YOUR responsibility to implement.** Flask-Pass0 does not include these features.

For examples of CSRF protection, rate limiting, token hashing, and other security measures, consult:
- [Flask-WTF Documentation](https://flask-wtf.readthedocs.io/)
- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [OWASP Security Guidelines](https://owasp.org/)

---

## Limitations

- No built-in token hashing (implement in your storage adapter)
- No built-in CSRF protection (add Flask-WTF)
- No built-in rate limiting (add Flask-Limiter)
- No password-based authentication (passwordless only)
- No multi-factor authentication (future roadmap)
- Email delivery requires Flask-Mail and external email service
- Session security depends on your Flask configuration

---

## Development Mode

When `PASS0_DEV_MODE = True`:
- Magic links are printed to console instead of being emailed
- Useful for testing without email configuration
- **Must be disabled in production**

Example console output:
```
MAGIC LINK for user@example.com: http://localhost:5000/auth/verify/abc123...
```

---

## Roadmap

Planned features for future releases:

- Passkey/WebAuthn support
- MFA options
- Admin interface
- Additional authentication methods
- Token cleanup utilities

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## License

MIT License - see LICENSE file for details.

---

## Support

- **Documentation:** [GitHub README](https://github.com/jeremydosborn/flask-pass0)
- **Issues:** [GitHub Issues](https://github.com/jeremydosborn/flask-pass0/issues)
- **Security:** Review and test your own implementation thoroughly

**Note:** The maintainers of Flask-Pass0 are not responsible for security vulnerabilities in your application. This extension provides authentication flow only.

---

## Additional Security Considerations

If taking the "bare bones" approach, be aware:

### Things You Need to Handle

1. **Token Storage:** Tokens are passed to your storage adapter in plaintext. Implement hashing/encryption in your adapter.

2. **Open Redirects:** The `next` parameter is not validated. Validate redirect URLs in your application.

3. **Account Enumeration:** Requesting a magic link for any email succeeds. Decide if this is acceptable for your use case.

4. **Email Bombing:** No rate limiting per email address. Implement in your application.

5. **Token Expiry:** Expired tokens remain in storage until manually cleaned. Implement cleanup in your storage adapter.

6. **Session Security:** Session hijacking prevention depends on your Flask configuration.

7. **Input Sanitization:** Basic email format validation only. Add comprehensive validation in your application.

These are design decisions, not bugs. Flask-Pass0 gives you control over security implementation.