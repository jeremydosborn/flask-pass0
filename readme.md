---

# **Flask-Pass0 (v1.0)**

Passwordless authentication for Flask using time-limited magic links.

Flask-Pass0 provides a simple, clean interface for passwordless login flows while keeping your Flask application lightweight and easy to maintain. This is **Version 1.0**, the initial public release. Review the security notes below before using in production.

---

## **Features**

* Magic link authentication (no passwords required)
* Database-agnostic design via pluggable storage adapters
* Easy integration through a self-contained Flask Blueprint
* Works out of the box with an in-memory dev store
* Optional SQLAlchemy adapter for database-backed storage
* Extensible design for additional login methods (e.g., passkeys)

---

## **Installation**

```bash
pip install flask-pass0
```

For SQLAlchemy support:

```bash
pip install flask-pass0[sqlalchemy]
```

---

## **Quickstart**

```python
from flask import Flask, render_template
from flask_pass0 import Pass0
from flask_pass0.utils import login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['PASS0_DEV_MODE'] = True  # Shows magic link directly (dev only)

pass0 = Pass0(app)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
```

---

## **Configuration Options**

| Option                   | Default              | Description                                |
| ------------------------ | -------------------- | ------------------------------------------ |
| `PASS0_TOKEN_EXPIRY`     | `10`                 | Magic link token expiry (minutes)          |
| `PASS0_REDIRECT_URL`     | `/`                  | Redirect after login                       |
| `PASS0_LOGIN_URL`        | `/auth/login`        | Login page URL                             |
| `PASS0_DEV_MODE`         | `True`               | Shows magic links instead of emailing them |
| `PASS0_SESSION_DURATION` | `86400`              | Session lifetime in seconds                |
| `PASS0_APP_NAME`         | `"Your Application"` | Display name for emails (future)           |

---

## **Database Integration**

Flask-Pass0 includes:

* a built-in in-memory adapter for development
* an SQLAlchemy storage adapter for real applications

### **Using SQLAlchemy**

```python
from flask import Flask
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
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

---

## **Custom Storage Adapters**

Create your own adapter by implementing the StorageAdapter interface:

```python
from flask_pass0.storage import StorageAdapter

class MyStorage(StorageAdapter):
    def get_user_by_email(self, email):
        ...
    def get_user_by_id(self, user_id):
        ...
```

---

## **Security Notes (Version 1.0)**

* This is the **initial** release; review the source code for your security requirements.
* `PASS0_DEV_MODE` must be **disabled in production**.
* Magic link authentication depends on the user’s email security.
* Always run behind HTTPS.
* No built-in rate limiting—pair with Flask-Limiter if needed.
* Token hashing and additional hardening may be added in future versions.

---

## **Roadmap**

* Passkeys (WebAuthn)
* Token hashing
* Optional email-sending integration
* Rate limiting helpers
* MFA and advanced flows
* Admin UI

---

## **License**

MIT License (see LICENSE file)

---
