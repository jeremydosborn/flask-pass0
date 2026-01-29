from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, session, request, redirect
from flask_sqlalchemy import SQLAlchemy

from flask_pass0 import Pass0, SQLAlchemyStorageAdapter

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["PASS0_RP_ID"] = "localhost"
app.config["PASS0_RP_NAME"] = "Pass0 Test"
app.config["PASS0_ORIGIN"] = "http://localhost:5000"
app.config["PASS0_DEV_MODE"] = True

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


with app.app_context():
    db.create_all()
    storage = SQLAlchemyStorageAdapter(User, db.session, app.config["SECRET_KEY"])
    pass0 = Pass0(app, storage=storage)


# Routes

@app.route("/")
def index():
    if pass0.is_authenticated():
        user = pass0.current_user()
        has_2fa = pass0.totp.is_enabled(user["id"])
        return render_template("dashboard.html", user=user, has_2fa=has_2fa)
    return redirect("/login")


@app.route("/login")
def login():
    if pass0.is_authenticated():
        return redirect("/")
    return render_template("login.html")


@app.route("/logout")
def logout():
    pass0.logout()
    return redirect("/login")


# Passkey endpoints

@app.route("/auth/passkey/register/options", methods=["POST"])
def passkey_register_options():
    result = pass0.passkey.registration_options()
    session["passkey_challenge"] = result["challenge"]
    session["passkey_user_handle"] = result["user_handle"]
    return result["options"], 200, {"Content-Type": "application/json"}


@app.route("/auth/passkey/register/verify", methods=["POST"])
def passkey_register_verify():
    credential = request.json.get("credential")
    challenge = session.pop("passkey_challenge", None)
    if not challenge:
        return jsonify({"success": False, "error": "No challenge"}), 400

    result = pass0.passkey.verify_registration(credential, challenge)
    if result["success"]:
        pass0.login(result["user"]["id"])
    return jsonify(result)


@app.route("/auth/passkey/login/options", methods=["POST"])
def passkey_login_options():
    result = pass0.passkey.authentication_options()
    session["passkey_challenge"] = result["challenge"]
    return result["options"], 200, {"Content-Type": "application/json"}


@app.route("/auth/passkey/login/verify", methods=["POST"])
def passkey_login_verify():
    credential = request.json.get("credential")
    challenge = session.pop("passkey_challenge", None)
    if not challenge:
        return jsonify({"success": False, "error": "No challenge"}), 400

    result = pass0.passkey.verify_authentication(credential, challenge)
    if result["success"]:
        if pass0.totp.is_enabled(result["user"]["id"]):
            session["user_id"] = result["user"]["id"]
            session["2fa_pending"] = True
            return jsonify({"success": True, "requires_2fa": True})
        pass0.login(result["user"]["id"])
    return jsonify(result)


# 2FA endpoints

@app.route("/auth/2fa/setup", methods=["GET"])
def totp_setup():
    if not pass0.is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    user = pass0.current_user()
    identifier = user.get("email") or f"user-{user['id']}"
    data = pass0.totp.setup(identifier)
    session["totp_secret"] = data["secret"]
    return jsonify(data)


@app.route("/auth/2fa/setup", methods=["POST"])
def totp_setup_verify():
    if not pass0.is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    code = request.json.get("code")
    secret = session.pop("totp_secret", None)
    if not secret:
        return jsonify({"success": False, "error": "No setup in progress"}), 400
    if not pass0.totp.verify_code(secret, code):
        session["totp_secret"] = secret
        return jsonify({"success": False, "error": "Invalid code"}), 400
    backup_codes = pass0.totp.generate_backup_codes()
    pass0.totp.enable(session["user_id"], secret, backup_codes)
    return jsonify({"success": True, "backup_codes": backup_codes})


@app.route("/auth/2fa/verify", methods=["POST"])
def totp_verify():
    if not session.get("2fa_pending"):
        return jsonify({"error": "No 2FA pending"}), 400
    user_id = session.get("user_id")
    code = request.json.get("code")
    use_backup = request.json.get("use_backup", False)

    if use_backup:
        valid = pass0.totp.verify_backup_code(user_id, code)
    else:
        secret = pass0.totp.get_secret(user_id)
        valid = pass0.totp.verify_code(secret, code)

    if valid:
        session.pop("2fa_pending", None)
        pass0.login(user_id)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid code"}), 400


@app.route("/auth/2fa/disable", methods=["POST"])
def totp_disable():
    if not pass0.is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    pass0.totp.disable(session["user_id"])
    return jsonify({"success": True})


@app.route("/2fa-verify")
def totp_verify_page():
    if not session.get("2fa_pending"):
        return redirect("/login")
    return render_template("2fa_verify.html")


if __name__ == "__main__":
    app.run(debug=True)
