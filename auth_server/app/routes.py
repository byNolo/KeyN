from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from .models import User, RefreshToken
from .forms import LoginForm
from . import db, login_manager
import jwt
import datetime
import secrets

auth_bp = Blueprint("auth", __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                form.username.errors.append("Please verify your email first.")
                return render_template("login.html", form=form)
            login_user(user)
            session["token"] = generate_access_token(user.id)
            session["refresh_token"] = generate_refresh_token(user.id)
            redirect_url = request.args.get("redirect") or url_for("auth.user_info")
            return redirect(redirect_url)
        form.username.errors.append("Invalid username or password")
    return render_template("login.html", form=form)

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    # Revoke all refresh tokens for user
    RefreshToken.query.filter_by(user_id=current_user.id).update({ "revoked": True })
    db.session.commit()

    logout_user()
    session.clear()
    return jsonify({"status": "logged out"})

@auth_bp.route("/api/validate-token", methods=["GET"])
def validate_token():
    token = request.args.get("token") or session.get("token")
    try:
        decoded = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        return jsonify({"valid": True, "user_id": decoded["user_id"]})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401

@auth_bp.route("/api/user", methods=["GET"])
@login_required
def user_info():
    return jsonify({
        "user_id": current_user.id,
        "username": current_user.username
    })

def generate_access_token(user_id):
    return jwt.encode({
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }, current_app.config["SECRET_KEY"], algorithm="HS256")

def generate_refresh_token(user_id):
    raw_token = secrets.token_urlsafe(64)
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=7)

    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "unknown")

    db_token = RefreshToken(
        token=raw_token,
        user_id=user_id,
        expires_at=expires,
        ip_address=ip,
        user_agent=ua
    )
    db.session.add(db_token)
    db.session.commit()

    return raw_token

@auth_bp.route("/api/refresh-token", methods=["POST"])
def refresh_token():
    raw_token = request.json.get("refresh_token") or session.get("refresh_token")
    if not raw_token:
        return jsonify({"error": "Missing refresh token"}), 400

    token_record = RefreshToken.query.filter_by(token=raw_token).first()

    if not token_record:
        return jsonify({"error": "Invalid token"}), 401
    if token_record.revoked:
        return jsonify({"error": "Token revoked"}), 401
    if token_record.expires_at < datetime.datetime.utcnow():
        return jsonify({"error": "Token expired"}), 401

    # Rotate: revoke old and create new
    token_record.revoked = True
    db.session.commit()

    new_token = generate_refresh_token(token_record.user_id)
    new_access_token = generate_access_token(token_record.user_id)

    # Save to session (optional)
    session["token"] = new_access_token
    session["refresh_token"] = new_token

    return jsonify({
        "access_token": new_access_token,
        "refresh_token": new_token
    })

@auth_bp.route("/api/sessions", methods=["GET"])
@login_required
def list_sessions():
    tokens = RefreshToken.query.filter_by(user_id=current_user.id, revoked=False).all()
    sessions = [{
        "id": t.id,
        "issued_at": t.issued_at.isoformat(),
        "expires_at": t.expires_at.isoformat(),
        "ip_address": t.ip_address,
        "user_agent": t.user_agent
    } for t in tokens]

    return jsonify(sessions)

@auth_bp.route("/api/sessions/<int:session_id>/revoke", methods=["DELETE"])
@login_required
def revoke_session(session_id):
    token = RefreshToken.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not token:
        return jsonify({"error": "Not found"}), 404

    token.revoked = True
    db.session.commit()
    return jsonify({"status": "revoked"})

from .forms import RegisterForm
from .auth_utils import send_verification_email
from . import mail

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            form.username.errors.append("Username already exists")
        elif User.query.filter_by(email=form.email.data).first():
            form.email.errors.append("Email already in use")
        else:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=generate_password_hash(form.password.data),
                is_verified=False
            )
            db.session.add(new_user)
            db.session.commit()
            send_verification_email(new_user, current_app, mail)
            return "Check your email to verify your account."
    return render_template("register.html", form=form)

@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    try:
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        if user and not user.is_verified:
            user.is_verified = True
            db.session.commit()
            return "Email verified. You can now log in."
        else:
            return "Already verified or invalid."
    except jwt.ExpiredSignatureError:
        return "Verification link expired."
    except jwt.InvalidTokenError:
        return "Invalid verification token."

from flask import flash, render_template

@auth_bp.route("/sessions", methods=["GET"])
@login_required
def session_ui():
    tokens = RefreshToken.query.filter_by(user_id=current_user.id, revoked=False).all()
    sessions = [{
        "id": t.id,
        "issued_at": t.issued_at.strftime("%Y-%m-%d %H:%M"),
        "expires_at": t.expires_at.strftime("%Y-%m-%d %H:%M"),
        "ip_address": t.ip_address,
        "user_agent": t.user_agent
    } for t in tokens]

    return render_template("sessions.html", sessions=sessions)

@auth_bp.route("/sessions/<int:session_id>/revoke", methods=["POST"])
@login_required
def revoke_session_ui(session_id):
    token = RefreshToken.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not token:
        flash("Session not found", "error")
    else:
        token.revoked = True
        db.session.commit()
        flash("Session revoked", "success")
    return redirect(url_for("auth.session_ui"))
