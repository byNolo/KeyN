from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from .models import User, RefreshToken
from .forms import LoginForm, RegisterForm, ForgotPasswordForm, ForgotUsernameForm
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from . import db, login_manager
from .security_utils import (
    get_real_ip, generate_device_fingerprint, is_ip_banned, is_device_banned,
    log_login_attempt, is_rate_limited, ban_ip, ban_device, unban_ip, unban_device
)
import jwt
import datetime
import secrets
import os

auth_bp = Blueprint("auth", __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    # Get real IP and device fingerprint
    ip_address = get_real_ip()
    device_fingerprint = generate_device_fingerprint()
    
    # Check if IP or device is banned
    if is_ip_banned(ip_address):
        return jsonify({"error": "Your IP address has been banned"}), 403
    
    if is_device_banned(device_fingerprint):
        return jsonify({"error": "Your device has been banned"}), 403
    
    # Check rate limiting
    if is_rate_limited(ip_address):
        return jsonify({"error": "Too many failed login attempts. Please try again later."}), 429
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                # Log failed attempt for unverified user
                log_login_attempt(ip_address, device_fingerprint, username, False)
                form.username.errors.append("Please verify your email first.")
                return render_template("login.html", form=form)
            
            # Log successful login
            log_login_attempt(ip_address, device_fingerprint, username, True, user.id)
            
            # Update user's last login
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            
            # Debug: Check user before login
            print(f"DEBUG: About to login user {user.id} - {user.username}")
            print(f"DEBUG: User.is_verified = {user.is_verified}")
            
            login_user(user, remember=True)  # Enable remember me
            
            # Debug: Check current_user after login
            print(f"DEBUG: After login_user - current_user.is_authenticated = {current_user.is_authenticated}")
            print(f"DEBUG: After login_user - current_user.id = {current_user.id if current_user.is_authenticated else 'Not authenticated'}")
            
            session["token"] = generate_access_token(user.id)
            session["refresh_token"] = generate_refresh_token(user.id)
            session.permanent = True  # Make session permanent
            
            print(f"DEBUG: Session after login = {dict(session)}")
            
            redirect_url = request.args.get("redirect") or url_for("auth.user_info")
            return redirect(redirect_url)
        
        # Log failed login attempt
        log_login_attempt(ip_address, device_fingerprint, username, False)
        form.username.errors.append("Invalid username or password")
    
    return render_template("login.html", form=form)

@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    # Check if user is logged in
    if current_user.is_authenticated:
        # Revoke all refresh tokens for user
        RefreshToken.query.filter_by(user_id=current_user.id).update({ "revoked": True })
        db.session.commit()
        
        logout_user()
    
    # Clear session regardless of login status
    session.clear()

    # Prepare response to clear cookies
    from flask import make_response
    if request.method == "GET":
        # Check for redirect parameter (like from demo client)
        redirect_url = request.args.get("redirect")
        if redirect_url:
            from config import Config
            allowed_domains = Config.ALLOWED_REDIRECT_DOMAINS

            if any(redirect_url.startswith(domain) for domain in allowed_domains):
                response = make_response(redirect(redirect_url))
                # Delete cookies for .nolanbc.ca and current domain
                response.delete_cookie('keyn_session', domain='.nolanbc.ca', path='/')
                response.delete_cookie('remember_token', domain='.nolanbc.ca', path='/')
                response.delete_cookie('keyn_session', domain=request.host, path='/')
                response.delete_cookie('remember_token', domain=request.host, path='/')
                response.delete_cookie('keyn_session', path='/')
                response.delete_cookie('remember_token', path='/')
                return response
        # Default: redirect to login page
        response = make_response(redirect(url_for("auth.login")))
        response.delete_cookie('keyn_session', domain='.nolanbc.ca', path='/')
        response.delete_cookie('remember_token', domain='.nolanbc.ca', path='/')
        response.delete_cookie('keyn_session', domain=request.host, path='/')
        response.delete_cookie('remember_token', domain=request.host, path='/')
        response.delete_cookie('keyn_session', path='/')
        response.delete_cookie('remember_token', path='/')
        return response
    else:
        response = make_response(jsonify({"status": "logged out"}))
        response.delete_cookie('keyn_session', domain='.nolanbc.ca', path='/')
        response.delete_cookie('remember_token', domain='.nolanbc.ca', path='/')
        response.delete_cookie('keyn_session', domain=request.host, path='/')
        response.delete_cookie('remember_token', domain=request.host, path='/')
        response.delete_cookie('keyn_session', path='/')
        response.delete_cookie('remember_token', path='/')
        return response

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
def user_info():
    """Get user info - supports both session-based and token-based auth"""
    user = None
    
    # Debug information
    print(f"DEBUG: current_user.is_authenticated = {current_user.is_authenticated if current_user else 'current_user is None'}")
    print(f"DEBUG: session contents = {dict(session)}")
    
    # Try session-based authentication first (for same-domain)
    if current_user and current_user.is_authenticated:
        user = current_user
    else:
        # Try Bearer token authentication (for cross-domain)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                decoded = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
                user = User.query.get(decoded["user_id"])
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401
    
    if user:
        return jsonify({
            "user_id": user.id,
            "username": user.username
        })
    else:
        return jsonify({"error": "Not authenticated"}), 401

def generate_access_token(user_id):
    return jwt.encode({
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }, current_app.config["SECRET_KEY"], algorithm="HS256")

def generate_refresh_token(user_id):
    raw_token = secrets.token_urlsafe(64)
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=7)

    ip = get_real_ip()  # Use the real IP function
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

from .auth_utils import send_verification_email, verify_email_token
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Message
def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

# Forgot Password
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            serializer = get_serializer()
            token = serializer.dumps(user.email, salt="password-reset-salt")
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            msg = Message("KeyN Password Reset", recipients=[user.email])
            msg.html = render_template("email/password_reset.html", username=user.username, link=reset_url)
            # Attach logo.png as inline image
            try:
                with current_app.open_resource("static/logos/logo.png") as f:
                    logo_data = f.read()
                    msg.attach(
                        "logo.png", "image/png", logo_data,
                        disposition='inline',
                        headers={"Content-ID": "<logo_image>"}
                    )
            except Exception as e:
                print(f"[EMAIL] Warning: Could not attach logo.png: {e}")
            # Attach favicon.png as inline image
            try:
                with current_app.open_resource("static/logos/favicon.png") as f:
                    favicon_data = f.read()
                    msg.attach(
                        "favicon.png", "image/png", favicon_data,
                        disposition='inline',
                        headers={"Content-ID": "<favicon_image>"}
                    )
            except Exception as e:
                print(f"[EMAIL] Warning: Could not attach favicon.png: {e}")
            mail.send(msg)
        return render_template("forgot_password_sent.html")
    return render_template("forgot_password.html", form=form)

# Reset Password
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    serializer = get_serializer()
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except (SignatureExpired, BadSignature):
        return "Invalid or expired token."
    user = User.query.filter_by(email=email).first()
    if not user:
        return "User not found."
    class ResetPasswordForm(FlaskForm):
        password = PasswordField("New Password", validators=[DataRequired()])
        confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
        submit = SubmitField("Reset Password")
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        return "Password reset successful. You may now log in."
    return render_template("reset_password.html", form=form)

# Forgot Username
@auth_bp.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    form = ForgotUsernameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            msg = Message("KeyN Username Recovery", recipients=[user.email])
            msg.html = render_template("email/username_reminder.html", username=user.username)
            # Attach logo.png as inline image
            try:
                with current_app.open_resource("static/logos/logo.png") as f:
                    logo_data = f.read()
                    msg.attach(
                        "logo.png", "image/png", logo_data,
                        disposition='inline',
                        headers={"Content-ID": "<logo_image>"}
                    )
            except Exception as e:
                print(f"[EMAIL] Warning: Could not attach logo.png: {e}")
            # Attach favicon.png as inline image
            try:
                with current_app.open_resource("static/logos/favicon.png") as f:
                    favicon_data = f.read()
                    msg.attach(
                        "favicon.png", "image/png", favicon_data,
                        disposition='inline',
                        headers={"Content-ID": "<favicon_image>"}
                    )
            except Exception as e:
                print(f"[EMAIL] Warning: Could not attach favicon.png: {e}")
            mail.send(msg)
        return render_template("forgot_username_sent.html")
    return render_template("forgot_username.html", form=form)
from . import mail

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    redirect_url = request.args.get("redirect")
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
            return render_template("email_verification_sent.html", redirect_url=redirect_url)
    return render_template("register.html", form=form, redirect_url=redirect_url)

@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    user_id = verify_email_token(token, current_app)
    if user_id:
        user = User.query.get(user_id)
        if user and not user.is_verified:
            user.is_verified = True
            db.session.commit()
            return render_template("email_verified.html")
        else:
            return "Email already verified or user not found."
    else:
        return "Invalid or expired verification token. Please request a new verification email."
        return "Invalid or expired token."

# Admin routes for managing bans
@auth_bp.route("/admin/ban-ip", methods=["POST"])
@login_required
def admin_ban_ip():
    """Admin endpoint to ban an IP address"""
    # You should add proper admin authorization here
    data = request.get_json()
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual admin ban')
    duration_hours = data.get('duration_hours')  # None for permanent
    
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400
    
    expires_at = None
    if duration_hours:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=duration_hours)
    
    ban_ip(ip_address, reason, current_user.id, expires_at)
    
    return jsonify({
        "success": True, 
        "message": f"IP {ip_address} has been banned",
        "expires_at": expires_at.isoformat() if expires_at else None
    })

@auth_bp.route("/admin/ban-device", methods=["POST"])
@login_required
def admin_ban_device():
    """Admin endpoint to ban a device fingerprint"""
    data = request.get_json()
    device_fingerprint = data.get('device_fingerprint')
    reason = data.get('reason', 'Manual admin ban')
    duration_hours = data.get('duration_hours')  # None for permanent
    
    if not device_fingerprint:
        return jsonify({"error": "Device fingerprint required"}), 400
    
    expires_at = None
    if duration_hours:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=duration_hours)
    
    ban_device(device_fingerprint, reason, current_user.id, expires_at)
    
    return jsonify({
        "success": True, 
        "message": f"Device has been banned",
        "expires_at": expires_at.isoformat() if expires_at else None
    })

@auth_bp.route("/admin/unban-ip", methods=["POST"])
@login_required
def admin_unban_ip():
    """Admin endpoint to unban an IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400
    
    unban_ip(ip_address)
    return jsonify({"success": True, "message": f"IP {ip_address} has been unbanned"})

@auth_bp.route("/admin/unban-device", methods=["POST"])
@login_required
def admin_unban_device():
    """Admin endpoint to unban a device"""
    data = request.get_json()
    device_fingerprint = data.get('device_fingerprint')
    
    if not device_fingerprint:
        return jsonify({"error": "Device fingerprint required"}), 400
    
    unban_device(device_fingerprint)
    return jsonify({"success": True, "message": "Device has been unbanned"})

@auth_bp.route("/admin/login-attempts", methods=["GET"])
@login_required
def admin_login_attempts():
    """Admin endpoint to view recent login attempts"""
    from .models import LoginAttempt
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        "attempts": [
            {
                "id": attempt.id,
                "ip_address": attempt.ip_address,
                "device_fingerprint": attempt.device_fingerprint,
                "username_attempted": attempt.username_attempted,
                "success": attempt.success,
                "timestamp": attempt.timestamp.isoformat(),
                "user_agent": attempt.user_agent
            }
            for attempt in attempts.items
        ],
        "total": attempts.total,
        "pages": attempts.pages,
        "current_page": page
    })

@auth_bp.route("/admin/bans", methods=["GET"])
@login_required
def admin_view_bans():
    """Admin endpoint to view active bans"""
    from .models import IPBan, DeviceBan
    
    ip_bans = IPBan.query.filter_by(is_active=True).all()
    device_bans = DeviceBan.query.filter_by(is_active=True).all()
    
    return jsonify({
        "ip_bans": [
            {
                "id": ban.id,
                "ip_address": ban.ip_address,
                "reason": ban.reason,
                "banned_at": ban.banned_at.isoformat(),
                "expires_at": ban.expires_at.isoformat() if ban.expires_at else None
            }
            for ban in ip_bans
        ],
        "device_bans": [
            {
                "id": ban.id,
                "device_fingerprint": ban.device_fingerprint,
                "reason": ban.reason,
                "banned_at": ban.banned_at.isoformat(),
                "expires_at": ban.expires_at.isoformat() if ban.expires_at else None
            }
            for ban in device_bans
        ]
    })

@auth_bp.route("/admin")
@login_required
def admin_interface():
    """Admin interface for managing security"""
    # You should add proper admin authorization here
    return render_template("admin.html")

@auth_bp.route("/api/cross-domain-auth", methods=["POST"])
@login_required
def cross_domain_auth():
    """Provide tokens for cross-domain authentication"""
    data = request.get_json()
    client_domain = data.get('client_domain')
    
    # Generate a temporary token for the client app
    access_token = generate_access_token(current_user.id)
    
    return jsonify({
        'access_token': access_token,
        'user_id': current_user.id,
        'username': current_user.username,
        'expires_in': 900  # 15 minutes
    })

@auth_bp.route("/health")
def health_check():
    """Health check endpoint for monitoring service status"""
    try:
        # Check database connectivity
        db_status = "healthy"
        try:
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
            user_count = User.query.count()
        except Exception as e:
            db_status = f"error: {str(e)}"
            user_count = -1
        
        # Check email configuration
        email_status = "configured" if current_app.config.get("MAIL_USERNAME") else "not_configured"
        
        # Check database file size
        db_path = current_app.config.get("SQLALCHEMY_DATABASE_URI", "").replace("sqlite:///", "")
        db_size = 0
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path)
        
        # Get service uptime (approximate)
        import time
        uptime = time.time()
        
        health_data = {
            "status": "healthy" if db_status == "healthy" else "degraded",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "services": {
                "database": {
                    "status": db_status,
                    "user_count": user_count,
                    "size_bytes": db_size
                },
                "email": {
                    "status": email_status
                },
                "auth": {
                    "status": "healthy"
                }
            },
            "version": "1.0.0",
            "uptime_seconds": int(uptime % 86400)  # Rough uptime within day
        }
        
        status_code = 200 if health_data["status"] == "healthy" else 503
        return jsonify(health_data), status_code
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "error": str(e)
        }), 500
