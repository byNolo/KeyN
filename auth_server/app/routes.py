from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from .models import User, RefreshToken, ClientApplication, DataScope, UserAuthorization
from .forms import LoginForm, RegisterForm, ForgotPasswordForm, ForgotUsernameForm, ProfileForm, ChangePasswordForm, ProfileCompletionForm
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from . import db, login_manager
from .security_utils import (
    get_real_ip, generate_device_fingerprint, is_ip_banned, is_device_banned,
    log_login_attempt, is_rate_limited, ban_ip, ban_device, unban_ip, unban_device
)
from .auth_utils import admin_required
from .oauth_utils import ScopeManager, ClientManager, AuthorizationManager
import jwt
import datetime
import secrets
import os
import json

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
            
            # Determine redirect destination
            redirect_url = request.args.get("redirect")
            
            # If no specific redirect and user needs profile completion, suggest it
            # But don't force it if they have a specific destination (like OAuth flow)
            if not redirect_url and user.needs_profile_completion():
                flash("Welcome back! Consider completing your profile for a better experience.", "info")
                redirect_url = url_for("auth.complete_profile")
            elif not redirect_url:
                redirect_url = url_for("auth.profile")
            
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
            
            # Log the user in automatically after email verification
            login_user(user, remember=True)
            
            # Check if user needs to complete profile
            if user.needs_profile_completion():
                # Redirect to profile completion with a message
                flash("Welcome to KeyN! Let's complete your profile to get started.", "info")
                return redirect(url_for("auth.complete_profile"))
            else:
                # User already has some profile info, go to regular verified page
                return render_template("email_verified.html")
        else:
            return "Email already verified or user not found."
    else:
        return "Invalid or expired verification token. Please request a new verification email."
        return "Invalid or expired token."

# Admin routes for managing bans
@auth_bp.route("/admin/ban-ip", methods=["POST"])
@admin_required
def admin_ban_ip():
    """Admin endpoint to ban an IP address"""
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
@admin_required
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
@admin_required
def admin_unban_ip():
    """Admin endpoint to unban an IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400
    
    unban_ip(ip_address)
    return jsonify({"success": True, "message": f"IP {ip_address} has been unbanned"})

@auth_bp.route("/admin/unban-device", methods=["POST"])
@admin_required
def admin_unban_device():
    """Admin endpoint to unban a device"""
    data = request.get_json()
    device_fingerprint = data.get('device_fingerprint')
    
    if not device_fingerprint:
        return jsonify({"error": "Device fingerprint required"}), 400
    
    unban_device(device_fingerprint)
    return jsonify({"success": True, "message": "Device has been unbanned"})

@auth_bp.route("/admin/login-attempts", methods=["GET"])
@admin_required
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
@admin_required
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
@admin_required
def admin_interface():
    """Admin interface for managing security"""
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

# ===============================
# OAuth-like Scoped Authorization
# ===============================

@auth_bp.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    """OAuth-like authorization endpoint"""
    # Check if user is authenticated - if not, redirect to login with OAuth parameters preserved
    if not current_user.is_authenticated:
        # Preserve OAuth parameters in the redirect URL
        from urllib.parse import urlencode
        oauth_params = {
            'client_id': request.args.get('client_id') or request.form.get('client_id'),
            'redirect_uri': request.args.get('redirect_uri') or request.form.get('redirect_uri'),
            'scope': request.args.get('scope') or request.form.get('scope'),
            'state': request.args.get('state') or request.form.get('state'),
        }
        # Remove None values
        oauth_params = {k: v for k, v in oauth_params.items() if v is not None}
        
        # Create the complete OAuth authorize URL to redirect back to after login
        oauth_url = url_for('auth.oauth_authorize', **oauth_params)
        login_url = url_for('auth.login', redirect=oauth_url)
        return redirect(login_url)
    
    # Security checks - verify IP and device are not banned
    ip_address = get_real_ip()
    device_fingerprint = generate_device_fingerprint()
    
    if is_ip_banned(ip_address):
        return jsonify({"error": "Your IP address has been banned"}), 403
    
    if is_device_banned(device_fingerprint):
        return jsonify({"error": "Your device has been banned"}), 403
    
    if request.method == "GET":
        # Parse authorization request
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope', '')
        state = request.args.get('state', '')
        
        if not client_id or not redirect_uri:
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Validate client
        client = ClientManager.get_client(client_id)
        if not client:
            return jsonify({"error": "Invalid client"}), 400
        
        # Validate redirect URI
        if not ClientManager.is_redirect_uri_valid(client, redirect_uri):
            return jsonify({"error": "Invalid redirect URI"}), 400
        
        # Parse and validate scopes
        scope_names = [s.strip() for s in scope.split(',') if s.strip()]
        valid, scopes = ScopeManager.validate_scopes(scope_names)
        if not valid:
            return jsonify({"error": f"Invalid scopes: {scopes}"}), 400
        
        # Check if user has already authorized this client with these scopes
        existing_auth = AuthorizationManager.get_user_authorization(current_user.id, client_id)
        if existing_auth:
            authorized_scopes = set(AuthorizationManager.get_authorized_scopes(current_user.id, client_id))
            requested_scopes = set(scope_names)
            
            if requested_scopes.issubset(authorized_scopes):
                # Auto-approve if user has already granted these scopes
                auth_code, error = AuthorizationManager.create_authorization_code(
                    current_user.id, client_id, scope_names, redirect_uri
                )
                if error:
                    return jsonify({"error": error}), 400
                
                # Redirect back to client with code
                redirect_url = f"{redirect_uri}?code={auth_code.code}"
                if state:
                    redirect_url += f"&state={state}"
                return redirect(redirect_url)
        
        # Show consent screen
        return render_template('oauth_consent.html',
                             client=client,
                             scopes=scopes,
                             client_id=client_id,
                             redirect_uri=redirect_uri,
                             scope=scope,
                             state=state)
    
    elif request.method == "POST":
        # Handle user consent
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        scope = request.form.get('scope')
        state = request.form.get('state')
        action = request.form.get('action')
        
        if action == 'deny':
            # User denied access
            error_url = f"{redirect_uri}?error=access_denied"
            if state:
                error_url += f"&state={state}"
            return redirect(error_url)
        
        # User approved access
        scope_names = [s.strip() for s in scope.split(',') if s.strip()]
        
        # Create authorization code
        auth_code, error = AuthorizationManager.create_authorization_code(
            current_user.id, client_id, scope_names, redirect_uri
        )
        if error:
            error_url = f"{redirect_uri}?error=server_error"
            if state:
                error_url += f"&state={state}"
            return redirect(error_url)
        
        # Redirect back to client with code
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"
        return redirect(redirect_url)

@auth_bp.route("/oauth/token", methods=["POST"])
def oauth_token():
    """OAuth token endpoint - exchange authorization code for access token"""
    # Security checks - verify IP and device are not banned
    ip_address = get_real_ip()
    device_fingerprint = generate_device_fingerprint()
    
    if is_ip_banned(ip_address):
        return jsonify({"error": "access_denied", "error_description": "IP address banned"}), 403
    
    if is_device_banned(device_fingerprint):
        return jsonify({"error": "access_denied", "error_description": "Device banned"}), 403
    
    grant_type = request.form.get('grant_type')
    if grant_type != 'authorization_code':
        return jsonify({"error": "unsupported_grant_type"}), 400
    
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    redirect_uri = request.form.get('redirect_uri')
    
    if not all([code, client_id, client_secret, redirect_uri]):
        return jsonify({"error": "invalid_request"}), 400
    
    # Verify client credentials
    client = ClientManager.verify_client(client_id, client_secret)
    if not client:
        return jsonify({"error": "invalid_client"}), 401
    
    # Exchange code for authorization
    authorization, error = AuthorizationManager.exchange_code_for_authorization(
        code, client_id, redirect_uri
    )
    if error:
        return jsonify({"error": "invalid_grant", "error_description": error}), 400
    
    # Generate access token with scopes
    scope_names = AuthorizationManager.get_authorized_scopes(authorization.user_id, client_id)
    token_payload = {
        "user_id": authorization.user_id,
        "client_id": client_id,
        "scopes": scope_names,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iat": datetime.datetime.utcnow()
    }
    
    access_token = jwt.encode(token_payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": ','.join(scope_names)
    })

@auth_bp.route("/api/user-scoped", methods=["GET"])
def user_scoped_info():
    """Get user info based on scoped access token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid authorization header"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        decoded = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = decoded.get("user_id")
        client_id = decoded.get("client_id")
        scopes = decoded.get("scopes", [])
        
        if not user_id or not client_id or not scopes:
            return jsonify({"error": "Invalid token payload"}), 401
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Verify authorization is still active
        authorization = AuthorizationManager.get_user_authorization(user_id, client_id)
        if not authorization:
            return jsonify({"error": "Authorization revoked"}), 401
        
        # Update last used
        AuthorizationManager.update_last_used(user_id, client_id)
        
        # Return scoped user data
        user_data = user.get_scoped_data(scopes)
        return jsonify(user_data)
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@auth_bp.route("/api/client/register", methods=["POST"])
@login_required
def register_client():
    """Register a new OAuth client application"""
    # Security checks - verify IP and device are not banned
    ip_address = get_real_ip()
    device_fingerprint = generate_device_fingerprint()
    
    if is_ip_banned(ip_address):
        return jsonify({"error": "Your IP address has been banned"}), 403
    
    if is_device_banned(device_fingerprint):
        return jsonify({"error": "Your device has been banned"}), 403
    
    data = request.get_json()
    
    name = data.get('name')
    description = data.get('description', '')
    website_url = data.get('website_url', '')
    redirect_uris = data.get('redirect_uris', [])
    
    if not name or not redirect_uris:
        return jsonify({"error": "Name and redirect URIs are required"}), 400
    
    if not isinstance(redirect_uris, list):
        return jsonify({"error": "Redirect URIs must be a list"}), 400
    
    try:
        client = ClientManager.create_client(
            name=name,
            description=description,
            website_url=website_url,
            redirect_uris=redirect_uris,
            created_by_user_id=current_user.id
        )
        
        return jsonify({
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "name": client.name,
            "created_at": client.created_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({"error": "Failed to create client"}), 500

@auth_bp.route("/api/scopes", methods=["GET"])
def list_scopes():
    """List available data scopes"""
    scopes = DataScope.query.filter_by(is_active=True).all()
    return jsonify([{
        "name": scope.name,
        "display_name": scope.display_name,
        "description": scope.description
    } for scope in scopes])

@auth_bp.route("/api/user/authorizations", methods=["GET"])
@login_required
def user_authorizations():
    """List user's active authorizations"""
    authorizations = UserAuthorization.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).all()
    
    result = []
    for auth in authorizations:
        client = ClientManager.get_client(auth.client_id)
        if client:
            scope_names = AuthorizationManager.get_authorized_scopes(auth.user_id, auth.client_id)
            scopes = ScopeManager.get_scopes_by_names(scope_names)
            
            result.append({
                "client_id": auth.client_id,
                "client_name": client.name,
                "client_description": client.description,
                "granted_at": auth.granted_at.isoformat(),
                "last_used": auth.last_used.isoformat() if auth.last_used else None,
                "scopes": [{
                    "name": scope.name,
                    "display_name": scope.display_name,
                    "description": scope.description
                } for scope in scopes]
            })
    
    return jsonify(result)

@auth_bp.route("/api/user/authorizations/<client_id>", methods=["DELETE"])
@login_required
def revoke_authorization(client_id):
    """Revoke authorization for a client"""
    print(f"DEBUG: Attempting to revoke authorization for user {current_user.id}, client {client_id}")
    success = AuthorizationManager.revoke_authorization(current_user.id, client_id)
    print(f"DEBUG: Revocation result: {success}")
    if success:
        return jsonify({"message": "Authorization revoked"})
    else:
        return jsonify({"error": "Authorization not found"}), 404

@auth_bp.route("/authorizations")
@login_required
def authorizations_page():
    """Page for managing user authorizations"""
    return render_template("authorizations.html")

@auth_bp.route("/sessions")
@login_required
def sessions_page():
    """Page for managing user sessions"""
    tokens = RefreshToken.query.filter_by(user_id=current_user.id, revoked=False).all()
    sessions = [{
        "id": t.id,
        "issued_at": t.issued_at.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": t.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": t.ip_address,
        "user_agent": t.user_agent
    } for t in tokens]
    return render_template("sessions.html", sessions=sessions)

@auth_bp.route("/sessions/<int:session_id>/revoke", methods=["POST"])
@login_required
def revoke_session_ui(session_id):
    """Revoke a session from the UI"""
    token = RefreshToken.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not token:
        flash("Session not found", "error")
        return redirect(url_for("auth.sessions_page"))

    token.revoked = True
    db.session.commit()
    flash("Session revoked successfully", "success")
    return redirect(url_for("auth.sessions_page"))

@auth_bp.route("/unauthorized")
def unauthorized():
    """Unauthorized access page"""
    return render_template("unauthorized.html")

@auth_bp.route("/profile")
@login_required
def profile():
    """User profile page"""
    return render_template("profile.html", user=current_user)

@auth_bp.route("/profile/complete", methods=["GET", "POST"])
@login_required
def complete_profile():
    """Complete user profile after registration"""
    form = ProfileCompletionForm()
    redirect_url = request.args.get("redirect")
    
    if form.validate_on_submit():
        if form.skip.data:
            # User chose to skip profile completion
            if redirect_url:
                return redirect(redirect_url)
            return redirect(url_for("auth.profile"))
        
        # User submitted profile information
        if form.first_name.data:
            current_user.first_name = form.first_name.data
        if form.last_name.data:
            current_user.last_name = form.last_name.data
        if form.display_name.data:
            current_user.display_name = form.display_name.data
        if form.bio.data:
            current_user.bio = form.bio.data
        if form.location.data:
            current_user.location = form.location.data
        if form.date_of_birth.data:
            current_user.date_of_birth = form.date_of_birth.data
        if form.website.data:
            current_user.website = form.website.data
        
        current_user.updated_at = datetime.datetime.utcnow()
        db.session.commit()
        
        flash("Profile completed successfully! Welcome to KeyN!", "success")
        
        if redirect_url:
            return redirect(redirect_url)
        return redirect(url_for("auth.profile"))
    
    return render_template("complete_profile.html", form=form, redirect_url=redirect_url)

@auth_bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    """Edit user profile"""
    form = ProfileForm()
    
    if form.validate_on_submit():
        # Check if email is being changed and if it's already taken
        if form.email.data != current_user.email:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash("Email address is already in use", "error")
                return render_template("edit_profile.html", form=form)
        
        # Update user profile
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.display_name = form.display_name.data
        current_user.email = form.email.data
        current_user.bio = form.bio.data
        current_user.website = form.website.data
        current_user.location = form.location.data
        current_user.date_of_birth = form.date_of_birth.data
        current_user.updated_at = datetime.datetime.utcnow()
        
        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for("auth.profile"))
    
    # Pre-populate form with current user data
    if request.method == "GET":
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.display_name.data = current_user.display_name
        form.email.data = current_user.email
        form.bio.data = current_user.bio
        form.website.data = current_user.website
        form.location.data = current_user.location
        form.date_of_birth.data = current_user.date_of_birth
    
    return render_template("edit_profile.html", form=form)

@auth_bp.route("/profile/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user password"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Verify current password
        if not check_password_hash(current_user.password_hash, form.current_password.data):
            flash("Current password is incorrect", "error")
            return render_template("change_password.html", form=form)
        
        # Update password
        current_user.password_hash = generate_password_hash(form.new_password.data)
        current_user.updated_at = datetime.datetime.utcnow()
        db.session.commit()
        
        flash("Password changed successfully", "success")
        return redirect(url_for("auth.profile"))
    
    return render_template("change_password.html", form=form)

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
