from flask_mail import Message
from flask import url_for, render_template, current_app
import jwt
import datetime
import os

def send_verification_email(user, app, mail):
    print(f"[EMAIL] Starting verification email send to {user.email}")

    token = jwt.encode({
        "user_id": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    link = url_for("auth.verify_email", token=token, _external=True)
    print(f"[EMAIL] Generated verification link: {link}")

    html_body = render_template("email/verify_email.html", 
                               username=user.username, 
                               link=link)
    print(f"[EMAIL] Template rendered successfully, HTML length: {len(html_body)}")

    msg = Message(
        subject="Verify Your Email - KeyN",
        recipients=[user.email],
        html=html_body
    )
    print(f"[EMAIL] Message object created")

    # Attach logo.png as inline image
    try:
        with app.open_resource("static/logos/logo.png") as f:
            logo_data = f.read()
            msg.attach(
                "logo.png", "image/png", logo_data, 
                disposition='inline', 
                headers={"Content-ID": "<logo_image>"}
            )
        print(f"[EMAIL] Logo attached successfully ({len(logo_data)} bytes)")
    except Exception as e:
        print(f"[EMAIL] Warning: Could not attach logo.png: {e}")

    # Attach favicon.png as inline image
    try:
        with app.open_resource("static/logos/favicon.png") as f:
            favicon_data = f.read()
            msg.attach(
                "favicon.png", "image/png", favicon_data, 
                disposition='inline', 
                headers={"Content-ID": "<favicon_image>"}
            )
        print(f"[EMAIL] Favicon attached successfully ({len(favicon_data)} bytes)")
    except Exception as e:
        print(f"[EMAIL] Warning: Could not attach favicon.png: {e}")

    try:
        print(f"[EMAIL] Attempting to send email via SMTP...")
        mail.send(msg)
        print(f"[EMAIL] ✓ Verification email sent successfully to {user.email}")
    except Exception as e:
        print(f"[EMAIL] ✗ Failed to send email: {e}")
        import traceback
        print(f"[EMAIL] Full traceback:")
        traceback.print_exc()
        traceback.print_exc()


def send_password_reset_email(user, app, mail):
    """Send password reset email with PNG attachments"""
    print("Sending password reset email to", user.email)

    token = jwt.encode({
        "user_id": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    link = url_for("auth.reset_password", token=token, _external=True)

    html_body = render_template("email/password_reset.html", 
                               username=user.username, 
                               link=link)

    msg = Message(
        subject="Reset Your KeyN Password",
        recipients=[user.email],
        html=html_body
    )
    
    # Attach logo.png as inline image
    try:
        with app.open_resource("static/logos/logo.png") as f:
            msg.attach(
                "logo.png", "image/png", f.read(), 
                disposition='inline', 
                headers={"Content-ID": "<logo_image>"}
            )
    except Exception as e:
        print(f"Warning: Could not attach logo.png: {e}")

    # Attach favicon.png as inline image
    try:
        with app.open_resource("static/logos/favicon.png") as f:
            msg.attach(
                "favicon.png", "image/png", f.read(), 
                disposition='inline', 
                headers={"Content-ID": "<favicon_image>"}
            )
    except Exception as e:
        print(f"Warning: Could not attach favicon.png: {e}")
    
    try:
        mail.send(msg)
        print(f"[✓] Password reset email sent to {user.email}")
    except Exception as e:
        print(f"[X] Failed to send password reset email: {e}")
        import traceback
        traceback.print_exc()

def verify_email_token(token, app):
    """Verify email verification token"""
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return data["user_id"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def admin_required(f):
    """Decorator to require admin access"""
    from functools import wraps
    from flask_login import current_user
    from flask import abort, jsonify, request
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            else:
                from flask import redirect, url_for
                return redirect(url_for('auth.login'))
        
        if not current_user.is_admin:
            if request.is_json:
                return jsonify({"error": "Admin access required"}), 403
            else:
                from flask import redirect, url_for
                return redirect(url_for('auth.unauthorized'))
                
        return f(*args, **kwargs)
    return decorated_function

def send_admin_action_email(user, action_token, app, mail):
    """Send admin action confirmation email using standard base template and inline images."""
    try:
        confirm_link = url_for('auth.admin_confirm_action', token=action_token.token, _external=True)
        html_body = render_template('email/admin_action_confirm.html', user=user, action=action_token, confirm_link=confirm_link)
        msg = Message(
            subject=f"Confirm Admin Action - {action_token.action_type}",
            recipients=[user.email],
            html=html_body
        )
        # Attach images like other templates
        for fname, cid in [('logo.png','<logo_image>'), ('favicon.png','<favicon_image>')]:
            try:
                with app.open_resource(f'static/logos/{fname}') as f:
                    msg.attach(fname, 'image/png', f.read(), disposition='inline', headers={'Content-ID': cid})
            except Exception as e:
                current_app.logger.warning(f"Could not attach {fname}: {e}")
        mail.send(msg)
    except Exception as e:
        current_app.logger.error(f"Failed to send admin action email: {e}")


def send_announcement_email(user, announcement_data, app, mail):
    """
    Send branded announcement email to user
    
    Args:
        user: User object
        announcement_data: dict with keys:
            - title: Announcement title
            - subtitle: Announcement subtitle
            - content: HTML content (will be marked as safe)
            - benefits: List of benefit strings
            - cta_text: Call-to-action button text (optional)
            - cta_link: Call-to-action button link (optional)
        app: Flask app instance
        mail: Flask-Mail instance
    """
    print(f"[EMAIL] Sending announcement to {user.email}: {announcement_data.get('title', 'Untitled')}")
    
    try:
        html_body = render_template(
            "email/announcement.html",
            username=user.username,
            user_email=user.email,
            announcement_title=announcement_data.get('title', 'Important Announcement'),
            announcement_subtitle=announcement_data.get('subtitle', ''),
            announcement_content=announcement_data.get('content', ''),
            benefits=announcement_data.get('benefits', []),
            cta_text=announcement_data.get('cta_text'),
            cta_link=announcement_data.get('cta_link')
        )
        
        msg = Message(
            subject=f"{announcement_data.get('title', 'Important Announcement')} - KeyN by byNolo",
            recipients=[user.email],
            html=html_body
        )
        
        # Attach logo and favicon as inline images
        for fname, cid in [('logo.png', '<logo_image>'), ('favicon.png', '<favicon_image>')]:
            try:
                with app.open_resource(f'static/logos/{fname}') as f:
                    msg.attach(fname, 'image/png', f.read(), disposition='inline', headers={'Content-ID': cid})
            except Exception as e:
                print(f"[EMAIL] Warning: Could not attach {fname}: {e}")
        
        mail.send(msg)
        print(f"[EMAIL] ✓ Announcement email sent successfully to {user.email}")
        return True
        
    except Exception as e:
        print(f"[EMAIL] ✗ Failed to send announcement email: {e}")
        import traceback
        traceback.print_exc()
        return False
