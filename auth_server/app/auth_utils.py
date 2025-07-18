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
