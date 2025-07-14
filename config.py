import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "fallback-secret")

    # Email (Flask-Mail) configuration
    MAIL_SERVER = os.environ.get("FLASK_MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("FLASK_MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("FLASK_MAIL_USE_TLS", "True") == "True"
    MAIL_USERNAME = os.environ.get("FLASK_MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("FLASK_MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("FLASK_MAIL_DEFAULT_SENDER")
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        raise ValueError("MAIL_USERNAME and MAIL_PASSWORD must be set in the environment variables.")
    if not MAIL_DEFAULT_SENDER:
        raise ValueError("MAIL_DEFAULT_SENDER must be set in the environment variables.")
    

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///instance/keyn_auth.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get("FLASK_SQLALCHEMY_TRACK_MODIFICATIONS", "False") == "True"
    
    # Session/Cookie configuration for SSO
    # For security with multiple sites on nolanbc.ca, we don't set a cookie domain
    # This keeps KeyN cookies isolated to their specific subdomains
    # SSO will work through API calls rather than shared cookies
    SESSION_COOKIE_DOMAIN = os.environ.get("FLASK_SESSION_COOKIE_DOMAIN")  # None = current domain only
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_SESSION_COOKIE_SECURE", "True") == "True"  # True for HTTPS in production
    SESSION_COOKIE_HTTPONLY = os.environ.get("FLASK_SESSION_COOKIE_HTTPONLY", "True") == "True"
    SESSION_COOKIE_SAMESITE = os.environ.get("FLASK_SESSION_COOKIE_SAMESITE", "Lax")  # Lax for cross-site functionality
    
    # CORS configuration for client apps
    ALLOWED_ORIGINS = os.environ.get("FLASK_ALLOWED_ORIGINS", "").split(",") if os.environ.get("FLASK_ALLOWED_ORIGINS") else []
