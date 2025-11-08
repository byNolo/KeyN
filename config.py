import os
from dotenv import load_dotenv
import sys

load_dotenv()

class Config:
    # Allowed redirect domains for logout and other flows
    ALLOWED_REDIRECT_DOMAINS = os.environ.get("FLASK_ALLOWED_REDIRECT_DOMAINS", "http://localhost:6002,http://localhost:6001").split(",")
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "fallback-secret")
    # PERMANENT_SESSION_LIFETIME = int(os.environ.get("FLASK_PERMANENT_SESSION_LIFETIME", 7 * 24 * 60 * 60))  # Default to 7 days in seconds

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
    # For security with multiple sites on bynolo.ca, we don't set a cookie domain
    # This keeps KeyN cookies isolated to their specific subdomains
    # SSO will work through API calls rather than shared cookies
    SESSION_COOKIE_DOMAIN = os.environ.get("FLASK_SESSION_COOKIE_DOMAIN")  # None = current domain only
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_SESSION_COOKIE_SECURE", "True") == "True"  # True for HTTPS in production
    SESSION_COOKIE_HTTPONLY = os.environ.get("FLASK_SESSION_COOKIE_HTTPONLY", "True") == "True"
    SESSION_COOKIE_SAMESITE = os.environ.get("FLASK_SESSION_COOKIE_SAMESITE", "Lax")  # Lax for cross-site functionality
    
    # CORS configuration for client apps
    ALLOWED_ORIGINS = os.environ.get("FLASK_ALLOWED_ORIGINS", "").split(",") if os.environ.get("FLASK_ALLOWED_ORIGINS") else []

    # Passkey / WebAuthn debug (exposes detailed errors if True)
    PASSKEY_DEBUG = os.environ.get("PASSKEY_DEBUG", "False") == "True"

    # Cloudflare Turnstile (human verification)
    # Enable by setting both keys; can be toggled explicitly with TURNSTILE_ENABLED
    TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY")
    TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY")
    TURNSTILE_SIZE = os.environ.get("TURNSTILE_SIZE", "invisible")  # invisible | normal | compact
    TURNSTILE_ENABLED = os.environ.get("TURNSTILE_ENABLED")
    if TURNSTILE_ENABLED is None:
        # Auto-enable when both keys are present
        TURNSTILE_ENABLED = bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY)
    else:
        TURNSTILE_ENABLED = TURNSTILE_ENABLED == "True"
    
    @staticmethod
    def validate_production_security():
        """
        Validate security settings for production deployment.
        Raises errors for critical misconfigurations and warns about recommendations.
        """
        environment = os.environ.get('ENVIRONMENT', 'development')
        
        if environment != 'production':
            return  # Only validate in production
        
        print("=" * 60)
        print("KeyN Production Security Validation")
        print("=" * 60)
        
        errors = []
        warnings = []
        
        # Critical: SECRET_KEY must be set and strong
        if Config.SECRET_KEY == "fallback-secret":
            errors.append("SECRET_KEY is using default value - MUST be changed in production!")
        elif len(Config.SECRET_KEY) < 32:
            warnings.append(f"SECRET_KEY is only {len(Config.SECRET_KEY)} characters - recommend at least 32")
        
        # Critical: Cookie security in production
        if not Config.SESSION_COOKIE_SECURE:
            errors.append("SESSION_COOKIE_SECURE must be True in production (requires HTTPS)")
        
        if not Config.SESSION_COOKIE_HTTPONLY:
            warnings.append("SESSION_COOKIE_HTTPONLY should be True to prevent XSS attacks")
        
        # Recommendations
        if Config.SESSION_COOKIE_SAMESITE not in ['Strict', 'Lax']:
            warnings.append(f"SESSION_COOKIE_SAMESITE is '{Config.SESSION_COOKIE_SAMESITE}' - consider 'Strict' or 'Lax'")
        
        # Database security
        if 'sqlite' in Config.SQLALCHEMY_DATABASE_URI.lower():
            warnings.append("Using SQLite in production - consider PostgreSQL or MySQL for better performance and reliability")
        
        # Debug mode checks
        if Config.PASSKEY_DEBUG:
            errors.append("PASSKEY_DEBUG must be False in production!")
        
        # Email configuration
        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            errors.append("Email configuration incomplete - required for user verification")
        
        # Turnstile recommendation
        if not Config.TURNSTILE_ENABLED:
            warnings.append("Cloudflare Turnstile is disabled - consider enabling for bot protection")
        
        # Print results
        if errors:
            print("\n🔴 CRITICAL SECURITY ERRORS:")
            for error in errors:
                print(f"  ❌ {error}")
            print("\n⚠️  Production deployment BLOCKED due to security errors!")
            print("=" * 60)
            sys.exit(1)
        
        if warnings:
            print("\n⚠️  SECURITY WARNINGS:")
            for warning in warnings:
                print(f"  ⚠️  {warning}")
        
        if not errors and not warnings:
            print("\n✅ All security checks passed!")
        
        print("=" * 60)
        print()
