from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_cors import CORS
import sys
import os
import time
import logging
from logging.handlers import RotatingFileHandler
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

BRAND_PRODUCT = "KeyN"
BRAND_OWNER = "byNolo"  # stylized: lowercase b, uppercase N
BRAND_LOCKUP = f"{BRAND_PRODUCT} – {BRAND_OWNER}"


def setup_audit_logging(app):
    """
    Setup dedicated audit logging for security events.
    Creates a separate log file for security-critical events.
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError:
            pass  # Directory might have been created by another process
    
    # Setup audit logger
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    
    # Only add handler if not already present (prevents duplicate logs)
    if not audit_logger.handlers:
        handler = RotatingFileHandler(
            os.path.join(log_dir, 'audit.log'),
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)
    
    # Also setup application logger
    if not app.logger.handlers:
        handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=10485760,
            backupCount=5
        )
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('KeyN Auth Server startup')


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Validate production security settings
    Config.validate_production_security()
    
    # Generate cache busting version based on app start time
    app.config['CACHE_VERSION'] = str(int(time.time()))
    
    # Setup audit logging
    setup_audit_logging(app)

    # Configure CORS for client apps
    if app.config.get('ALLOWED_ORIGINS'):
        CORS(app, origins=app.config['ALLOWED_ORIGINS'], supports_credentials=True)
    else:
        # Development mode - allow all origins with credentials
        CORS(app, supports_credentials=True)

    # Configure session cookies for SSO
    app.config['SESSION_COOKIE_NAME'] = 'keyn_session'  # Use KeyN-specific cookie name
    if app.config.get('SESSION_COOKIE_DOMAIN'):
        app.config['SESSION_COOKIE_DOMAIN'] = app.config['SESSION_COOKIE_DOMAIN']
    app.config['SESSION_COOKIE_SECURE'] = app.config.get('SESSION_COOKIE_SECURE', False)
    app.config['SESSION_COOKIE_HTTPONLY'] = app.config.get('SESSION_COOKIE_HTTPONLY', True)
    app.config['SESSION_COOKIE_SAMESITE'] = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # Set login view
    login_manager.login_message = "Please log in to access this page."
    mail.init_app(app)

    from .routes import auth_bp
    app.register_blueprint(auth_bp)
    
    # Initialize database and default scopes
    with app.app_context():
        db.create_all()
        from .oauth_utils import ScopeManager
        ScopeManager.initialize_default_scopes()
    
    # Add cache busting version to template context
    @app.context_processor
    def inject_cache_version():
        return dict(
            cache_version=app.config['CACHE_VERSION'],
            BRAND_PRODUCT=BRAND_PRODUCT,
            BRAND_OWNER=BRAND_OWNER,
            BRAND_LOCKUP=BRAND_LOCKUP,
            current_year=time.strftime('%Y'),
            TURNSTILE_SITE_KEY=app.config.get('TURNSTILE_SITE_KEY'),
            TURNSTILE_ENABLED=app.config.get('TURNSTILE_ENABLED', False),
            TURNSTILE_SIZE=app.config.get('TURNSTILE_SIZE', 'invisible')
        )
    
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # XSS protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # HSTS (only in production with HTTPS)
        if app.config.get('SESSION_COOKIE_SECURE', False):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Content Security Policy
        # Allow Turnstile, Font Awesome CDN, Cloudflare Insights, and inline scripts/styles needed for functionality
        csp_parts = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://static.cloudflareinsights.com",
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
            "img-src 'self' data: https:",
            "font-src 'self' https://cdnjs.cloudflare.com",
            "connect-src 'self' https://cloudflareinsights.com",
            "frame-src https://challenges.cloudflare.com",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            # Allow form submissions to same origin and any HTTPS destination (helps OAuth flows
            # where a client may POST to the auth server endpoint). If you want to restrict this
            # further, replace `https:` with specific origins (e.g. https://auth-keyn.bynolo.ca).
            "form-action 'self' https:"
        ]
        response.headers['Content-Security-Policy'] = '; '.join(csp_parts)
        
        # Permissions Policy (restrict sensitive features)
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response

    return app
