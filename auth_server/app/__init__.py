from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_cors import CORS
import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

BRAND_PRODUCT = "KeyN"
BRAND_OWNER = "byNolo"  # stylized: lowercase b, uppercase N
BRAND_LOCKUP = f"{BRAND_PRODUCT} – {BRAND_OWNER}"

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Generate cache busting version based on app start time
    app.config['CACHE_VERSION'] = str(int(time.time()))

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

    return app
