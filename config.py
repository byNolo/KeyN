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
    SQLALCHEMY_DATABASE_URI = os.environ.get("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///site.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get("FLASK_SQLALCHEMY_TRACK_MODIFICATIONS", "False") == "True"
