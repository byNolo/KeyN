from . import db
from flask_login import UserMixin
from . import db
import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

class RefreshToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)

    # NEW FIELDS:
    user_agent = db.Column(db.String(512))
    ip_address = db.Column(db.String(64))

class IPBan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False, unique=True)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    banned_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # None for permanent ban
    is_active = db.Column(db.Boolean, default=True)

class DeviceBan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_fingerprint = db.Column(db.String(128), nullable=False, unique=True)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    banned_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # None for permanent ban
    is_active = db.Column(db.Boolean, default=True)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False)
    device_fingerprint = db.Column(db.String(128))
    user_agent = db.Column(db.String(512))
    username_attempted = db.Column(db.String(150))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)