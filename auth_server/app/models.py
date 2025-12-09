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
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Additional profile fields for scoped access
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    display_name = db.Column(db.String(200))
    bio = db.Column(db.Text)
    website = db.Column(db.String(500))
    location = db.Column(db.String(200))
    date_of_birth = db.Column(db.Date)
    
    def get_full_name(self):
        """Get user's full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.display_name:
            return self.display_name
        else:
            return self.username
    
    def get_public_profile(self):
        """Get publicly available profile data"""
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name or self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def get_scoped_data(self, scope_names):
        """Get user data based on requested scopes"""
        data = {}
        scope_map = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.get_full_name(),
            'first_name': self.first_name,
            'last_name': self.last_name,
            'display_name': self.display_name,
            'bio': self.bio,
            'website': self.website,
            'location': self.location,
            'date_of_birth': self.date_of_birth.isoformat() if self.date_of_birth else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_verified': self.is_verified
        }
        
        for scope in scope_names:
            if scope in scope_map:
                data[scope] = scope_map[scope]
        
        return data
    
    def needs_profile_completion(self):
        """Check if user should be prompted to complete their profile"""
        # Profile completion is suggested if user has no first_name, last_name, or display_name
        return not any([self.first_name, self.last_name, self.display_name])
    
    def mark_profile_completed(self):
        """Mark that user has completed initial profile setup"""
        # We don't need a special flag - having any profile info means it's "completed"
        # This method is for future use if we want to track completion explicitly
        pass
    
    def has_mfa_enabled(self):
        """Check if user has MFA enabled"""
        return hasattr(self, 'mfa_secret') and self.mfa_secret and self.mfa_secret.is_enabled()
    
    def get_unused_backup_codes_count(self):
        """Get count of unused backup codes"""
        if not hasattr(self, 'mfa_backup_codes'):
            return 0
        return sum(1 for code in self.mfa_backup_codes if not code.used)

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
    failure_reason = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

class ClientApplication(db.Model):
    """Represents external applications that can request user data"""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False)
    client_secret = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    website_url = db.Column(db.String(500))
    redirect_uris = db.Column(db.Text)  # JSON array of allowed redirect URIs
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    authorizations = db.relationship('UserAuthorization', backref='client', lazy=True, cascade='all, delete-orphan')

    def get_redirect_uris(self):
        """Return list of redirect URIs parsed from JSON text field."""
        try:
            import json
            return json.loads(self.redirect_uris) if self.redirect_uris else []
        except Exception:
            return []

    def set_redirect_uris(self, uris_list):
        """Store list as JSON."""
        import json
        self.redirect_uris = json.dumps(uris_list or [])

class AdminActionToken(db.Model):
    """Email-confirmed admin actions for sensitive client application changes"""
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action_type = db.Column(db.String(64), nullable=False)  # create_client, update_client, delete_client, rotate_secret
    payload = db.Column(db.Text)  # JSON describing the action
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('admin_action_tokens', lazy=True, cascade='all, delete-orphan'))

    def is_valid(self):
        return (not self.used) and (self.expires_at > datetime.datetime.utcnow())

class DataScope(db.Model):
    """Defines available data scopes that can be requested"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)  # e.g., 'username', 'email', 'full_name'
    display_name = db.Column(db.String(128), nullable=False)  # e.g., 'Username', 'Email Address', 'Full Name'
    description = db.Column(db.Text)  # Description shown to users
    data_field = db.Column(db.String(64))  # Field name in User model or callable method
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class UserAuthorization(db.Model):
    """Tracks user permissions granted to client applications"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    client_id = db.Column(db.String(64), db.ForeignKey("client_application.client_id"), nullable=False)
    scope_ids = db.Column(db.Text)  # JSON array of authorized scope IDs
    granted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref='authorizations')

class AuthorizationCode(db.Model):
    """Temporary codes for OAuth-like flow"""
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(128), unique=True, nullable=False)
    client_id = db.Column(db.String(64), db.ForeignKey("client_application.client_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scope_ids = db.Column(db.Text)  # JSON array of requested scope IDs
    redirect_uri = db.Column(db.String(500), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class PasskeyCredential(db.Model):
    """Stores a user's WebAuthn / Passkey credential"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    credential_id = db.Column(db.String(255), unique=True, nullable=False)  # base64url encoded
    public_key = db.Column(db.Text, nullable=False)  # PEM or COSE (we'll store base64url of COSE key bytes)
    sign_count = db.Column(db.Integer, default=0)
    transports = db.Column(db.String(255))  # comma-separated transports
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_used = db.Column(db.DateTime)
    friendly_name = db.Column(db.String(255))  # Optional user label for the credential

    user = db.relationship('User', backref=db.backref('passkeys', lazy=True, cascade='all, delete-orphan'))

    def to_dict(self):
        return {
            'id': self.id,
            'credential_id': self.credential_id,
            'sign_count': self.sign_count,
            'transports': (self.transports.split(',') if self.transports else []),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'friendly_name': self.friendly_name or 'Passkey'
        }


class MFASecret(db.Model):
    """Stores encrypted TOTP secrets for multi-factor authentication"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True, index=True)
    encrypted_secret = db.Column(db.String(255), nullable=False)  # Encrypted TOTP secret
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    enabled = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime)
    
    user = db.relationship('User', backref=db.backref('mfa_secret', uselist=False, cascade='all, delete-orphan'))

    def is_enabled(self):
        """Check if MFA is enabled for this user"""
        return self.enabled


class MFABackupCode(db.Model):
    """Stores hashed backup codes for MFA recovery"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)  # Hashed backup code
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('mfa_backup_codes', lazy=True, cascade='all, delete-orphan'))


class MFATrustedDevice(db.Model):
    """Tracks trusted devices that can skip MFA for a limited time"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    device_fingerprint = db.Column(db.String(128), nullable=False)
    device_name = db.Column(db.String(255))  # User-friendly device name
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(512))
    trusted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)  # Trust expires after 30 days
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('mfa_trusted_devices', lazy=True, cascade='all, delete-orphan'))

    def is_valid(self):
        """Check if this trusted device is still valid"""
        return self.is_active and self.expires_at > datetime.datetime.utcnow()

    def to_dict(self):
        return {
            'id': self.id,
            'device_name': self.device_name,
            'ip_address': self.ip_address,
            'trusted_at': self.trusted_at.isoformat() if self.trusted_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }
