"""
Multi-Factor Authentication (MFA) utilities for KeyN Auth Server.

Provides TOTP (Time-based One-Time Password) functionality compatible with
Google Authenticator, Authy, 1Password, and other authenticator apps.
"""

import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask import current_app
import datetime
from .models import MFASecret, MFABackupCode, MFATrustedDevice, db


def get_encryption_key():
    """
    Get or generate encryption key for MFA secrets.
    In production, this should come from a secure environment variable.
    """
    key = current_app.config.get('MFA_ENCRYPTION_KEY')
    if not key:
        # Generate a key from SECRET_KEY for backwards compatibility
        # In production, use a dedicated MFA_ENCRYPTION_KEY
        secret = current_app.config['SECRET_KEY'].encode('utf-8')
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    return key


def encrypt_secret(secret: str) -> str:
    """Encrypt a TOTP secret for storage"""
    f = Fernet(get_encryption_key())
    encrypted = f.encrypt(secret.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_secret(encrypted_secret: str) -> str:
    """Decrypt a stored TOTP secret"""
    f = Fernet(get_encryption_key())
    encrypted_bytes = base64.b64decode(encrypted_secret.encode('utf-8'))
    decrypted = f.decrypt(encrypted_bytes)
    return decrypted.decode('utf-8')


def generate_totp_secret() -> str:
    """Generate a new TOTP secret (base32 encoded)"""
    return pyotp.random_base32()


def generate_totp_uri(secret: str, username: str, issuer: str = "KeyN") -> str:
    """
    Generate a TOTP URI for QR code generation.
    
    Args:
        secret: Base32 encoded TOTP secret
        username: User's username or email
        issuer: Service name (default: "KeyN")
    
    Returns:
        otpauth:// URI string
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code(uri: str) -> str:
    """
    Generate a QR code image from a TOTP URI.
    
    Args:
        uri: otpauth:// URI string
    
    Returns:
        Base64 encoded PNG image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return f"data:image/png;base64,{img_base64}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code against a secret.
    
    Args:
        secret: Base32 encoded TOTP secret
        code: 6-digit code from authenticator app
        window: Number of time steps to check (default: 1, allows 30s drift)
    
    Returns:
        True if code is valid, False otherwise
    """
    if not code or not secret:
        return False
    
    # Remove any spaces or dashes from code
    code = code.replace(' ', '').replace('-', '')
    
    # Verify code is 6 digits
    if not code.isdigit() or len(code) != 6:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=window)


def generate_backup_codes(count: int = 10) -> list:
    """
    Generate backup codes for MFA recovery.
    
    Args:
        count: Number of codes to generate (default: 10)
    
    Returns:
        List of backup codes (format: XXXX-XXXX)
    """
    codes = []
    for _ in range(count):
        # Generate 8 random characters (alphanumeric, uppercase)
        code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
        # Format as XXXX-XXXX for readability
        formatted_code = f"{code[:4]}-{code[4:]}"
        codes.append(formatted_code)
    
    return codes


def hash_backup_code(code: str) -> str:
    """Hash a backup code for secure storage"""
    # Remove formatting
    code = code.replace('-', '').replace(' ', '').upper()
    return generate_password_hash(code, method='pbkdf2:sha256')


def verify_backup_code(user, code: str) -> bool:
    """
    Verify a backup code and mark it as used if valid.
    
    Args:
        user: User object
        code: Backup code to verify
    
    Returns:
        True if code is valid and unused, False otherwise
    """
    if not code:
        return False
    
    # Normalize code
    code = code.replace('-', '').replace(' ', '').upper()
    
    # Find matching unused backup code
    for backup_code in user.mfa_backup_codes:
        if not backup_code.used and check_password_hash(backup_code.code_hash, code):
            # Mark as used
            backup_code.used = True
            backup_code.used_at = datetime.datetime.utcnow()
            db.session.commit()
            return True
    
    return False


def create_mfa_for_user(user, secret: str = None) -> tuple:
    """
    Create MFA secret for a user.
    
    Args:
        user: User object
        secret: Optional pre-generated secret (if None, generates new one)
    
    Returns:
        tuple: (secret, qr_code_data_uri, backup_codes)
    """
    # Generate or use provided secret
    if not secret:
        secret = generate_totp_secret()
    
    # Encrypt and store secret
    encrypted_secret = encrypt_secret(secret)
    
    # Clear existing backup codes first (before adding new MFA secret to avoid autoflush issues)
    MFABackupCode.query.filter_by(user_id=user.id).delete()
    db.session.flush()  # Flush the delete operation
    
    # Check if user already has MFA
    if hasattr(user, 'mfa_secret') and user.mfa_secret:
        mfa_secret = user.mfa_secret
        mfa_secret.encrypted_secret = encrypted_secret
        mfa_secret.enabled = False  # Disabled until verified
        mfa_secret.created_at = datetime.datetime.utcnow()
    else:
        mfa_secret = MFASecret(
            user_id=user.id,
            encrypted_secret=encrypted_secret,
            enabled=False  # Disabled until verified
        )
        db.session.add(mfa_secret)
    
    db.session.flush()  # Flush the MFA secret
    
    # Generate QR code
    uri = generate_totp_uri(secret, user.username)
    qr_code = generate_qr_code(uri)
    
    # Generate backup codes
    backup_codes = generate_backup_codes()
    
    # Store hashed backup codes
    for code in backup_codes:
        backup_code = MFABackupCode(
            user_id=user.id,
            code_hash=hash_backup_code(code)
        )
        db.session.add(backup_code)
    
    db.session.commit()
    
    return secret, qr_code, backup_codes


def enable_mfa_for_user(user) -> bool:
    """
    Enable MFA for a user after successful verification.
    
    Args:
        user: User object
    
    Returns:
        True if successful, False otherwise
    """
    if not hasattr(user, 'mfa_secret') or not user.mfa_secret:
        return False
    
    user.mfa_secret.enabled = True
    user.mfa_secret.last_used = datetime.datetime.utcnow()
    db.session.commit()
    
    return True


def disable_mfa_for_user(user) -> bool:
    """
    Disable MFA for a user.
    
    Args:
        user: User object
    
    Returns:
        True if successful, False otherwise
    """
    if not hasattr(user, 'mfa_secret') or not user.mfa_secret:
        return False
    
    # Delete MFA secret and backup codes
    db.session.delete(user.mfa_secret)
    MFABackupCode.query.filter_by(user_id=user.id).delete()
    MFATrustedDevice.query.filter_by(user_id=user.id).delete()
    
    db.session.commit()
    
    return True


def verify_mfa_code(user, code: str) -> bool:
    """
    Verify an MFA code (either TOTP or backup code).
    
    Args:
        user: User object
        code: MFA code to verify
    
    Returns:
        True if code is valid, False otherwise
    """
    if not user.has_mfa_enabled():
        return False
    
    # Try TOTP first
    secret = decrypt_secret(user.mfa_secret.encrypted_secret)
    if verify_totp(secret, code):
        user.mfa_secret.last_used = datetime.datetime.utcnow()
        db.session.commit()
        return True
    
    # Try backup codes
    if verify_backup_code(user, code):
        return True
    
    return False


def trust_device(user, device_fingerprint: str, device_name: str = None, 
                 ip_address: str = None, user_agent: str = None, 
                 trust_days: int = 30) -> MFATrustedDevice:
    """
    Mark a device as trusted for MFA purposes.
    
    Args:
        user: User object
        device_fingerprint: Unique device identifier
        device_name: Optional friendly name for the device
        ip_address: IP address of the device
        user_agent: User agent string
        trust_days: Number of days to trust this device (default: 30)
    
    Returns:
        MFATrustedDevice object
    """
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=trust_days)
    
    # Check if device already exists
    existing = MFATrustedDevice.query.filter_by(
        user_id=user.id,
        device_fingerprint=device_fingerprint,
        is_active=True
    ).first()
    
    if existing:
        # Update existing trust
        existing.expires_at = expires_at
        existing.last_used = datetime.datetime.utcnow()
        existing.ip_address = ip_address
        existing.user_agent = user_agent
        if device_name:
            existing.device_name = device_name
        db.session.commit()
        return existing
    
    # Create new trusted device
    trusted_device = MFATrustedDevice(
        user_id=user.id,
        device_fingerprint=device_fingerprint,
        device_name=device_name or "Unknown Device",
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at
    )
    
    db.session.add(trusted_device)
    db.session.commit()
    
    return trusted_device


def is_device_trusted(user, device_fingerprint: str) -> bool:
    """
    Check if a device is trusted for MFA purposes.
    
    Args:
        user: User object
        device_fingerprint: Unique device identifier
    
    Returns:
        True if device is trusted and not expired, False otherwise
    """
    trusted_device = MFATrustedDevice.query.filter_by(
        user_id=user.id,
        device_fingerprint=device_fingerprint,
        is_active=True
    ).first()
    
    if not trusted_device:
        return False
    
    # Check if still valid
    if trusted_device.is_valid():
        # Update last used
        trusted_device.last_used = datetime.datetime.utcnow()
        db.session.commit()
        return True
    else:
        # Expired, deactivate it
        trusted_device.is_active = False
        db.session.commit()
        return False


def revoke_trusted_device(user, device_id: int) -> bool:
    """
    Revoke trust for a specific device.
    
    Args:
        user: User object
        device_id: ID of the trusted device to revoke
    
    Returns:
        True if successful, False otherwise
    """
    device = MFATrustedDevice.query.filter_by(
        id=device_id,
        user_id=user.id
    ).first()
    
    if not device:
        return False
    
    device.is_active = False
    db.session.commit()
    
    return True


def get_trusted_devices(user) -> list:
    """
    Get all active trusted devices for a user.
    
    Args:
        user: User object
    
    Returns:
        List of MFATrustedDevice objects
    """
    return MFATrustedDevice.query.filter_by(
        user_id=user.id,
        is_active=True
    ).order_by(MFATrustedDevice.trusted_at.desc()).all()


def regenerate_backup_codes(user) -> list:
    """
    Regenerate backup codes for a user.
    
    Args:
        user: User object
    
    Returns:
        List of new backup codes
    """
    # Delete existing backup codes
    MFABackupCode.query.filter_by(user_id=user.id).delete()
    
    # Generate new codes
    backup_codes = generate_backup_codes()
    
    # Store hashed backup codes
    for code in backup_codes:
        backup_code = MFABackupCode(
            user_id=user.id,
            code_hash=hash_backup_code(code)
        )
        db.session.add(backup_code)
    
    db.session.commit()
    
    return backup_codes
