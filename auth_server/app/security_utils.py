from flask import request
import hashlib
import hmac
import datetime
from . import db
from .models import User, IPBan, DeviceBan, LoginAttempt

def get_real_ip():
    """
    Get the real IP address, accounting for proxies like Cloudflare
    """
    # Cloudflare headers (most reliable for your setup)
    cf_connecting_ip = request.headers.get('CF-Connecting-IP')
    if cf_connecting_ip:
        return cf_connecting_ip
    
    # Standard proxy headers (fallback)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # Take the first IP (client IP) from the chain
        return x_forwarded_for.split(',')[0].strip()
    
    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip:
        return x_real_ip
    
    # Fallback to remote_addr (not reliable behind proxies)
    return request.remote_addr or 'unknown'

def generate_device_fingerprint():
    """
    Generate a unique device fingerprint based on various browser/device characteristics
    """
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    # Create a fingerprint from browser characteristics
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
    
    # Hash the fingerprint for storage
    device_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    
    return device_fingerprint

def is_ip_banned(ip_address):
    """
    Check if an IP address is banned
    """
    ban = IPBan.query.filter_by(ip_address=ip_address, is_active=True).first()
    
    if not ban:
        return False
    
    # Check if ban has expired
    if ban.expires_at and ban.expires_at < datetime.datetime.utcnow():
        ban.is_active = False
        db.session.commit()
        return False
    
    return True

def is_device_banned(device_fingerprint):
    """
    Check if a device fingerprint is banned
    """
    ban = DeviceBan.query.filter_by(device_fingerprint=device_fingerprint, is_active=True).first()
    
    if not ban:
        return False
    
    # Check if ban has expired
    if ban.expires_at and ban.expires_at < datetime.datetime.utcnow():
        ban.is_active = False
        db.session.commit()
        return False
    
    return True

def log_login_attempt(ip_address, device_fingerprint, username, success, user_id=None):
    """Log a login attempt for tracking purposes"""
    attempt = LoginAttempt(
        ip_address=ip_address,
        device_fingerprint=device_fingerprint,
        user_agent=request.headers.get('User-Agent', ''),
        username_attempted=username,
        success=success,
        user_id=user_id
    )
    db.session.add(attempt)
    db.session.commit()

def ban_ip(ip_address, reason="Manual ban", banned_by_user_id=None, expires_at=None):
    """Ban an IP address"""
    existing_ban = IPBan.query.filter_by(ip_address=ip_address).first()
    
    if existing_ban:
        existing_ban.is_active = True
        existing_ban.reason = reason
        existing_ban.banned_at = datetime.datetime.utcnow()
        existing_ban.banned_by = banned_by_user_id
        existing_ban.expires_at = expires_at
    else:
        ban = IPBan(
            ip_address=ip_address,
            reason=reason,
            banned_by=banned_by_user_id,
            expires_at=expires_at
        )
        db.session.add(ban)
    
    db.session.commit()

def ban_device(device_fingerprint, reason="Manual ban", banned_by_user_id=None, expires_at=None):
    """Ban a device fingerprint"""
    existing_ban = DeviceBan.query.filter_by(device_fingerprint=device_fingerprint).first()
    
    if existing_ban:
        existing_ban.is_active = True
        existing_ban.reason = reason
        existing_ban.banned_at = datetime.datetime.utcnow()
        existing_ban.banned_by = banned_by_user_id
        existing_ban.expires_at = expires_at
    else:
        ban = DeviceBan(
            device_fingerprint=device_fingerprint,
            reason=reason,
            banned_by=banned_by_user_id,
            expires_at=expires_at
        )
        db.session.add(ban)
    
    db.session.commit()

def unban_ip(ip_address):
    """Remove ban from an IP address"""
    ban = IPBan.query.filter_by(ip_address=ip_address, is_active=True).first()
    if ban:
        ban.is_active = False
        db.session.commit()

def unban_device(device_fingerprint):
    """Remove ban from a device fingerprint"""
    ban = DeviceBan.query.filter_by(device_fingerprint=device_fingerprint, is_active=True).first()
    if ban:
        ban.is_active = False
        db.session.commit()

def get_failed_login_attempts(ip_address, minutes=15):
    """Get number of failed login attempts from an IP in the last X minutes"""
    since = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)
    return LoginAttempt.query.filter_by(
        ip_address=ip_address, 
        success=False
    ).filter(LoginAttempt.timestamp >= since).count()

def is_rate_limited(ip_address, max_attempts=5, window_minutes=15):
    """Check if IP should be rate limited based on failed attempts"""
    failed_attempts = get_failed_login_attempts(ip_address, window_minutes)
    return failed_attempts >= max_attempts