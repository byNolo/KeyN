from flask import request, current_app
import hashlib
import hmac
import datetime
from . import db
from .models import User, IPBan, DeviceBan, LoginAttempt
import requests
from typing import Tuple, Optional
from urllib.parse import urlparse

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
    Generate a unique device fingerprint based on various browser/device characteristics.
    Enhanced version with more entropy for better tracking while maintaining backwards compatibility.
    """
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    accept = request.headers.get('Accept', '')
    
    # Include IP subnet for better tracking (not full IP for privacy)
    # This provides more entropy while respecting user privacy
    ip = get_real_ip()
    ip_subnet = ''
    if '.' in ip:  # IPv4
        ip_subnet = '.'.join(ip.split('.')[:3])  # First 3 octets
    elif ':' in ip:  # IPv6
        ip_subnet = ':'.join(ip.split(':')[:4])  # First 4 hextets
    
    # Combine multiple factors for stronger fingerprint
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}|{accept}|{ip_subnet}"
    
    # Use full SHA256 hash (64 characters = 256 bits) for better collision resistance
    # This is more secure than the previous 32-character truncated version
    device_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
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


def get_rate_limit_key(identifier, action_type):
    """Generate a rate limit tracking key"""
    return f"rate_limit:{action_type}:{identifier}"


def check_rate_limit(identifier, action_type, max_attempts=5, window_minutes=15):
    """
    Generic rate limiting function for any action type.
    Returns True if rate limit is exceeded, False otherwise.
    
    Args:
        identifier: Unique identifier (IP address, email, etc.)
        action_type: Type of action (password_reset, registration, etc.)
        max_attempts: Maximum number of attempts allowed
        window_minutes: Time window in minutes
    """
    from .models import LoginAttempt
    
    since = datetime.datetime.utcnow() - datetime.timedelta(minutes=window_minutes)
    
    # Count attempts for this action type and identifier
    attempts = LoginAttempt.query.filter_by(
        ip_address=identifier,
        username_attempted=action_type,  # Repurpose this field for action type
        success=False
    ).filter(LoginAttempt.timestamp >= since).count()
    
    return attempts >= max_attempts


def log_rate_limit_attempt(identifier, action_type, success=False):
    """Log a rate-limited action attempt"""
    from .models import LoginAttempt
    
    attempt = LoginAttempt(
        ip_address=identifier,
        device_fingerprint=generate_device_fingerprint(),
        user_agent=request.headers.get('User-Agent', ''),
        username_attempted=action_type,
        success=success,
        failure_reason='Rate limit check' if not success else None
    )
    db.session.add(attempt)
    db.session.commit()


def verify_turnstile(token: str, remoteip: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verify Cloudflare Turnstile token.
    Returns (is_valid, error_message)
    If Turnstile is disabled or keys missing, returns (True, '') to avoid blocking dev.
    """
    try:
        enabled = current_app.config.get('TURNSTILE_ENABLED', False)
        secret = current_app.config.get('TURNSTILE_SECRET_KEY')
        if not enabled or not secret:
            return True, ''
        if not token:
            return False, 'Missing Turnstile token'
        data = {'secret': secret, 'response': token}
        if remoteip:
            data['remoteip'] = remoteip
        resp = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=data, timeout=5)
        ok = False
        err_msg = ''
        if resp.ok:
            j = resp.json()
            ok = bool(j.get('success'))
            if not ok:
                errors = j.get('error-codes') or []
                err_msg = ', '.join(errors) if errors else 'Verification failed'
        else:
            err_msg = f'Verification HTTP {resp.status_code}'
        return ok, err_msg
    except Exception as e:
        # Fail-closed only if explicitly enabled; otherwise pass in dev
        if current_app.config.get('TURNSTILE_ENABLED', False):
            return False, str(e)
        return True, ''


def validate_redirect_url(url):
    """
    Validate redirect URL against whitelist to prevent open redirect attacks.
    Returns the URL if valid, None otherwise.
    """
    if not url:
        return None
    
    try:
        parsed = urlparse(url)
        
        # Check against allowed domains from config
        allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', [])
        
        # Check if URL starts with an allowed domain
        if not any(url.startswith(domain) for domain in allowed_domains):
            current_app.logger.warning(f"Blocked redirect to unauthorized domain: {url}")
            return None
        
        # Additional security checks
        if parsed.scheme not in ['http', 'https', '']:
            current_app.logger.warning(f"Blocked redirect with invalid scheme: {parsed.scheme}")
            return None
        
        # Block javascript: and data: URIs
        if parsed.scheme in ['javascript', 'data', 'file', 'vbscript']:
            current_app.logger.warning(f"Blocked dangerous redirect scheme: {parsed.scheme}")
            return None
        
        return url
        
    except Exception as e:
        current_app.logger.error(f"Error validating redirect URL: {e}")
        return None


def sanitize_string(value, max_length=255, allow_newlines=False):
    """
    Sanitize and validate string input.
    
    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to preserve newline characters
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        return ""
    
    # Strip leading/trailing whitespace
    value = value.strip()
    
    # Remove null bytes (security issue)
    value = value.replace('\x00', '')
    
    # Remove other control characters except tabs and newlines
    if not allow_newlines:
        value = ''.join(char for char in value if ord(char) >= 32 or char == '\t')
    else:
        value = ''.join(char for char in value if ord(char) >= 32 or char in ['\t', '\n', '\r'])
    
    # Truncate to max length
    if len(value) > max_length:
        value = value[:max_length]
    
    return value


def validate_email_format(email):
    """
    Basic email format validation.
    More thorough validation is done by WTForms Email validator.
    
    Returns:
        True if format looks valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    # Basic checks
    if len(email) > 254:  # RFC 5321
        return False
    
    if '@' not in email:
        return False
    
    local, domain = email.rsplit('@', 1)
    
    # Check local part
    if not local or len(local) > 64:
        return False
    
    # Check domain part
    if not domain or len(domain) > 253:
        return False
    
    if '..' in email:  # No consecutive dots
        return False
    
    return True