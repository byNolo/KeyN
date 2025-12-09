# Multi-Factor Authentication (MFA) for KeyN

This document describes the Multi-Factor Authentication implementation in KeyN Auth Server.

## Overview

KeyN now supports **Time-based One-Time Password (TOTP)** multi-factor authentication, compatible with popular authenticator apps like:
- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password
- Bitwarden
- Any TOTP-compatible authenticator app

## Features

### ✅ Core Functionality
- **TOTP Authentication**: Standard 6-digit time-based codes
- **QR Code Enrollment**: Easy setup by scanning a QR code
- **Backup Codes**: 10 one-time use recovery codes
- **Trusted Devices**: Optional "remember this device for 30 days" feature
- **Device Management**: View and revoke trusted devices
- **Backup Code Regeneration**: Create new backup codes with password confirmation

### 🔒 Security Features
- **Encrypted Secret Storage**: TOTP secrets are encrypted using Fernet (symmetric encryption)
- **Hashed Backup Codes**: Backup codes are hashed using pbkdf2:sha256
- **Audit Logging**: All MFA events are logged for security monitoring
- **Rate Limiting**: Protection against brute force attacks
- **Device Fingerprinting**: Unique device identification for trusted device feature

## Database Schema

### `mfa_secret`
Stores encrypted TOTP secrets for users who have MFA enabled.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `user_id` | INTEGER | Foreign key to user (UNIQUE) |
| `encrypted_secret` | VARCHAR(255) | Encrypted base32 TOTP secret |
| `created_at` | DATETIME | When MFA was first set up |
| `enabled` | BOOLEAN | Whether MFA is currently active |
| `last_used` | DATETIME | Last successful MFA verification |

### `mfa_backup_code`
Stores hashed backup codes for MFA recovery.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `user_id` | INTEGER | Foreign key to user |
| `code_hash` | VARCHAR(255) | Hashed backup code (pbkdf2:sha256) |
| `used` | BOOLEAN | Whether code has been consumed |
| `used_at` | DATETIME | When code was used |
| `created_at` | DATETIME | When code was generated |

### `mfa_trusted_device`
Tracks devices that can skip MFA for a limited time.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `user_id` | INTEGER | Foreign key to user |
| `device_fingerprint` | VARCHAR(128) | Unique device identifier |
| `device_name` | VARCHAR(255) | User-friendly device name |
| `ip_address` | VARCHAR(64) | IP address when trusted |
| `user_agent` | VARCHAR(512) | Browser user agent |
| `trusted_at` | DATETIME | When device was trusted |
| `expires_at` | DATETIME | When trust expires (30 days) |
| `last_used` | DATETIME | Last login from this device |
| `is_active` | BOOLEAN | Whether trust is still valid |

## User Flow

### Setting Up MFA

1. User navigates to their profile
2. Clicks "Enable Two-Factor Auth"
3. System generates:
   - A random TOTP secret (base32 encoded)
   - A QR code containing the secret
   - 10 backup codes
4. User scans QR code with authenticator app
5. User saves backup codes
6. User enters a 6-digit code to verify setup
7. MFA is now enabled!

### Logging In with MFA

1. User enters username/email and password
2. System verifies credentials
3. If MFA is enabled and device is not trusted:
   - Redirect to MFA verification page
   - User enters 6-digit code from app (or backup code)
   - Optional: Check "Trust this device for 30 days"
4. User is logged in

### Using a Backup Code

Backup codes are 8 characters formatted as `XXXX-XXXX` (e.g., `A3B7-2K9M`).

- Each code can only be used once
- Useful if authenticator app is lost or unavailable
- Can be regenerated from MFA management page

### Managing MFA

From the MFA management page (`/mfa/manage`), users can:
- View number of unused backup codes
- Regenerate backup codes (requires password)
- View trusted devices
- Revoke trust from devices
- Disable MFA entirely (requires password)

## Routes

### User-Facing Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/mfa/setup` | GET, POST | MFA enrollment page |
| `/mfa/verify` | GET, POST | MFA verification during login |
| `/mfa/manage` | GET | MFA management dashboard |
| `/mfa/disable` | POST | Disable MFA (requires password) |
| `/mfa/regenerate-codes` | POST | Generate new backup codes |
| `/mfa/revoke-device/<id>` | POST | Revoke a trusted device |

## Configuration

### Environment Variables

```bash
# Optional: Custom encryption key for MFA secrets
# If not set, derives key from SECRET_KEY
MFA_ENCRYPTION_KEY=your-32-byte-base64-key
```

### Generating a Secure Encryption Key

```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())  # Use this as MFA_ENCRYPTION_KEY
```

## Installation

### 1. Install Dependencies

```bash
pip install pyotp qrcode[pil]
```

### 2. Run Database Migration

```bash
python scripts/migrate_mfa.py
```

Or use the convenience script:

```bash
./scripts/update_database.sh
```

### 3. Restart the Auth Server

```bash
./scripts/deploy_production.sh
```

## Testing MFA

### Manual Testing Steps

1. **Setup Test**
   - Create a test user account
   - Enable MFA from profile
   - Scan QR code with authenticator app
   - Save backup codes
   - Verify with 6-digit code

2. **Login Test**
   - Log out
   - Log in with username/password
   - Should redirect to MFA verification
   - Enter code from app
   - Should successfully log in

3. **Backup Code Test**
   - Log out
   - Log in with username/password
   - Click "Use a backup code"
   - Enter one of the saved backup codes
   - Should successfully log in
   - Verify code is marked as used

4. **Trusted Device Test**
   - Log out
   - Log in and check "Trust this device"
   - Complete MFA verification
   - Log out and log in again
   - Should NOT be asked for MFA code

5. **Disable MFA Test**
   - Navigate to MFA management
   - Click "Disable MFA"
   - Enter password
   - MFA should be disabled
   - Log out and log in with just password

## Security Considerations

### Encryption
- TOTP secrets are encrypted using Fernet (AES-128 in CBC mode with HMAC)
- Encryption key is derived from `SECRET_KEY` or `MFA_ENCRYPTION_KEY`
- **Important**: Use a strong, unique `SECRET_KEY` in production

### Hashing
- Backup codes are hashed using `pbkdf2:sha256` with salt
- Same security level as password hashing

### Device Trust
- Device fingerprinting uses: User-Agent, Accept headers, IP subnet
- Fingerprints are SHA-256 hashed for consistency
- Trust expires after 30 days
- Users can revoke trust at any time

### Audit Logging
All MFA events are logged:
- MFA enabled/disabled
- Verification successes/failures
- Device trusted/revoked
- Backup codes regenerated

## Troubleshooting

### "Invalid verification code"
- Ensure device time is synchronized (TOTP depends on accurate time)
- Try the next code if the current one expired
- Check if caps lock is on
- Verify you're using the correct account in your authenticator app

### "No backup codes remaining"
- Regenerate codes from MFA management page
- Requires password verification
- Old codes are immediately invalidated

### Lost Access to Authenticator
1. Use a backup code to log in
2. Navigate to MFA management
3. Disable MFA (requires password)
4. Re-enable MFA with a new QR code

### Migration Failed
- Ensure database file exists and is writable
- Check that SQLite is being used (PostgreSQL/MySQL not yet supported)
- Review migration script output for specific errors

## Future Enhancements

Potential improvements for future versions:
- SMS-based MFA option
- Email-based MFA option
- Hardware security key support (WebAuthn/FIDO2 for second factor)
- Risk-based authentication (skip MFA for low-risk logins)
- Admin ability to enforce MFA for all users
- Recovery via admin or support contact

## API Reference

### Python Functions (`mfa_utils.py`)

```python
# Setup
create_mfa_for_user(user, secret=None) -> (secret, qr_code, backup_codes)
enable_mfa_for_user(user) -> bool
disable_mfa_for_user(user) -> bool

# Verification
verify_mfa_code(user, code) -> bool
verify_totp(secret, code, window=1) -> bool
verify_backup_code(user, code) -> bool

# Device Trust
trust_device(user, fingerprint, name, ip, user_agent, days=30) -> MFATrustedDevice
is_device_trusted(user, fingerprint) -> bool
revoke_trusted_device(user, device_id) -> bool
get_trusted_devices(user) -> list[MFATrustedDevice]

# Backup Codes
generate_backup_codes(count=10) -> list[str]
regenerate_backup_codes(user) -> list[str]

# Encryption
encrypt_secret(secret) -> str
decrypt_secret(encrypted_secret) -> str
```


## License

Part of the KeyN authentication system.
Copyright © 2025 byNolo
