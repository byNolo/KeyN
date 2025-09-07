import base64
import os
import datetime
import json
from flask import current_app
from .models import PasskeyCredential, User, db
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    RegistrationCredential,
    AuthenticationCredential,
)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def get_rp_id():
    # Allow override via env for development; fallback to request host can be implemented in routes
    return os.environ.get('WEBAUTHN_RP_ID', 'localhost')


def get_origin():
    return os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:5000')


def start_registration(user: User):
    """Create options for WebAuthn registration using library's current signature."""
    existing_credentials = [b64url_decode(c.credential_id) for c in user.passkeys]
    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name='KeyN',
        user_id=str(user.id).encode('utf-8'),  # must be bytes
        user_name=user.username,
        user_display_name=user.get_full_name(),
        exclude_credentials=existing_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification='preferred'),
        attestation='none'
    )
    return options


def finish_registration(user: User, data: dict, expected_challenge: str):
    # Manual construction of credential object to avoid version incompatibilities
    from flask import current_app
    class _RegResponse:
        def __init__(self, attestation_object, client_data_json, transports):
            self.attestation_object = attestation_object
            self.client_data_json = client_data_json
            self.transports = transports or []
    class _RegCredential:
        def __init__(self, _id, raw_id, response, _type='public-key'):
            self.id = _id
            self.raw_id = raw_id
            self.response = response
            self.type = _type
            self.client_extension_results = {}
            self.authenticator_attachment = None
    try:
        resp = data.get('response', {})
        att_obj = b64url_decode(resp.get('attestationObject')) if resp.get('attestationObject') else b''
        client_data = b64url_decode(resp.get('clientDataJSON')) if resp.get('clientDataJSON') else b''
        raw_id = b64url_decode(data.get('rawId')) if data.get('rawId') else b''
        cred_obj = _RegCredential(
            data.get('id'),
            raw_id,
            _RegResponse(att_obj, client_data, resp.get('transports'))
        )
        # Extract client challenge for debugging/normalization
        try:
            client_data = json.loads(cred_obj.response.client_data_json.decode('utf-8'))
            client_chal = client_data.get('challenge')
        except Exception:
            client_chal = None

        # Normalize expected challenge: store/manage as bytes
        final_expected: bytes
        if isinstance(expected_challenge, bytes):
            final_expected = expected_challenge
        else:
            # Try base64url decode first
            try:
                final_expected = b64url_decode(expected_challenge)
            except Exception:
                # Fallback: treat as latin1-encoded raw bytes
                final_expected = expected_challenge.encode('latin1')

        from flask import current_app
        if current_app.config.get('PASSKEY_DEBUG'):
            current_app.logger.info('[PasskeyDebug] Registration expected_challenge(bytes)=%s (len=%d)',
                                    base64.urlsafe_b64encode(final_expected).decode('utf-8').rstrip('='), len(final_expected))
            current_app.logger.info('[PasskeyDebug] Registration clientData.challenge=%s', client_chal)

        verification = verify_registration_response(
            credential=cred_obj,
            expected_challenge=final_expected,
            expected_rp_id=get_rp_id(),
            expected_origin=get_origin(),
            require_user_verification=True,
        )
    except Exception as e:
        current_app.logger.exception('Passkey registration verification failed')
        if current_app.config.get('PASSKEY_DEBUG'):
            raise
        raise ValueError('Passkey registration failed') from e
    cred = PasskeyCredential(
        user_id=user.id,
        credential_id=b64url_encode(verification.credential_id),
        public_key=b64url_encode(verification.credential_public_key),
        sign_count=verification.sign_count,
        transports=','.join(cred_obj.response.transports) if getattr(cred_obj.response, 'transports', None) else None,
        created_at=datetime.datetime.utcnow(),
        friendly_name=data.get('friendly_name') or None
    )
    db.session.add(cred)
    db.session.commit()
    return cred


def start_authentication(user: User | None = None):
    """Create authentication (assertion) options.
    If user supplied, restrict to their credentials; else allow discoverable creds."""
    allow_creds = None
    if user:
        allow_creds = [b64url_decode(c.credential_id) for c in user.passkeys]
    options = generate_authentication_options(
        rp_id=get_rp_id(),
        allow_credentials=allow_creds,
        user_verification='preferred'
    )
    return options


def finish_authentication(data: dict, expected_challenge: str, user: User | None = None):
    from flask import current_app
    class _AuthResponse:
        def __init__(self, authenticator_data, client_data_json, signature, user_handle):
            self.authenticator_data = authenticator_data
            self.client_data_json = client_data_json
            self.signature = signature
            self.user_handle = user_handle
    class _AuthCredential:
        def __init__(self, _id, raw_id, response, _type='public-key'):
            self.id = _id
            self.raw_id = raw_id
            self.response = response
            self.type = _type
            self.client_extension_results = {}
            self.authenticator_attachment = None
    try:
        resp = data.get('response', {})
        auth_data = b64url_decode(resp.get('authenticatorData')) if resp.get('authenticatorData') else b''
        client_data = b64url_decode(resp.get('clientDataJSON')) if resp.get('clientDataJSON') else b''
        signature = b64url_decode(resp.get('signature')) if resp.get('signature') else b''
        user_handle = b64url_decode(resp.get('userHandle')) if resp.get('userHandle') else None
        raw_id = b64url_decode(data.get('rawId')) if data.get('rawId') else b''
        cred_obj = _AuthCredential(
            data.get('id'),
            raw_id,
            _AuthResponse(auth_data, client_data, signature, user_handle)
        )
    except Exception as e:
        current_app.logger.exception('Failed to parse passkey authentication data')
        if current_app.config.get('PASSKEY_DEBUG'):
            return None, str(e)
        return None, 'Invalid passkey data'

    # If user passed, find among their creds; else search globally
    if user:
        cred_model = PasskeyCredential.query.filter_by(credential_id=b64url_encode(cred_obj.raw_id)).first()
    else:
        cred_model = PasskeyCredential.query.filter_by(credential_id=b64url_encode(cred_obj.raw_id)).first()

    if not cred_model:
        return None, 'Unknown credential'

    # Normalize challenge similar to registration
    if isinstance(expected_challenge, bytes):
        expected_challenge_bytes = expected_challenge
    else:
        try:
            expected_challenge_bytes = b64url_decode(expected_challenge)
        except Exception:
            expected_challenge_bytes = expected_challenge.encode('latin1')

    from flask import current_app
    if current_app.config.get('PASSKEY_DEBUG'):
        try:
            client_data = json.loads(cred_obj.response.client_data_json.decode('utf-8'))
            current_app.logger.info('[PasskeyDebug] Auth clientData.challenge=%s', client_data.get('challenge'))
        except Exception:
            pass
        current_app.logger.info('[PasskeyDebug] Auth expected_challenge(bytes)=%s (len=%d)',
                                base64.urlsafe_b64encode(expected_challenge_bytes).decode('utf-8').rstrip('='), len(expected_challenge_bytes))
    try:
        verification = verify_authentication_response(
            credential=cred_obj,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=get_rp_id(),
            expected_origin=get_origin(),
            credential_public_key=b64url_decode(cred_model.public_key),
            credential_current_sign_count=cred_model.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        current_app.logger.exception('Passkey authentication verification failed')
        if current_app.config.get('PASSKEY_DEBUG'):
            return None, str(e)
        return None, 'Passkey authentication failed'

    # Update sign count and last_used
    cred_model.sign_count = verification.new_sign_count
    cred_model.last_used = datetime.datetime.utcnow()
    db.session.commit()

    return cred_model, None


# -------- Serialization helpers (browser-facing) --------
def serialize_registration_options(options):
    """Convert library registration options to browser-friendly JSON structure."""
    pub_key_params = []
    for p in getattr(options, 'pub_key_cred_params', []) or []:
        # p may be a dataclass or simple object with type/alg
        alg = getattr(p, 'alg', None)
        typ = getattr(p, 'type', 'public-key')
        pub_key_params.append({'type': typ, 'alg': alg})

    exclude_list = []
    for c in getattr(options, 'exclude_credentials', []) or []:
        cid = getattr(c, 'id', c if isinstance(c, (bytes, bytearray)) else None)
        if isinstance(cid, (bytes, bytearray)):
            exclude_list.append({'type': 'public-key', 'id': b64url_encode(cid)})

    user = getattr(options, 'user', None)
    rp = getattr(options, 'rp', None)
    user_id_bytes = getattr(user, 'id', b'') if user else b''

    result = {
        'publicKey': {
            'rp': {
                'name': getattr(rp, 'name', 'KeyN'),
                'id': getattr(rp, 'id', get_rp_id()),
            },
            'user': {
                'id': b64url_encode(user_id_bytes),
                'name': getattr(user, 'name', ''),
                'displayName': getattr(user, 'display_name', getattr(user, 'name', '')),
            },
            'challenge': b64url_encode(getattr(options, 'challenge', b'')),
            'pubKeyCredParams': pub_key_params,
            'timeout': getattr(options, 'timeout', 60000),
            'attestation': getattr(options, 'attestation', 'none'),
        }
    }

    auth_sel = getattr(options, 'authenticator_selection', None)
    if auth_sel:
        result['publicKey']['authenticatorSelection'] = {
            'userVerification': getattr(auth_sel, 'user_verification', None)
        }
    if exclude_list:
        result['publicKey']['excludeCredentials'] = exclude_list
    return result


def serialize_authentication_options(options):
    """Convert library authentication options to browser-friendly JSON structure."""
    allow_list = []
    for c in getattr(options, 'allow_credentials', []) or []:
        cid = getattr(c, 'id', c if isinstance(c, (bytes, bytearray)) else None)
        if isinstance(cid, (bytes, bytearray)):
            allow_list.append({'type': 'public-key', 'id': b64url_encode(cid)})

    result = {
        'publicKey': {
            'challenge': b64url_encode(getattr(options, 'challenge', b'')),
            'timeout': getattr(options, 'timeout', 60000),
            'userVerification': getattr(options, 'user_verification', 'preferred'),
        }
    }
    rp_id = getattr(options, 'rp_id', None)
    if rp_id:
        result['publicKey']['rpId'] = rp_id
    if allow_list:
        result['publicKey']['allowCredentials'] = allow_list
    return result
