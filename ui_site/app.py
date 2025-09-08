import time
import os
import requests
from urllib.parse import urlencode
from flask import Flask, render_template, session, redirect, request, jsonify

"""UI / Marketing site for KeyN.

Enhancements:
 - Dynamic auth state (login/logout) leveraging KeyN auth server cookies or issued token
 - Account page with quick links to core auth server features
 - Reusable base template with navigation + theme toggle
"""

app = Flask(__name__)
app.secret_key = os.environ.get('KEYN_UI_SECRET_KEY', 'keyn-ui-dev-secret')

# External service configuration
AUTH_SERVER_URL = os.environ.get('KEYN_AUTH_SERVER_URL', 'https://auth-keyn.bynolo.ca')
UI_SITE_URL = os.environ.get('KEYN_UI_SITE_URL', 'https://keyn.bynolo.ca')

# Configure cache busting with automatic versioning
app.config['CACHE_VERSION'] = str(int(time.time()))

@app.context_processor
def inject_cache_version():
    return dict(cache_version=app.config['CACHE_VERSION'])

def _validate_with_auth_server():
    """Attempt to validate current user using session token, stored token or shared cookies.
    Returns dict with minimal user info or None.
    """
    # Already cached
    if session.get('keyn_authenticated') and session.get('keyn_user_id'):
        return {
            'user_id': session.get('keyn_user_id'),
            'username': session.get('keyn_username'),
            'access_token': session.get('keyn_access_token')
        }

    # Try token first
    token = session.get('keyn_access_token')
    if token:
        try:
            r = requests.get(f'{AUTH_SERVER_URL}/api/user', headers={'Authorization': f'Bearer {token}'}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                session['keyn_authenticated'] = True
                session['keyn_user_id'] = data.get('user_id')
                session['keyn_username'] = data.get('username')
                return {**data, 'access_token': token}
        except requests.RequestException:
            pass

    # Try shared cookies (works when on same parent domain)
    try:
        r = requests.get(f'{AUTH_SERVER_URL}/api/user', cookies=request.cookies, timeout=5)
        if r.status_code == 200:
            data = r.json()
            session['keyn_authenticated'] = True
            session['keyn_user_id'] = data.get('user_id')
            session['keyn_username'] = data.get('username')
            return data
    except requests.RequestException:
        pass

    return None

@app.context_processor
def inject_user():
    return {
        'keyn_user': _validate_with_auth_server(),
        'current_year': time.strftime('%Y')
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/account')
def account():
    user = _validate_with_auth_server()
    return render_template('account.html')

@app.route('/login')
def login():
    redirect_url = f"{UI_SITE_URL}/auth/callback"
    login_url = f"{AUTH_SERVER_URL}/login?" + urlencode({'redirect': redirect_url})
    return redirect(login_url)

@app.route('/auth/callback')
def auth_callback():
    # Small delay to allow cookie propagation (mirrors demo_client approach)
    try:
        import time as _t
        _t.sleep(0.3)
        r = requests.get(f'{AUTH_SERVER_URL}/api/user', cookies=request.cookies, timeout=8)
        if r.status_code == 200:
            data = r.json()
            session['keyn_authenticated'] = True
            session['keyn_user_id'] = data.get('user_id')
            session['keyn_username'] = data.get('username')
            # Attempt to mint cross-domain short-lived token
            try:
                token_resp = requests.post(f'{AUTH_SERVER_URL}/api/cross-domain-auth', json={'client_domain': UI_SITE_URL}, cookies=request.cookies, timeout=8)
                if token_resp.status_code == 200:
                    token_data = token_resp.json()
                    session['keyn_access_token'] = token_data.get('access_token')
            except requests.RequestException:
                pass
    except requests.RequestException:
        pass
    return redirect('/account')

@app.route('/logout')
def logout():
    session.clear()
    redirect_url = f'{UI_SITE_URL}/'
    logout_url = f'{AUTH_SERVER_URL}/logout?' + urlencode({'redirect': redirect_url})
    return redirect(logout_url)

@app.route('/api/status')
def api_status():
    user = _validate_with_auth_server()
    return jsonify({'authenticated': bool(user), 'user': user})

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=6001)
