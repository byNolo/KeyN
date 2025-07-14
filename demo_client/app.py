from flask import Flask, session, request, redirect, jsonify, render_template_string
import requests
import os
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'demo-client-secret'

# Configuration
AUTH_SERVER_URL = 'https://auth-keyn.nolanbc.ca'  # KeyN auth server (via Cloudflare Tunnel)
CLIENT_URL = 'https://demo-keyn.nolanbc.ca'  # This demo client (via Cloudflare Tunnel)

def check_auth():
    """Check if user is authenticated via KeyN"""
    # Check if we have authentication flag in session
    if session.get('keyn_authenticated'):
        return {'user_id': session.get('keyn_user_id'), 'valid': True}
    
    # Try to validate with KeyN using shared cookies
    try:
        response = requests.get(f'{AUTH_SERVER_URL}/api/user', 
                              cookies=request.cookies,
                              timeout=5)
        if response.status_code == 200:
            user_data = response.json()
            # Store in session for future requests
            session['keyn_authenticated'] = True
            session['keyn_user_id'] = user_data['user_id']
            session['keyn_username'] = user_data['username']
            return {'user_id': user_data['user_id'], 'valid': True}
    except requests.RequestException as e:
        print(f"Auth check error: {e}")
    
    return None

def get_user_info():
    """Get user info from session or KeyN auth server"""
    # First try from our session
    if session.get('keyn_username'):
        return {
            'user_id': session.get('keyn_user_id'),
            'username': session.get('keyn_username')
        }
    
    # Try to get from KeyN
    try:
        response = requests.get(f'{AUTH_SERVER_URL}/api/user',
                              cookies=request.cookies,
                              timeout=5)
        if response.status_code == 200:
            user_data = response.json()
            # Cache in session
            session['keyn_user_id'] = user_data['user_id']
            session['keyn_username'] = user_data['username']
            return user_data
    except requests.RequestException as e:
        print(f"Get user info error: {e}")
    return None

@app.route('/')
def home():
    auth_info = check_auth()
    user_info = get_user_info() if auth_info else None
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Demo Client App - KeyN SSO</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .auth-status { padding: 20px; border-radius: 5px; margin: 20px 0; }
            .authenticated { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
            .not-authenticated { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
            .btn { padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }
            .btn:hover { background: #0056b3; }
            pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>🎮 Demo Client App</h1>
        <p>This is a demo application that integrates with the KeyN authentication system.</p>
        
        {% if auth_info %}
            <div class="auth-status authenticated">
                <h3>✅ Authenticated via KeyN!</h3>
                <p><strong>User ID:</strong> {{ auth_info.user_id }}</p>
                {% if user_info %}
                    <p><strong>Username:</strong> {{ user_info.username }}</p>
                {% endif %}
                <p><strong>Token Status:</strong> Valid</p>
                <a href="/logout" class="btn">Logout</a>
                <a href="/protected" class="btn">Access Protected Content</a>
            </div>
        {% else %}
            <div class="auth-status not-authenticated">
                <h3>❌ Not Authenticated</h3>
                <p>You need to log in through KeyN to access this app.</p>
                <a href="/login" class="btn">Login with KeyN</a>
            </div>
        {% endif %}
        
        <h3>🔗 SSO Integration Demo</h3>
        <p>This demonstrates how your apps (Vinyl Vote, SideQuest, etc.) would integrate with KeyN:</p>
        <ul>
            <li>User visits this app</li>
            <li>App checks for valid KeyN session/token</li>
            <li>If not authenticated → redirect to KeyN login</li>
            <li>After KeyN login → redirect back with authentication</li>
            <li>App validates token with KeyN API</li>
        </ul>
        
        {% if auth_info %}
        <h3>🔍 Debug Info</h3>
        <p>Current authentication data:</p>
        <pre>{{ auth_info | tojson(indent=2) }}</pre>
        {% if user_info %}
        <p>User information:</p>
        <pre>{{ user_info | tojson(indent=2) }}</pre>
        {% endif %}
        {% endif %}
    </body>
    </html>
    '''
    
    return render_template_string(template, auth_info=auth_info, user_info=user_info)

@app.route('/login')
def login():
    """Redirect to KeyN auth server for login"""
    error = request.args.get('error')
    if error:
        return f"<h1>Login Error</h1><p>Error: {error}</p><a href='/'>Try Again</a>"
    
    redirect_url = f'{CLIENT_URL}/auth/callback'
    login_url = f'{AUTH_SERVER_URL}/login?' + urlencode({'redirect': redirect_url})
    return redirect(login_url)

@app.route('/auth/callback')
def auth_callback():
    """Handle return from KeyN auth server"""
    # Try to get user info from KeyN using shared session cookies
    try:
        # Check if we have a valid session by calling the user endpoint
        response = requests.get(f'{AUTH_SERVER_URL}/api/user', 
                              cookies=request.cookies,
                              timeout=5)
        if response.status_code == 200:
            user_data = response.json()
            # Store user info in our session
            session['keyn_user_id'] = user_data['user_id']
            session['keyn_username'] = user_data['username']
            
            # Try to get the access token from KeyN's session
            token_response = requests.get(f'{AUTH_SERVER_URL}/api/validate-token',
                                        cookies=request.cookies,
                                        timeout=5)
            if token_response.status_code == 200:
                # Store a flag that we're authenticated
                session['keyn_authenticated'] = True
                
            return redirect('/')
    except requests.RequestException as e:
        print(f"Auth callback error: {e}")
    
    # If authentication failed, redirect back to login
    return redirect('/login?error=auth_failed')

@app.route('/logout')
def logout():
    """Logout from KeyN and clear local session"""
    session.clear()
    # Redirect to KeyN logout
    logout_url = f'{AUTH_SERVER_URL}/logout'
    return redirect(logout_url)

@app.route('/protected')
def protected():
    """Protected route that requires authentication"""
    auth_info = check_auth()
    if not auth_info:
        return redirect('/login')
    
    user_info = get_user_info()
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Protected Content - Demo Client</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .success { background-color: #d4edda; padding: 20px; border-radius: 5px; margin: 20px 0; color: #155724; }
            .btn { padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>🔒 Protected Content</h1>
        <div class="success">
            <h3>✅ Access Granted!</h3>
            <p>You successfully accessed protected content through KeyN authentication.</p>
            {% if user_info %}
                <p>Welcome, <strong>{{ user_info.username }}</strong>!</p>
            {% endif %}
        </div>
        
        <p>This demonstrates how protected routes in your apps would work with KeyN SSO.</p>
        
        <a href="/" class="btn">← Back to Home</a>
        <a href="/logout" class="btn">Logout</a>
    </body>
    </html>
    '''
    
    return render_template_string(template, user_info=user_info)

@app.route('/api/status')
def api_status():
    """API endpoint to check authentication status"""
    auth_info = check_auth()
    return jsonify({
        'authenticated': bool(auth_info),
        'auth_info': auth_info,
        'user_info': get_user_info() if auth_info else None
    })

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=6002)
