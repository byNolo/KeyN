from flask import Flask, session, request, redirect, jsonify, render_template_string, url_for
import requests
import os
import secrets
from urllib.parse import urlencode, parse_qs
from dotenv import load_dotenv

# Load environment variables from parent directory
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

app = Flask(__name__)
app.secret_key = os.environ.get('DEMO_CLIENT_SECRET_KEY', 'demo-client-fallback-secret')

# Configuration - use environment variables for production
AUTH_SERVER_URL = os.environ.get('KEYN_AUTH_SERVER_URL', 'https://auth-keyn.nolanbc.ca')
CLIENT_URL = os.environ.get('KEYN_DEMO_CLIENT_URL', 'https://demo-keyn.nolanbc.ca')

# OAuth client credentials (in production, these would be registered with KeyN)
CLIENT_ID = os.environ.get('KEYN_CLIENT_ID', 'tGlEIvYnAYpsWCYUjb1BH1sJPmzzjBilka03MOAHafI')
CLIENT_SECRET = os.environ.get('KEYN_CLIENT_SECRET', 'JKC-NUxy2wiCJxMf1EupJGP60wqrcA0O5qH-sZut2X_brpjHysRTGyM_7a5qrvtxiOfjCJzAkH61ycGKoQBLLA')
REDIRECT_URI = f"{CLIENT_URL}/oauth/callback"

def is_authenticated():
    """Check if user is authenticated"""
    return session.get('authenticated', False) and session.get('access_token')

def get_user_data():
    """Get user data using stored access token"""
    if not is_authenticated():
        return None
    
    token = session.get('access_token')
    try:
        response = requests.get(
            f'{AUTH_SERVER_URL}/api/user-scoped',
            headers={'Authorization': f'Bearer {token}'},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
        else:
            # Token might be expired, clear session
            session.clear()
            return None
    except requests.RequestException:
        return None

@app.route('/')
def index():
    """Home page"""
    if is_authenticated():
        user_data = get_user_data()
        if user_data:
            return render_template_string(AUTHENTICATED_TEMPLATE, user_data=user_data)
        else:
            # Clear invalid session
            session.clear()
    
    return render_template_string(HOME_TEMPLATE, 
                                auth_server_url=AUTH_SERVER_URL,
                                client_url=CLIENT_URL)

@app.route('/login')
def login():
    """Initiate OAuth login flow"""
    # Generate state parameter for security
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Define scopes we want to request
    scopes = [
        'id', 'username', 'email', 'full_name', 
        'display_name', 'created_at', 'is_verified'
    ]
    
    # Build authorization URL
    auth_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': ','.join(scopes),
        'state': state
    }
    
    auth_url = f"{AUTH_SERVER_URL}/oauth/authorize?{urlencode(auth_params)}"
    return redirect(auth_url)

@app.route('/login/custom')
def login_custom():
    """Login with custom scope selection"""
    return render_template_string(CUSTOM_SCOPE_TEMPLATE)

@app.route('/login/custom-scopes', methods=['POST'])
def login_custom_scopes():
    """Initiate OAuth login with custom scopes"""
    # Get selected scopes from form
    selected_scopes = request.form.getlist('scopes')
    if not selected_scopes:
        return "Please select at least one scope", 400
    
    # Generate state parameter for security
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    auth_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': ','.join(selected_scopes),
        'state': state
    }
    
    auth_url = f"{AUTH_SERVER_URL}/oauth/authorize?{urlencode(auth_params)}"
    return redirect(auth_url)

@app.route('/oauth/callback')
def oauth_callback():
    """Handle OAuth callback"""
    # Check for errors
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        return render_template_string(ERROR_TEMPLATE, 
                                    error=error, 
                                    error_description=error_description)
    
    # Verify state parameter
    state = request.args.get('state')
    if not state or state != session.get('oauth_state'):
        return "Invalid state parameter", 400
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        return "Missing authorization code", 400
    
    # Exchange code for access token
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI
    }
    
    try:
        response = requests.post(
            f'{AUTH_SERVER_URL}/oauth/token',
            data=token_data,
            timeout=10
        )
        
        if response.status_code == 200:
            token_response = response.json()
            
            # Store access token in session
            session['access_token'] = token_response['access_token']
            session['token_type'] = token_response.get('token_type', 'Bearer')
            session['scopes'] = token_response.get('scope', '').split(',')
            session['authenticated'] = True
            
            # Clear OAuth state
            session.pop('oauth_state', None)
            
            return redirect(url_for('index'))
        else:
            error_data = response.json()
            return render_template_string(ERROR_TEMPLATE,
                                        error=error_data.get('error', 'token_exchange_failed'),
                                        error_description=error_data.get('error_description', 'Failed to exchange code for token'))
    
    except requests.RequestException as e:
        return render_template_string(ERROR_TEMPLATE,
                                    error='network_error',
                                    error_description=f'Network error: {str(e)}')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    """Show detailed user profile"""
    if not is_authenticated():
        return redirect(url_for('login'))
    
    user_data = get_user_data()
    if not user_data:
        return redirect(url_for('logout'))
    
    return render_template_string(PROFILE_TEMPLATE, 
                                user_data=user_data,
                                scopes=session.get('scopes', []))

# Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>KeyN OAuth Demo Client</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-shield-alt me-2"></i>
                            KeyN OAuth Demo Client
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-4">
                            <h4>Welcome to the KeyN OAuth Demo</h4>
                            <p class="text-muted">
                                This demo shows how external applications can request specific user data 
                                from KeyN using OAuth-like scoped permissions.
                            </p>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <div class="card h-100">
                                    <div class="card-body text-center">
                                        <i class="fas fa-user-shield fa-3x text-primary mb-3"></i>
                                        <h5>Standard Login</h5>
                                        <p class="text-muted">Login with common permissions (ID, username, email, full name)</p>
                                        <a href="{{ url_for('login') }}" class="btn btn-primary">
                                            <i class="fas fa-sign-in-alt me-2"></i>
                                            Login with KeyN
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6 mb-3">
                                <div class="card h-100">
                                    <div class="card-body text-center">
                                        <i class="fas fa-cogs fa-3x text-success mb-3"></i>
                                        <h5>Custom Scopes</h5>
                                        <p class="text-muted">Choose exactly what information to share</p>
                                        <a href="{{ url_for('login_custom') }}" class="btn btn-success">
                                            <i class="fas fa-sliders-h me-2"></i>
                                            Custom Login
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <h5><i class="fas fa-info-circle me-2"></i>How it works:</h5>
                            <ol>
                                <li>Click a login button to start the OAuth flow</li>
                                <li>You'll be redirected to KeyN to login (if not already logged in)</li>
                                <li>KeyN will show you what information this app is requesting</li>
                                <li>You can approve or deny the request</li>
                                <li>If approved, you'll be redirected back here with access to your data</li>
                            </ol>
                        </div>
                    </div>
                    <div class="card-footer text-center text-muted">
                        <small>
                            Auth Server: <code>{{ auth_server_url }}</code><br>
                            Demo Client: <code>{{ client_url }}</code>
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

CUSTOM_SCOPE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Custom Scopes - KeyN OAuth Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card shadow">
                    <div class="card-header bg-success text-white">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-sliders-h me-2"></i>
                            Choose Data to Share
                        </h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted mb-4">
                            Select which pieces of information you want to allow this demo app to access:
                        </p>
                        
                        <form method="post" action="{{ url_for('login_custom_scopes') }}">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="fas fa-user me-2"></i>Basic Information</h6>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="id" name="scopes" id="scope_id">
                                        <label class="form-check-label" for="scope_id">
                                            <strong>User ID</strong> - Unique identifier
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="username" name="scopes" id="scope_username">
                                        <label class="form-check-label" for="scope_username">
                                            <strong>Username</strong> - Your KeyN username
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="email" name="scopes" id="scope_email">
                                        <label class="form-check-label" for="scope_email">
                                            <strong>Email</strong> - Your email address
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="is_verified" name="scopes" id="scope_verified">
                                        <label class="form-check-label" for="scope_verified">
                                            <strong>Email Verified</strong> - Verification status
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-id-badge me-2"></i>Profile Information</h6>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="full_name" name="scopes" id="scope_full_name">
                                        <label class="form-check-label" for="scope_full_name">
                                            <strong>Full Name</strong> - First and last name
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="display_name" name="scopes" id="scope_display_name">
                                        <label class="form-check-label" for="scope_display_name">
                                            <strong>Display Name</strong> - Preferred display name
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="bio" name="scopes" id="scope_bio">
                                        <label class="form-check-label" for="scope_bio">
                                            <strong>Biography</strong> - Personal bio
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="website" name="scopes" id="scope_website">
                                        <label class="form-check-label" for="scope_website">
                                            <strong>Website</strong> - Personal website URL
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="location" name="scopes" id="scope_location">
                                        <label class="form-check-label" for="scope_location">
                                            <strong>Location</strong> - Your location
                                        </label>
                                    </div>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" value="created_at" name="scopes" id="scope_created">
                                        <label class="form-check-label" for="scope_created">
                                            <strong>Account Created</strong> - Registration date
                                        </label>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mt-4 d-grid gap-2 d-md-flex justify-content-md-end">
                                <a href="{{ url_for('index') }}" class="btn btn-secondary me-md-2">
                                    <i class="fas fa-arrow-left me-2"></i>Back
                                </a>
                                <button type="submit" class="btn btn-success">
                                    <i class="fas fa-sign-in-alt me-2"></i>Login with Selected Scopes
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

AUTHENTICATED_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Authenticated - KeyN OAuth Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-10">
                <div class="card shadow">
                    <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-check-circle me-2"></i>
                            Successfully Authenticated!
                        </h3>
                        <div>
                            <a href="{{ url_for('profile') }}" class="btn btn-light btn-sm me-2">
                                <i class="fas fa-user me-1"></i>Profile
                            </a>
                            <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">
                                <i class="fas fa-sign-out-alt me-1"></i>Logout
                            </a>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-success">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Great!</strong> You have successfully authenticated with KeyN. 
                            The demo app now has access to the data you approved.
                        </div>
                        
                        <h5><i class="fas fa-database me-2"></i>Your Data:</h5>
                        <div class="row">
                            {% for key, value in user_data.items() %}
                            <div class="col-md-6 mb-3">
                                <div class="card">
                                    <div class="card-body">
                                        <h6 class="card-title text-primary">{{ key.replace('_', ' ').title() }}</h6>
                                        <p class="card-text">
                                            {% if value is none %}
                                                <em class="text-muted">Not provided</em>
                                            {% elif value is sameas true %}
                                                <span class="badge bg-success">Yes</span>
                                            {% elif value is sameas false %}
                                                <span class="badge bg-secondary">No</span>
                                            {% else %}
                                                <code>{{ value }}</code>
                                            {% endif %}
                                        </p>
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                        
                        <div class="mt-4">
                            <h6><i class="fas fa-shield-alt me-2"></i>Security Note:</h6>
                            <p class="text-muted">
                                This data was obtained using a secure OAuth-like flow. You can revoke 
                                this app's access at any time from your KeyN account settings.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

PROFILE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Profile - KeyN OAuth Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-10">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-user me-2"></i>
                            User Profile
                        </h3>
                        <div>
                            <a href="{{ url_for('index') }}" class="btn btn-light btn-sm me-2">
                                <i class="fas fa-home me-1"></i>Home
                            </a>
                            <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">
                                <i class="fas fa-sign-out-alt me-1"></i>Logout
                            </a>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-8">
                                <h5><i class="fas fa-id-badge me-2"></i>Profile Information</h5>
                                <table class="table table-striped">
                                    {% for key, value in user_data.items() %}
                                    <tr>
                                        <th scope="row" class="text-primary">{{ key.replace('_', ' ').title() }}</th>
                                        <td>
                                            {% if value is none %}
                                                <em class="text-muted">Not provided</em>
                                            {% elif value is sameas true %}
                                                <span class="badge bg-success">Yes</span>
                                            {% elif value is sameas false %}
                                                <span class="badge bg-secondary">No</span>
                                            {% else %}
                                                {{ value }}
                                            {% endif %}
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </table>
                            </div>
                            <div class="col-md-4">
                                <h5><i class="fas fa-key me-2"></i>Authorized Scopes</h5>
                                <div class="list-group">
                                    {% for scope in scopes %}
                                    <div class="list-group-item">
                                        <i class="fas fa-check text-success me-2"></i>
                                        {{ scope.replace('_', ' ').title() }}
                                    </div>
                                    {% endfor %}
                                </div>
                                
                                <div class="mt-4">
                                    <h6><i class="fas fa-info-circle me-2"></i>About Scopes</h6>
                                    <p class="small text-muted">
                                        Scopes determine what information this app can access. 
                                        You granted permission for these specific data points during login.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

ERROR_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Error - KeyN OAuth Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-header bg-danger text-white">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Authentication Error
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-danger">
                            <h5>{{ error }}</h5>
                            <p class="mb-0">{{ error_description }}</p>
                        </div>
                        
                        <div class="d-grid">
                            <a href="{{ url_for('index') }}" class="btn btn-primary">
                                <i class="fas fa-home me-2"></i>
                                Return to Home
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    # Development mode
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
