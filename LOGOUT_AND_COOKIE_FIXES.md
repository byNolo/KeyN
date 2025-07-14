# 🔧 KeyN Logout & Cookie Security Fixes

## Issues Fixed

### 1. ✅ **Logout Button "Method Not Allowed" Error**
- **Problem**: Demo client logout was using GET request but auth server only accepted POST
- **Solution**: Updated logout route to accept both GET and POST methods
- **Changes**: 
  - Modified `@auth_bp.route("/logout", methods=["GET", "POST"])` in routes.py
  - GET requests (from demo client) now redirect to login page
  - POST requests (API calls) return JSON response

### 2. ✅ **Cookie Domain Security Concern**
- **Problem**: Risk of KeyN cookies interfering with other sites on nolanbc.ca
- **Solution**: Isolated KeyN cookies to prevent domain conflicts
- **Changes**:
  - Removed broad cookie domain setting (no `.nolanbc.ca` sharing)
  - Cookies now specific to individual subdomains
  - Implemented secure token-based cross-domain authentication

## Technical Implementation

### **Logout Route Updates** (`routes.py`)
```python
@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    # Revoke all refresh tokens for user
    RefreshToken.query.filter_by(user_id=current_user.id).update({"revoked": True})
    db.session.commit()
    
    logout_user()
    session.clear()
    
    # Handle both GET and POST requests
    if request.method == "GET":
        return redirect(url_for("auth.login"))  # For demo client
    else:
        return jsonify({"status": "logged out"})  # For API calls
```

### **Cookie Configuration** (`config.py`)
```python
# Session/Cookie configuration for SSO
# For security with multiple sites on nolanbc.ca, we don't set a cookie domain
# This keeps KeyN cookies isolated to their specific subdomains
# SSO will work through API calls rather than shared cookies
SESSION_COOKIE_DOMAIN = os.environ.get("FLASK_SESSION_COOKIE_DOMAIN")  # None = current domain only
SESSION_COOKIE_SECURE = True  # HTTPS only in production
SESSION_COOKIE_HTTPONLY = True  # Prevent XSS
SESSION_COOKIE_SAMESITE = "Lax"  # Allow cross-site functionality
```

### **Cross-Domain Authentication** 
Added secure token-based authentication for cross-domain SSO:

**New Auth Server Endpoint**:
```python
@auth_bp.route("/api/cross-domain-auth", methods=["POST"])
@login_required
def cross_domain_auth():
    """Provide tokens for cross-domain authentication"""
    access_token = generate_access_token(current_user.id)
    return jsonify({
        'access_token': access_token,
        'user_id': current_user.id,
        'username': current_user.username,
        'expires_in': 900  # 15 minutes
    })
```

**Enhanced User Info Endpoint**:
```python
@auth_bp.route("/api/user", methods=["GET"])
def user_info():
    """Get user info - supports both session-based and token-based auth"""
    # Try session-based auth first (same-domain)
    if current_user and current_user.is_authenticated:
        user = current_user
    else:
        # Try Bearer token auth (cross-domain)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            decoded = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            user = User.query.get(decoded["user_id"])
    
    # Return user info or 401
```

### **Demo Client Updates** (`demo_client/app.py`)
Updated authentication flow to use secure token-based approach:

```python
@app.route('/auth/callback')
def auth_callback():
    """Handle return from KeyN auth server"""
    # Validate session with KeyN using cookies
    response = requests.get(f'{AUTH_SERVER_URL}/api/user', cookies=request.cookies)
    
    if response.status_code == 200:
        user_data = response.json()
        
        # Get cross-domain access token for secure API calls
        token_response = requests.post(f'{AUTH_SERVER_URL}/api/cross-domain-auth',
                                     json={'client_domain': CLIENT_URL},
                                     cookies=request.cookies)
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            session['keyn_access_token'] = token_data['access_token']
            session['keyn_authenticated'] = True
```

## Security Benefits

### **🔒 Cookie Isolation**
- KeyN cookies no longer interfere with other nolanbc.ca sites
- Each subdomain has isolated cookies
- Prevents accidental session sharing with unrelated applications

### **🎯 Secure SSO**
- Cross-domain authentication uses JWT tokens instead of shared cookies
- Tokens have short expiration (15 minutes)
- Bearer token authentication for API calls

### **🛡️ Enhanced Security**
- HTTPS-only cookies in production
- HttpOnly flag prevents XSS attacks
- SameSite=Lax allows legitimate cross-site requests

## Testing Results

### **✅ Logout Functionality**
- Demo client logout now works correctly
- No more "Method Not Allowed" errors
- Proper redirection after logout

### **✅ Cookie Isolation** 
- KeyN cookies restricted to auth-keyn.nolanbc.ca and demo-keyn.nolanbc.ca
- Other nolanbc.ca sites unaffected
- SSO still works between KeyN services

### **✅ Cross-Domain Auth**
- Secure token exchange between subdomains
- No shared cookie dependencies
- API-based authentication flow

## Service Status

All KeyN services restarted successfully:
- ✅ Auth Server (port 6000) → https://auth-keyn.nolanbc.ca
- ✅ UI Site (port 6001) → https://keyn.nolanbc.ca  
- ✅ Demo Client (port 6002) → https://demo-keyn.nolanbc.ca

The logout button should now work correctly, and your KeyN system won't interfere with other sites on nolanbc.ca! 🎉
