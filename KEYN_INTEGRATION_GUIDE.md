# 🔗 KeyN Integration Guide

> **Complete guide for adding KeyN Single Sign-On authentication to your applications**

## 🎯 Overview

This guide shows you how to integrate KeyN Single Sign-On authentication into any web application. KeyN uses a domain-wide `keyn_session` cookie approach that provides seamless SSO across all your `.nolanbc.ca` subdomains while avoiding conflicts with other services.

**Key Features:**
- ✅ **Seamless SSO**: Users login once and access all apps without redirects
- ✅ **Safe Cookie Design**: Uses `keyn_session` name to prevent conflicts
- ✅ **Fallback Support**: API token validation for additional security
- ✅ **Simple Integration**: Just include cookies in requests to KeyN API

---

## 🚀 Quick Integration (5 Minutes)

### 1. **Basic Authentication Check**

Add this to any route that requires authentication:

```python
import requests
from flask import request, redirect, session
from urllib.parse import urlencode

def require_keyn_auth():
    """Check if user is authenticated via KeyN, redirect if not"""
    
    # Check if we already have user in session
    if session.get('keyn_user_id'):
        return {
            'user_id': session.get('keyn_user_id'),
            'username': session.get('keyn_username')
        }
    
    # Try to authenticate with KeyN using cookies
    try:
        response = requests.get(
            'https://auth-keyn.nolanbc.ca/api/user',
            cookies=request.cookies,
            timeout=5
        )
        
        if response.status_code == 200:
            user_data = response.json()
            # Store in session for future requests
            session['keyn_user_id'] = user_data['user_id']
            session['keyn_username'] = user_data['username']
            return user_data
            
    except requests.RequestException:
        pass
    
    # Not authenticated - redirect to KeyN login
    return_url = request.url
    login_url = 'https://auth-keyn.nolanbc.ca/login?' + urlencode({
        'redirect': return_url
    })
    
    return redirect(login_url)

# Usage in your routes:
@app.route('/protected-page')
def protected_page():
    user = require_keyn_auth()
    if hasattr(user, 'location'):  # It's a redirect
        return user
    
    # User is authenticated
    return f"Hello {user['username']}! Your ID is {user['user_id']}"
```

### 2. **Add Logout Support**

```python
@app.route('/logout')
def logout():
    """Logout from current app and KeyN"""
    
    # Clear local session
    session.clear()
    
    # Redirect to KeyN logout (will logout from all apps)
    return redirect('https://auth-keyn.nolanbc.ca/logout')
```

That's it! Your app now has KeyN authentication. 🎉

---

## 🏗️ Complete Integration Class

For production use, here's a complete KeyN integration class:

```python
import requests
import logging
from flask import request, redirect, session, current_app
from urllib.parse import urlencode
from functools import wraps

class KeyNAuth:
    """Complete KeyN authentication integration"""
    
    def __init__(self, auth_server_url='https://auth-keyn.nolanbc.ca'):
        self.auth_server = auth_server_url
        self.logger = logging.getLogger('keyn_auth')
        
    def check_authentication(self, return_url=None):
        """
        Check if user is authenticated
        Returns: user_data dict if authenticated, redirect response if not
        """
        if return_url is None:
            return_url = request.url
            
        # Check session first (fastest)
        if session.get('keyn_user_id') and session.get('keyn_username'):
            return {
                'user_id': session.get('keyn_user_id'),
                'username': session.get('keyn_username'),
                'from_session': True
            }
        
        # Try cookie-based authentication
        try:
            response = requests.get(
                f'{self.auth_server}/api/user',
                cookies=request.cookies,
                timeout=10,
                headers={'User-Agent': request.headers.get('User-Agent', '')}
            )
            
            if response.status_code == 200:
                user_data = response.json()
                
                # Store in session for future requests
                session['keyn_user_id'] = user_data['user_id']
                session['keyn_username'] = user_data['username']
                session['keyn_authenticated'] = True
                
                self.logger.info(f"User {user_data['username']} authenticated via cookies")
                
                return {
                    'user_id': user_data['user_id'],
                    'username': user_data['username'],
                    'from_keyn': True
                }
                
        except requests.RequestException as e:
            self.logger.warning(f"KeyN authentication check failed: {e}")
        
        # Not authenticated - redirect to KeyN
        login_url = f"{self.auth_server}/login?" + urlencode({
            'redirect': return_url
        })
        
        return redirect(login_url)
    
    def get_current_user(self):
        """Get current authenticated user or None"""
        if session.get('keyn_authenticated'):
            return {
                'user_id': session.get('keyn_user_id'),
                'username': session.get('keyn_username')
            }
        return None
    
    def logout_user(self):
        """Logout user from local session and redirect to KeyN logout"""
        # Clear local session
        for key in ['keyn_user_id', 'keyn_username', 'keyn_authenticated']:
            session.pop(key, None)
        
        # Redirect to KeyN logout (clears SSO session)
        return redirect(f'{self.auth_server}/logout')
    
    def validate_token(self, token):
        """Validate a KeyN access token (for API endpoints)"""
        try:
            response = requests.get(
                f'{self.auth_server}/api/validate-token',
                params={'token': token},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return data if data.get('valid') else None
                
        except requests.RequestException as e:
            self.logger.warning(f"Token validation failed: {e}")
        
        return None
    
    def require_auth(self, f):
        """Decorator to require authentication for a route"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = self.check_authentication()
            if hasattr(user, 'location'):  # It's a redirect
                return user
            
            # Add user to request context
            request.keyn_user = user
            return f(*args, **kwargs)
        
        return decorated_function

# Initialize globally
keyn = KeyNAuth()

# Usage examples:
@app.route('/dashboard')
@keyn.require_auth
def dashboard():
    user = request.keyn_user
    return f"Welcome to your dashboard, {user['username']}!"

@app.route('/profile')
def profile():
    user = keyn.check_authentication()
    if hasattr(user, 'location'):
        return user
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    return keyn.logout_user()
```

---

## 🔧 Framework-Specific Examples

### **Flask Integration**

```python
from flask import Flask, request, session, redirect
import requests

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Copy the KeyNAuth class from above

keyn = KeyNAuth()

@app.route('/')
def home():
    user = keyn.get_current_user()
    if user:
        return f"Welcome back, {user['username']}! <a href='/logout'>Logout</a>"
    else:
        return '<a href="/login">Login with KeyN</a>'

@app.route('/login')
def login():
    return keyn.check_authentication('/')

@app.route('/protected')
@keyn.require_auth
def protected():
    return f"Secret page for {request.keyn_user['username']}"
```

### **Django Integration**

```python
# views.py
import requests
from django.shortcuts import redirect
from django.http import JsonResponse
from django.contrib.sessions.models import Session
from urllib.parse import urlencode

class KeyNMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth_server = 'https://auth-keyn.nolanbc.ca'

    def __call__(self, request):
        # Check KeyN authentication
        if not request.session.get('keyn_user_id'):
            self.check_keyn_auth(request)
        
        response = self.get_response(request)
        return response
    
    def check_keyn_auth(self, request):
        try:
            cookies = request.COOKIES
            response = requests.get(
                f'{self.auth_server}/api/user',
                cookies=cookies,
                timeout=5
            )
            
            if response.status_code == 200:
                user_data = response.json()
                request.session['keyn_user_id'] = user_data['user_id']
                request.session['keyn_username'] = user_data['username']
                
        except requests.RequestException:
            pass

def require_keyn_auth(view_func):
    """Decorator for Django views"""
    def wrapper(request, *args, **kwargs):
        if not request.session.get('keyn_user_id'):
            login_url = f"https://auth-keyn.nolanbc.ca/login?" + urlencode({
                'redirect': request.build_absolute_uri()
            })
            return redirect(login_url)
        
        return view_func(request, *args, **kwargs)
    
    return wrapper

# Usage:
@require_keyn_auth
def protected_view(request):
    username = request.session.get('keyn_username')
    return JsonResponse({'message': f'Hello {username}'})
```

### **Node.js/Express Integration**

```javascript
const express = require('express');
const session = require('express-session');
const axios = require('axios');

const app = express();

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

const KEYN_AUTH_SERVER = 'https://auth-keyn.nolanbc.ca';

// KeyN authentication middleware
async function checkKeyNAuth(req, res, next) {
    // Check session first
    if (req.session.keyn_user_id) {
        req.user = {
            user_id: req.session.keyn_user_id,
            username: req.session.keyn_username
        };
        return next();
    }
    
    // Try cookie authentication
    try {
        const response = await axios.get(`${KEYN_AUTH_SERVER}/api/user`, {
            headers: { Cookie: req.headers.cookie || '' },
            timeout: 5000
        });
        
        if (response.status === 200) {
            const userData = response.data;
            req.session.keyn_user_id = userData.user_id;
            req.session.keyn_username = userData.username;
            req.user = userData;
            return next();
        }
    } catch (error) {
        console.log('KeyN auth check failed:', error.message);
    }
    
    // Not authenticated
    const returnUrl = encodeURIComponent(req.originalUrl);
    const loginUrl = `${KEYN_AUTH_SERVER}/login?redirect=${returnUrl}`;
    res.redirect(loginUrl);
}

// Usage
app.get('/', (req, res) => {
    if (req.session.keyn_user_id) {
        res.send(`Welcome back, ${req.session.keyn_username}!`);
    } else {
        res.send('<a href="/login">Login with KeyN</a>');
    }
});

app.get('/login', checkKeyNAuth, (req, res) => {
    res.redirect('/');
});

app.get('/protected', checkKeyNAuth, (req, res) => {
    res.json({ message: `Hello ${req.user.username}` });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect(`${KEYN_AUTH_SERVER}/logout`);
});
```

---

## 🔐 API Authentication

For API endpoints, use token-based authentication:

```python
def require_api_auth(f):
    """Decorator for API endpoints requiring KeyN authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for Bearer token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Validate token with KeyN
        try:
            response = requests.get(
                'https://auth-keyn.nolanbc.ca/api/validate-token',
                params={'token': token},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('valid'):
                    request.keyn_user = {'user_id': data['user_id']}
                    return f(*args, **kwargs)
                    
        except requests.RequestException:
            pass
        
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    return decorated_function

# Usage:
@app.route('/api/data')
@require_api_auth
def api_data():
    return jsonify({
        'data': 'Secret API data',
        'user_id': request.keyn_user['user_id']
    })
```

---

## 🌐 Frontend JavaScript Integration

For single-page applications:

```javascript
class KeyNAuth {
    constructor() {
        this.authServer = 'https://auth-keyn.nolanbc.ca';
        this.currentUser = null;
    }
    
    async checkAuth() {
        try {
            const response = await fetch(`${this.authServer}/api/user`, {
                credentials: 'include'  // Include cookies
            });
            
            if (response.ok) {
                this.currentUser = await response.json();
                return this.currentUser;
            }
        } catch (error) {
            console.log('Auth check failed:', error);
        }
        
        this.currentUser = null;
        return null;
    }
    
    login() {
        const returnUrl = encodeURIComponent(window.location.href);
        window.location.href = `${this.authServer}/login?redirect=${returnUrl}`;
    }
    
    logout() {
        window.location.href = `${this.authServer}/logout`;
    }
    
    async makeAuthenticatedRequest(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            credentials: 'include'
        });
        
        if (response.status === 401) {
            this.login();
            return;
        }
        
        return response;
    }
}

// Usage:
const keyn = new KeyNAuth();

// Check authentication on page load
keyn.checkAuth().then(user => {
    if (user) {
        document.getElementById('username').textContent = user.username;
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('user-section').style.display = 'block';
    }
});

// Login button
document.getElementById('login-btn').onclick = () => keyn.login();

// Logout button  
document.getElementById('logout-btn').onclick = () => keyn.logout();

// Make authenticated API calls
keyn.makeAuthenticatedRequest('/api/user-data')
    .then(response => response.json())
    .then(data => console.log(data));
```

---

## ⚙️ Configuration

### **Environment Variables**

Add these to your application's environment:

```bash
# KeyN Configuration
KEYN_AUTH_SERVER=https://auth-keyn.nolanbc.ca
KEYN_ENABLED=true
KEYN_TIMEOUT=10  # seconds

# For development:
# KEYN_AUTH_SERVER=http://localhost:6000
```

### **CORS Configuration**

Make sure your domain is added to KeyN's CORS settings:

1. Add your domain to KeyN's `.env` file:
   ```bash
   FLASK_ALLOWED_ORIGINS=https://yourapp.com,https://anotherapp.com
   ```

2. Restart KeyN auth server:
   ```bash
   ./scripts/deploy_production.sh
   ```

---

## 🧪 Testing Your Integration

### **1. Basic Flow Test**

```bash
# Test the full authentication flow:
1. Visit your app's protected page
2. Should redirect to KeyN login
3. Login/register with KeyN
4. Should redirect back to your app, authenticated
5. Verify user data is available
```

### **2. Session Persistence Test**

```bash
# Test SSO between apps:
1. Login to your first app
2. Visit your second app (without logging in again)
3. Should be automatically authenticated
4. Logout from one app
5. Should be logged out of both apps
```

### **3. API Authentication Test**

```bash
# Test API token authentication:
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://yourapp.com/api/protected
```

---

## 🚨 Error Handling

### **Common Issues & Solutions**

1. **CORS Errors**
   ```python
   # Solution: Add your domain to KeyN CORS config
   FLASK_ALLOWED_ORIGINS=https://yourapp.com
   ```

2. **Cookie Not Working**
   ```python
   # Check domain settings - cookies work on same domain/subdomain
   # For cross-domain, use token-based auth
   ```

3. **Timeout Errors**
   ```python
   # Increase timeout and add retry logic:
   try:
       response = requests.get(url, timeout=10)
   except requests.Timeout:
       # Fallback or retry logic
   ```

### **Robust Error Handling Example**

```python
def safe_keyn_auth_check():
    """Robust authentication check with error handling"""
    try:
        response = requests.get(
            'https://auth-keyn.nolanbc.ca/api/user',
            cookies=request.cookies,
            timeout=5
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            # User not authenticated
            return None
        else:
            # KeyN server error
            app.logger.warning(f"KeyN returned {response.status_code}")
            return None
            
    except requests.ConnectionError:
        app.logger.error("Cannot connect to KeyN auth server")
        # Could show maintenance page or allow local auth
        return None
    except requests.Timeout:
        app.logger.warning("KeyN auth server timeout")
        return None
    except Exception as e:
        app.logger.error(f"KeyN auth error: {e}")
        return None
```

---

## 📊 Monitoring & Logging

### **Add Integration Logging**

```python
import logging

# Set up KeyN integration logging
keyn_logger = logging.getLogger('keyn_integration')
handler = logging.FileHandler('keyn_integration.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
keyn_logger.addHandler(handler)
keyn_logger.setLevel(logging.INFO)

# Log authentication events
def log_auth_event(event_type, user_id=None, details=None):
    keyn_logger.info(f"{event_type} - User: {user_id} - {details}")

# Usage:
log_auth_event("LOGIN_SUCCESS", user_data['user_id'], f"IP: {request.remote_addr}")
log_auth_event("AUTH_CHECK_FAILED", None, "KeyN server timeout")
```

---

## 🎯 Production Checklist

Before deploying your KeyN-integrated app:

- [ ] **Test full authentication flow**
- [ ] **Verify CORS configuration**
- [ ] **Add error handling for KeyN outages**
- [ ] **Set up logging for auth events**
- [ ] **Test logout functionality**
- [ ] **Verify session persistence across apps**
- [ ] **Add health checks for KeyN connectivity**
- [ ] **Document KeyN dependency for your team**

---

## 💡 Best Practices

1. **Cache User Data**: Store user info in session to reduce KeyN API calls
2. **Handle Failures Gracefully**: Don't break your app if KeyN is down
3. **Use HTTPS**: Required for cross-domain cookie authentication
4. **Monitor Integration**: Log auth events and monitor KeyN connectivity
5. **Test Regularly**: Ensure integration works after KeyN updates

---

## 🆘 Support

If you run into issues:

1. **Check KeyN Health**: Visit `https://auth-keyn.nolanbc.ca/health`
2. **Review Logs**: Check your integration logs and KeyN logs
3. **Test Manually**: Try the authentication flow manually
4. **CORS Issues**: Verify your domain is in KeyN's allowed origins

---

**🎉 Congratulations! Your app now has enterprise-grade SSO authentication!**

Users can now login once with KeyN and access all your applications seamlessly. The integration is secure, scalable, and production-ready.
