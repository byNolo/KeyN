# 🔧 KeyN Environment Configuration Guide

## 🚨 **Important: Security Setup Required**

Before deploying KeyN, you **must** configure environment variables to avoid using default/hardcoded values that are visible in the public repository.

---

## 📋 **Required Setup Steps**

### 1. **Copy Environment Template**
```bash
cp .env.example .env
```

### 2. **Edit Configuration**
```bash
# Edit the .env file with your actual values
nano .env  # or use your preferred editor
```

### 3. **Generate Secure Keys**
```bash
# Generate a secure Flask secret key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate demo client secret key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 🔑 **Critical Security Variables**

### **Secret Keys (REQUIRED)**
```bash
# Main Flask application secret key
FLASK_SECRET_KEY=your-super-secure-random-key-here

# Demo client secret key  
DEMO_CLIENT_SECRET_KEY=another-secure-random-key-here
```

⚠️ **Never use the default fallback values in production!**

### **Email Configuration (REQUIRED)**
```bash
FLASK_MAIL_USERNAME=your-email@gmail.com
FLASK_MAIL_PASSWORD=your-app-specific-password
FLASK_MAIL_DEFAULT_SENDER=your-email@gmail.com
```

---

## 🌐 **Domain Configuration**

### **Production URLs**
Update these with your actual domain:

```bash
# Your main domain (replace yourdomain.com)
KEYN_AUTH_SERVER_URL=https://auth.keyn.yourdomain.com
KEYN_UI_SITE_URL=https://keyn.yourdomain.com
KEYN_DEMO_CLIENT_URL=https://demo.keyn.yourdomain.com

# Cookie domain for SSO
FLASK_SESSION_COOKIE_DOMAIN=.yourdomain.com

# CORS origins (your apps that will use KeyN)
FLASK_ALLOWED_ORIGINS=https://app1.yourdomain.com,https://app2.yourdomain.com
```

### **Health Check URLs** (for monitoring)
```bash
KEYN_HEALTH_CHECK_AUTH_URL=https://auth.keyn.yourdomain.com/health
KEYN_HEALTH_CHECK_UI_URL=https://keyn.yourdomain.com
KEYN_HEALTH_CHECK_DEMO_URL=https://demo.keyn.yourdomain.com
```

---

## 🏗️ **Deployment Configuration**

### **Server Paths**
```bash
# Path to your KeyN project directory
KEYN_PROJECT_DIR=/path/to/your/keyn/project

# Path to your Python virtual environment
KEYN_VENV_PATH=/path/to/your/keyn/venv
```

### **Database Path**
```bash
# For production, use absolute path or external database
FLASK_SQLALCHEMY_DATABASE_URI=sqlite:////absolute/path/to/keyn_auth.db

# Or for development (relative path)
FLASK_SQLALCHEMY_DATABASE_URI=sqlite:///instance/keyn_auth.db
```

---

## 🔧 **Complete .env Template**

Here's a complete example for `yourdomain.com`:

```bash
# Security Keys (CHANGE THESE!)
FLASK_SECRET_KEY=abcd1234-super-secure-key-generated-with-secrets-module
DEMO_CLIENT_SECRET_KEY=efgh5678-another-secure-key-for-demo-client

# Email Configuration
FLASK_MAIL_SERVER=smtp.gmail.com
FLASK_MAIL_PORT=587
FLASK_MAIL_USE_TLS=True
FLASK_MAIL_USERNAME=keyn@yourdomain.com
FLASK_MAIL_PASSWORD=your-gmail-app-password
FLASK_MAIL_DEFAULT_SENDER=keyn@yourdomain.com

# Database
FLASK_SQLALCHEMY_DATABASE_URI=sqlite:////home/youruser/keyn/auth_server/instance/keyn_auth.db
FLASK_SQLALCHEMY_TRACK_MODIFICATIONS=False

# Production URLs
KEYN_AUTH_SERVER_URL=https://auth.keyn.yourdomain.com
KEYN_UI_SITE_URL=https://keyn.yourdomain.com
KEYN_DEMO_CLIENT_URL=https://demo.keyn.yourdomain.com

# Health Check URLs
KEYN_HEALTH_CHECK_AUTH_URL=https://auth.keyn.yourdomain.com/health
KEYN_HEALTH_CHECK_UI_URL=https://keyn.yourdomain.com
KEYN_HEALTH_CHECK_DEMO_URL=https://demo.keyn.yourdomain.com

# SSO Configuration
FLASK_SESSION_COOKIE_DOMAIN=.yourdomain.com
FLASK_SESSION_COOKIE_SECURE=True
FLASK_SESSION_COOKIE_HTTPONLY=True
FLASK_SESSION_COOKIE_SAMESITE=None

# CORS Origins
FLASK_ALLOWED_ORIGINS=https://app1.yourdomain.com,https://app2.yourdomain.com,https://yourdomain.com

# Deployment Paths
KEYN_PROJECT_DIR=/home/youruser/keyn
KEYN_VENV_PATH=/home/youruser/keyn/venv
```

---

## 🧪 **Development Configuration**

For local development, use these settings:

```bash
# Development Keys (still change these!)
FLASK_SECRET_KEY=dev-secret-key-change-this
DEMO_CLIENT_SECRET_KEY=dev-demo-secret-change-this

# Local URLs
KEYN_AUTH_SERVER_URL=http://localhost:6000
KEYN_UI_SITE_URL=http://localhost:6001
KEYN_DEMO_CLIENT_URL=http://localhost:6002

# Development cookie settings
FLASK_SESSION_COOKIE_SECURE=False
FLASK_SESSION_COOKIE_SAMESITE=Lax
FLASK_SESSION_COOKIE_DOMAIN=

# Development CORS
FLASK_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5000

# Local paths
KEYN_PROJECT_DIR=/path/to/your/local/keyn
KEYN_VENV_PATH=/path/to/your/local/keyn/venv
```

---

## ✅ **Verification Checklist**

Before deploying, verify:

- [ ] ✅ **Unique secret keys** generated and set
- [ ] ✅ **Email credentials** configured and tested
- [ ] ✅ **Domain URLs** updated for your domain
- [ ] ✅ **Database path** set correctly
- [ ] ✅ **CORS origins** include your app domains
- [ ] ✅ **File permissions** on .env file (600)
- [ ] ✅ **.env file** not committed to git
- [ ] ✅ **Health check URLs** accessible

---

## 🔒 **Security Best Practices**

### **File Permissions**
```bash
# Secure your .env file
chmod 600 .env
```

### **Never Commit Secrets**
```bash
# Verify .env is ignored
git status  # Should not show .env file

# Check .gitignore includes .env
grep -n "\.env" .gitignore
```

### **Test Configuration**
```bash
# Test that environment variables are loaded
python3 -c "import os; print('Flask key set:', bool(os.environ.get('FLASK_SECRET_KEY')))"

# Test health endpoint
curl -s http://localhost:6000/health | python3 -m json.tool
```

---

## 🚨 **Production Deployment**

### **Before Going Live:**

1. ✅ **Generate production secret keys**
2. ✅ **Configure production email account**
3. ✅ **Set up production database path**
4. ✅ **Update all domain URLs**
5. ✅ **Test health checks work**
6. ✅ **Verify HTTPS settings**
7. ✅ **Test SSO flow end-to-end**

### **Server Environment Loading**
Ensure your server loads the .env file:

```bash
# For systemd services, add:
EnvironmentFile=/path/to/your/keyn/.env

# For manual deployment, source before starting:
source .env && ./scripts/deploy_production.sh
```

---

## 🆘 **Troubleshooting**

### **Common Issues:**

1. **"fallback-secret" in logs**
   - ✅ Set `FLASK_SECRET_KEY` in .env file

2. **Cookie authentication not working**
   - ✅ Check `FLASK_SESSION_COOKIE_DOMAIN` setting
   - ✅ Verify HTTPS is enabled in production

3. **CORS errors**
   - ✅ Add your app domains to `FLASK_ALLOWED_ORIGINS`

4. **Health check failures**
   - ✅ Verify health check URLs are correct
   - ✅ Test endpoints manually with curl

5. **Email verification not working**
   - ✅ Check email credentials in .env
   - ✅ Use app-specific password for Gmail

---

**🎯 Your KeyN system is secure and ready for production when all environment variables are properly configured!**
