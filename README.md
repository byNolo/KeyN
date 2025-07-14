# 🔐 KeyN - Single Sign-On Authentication System

> A centralized, secure authentication system that allows users to login once and access all your applications with shared login sessions.

## � **Security Setup Required**

⚠️ **Before deploying, you MUST configure environment variables:**

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit with your secure values
nano .env  # Update secret keys, email, domains

# 3. Generate secure keys
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

📖 **See [`ENVIRONMENT_SETUP.md`](ENVIRONMENT_SETUP.md) for complete configuration guide**

---

## �🚀 Quick Start

1. **Start Services**: `./scripts/deploy_production.sh`
2. **Configure Tunnel**: `./scripts/setup_cloudflare_tunnel.sh`
3. **Run Tunnel**: Configure your Cloudflare tunnel with the provided settings
4. **Test**: Visit https://demo-keyn.nolanbc.ca

## 📁 Project Structure

```
KeyN/
├── 📋 PRODUCTION_STATUS.md     # Main production guide
├── 🔐 KeyN – Custom Auth System Overview.md  # System design overview
├── 🛠️ scripts/
│   ├── deploy_production.sh    # Start all services
│   ├── stop_keyn_services.sh   # Stop all services
│   ├── setup_cloudflare_tunnel.sh  # Tunnel configuration
│   └── create-db.py           # Database initialization
├── 🔧 Configuration/
│   ├── .env                    # Environment variables
│   ├── .env.example           # Environment template
│   ├── config.py              # Flask configuration
│   └── requirements.txt       # Python dependencies
├── 🏠 Services/
│   ├── auth_server/           # Main authentication backend
│   ├── ui_site/              # Public KeyN landing page
│   └── demo_client/          # Demo SSO integration
└── 📊 scripts/
    └── create-db.py          # Database initialization
```

## 🌐 Production URLs

- **KeyN Landing**: https://keyn.nolanbc.ca
- **Authentication**: https://auth-keyn.nolanbc.ca  
- **Demo Client**: https://demo-keyn.nolanbc.ca

## 🔧 Key Features

✅ **JWT Authentication** with refresh tokens  
✅ **Email Verification** system  
✅ **Session Management** with device tracking  
✅ **Cross-domain SSO** via `.nolanbc.ca` cookies  
✅ **CORS Configuration** for client apps  
✅ **Production Security** (HTTPS, secure cookies)  
✅ **Cloudflare Tunnels** integration  

## 🔗 Integration

To integrate with other apps (like Vinyl Vote):

```python
# Check authentication
response = requests.get('https://auth-keyn.nolanbc.ca/api/validate-token',
                       cookies=request.cookies)
if response.status_code != 200:
    # Redirect to KeyN login
    return redirect('https://auth-keyn.nolanbc.ca/login?redirect=' + callback_url)
```

## 📝 Environment Configuration

Copy `.env.example` to `.env` and configure:
- Email settings (Flask-Mail)
- Domain cookie settings
- CORS origins
- Database path

## 🛠️ Development

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python scripts/create-db.py

# Start services individually
python auth_server/run.py     # Port 6000
python ui_site/app.py         # Port 6001
python demo_client/app.py     # Port 6002
```

## 📊 Service Management

```bash
# Start all services
./scripts/deploy_production.sh

# Stop all services  
./scripts/stop_keyn_services.sh

# Check status
ss -tln | grep -E ":(6000|6001|6002)"
```

## 📖 Documentation

- **🔧 Environment Setup**: `ENVIRONMENT_SETUP.md` - **REQUIRED** security configuration
- **Production Guide**: `PRODUCTION_STATUS.md` - Complete setup and deployment
- **Integration Guide**: `KEYN_INTEGRATION_GUIDE.md` - Add KeyN to your apps
- **System Overview**: `🔐 KeyN – Custom Auth System Overview.md` - Architecture and design
- **Security Features**: `SECURITY_ENHANCEMENT_SUMMARY.md` - Security capabilities
- **Environment Template**: `.env.example` - Configuration template

## 🛠️ Management Scripts

```bash
# Health monitoring
./scripts/health_check.sh           # Check service status
./scripts/health_check.sh true      # Check status and auto-restart if needed

# Log management
./scripts/manage_logs.sh            # Rotate logs and cleanup old files

# Service management
./scripts/deploy_production.sh      # Start all services
./scripts/stop_keyn_services.sh     # Stop all services
```

---

**Ready for production with Cloudflare Tunnels! 🌩️**
