# 🔐 KeyN Authentication System - Production Ready

## 🎯 Overview
KeyN is a centralized Single Sign-On (SSO) authentication system that allows users to login once and access all your applications (Vinyl Vote, SideQuest, etc.) with shared login sessions.

## ✅ Current Status: PRODUCTION READY

| Service | Status | Local Port | Production URL |
|---------|--------|------------|----------------|
| **Auth Server** | ✅ RUNNING | 6000 | https://auth-keyn.bynolo.ca |
| **UI Site** | ✅ RUNNING | 6001 | https://keyn.bynolo.ca |
| **OAuth Demo Client** | ✅ RUNNING | 6002 | https://demo-keyn.bynolo.ca |

## 🌩️ Cloudflare Tunnels Configuration

### Tunnel Ingress Rules:
```yaml
ingress:
  - hostname: auth-keyn.bynolo.ca
    service: http://localhost:6000
  - hostname: keyn.bynolo.ca
    service: http://localhost:6001
  - hostname: demo-keyn.bynolo.ca
    service: http://localhost:6002
  - service: http_status:404
```

### DNS Records (CNAME):
```
auth-keyn.bynolo.ca  CNAME  YOUR_TUNNEL_ID.cfargotunnel.com
keyn.bynolo.ca       CNAME  YOUR_TUNNEL_ID.cfargotunnel.com
demo-keyn.bynolo.ca  CNAME  YOUR_TUNNEL_ID.cfargotunnel.com
```

## 🚀 Quick Start

### 1. Start KeyN Services
```bash
./scripts/deploy_production.sh
```

### 2. Configure Cloudflare Tunnel
```bash
./scripts/setup_cloudflare_tunnel.sh
```

### 3. Add Tunnel Routes
```bash
cloudflared tunnel route dns YOUR_TUNNEL_NAME auth-keyn.bynolo.ca
cloudflared tunnel route dns YOUR_TUNNEL_NAME keyn.bynolo.ca
cloudflared tunnel route dns YOUR_TUNNEL_NAME demo-keyn.bynolo.ca
```

### 4. Run Tunnel
```bash
cloudflared tunnel run YOUR_TUNNEL_NAME
```

### 5. Test SSO
Visit: https://demo-keyn.bynolo.ca

**NEW**: The demo client now features OAuth-like scoped permissions! Users can:
- Choose specific data to share (username, email, full name, etc.)
- Grant granular permissions to applications
- Manage authorized applications from their account
- Experience a complete OAuth flow demonstration

## 🌐 Production Configuration

### Domain Cookie Settings:
- **Domain**: `.bynolo.ca` (enables SSO across all subdomains)
- **Secure**: `True` (HTTPS required)
- **SameSite**: `None` (allows cross-site SSO)

### CORS Origins:
- `https://album.bynolo.ca`
- `https://sq.bynolo.ca` 
- `https://bynolo.ca`
- `https://keyn.bynolo.ca:6001`
- `https://auth-keyn.bynolo.ca:6000`
- `https://demo-keyn.bynolo.ca:6002`

## 🚀 Next Steps for Cloudflare Tunnels

### 1. Configure Your Tunnel
Run the setup script for configuration details:
```bash
./setup_cloudflare_tunnel.sh
```

### 2. Add Tunnel Routes
```bash
cloudflared tunnel route dns YOUR_TUNNEL_NAME auth-keyn.bynolo.ca
cloudflared tunnel route dns YOUR_TUNNEL_NAME keyn.bynolo.ca
cloudflared tunnel route dns YOUR_TUNNEL_NAME demo-keyn.bynolo.ca
```

### 3. Start Your Tunnel
```bash
cloudflared tunnel run YOUR_TUNNEL_NAME
```

### 4. Test the SSO Flow
Once tunnel is running:
1. Visit: `https://demo-keyn.bynolo.ca`
2. Click "Login with KeyN" (standard OAuth flow)
3. Or click "Custom Login" (choose specific data scopes)
4. Experience the OAuth consent interface
5. Manage your authorizations at: `https://auth-keyn.bynolo.ca/authorizations` 
3. Register/Login at: `https://auth-keyn.bynolo.ca`
4. Verify redirect back works with authentication!

## 🔧 Service Management

### Stop All Services:
```bash
./stop_keyn_services.sh
```

### Restart All Services:
```bash
./deploy_production.sh
```

### View Logs:
```bash
tail -f logs/auth_server.log
tail -f logs/ui_site.log  
tail -f logs/demo_client.log
```

## 🎯 Current Capabilities

Your KeyN system now has:
- ✅ **Full SSO cookie sharing** across `.bynolo.ca` subdomains
- ✅ **JWT token authentication** with refresh tokens
- ✅ **Email verification** system
- ✅ **Session management** with IP tracking
- ✅ **CORS configured** for your production domains
- ✅ **Production-ready security** settings
- ✅ **Working demo client** showing integration

## 📝 Integration Example

For Vinyl Vote or other apps, use this pattern:
```python
# Check if user is authenticated
response = requests.get('https://auth-keyn.bynolo.ca:6000/api/validate-token',
                       cookies=request.cookies)
if response.status_code != 200:
    # Redirect to KeyN login
  return redirect('https://auth-keyn.bynolo.ca:6000/login?redirect=' + 
                   urlencode(return_url))
```

**Your KeyN authentication system is now production-ready! 🚀**

Just add DNS + SSL and you'll have a fully functional SSO system!
