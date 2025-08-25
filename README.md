# KeyN Authentication System

A production-ready, centralized authentication system with OAuth 2.0 support, advanced security features, and seamless single sign-on capabilities.

## Features

- **OAuth 2.0 Authorization Server** - Full OAuth implementation with scoped permissions
- **Single Sign-On (SSO)** - Centralized authentication across multiple applications
- **Advanced Security** - IP banning, device tracking, rate limiting, and audit logging
- **User Management** - Registration, email verification, password reset, and profile management
- **Admin Interface** - Web-based administration for user and security management
- **Session Management** - Secure JWT tokens with refresh capabilities and device tracking
- **Cross-Domain Support** - Seamless authentication across subdomains

## Quick Start

### Prerequisites

- Python 3.8+
- SQLite (default) or PostgreSQL
- Domain with SSL/TLS certificate (for production)

### Installation

1. **Clone and setup**
   ```bash
   git clone https://github.com/SamN20/KeyN.git
   cd KeyN
   pip install -r requirements.txt
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (see ENVIRONMENT_SETUP.md)
   ```

3. **Initialize database**
   ```bash
   python scripts/create-db.py
   ```

4. **Start services**
   ```bash
   ./scripts/deploy_production.sh
   ```

## OAuth 2.0 Integration

KeyN provides a complete OAuth 2.0 authorization server for third-party application integration.

### Register Your Application

**Via Management Script:**
```bash
python scripts/manage_oauth.py create "My App" creator_username \
  --description "My application description" \
  --website "https://myapp.com" \
  --redirect-uris "https://myapp.com/auth/callback"
```

**Via API (requires authentication):**
```python
import requests

response = requests.post('https://auth.yourdomain.com/api/client/register', 
    json={
        'name': 'My Application',
        'description': 'Description of my app',
        'website_url': 'https://myapp.com',
        'redirect_uris': ['https://myapp.com/auth/callback']
    },
    cookies=auth_cookies  # Must be authenticated
)

client_data = response.json()
client_id = client_data['client_id']
client_secret = client_data['client_secret']
```

### Authorization Flow

1. **Redirect to KeyN for authorization**
   ```
   https://auth.yourdomain.com/oauth/authorize?
     client_id=YOUR_CLIENT_ID&
     redirect_uri=https://myapp.com/callback&
     scope=id,username,email&
     state=RANDOM_STATE
   ```

2. **Exchange code for access token**
   ```python
   response = requests.post('https://auth.yourdomain.com/oauth/token', data={
       'grant_type': 'authorization_code',
       'code': authorization_code,
       'client_id': client_id,
       'client_secret': client_secret,
       'redirect_uri': redirect_uri
   })
   ```

3. **Access user data**
   ```python
   user_data = requests.get('https://auth.yourdomain.com/api/user-scoped',
       headers={'Authorization': f'Bearer {access_token}'}
   ).json()
   ```

See [OAUTH_INTEGRATION_GUIDE.md](OAUTH_INTEGRATION_GUIDE.md) for complete documentation.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │───▶│   KeyN Auth     │───▶│   User Data     │
│                 │     │   Server        │    │   & Sessions    │
└─────────────────┘     └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └─────────────▶│   OAuth 2.0     │◀─────────────┘
                        │   Authorization │
                        └─────────────────┘
```

### Components

- **Auth Server** (`auth_server/`) - Core authentication and OAuth 2.0 service (Port 6000)
- **UI Site** (`ui_site/`) - Public landing page and documentation (Port 6001)  
- **Demo Client** (`demo_client/app.py`) - Example SSO integration (Port 6002)
- **OAuth Demo** (`demo_client/oauth_app.py`) - OAuth 2.0 integration example (Port 5001)
- **Management Scripts** (`scripts/`) - Administration and deployment tools
- **Configuration** (`config.py`, `.env`) - Environment and Flask configuration

## Security Features

- **IP Address Banning** - Automatic and manual IP blocking with temporary/permanent bans
- **Device Fingerprinting** - Track and ban devices across IP changes
- **Rate Limiting** - Brute force protection with configurable thresholds
- **Audit Logging** - Comprehensive logging of all authentication events
- **CSRF Protection** - State parameters and token validation
- **Secure Token Generation** - Cryptographically secure tokens and secrets

### Admin Interface

Access the admin panel at `/admin` to:
- Manage user accounts and permissions
- Monitor security events and login attempts
- Configure IP and device bans
- View system statistics and logs

## API Reference

### Authentication Endpoints

- `POST /login` - User login
- `POST /register` - User registration
- `POST /logout` - User logout
- `GET /api/validate-token` - Token validation
- `GET /api/user` - Get user information
- `POST /api/refresh-token` - Refresh access token

### OAuth 2.0 Endpoints

- `GET /oauth/authorize` - OAuth authorization endpoint
- `POST /oauth/token` - Token exchange endpoint
- `GET /api/user-scoped` - Scoped user data access
- `GET /api/scopes` - Available data scopes
- `POST /api/client/register` - Register OAuth client (authenticated)

### User Management

- `GET /profile` - User profile page
- `POST /profile/edit` - Update profile
- `GET /sessions` - Active sessions management
- `GET /authorizations` - OAuth authorizations management
- `GET /api/sessions` - Get user sessions via API
- `DELETE /api/sessions/{id}/revoke` - Revoke session via API
- `GET /api/user/authorizations` - Get user's OAuth authorizations
- `DELETE /api/user/authorizations/{client_id}` - Revoke OAuth authorization

### Admin Endpoints (Admin Required)

- `GET /admin` - Admin interface
- `POST /admin/ban-ip` - Ban IP address
- `POST /admin/ban-device` - Ban device
- `POST /admin/unban-ip` - Unban IP address
- `POST /admin/unban-device` - Unban device
- `GET /admin/login-attempts` - View login attempts
- `GET /admin/bans` - View active bans

## Development

### Local Development

```bash
# Start individual services
python auth_server/run.py     # Port 6000
python ui_site/app.py         # Port 6001
python demo_client/app.py     # Port 6002 (SSO demo)
python demo_client/oauth_app.py # Port 5001 (OAuth demo)
```

### Database Management

```bash
# Add admin privileges to user
python scripts/add_admin_field.py

# Manage OAuth clients
python scripts/manage_oauth.py list
python scripts/manage_oauth.py show CLIENT_ID

# Database migrations
python scripts/migrate_oauth.py
```

### Health Monitoring

```bash
# Check service status
./scripts/health_check.sh

# Auto-restart services if down
./scripts/health_check.sh true

# Manage logs
./scripts/manage_logs.sh
```

## Configuration

Key environment variables (see `.env.example`):

```bash
# Security
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Database
DATABASE_URL=sqlite:///instance/keyn_auth.db

# Email (for verification)
MAIL_SERVER=smtp.gmail.com
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Domain configuration
COOKIE_DOMAIN=.yourdomain.com
CORS_ORIGINS=https://app1.yourdomain.com,https://app2.yourdomain.com
```

## Deployment

### Production Deployment

1. **Configure environment** - See [ENVIRONMENT_SETUP.md](ENVIRONMENT_SETUP.md)
2. **Set up SSL/TLS** - Required for OAuth and secure cookies
3. **Configure reverse proxy** - nginx, Cloudflare, or similar
4. **Deploy services** - Use `./scripts/deploy_production.sh`
5. **Monitor logs** - Check `logs/` directory for service logs

### Docker Deployment

*Note: Docker configuration not currently included. Use the deployment scripts for production setup.*

## Documentation

- [OAuth Integration Guide](OAUTH_INTEGRATION_GUIDE.md) - Complete OAuth implementation guide
- [Environment Setup](ENVIRONMENT_SETUP.md) - Required configuration
- [Production Guide](PRODUCTION_STATUS.md) - Deployment and operations
- [Security Features](SECURITY_ENHANCEMENT_SUMMARY.md) - Security capabilities
- [Integration Guide](KEYN_INTEGRATION_GUIDE.md) - Add KeyN to existing apps

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/SamN20/KeyN/issues)
- **Documentation**: See the `docs/` directory
- **Security**: Report security issues privately to the repository owner

---

Built with security and scalability in mind. Production-tested and ready for enterprise use.

