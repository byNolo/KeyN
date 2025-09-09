<div align="center">

# KeyN - byNolo

**Authentication & identity platform with SSO, OAuth 2.0, sessions, and security management.**  
SSO · OAuth 2.0 · Passkeys-ready · Device visibility · Admin controls

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-10B981)](LICENSE)
![Status](https://img.shields.io/badge/Status-Active-success)
![Security](https://img.shields.io/badge/Security-Hardened-0f766e)
![byNolo](https://img.shields.io/badge/byNolo-Studios-34d399?labelColor=0b0f12)

<br />
<sub>Designed, secured &amp; deployed · <strong>KeyN - byNolo</strong></sub>

</div>

---

## Key Highlights

| Capability | What You Get | Notes |
|------------|--------------|-------|
| OAuth 2.0 / Authorization Server | Standard flows + scopes | Scripted client registration |
| Single Sign-On (SSO) | Cross‑app & cross‑subdomain continuity | Cookie isolation & revocation |
| Passkeys Path | WebAuthn groundwork prepared | Extensible module structure |
| Device & Session Intelligence | Session listing & per‑device revocation | Visibility for users/admins |
| Security Toolkit | Rate limiting, bans, audit trails | Defense-in-depth approach |
| Admin Portal | Real‑time operational dashboard | Minimal friction controls |
| Token Lifecycle | Refresh + scoped + cross-domain handshake | Reduces replay & leakage impact |
| Developer Simplicity | Clear Flask modules | Easy to fork & extend |

---

## Table of Contents
1. [Features](#features)
2. [Quick Start](#quick-start)
3. [OAuth 2.0 Integration](#oauth-20-integration)
4. [Architecture](#architecture)
5. [Security Features](#security-features)
6. [API Reference](#api-reference)
7. [Development](#development)
8. [Configuration](#configuration)
9. [Deployment](#deployment)
10. [Documentation](#documentation)
11. [Brand & Attribution](#brand--attribution)
12. [License](#license)
13. [Support](#support)

---

## Features
Core foundations for modern identity:
- **OAuth 2.0 Authorization Server** – Complete implementation with scoped permissions
- **Single Sign-On (SSO)** – Centralized identity across apps & subdomains
- **Passkey-Friendly Architecture** – Utility scaffold for FIDO2 expansion
- **Advanced Security** – IP & device bans, rate limiting, audit trails, anomaly surfacing
- **User Lifecycle** – Registration, verification, recovery, profile completion guidance
- **Session Management** – Device enumeration + revocation + refresh rotation
- **Cross-Domain Support** – Secure cookie scoping & domain isolation
- **Operational Admin UI** – Real-time visibility & action controls
- **Extensible Modules** – Add custom factors, scopes, or policies cleanly

---

## Quick Start

### Prerequisites
* Python 3.11+  
* SQLite (default) or PostgreSQL  
* Domain + TLS (for production tokens & OAuth redirects)

### Installation
```bash
git clone https://github.com/SamN20/KeyN.git
cd KeyN
pip install -r requirements.txt
cp .env.example .env
# edit .env → secrets, domains, mail config
python scripts/create-db.py
./scripts/deploy_production.sh
```

### Minimal Dev Run
```bash
python auth_server/run.py &
python ui_site/app.py &
python demo_client/app.py &
```

---

## OAuth 2.0 Integration
KeyN exposes a standards-aligned authorization server.

**Register via Script**
```bash
python scripts/manage_oauth.py create "My App" creator_username \
   --description "My application" \
   --website "https://myapp.com" \
   --redirect-uris "https://myapp.com/auth/callback"
```

**Register via API**
```python
import requests
r = requests.post('https://auth.yourdomain.com/api/client/register',
                           json={
                                 'name':'My Application',
                                 'description':'Description',
                                 'website_url':'https://myapp.com',
                                 'redirect_uris':['https://myapp.com/auth/callback']
                           },
                           cookies=auth_cookies)
data = r.json()
```

**Authorization Flow**
1. User redirected to `/oauth/authorize`  
2. User consents (scopes)  
3. App exchanges code at `/oauth/token`  
4. App calls `/api/user-scoped` with access token

---

## Architecture
```
┌──────────────┐     ┌────────────────┐     ┌────────────────┐
│  Client App  │ ─▶  │  KeyN Auth     │ ─▶  │  Sessions &     │
│  (Browser /  │     │  Server (API)  │     │  Security Data  │
└──────────────┘     └────────────────┘     └────────────────┘
             │                      │                       │
             │             ┌────────────────┐               │
             └────────────▶│  OAuth Layer   │◀──────────────┘
                                  └────────────────┘
```

### Components
* `auth_server/` – Core auth + OAuth + security logic (6000)  
* `ui_site/` – Public/marketing & account portal (6001)  
* `demo_client/` – Example SSO & OAuth usage (6002 / 5001)  
* `scripts/` – Operational & migration utilities  
* `config.py` – Central configuration surface  

---

## Security Features
* IP / Device bans (manual + triggered)  
* Rate limiting hints (extendable)  
* Session & refresh token lifecycle management  
* Email verification & recovery flows  
* Planned: enriched anomaly scoring & passkey-first flows  

### Admin Interface
Navigate to `/admin` to manage users, sessions, bans, security events.

---

## API Reference
### Authentication
`POST /login` · `POST /register` · `POST /logout` · `GET /api/user` · `POST /api/refresh-token`

### OAuth
`GET /oauth/authorize` · `POST /oauth/token` · `GET /api/user-scoped` · `GET /api/scopes` · `POST /api/client/register`

### User / Session
`GET /sessions` · `GET /authorizations` · `GET /api/sessions` · `DELETE /api/sessions/{id}/revoke`

### Admin (restricted)
`POST /admin/ban-ip` · `POST /admin/unban-ip` · `POST /admin/ban-device` · `POST /admin/unban-device`  
`GET /admin/login-attempts` · `GET /admin/bans`

---

## Development
### Run Services
```bash
python auth_server/run.py
python ui_site/app.py
python demo_client/app.py
```

### OAuth Client Management
```bash
python scripts/manage_oauth.py list
python scripts/manage_oauth.py show CLIENT_ID
```

### Database / Admin Helper
```bash
python scripts/add_admin_field.py
python scripts/migrate_oauth.py
```

### Health / Ops
```bash
./scripts/health_check.sh        # status
./scripts/health_check.sh true   # auto-restart loop
./scripts/manage_logs.sh         # rotate + inspect
```

---

## Configuration
Key environment variables (see `.env.example`):
```bash
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
DATABASE_URL=sqlite:///instance/keyn_auth.db
MAIL_SERVER=smtp.gmail.com
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
COOKIE_DOMAIN=.yourdomain.com
CORS_ORIGINS=https://app1.yourdomain.com,https://app2.yourdomain.com
```

---

## Deployment
1. Configure env + secrets (see `ENVIRONMENT_SETUP.md`)  
2. Enable TLS (mandatory for OAuth + secure cookies)  
3. Reverse proxy (nginx / Caddy / Cloudflare)  
4. Run `./scripts/deploy_production.sh`  
5. Monitor logs (`logs/` dir)  

Docker packaging not yet included (future enhancement).

---

## Documentation
* [OAuth Integration Guide](OAUTH_INTEGRATION_GUIDE.md)
* [Environment Setup](ENVIRONMENT_SETUP.md)
* [Production Ops](PRODUCTION_STATUS.md)
* [Security Enhancements](SECURITY_ENHANCEMENT_SUMMARY.md)
* [Integration Guide](KEYN_INTEGRATION_GUIDE.md)

---

## Brand & Attribution
First mention: **KeyN – byNolo**. Thereafter: **KeyN**. Preserve *byNolo* stylization (lowercase b, uppercase N). Optional attribution footer: “Powered by KeyN – byNolo”.

---

## License
MIT – see [LICENSE](LICENSE).

---

## Support
* Issues: [GitHub Issues](https://github.com/SamN20/KeyN/issues)
* Security: report privately to repo owner
* Enhancements welcome via PR

---

### Why KeyN – byNolo?
Focused on **operational security realism**: visibility, containment, progressive hardening, and extensibility without framework lock‑in.

| Principle | Example |
|-----------|---------|
| Visibility | Session & authorization listings |
| Containment | Cookie scoping + explicit revocation endpoints |
| Progressive Hardening | Passkey utilities + device ban logic |
| Operability | Scripts for DB, OAuth client lifecycle |
| Extensibility | Modular separation (auth server / UI / demo) |

---

<p align="center"><sub>Written, designed, deployed -<strong> byNolo</strong>.</sub></p>
