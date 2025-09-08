# 🔐 KeyN – Custom Auth System Overview

### 🎯 Goal:

Create a centralized, secure, and resume-worthy authentication system (KeyN) that allows users to log in once and access all your apps (Vinyl Vote, SideQuest, etc.) through a shared login session.

---

## 🏗️ System Architecture

| Component | Description | URL (for now) |
| --- | --- | --- |
| **KeyN UI Site** | Public-facing marketing/promo/info page for KeyN | `https://KeyN.bynolo.ca` |
| **KeyN Auth Server** | The backend auth system that handles login & tokens | `https://auth-keyn.bynolo.ca` |
| **Vinyl Vote** | Album rating app that consumes KeyN's login system | `https://Album.bynolo.ca` |
| **SideQuest** | Challenge/quest app that also uses KeyN login | `https://sq.bynolo.ca` | (not made yet)
| **Landing Page** | Central hub that also authenticates via KeyN | `https://bynolo.ca` |

---

## 🛠️ KeyN Auth Server Features (`auth-keyn.bynolo.ca`)

### Core Endpoints

| Route | Method | Purpose |
| --- | --- | --- |
| `/login` | GET | Render login page |
| `/login` | POST | Authenticate, create session/token |
| `/logout` | POST | Invalidate session/token |
| `/api/validate-token` | GET | Validate session or token from client site |
| `/api/user` | GET | Get info about logged-in user |
| `/oauth/authorize` *(future)* | GET | Optional OAuth-style login page |
| `/oauth/token` *(future)* | POST | Exchange login code for token |

---

## 🧱 KeyN UI Site (`KeyN.bynolo.ca`)

- Landing page for your auth system
- Public documentation / about / contact info
- Optionally demo login experience or list apps that use it
- Clean, branded identity to make it feel legit (maybe build in Flask or static HTML)

---

## 🔑 Auth Method Summary

| Auth Method | Status |
| --- | --- |
| Cookie-based session | ✅ Primary login system (via `.bynolo.ca`) |
| JWT-based token API | ✅ Used by client apps to validate session |
| Refresh tokens | ✅ Optional but recommended |
| OAuth2-style flow | 🔜 Future upgrade path |

---

## 🔄 Login Flow (SSO Style)

1. User visits `vv.bynolo.ca` or `sq.bynolo.ca`
2. Site checks session or access token
3. If missing/expired → redirect to `auth-keyn.bynolo.ca/login?redirect=https://vv.bynolo.ca/return`
4. User logs in → KeyN sets a cookie for `.bynolo.ca`
5. User is redirected back, fully authenticated
6. Client app uses access token or verifies session with `GET /api/validate-token`

---

## 📦 Project Phases

### 🧩 Phase 1: Core Auth

- Login, logout, registration
- Session + cookie handling
- Basic `/api/validate-token` for client sites

### 🔐 Phase 2: Security & Extras

- Refresh token support
- Rate limiting, brute force protection
- Session expiration & revocation

### 🚀 Phase 3: OAuth2 Support (Optional)

- `/authorize`, `/token` flows
- Granular scopes
- Third-party app support

---

## ✅ Naming Summary

| Name | Role |
| --- | --- |
| **KeyN** | Your custom authentication system |
| `KeyN.bynolo.ca` | The public-facing site for KeyN |
| `auth-keyn.bynolo.ca` | The backend auth API and login server |