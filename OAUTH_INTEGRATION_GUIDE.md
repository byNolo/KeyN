# KeyN OAuth-like Scoped Authorization System

KeyN now supports OAuth-like scoped authorization that allows external websites and applications to request specific user data with granular permissions.

## Overview

This system allows:
- **Websites** to request specific user information (username, email, full name, etc.)
- **Users** to grant or deny access to specific data fields
- **Administrators** to manage client applications and data scopes
- **Easy expansion** for new data fields and permissions

## Available Data Scopes

| Scope | Display Name | Description |
|-------|-------------|-------------|
| `id` | User ID | Unique identifier for the account |
| `username` | Username | User's KeyN username |
| `email` | Email Address | User's email address |
| `full_name` | Full Name | Combined first and last name |
| `first_name` | First Name | User's first name |
| `last_name` | Last Name | User's last name |
| `display_name` | Display Name | Preferred display name |
| `bio` | Biography | Personal biography |
| `website` | Website | Personal website URL |
| `location` | Location | User's location |
| `date_of_birth` | Date of Birth | User's date of birth |
| `created_at` | Account Created | Account registration date |
| `is_verified` | Email Verified | Email verification status |

## OAuth Flow

### 1. Client Registration

First, register your application with KeyN:

```bash
# Using the management script
python scripts/manage_oauth.py create "My App" admin_username \
  --description "My awesome application" \
  --website "https://myapp.com" \
  --redirect-uris "https://myapp.com/auth/callback"
```

Or via API:
```python
import requests

response = requests.post('https://auth-keyn.nolanbc.ca/api/client/register', 
    json={
        'name': 'My Application',
        'description': 'Description of my app',
        'website_url': 'https://myapp.com',
        'redirect_uris': ['https://myapp.com/auth/callback']
    },
    # Include authentication headers
)

client_data = response.json()
client_id = client_data['client_id']
client_secret = client_data['client_secret']
```

### 2. Authorization Request

Redirect users to KeyN for authorization:

```
https://auth-keyn.nolanbc.ca/oauth/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://myapp.com/auth/callback&
  scope=id,username,email,full_name&
  state=RANDOM_STATE_STRING
```

### 3. User Consent

Users will see a consent screen showing:
- Your application details
- Requested permissions with descriptions
- Option to approve or deny

### 4. Authorization Code

If approved, user is redirected back with a code:
```
https://myapp.com/auth/callback?
  code=AUTHORIZATION_CODE&
  state=RANDOM_STATE_STRING
```

### 5. Token Exchange

Exchange the code for an access token:

```python
import requests

response = requests.post('https://auth-keyn.nolanbc.ca/oauth/token', data={
    'grant_type': 'authorization_code',
    'code': authorization_code,
    'client_id': client_id,
    'client_secret': client_secret,
    'redirect_uri': redirect_uri
})

token_data = response.json()
access_token = token_data['access_token']
```

### 6. Access User Data

Use the access token to get user data:

```python
response = requests.get('https://auth-keyn.nolanbc.ca/api/user-scoped',
    headers={'Authorization': f'Bearer {access_token}'}
)

user_data = response.json()
# Returns only the data fields the user authorized
```

## API Endpoints

### Public Endpoints

- `GET /api/scopes` - List available data scopes
- `POST /oauth/authorize` - Start authorization flow
- `POST /oauth/token` - Exchange code for token
- `GET /api/user-scoped` - Get scoped user data (requires token)

### Authenticated Endpoints

- `POST /api/client/register` - Register new client
- `GET /api/user/authorizations` - List user's authorizations
- `DELETE /api/user/authorizations/{client_id}` - Revoke authorization

### Admin Pages

- `/authorizations` - User authorization management page

## Client Management

### List Clients
```bash
python scripts/manage_oauth.py list
```

### Show Client Details
```bash
python scripts/manage_oauth.py show CLIENT_ID
```

### Create Client
```bash
python scripts/manage_oauth.py create "App Name" creator_username \
  --description "App description" \
  --website "https://app.com" \
  --redirect-uris "https://app.com/callback" "http://localhost:3000/callback"
```

### Deactivate Client
```bash
python scripts/manage_oauth.py deactivate CLIENT_ID
```

### List Authorizations
```bash
python scripts/manage_oauth.py authorizations --user username
```

## Demo Application

A complete demo application is available at `demo_client/oauth_app.py`. To run it:

1. Ensure the auth server is running
2. Set up the demo client:
   ```bash
   python scripts/setup_oauth.py
   ```
3. Run the demo:
   ```bash
   cd demo_client
   python oauth_app.py
   ```
4. Visit http://localhost:5002

## Security Features

- **State parameter** prevents CSRF attacks during authorization flow
- **Short-lived authorization codes** (10 minutes) minimize exposure window
- **Scoped access tokens** limit data access to what users explicitly approved
- **Redirect URI validation** prevents authorization code interception
- **Client authentication** required for all token exchanges
- **Authorization revocation** allows users to remove access at any time
- **Audit trail** with timestamps tracks all authorization grants and usage
- **IP and device security** integrates with KeyN's IP banning and device tracking
- **Single-use codes** prevent replay attacks
- **Secure token generation** uses cryptographically secure random values

## Adding New Scopes

To add new data scopes:

1. Add the field to the `User` model in `models.py`
2. Update the `get_scoped_data()` method in the `User` class
3. Add the scope to the default scopes in `oauth_utils.py`
4. Run database migration if needed

Example:
```python
# In models.py
class User(UserMixin, db.Model):
    # ... existing fields ...
    phone_number = db.Column(db.String(20))
    
    def get_scoped_data(self, scope_names):
        # ... existing scope_map ...
        scope_map['phone_number'] = self.phone_number
        # ... rest of method ...

# In oauth_utils.py ScopeManager.initialize_default_scopes()
{
    'name': 'phone_number',
    'display_name': 'Phone Number',
    'description': 'Your phone number',
    'data_field': 'phone_number'
}
```

## Configuration

The system uses the same configuration as the main KeyN auth server. No additional configuration is required.

## Production Deployment

For production:

1. **Use HTTPS for all endpoints** - OAuth tokens must never be transmitted over HTTP
2. **Store client secrets securely** - Use environment variables or secure vaults
3. **Implement proper logging and monitoring** - Track all OAuth flows and errors
4. **Consider rate limiting on OAuth endpoints** - Prevent abuse of authorization flow
5. **Regular cleanup of expired authorization codes** - Remove old codes from database
6. **Backup authorization data** - Include OAuth tables in backups
7. **Validate redirect URIs strictly** - Only allow pre-registered HTTPS URIs
8. **Use short-lived access tokens** - Consider implementing refresh tokens for longer sessions
9. **Monitor for suspicious activity** - Watch for unusual authorization patterns

## Troubleshooting

### Common Issues

1. **Invalid redirect URI**: Ensure the redirect URI exactly matches what's registered
2. **Expired authorization code**: Codes expire in 10 minutes, exchange them quickly
3. **Invalid scopes**: Check that requested scopes exist and are active
4. **Token expired**: Access tokens expire in 1 hour, handle refresh appropriately

### Debug Commands

```bash
# Check client configuration
python scripts/manage_oauth.py show CLIENT_ID

# List available scopes
python scripts/manage_oauth.py scopes

# Check user authorizations
python scripts/manage_oauth.py authorizations --user USERNAME
```

## Migration from Legacy System

The new OAuth system is fully backward compatible. Existing integrations using `/api/user` will continue to work, but new integrations should use the scoped OAuth flow for better security and user control.
