import json
import secrets
import datetime
from flask import current_app
from .models import DataScope, ClientApplication, UserAuthorization, AuthorizationCode, User
from . import db

class ScopeManager:
    """Manages data scopes and permissions"""
    
    @staticmethod
    def initialize_default_scopes():
        """Initialize default data scopes"""
        default_scopes = [
            {
                'name': 'id',
                'display_name': 'User ID',
                'description': 'Unique identifier for your account',
                'data_field': 'id'
            },
            {
                'name': 'username',
                'display_name': 'Username',
                'description': 'Your username on KeyN',
                'data_field': 'username'
            },
            {
                'name': 'email',
                'display_name': 'Email Address',
                'description': 'Your email address',
                'data_field': 'email'
            },
            {
                'name': 'full_name',
                'display_name': 'Full Name',
                'description': 'Your first and last name',
                'data_field': 'get_full_name'
            },
            {
                'name': 'first_name',
                'display_name': 'First Name',
                'description': 'Your first name',
                'data_field': 'first_name'
            },
            {
                'name': 'last_name',
                'display_name': 'Last Name',
                'description': 'Your last name',
                'data_field': 'last_name'
            },
            {
                'name': 'display_name',
                'display_name': 'Display Name',
                'description': 'Your preferred display name',
                'data_field': 'display_name'
            },
            {
                'name': 'bio',
                'display_name': 'Biography',
                'description': 'Your personal biography',
                'data_field': 'bio'
            },
            {
                'name': 'website',
                'display_name': 'Website',
                'description': 'Your personal website URL',
                'data_field': 'website'
            },
            {
                'name': 'location',
                'display_name': 'Location',
                'description': 'Your location',
                'data_field': 'location'
            },
            {
                'name': 'date_of_birth',
                'display_name': 'Date of Birth',
                'description': 'Your date of birth',
                'data_field': 'date_of_birth'
            },
            {
                'name': 'created_at',
                'display_name': 'Account Created',
                'description': 'When your account was created',
                'data_field': 'created_at'
            },
            {
                'name': 'is_verified',
                'display_name': 'Email Verified',
                'description': 'Whether your email is verified',
                'data_field': 'is_verified'
            }
        ]
        
        for scope_data in default_scopes:
            if not DataScope.query.filter_by(name=scope_data['name']).first():
                scope = DataScope(**scope_data)
                db.session.add(scope)
        
        db.session.commit()
    
    @staticmethod
    def get_scope_by_name(name):
        """Get scope by name"""
        return DataScope.query.filter_by(name=name, is_active=True).first()
    
    @staticmethod
    def get_scopes_by_names(names):
        """Get multiple scopes by names"""
        return DataScope.query.filter(DataScope.name.in_(names), DataScope.is_active == True).all()
    
    @staticmethod
    def validate_scopes(scope_names):
        """Validate that all requested scopes exist"""
        if not scope_names:
            return False, "No scopes requested"
        
        existing_scopes = ScopeManager.get_scopes_by_names(scope_names)
        existing_names = {scope.name for scope in existing_scopes}
        requested_names = set(scope_names)
        
        invalid_scopes = requested_names - existing_names
        if invalid_scopes:
            return False, f"Invalid scopes: {', '.join(invalid_scopes)}"
        
        return True, existing_scopes

class ClientManager:
    """Manages client applications"""

    @staticmethod
    def generate_client_credentials():
        """Generate a new (client_id, client_secret) pair.

        Returns:
            tuple: (client_id, client_secret)
        """
        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(64)
        return client_id, client_secret
    
    @staticmethod
    def create_client(name, description, website_url, redirect_uris, created_by_user_id):
        """Create a new client application"""
        # Reuse the shared credential generator for consistency
        client_id, client_secret = ClientManager.generate_client_credentials()
        
        client = ClientApplication(
            client_id=client_id,
            client_secret=client_secret,
            name=name,
            description=description,
            website_url=website_url,
            redirect_uris=json.dumps(redirect_uris) if isinstance(redirect_uris, list) else redirect_uris,
            created_by=created_by_user_id
        )
        
        db.session.add(client)
        db.session.commit()
        
        return client
    
    @staticmethod
    def get_client(client_id):
        """Get client by ID"""
        return ClientApplication.query.filter_by(client_id=client_id, is_active=True).first()
    
    @staticmethod
    def verify_client(client_id, client_secret):
        """Verify client credentials"""
        client = ClientApplication.query.filter_by(
            client_id=client_id,
            client_secret=client_secret,
            is_active=True
        ).first()
        return client
    
    @staticmethod
    def is_redirect_uri_valid(client, redirect_uri):
        """Check if redirect URI is valid for client"""
        try:
            allowed_uris = json.loads(client.redirect_uris)
            return redirect_uri in allowed_uris
        except (json.JSONDecodeError, TypeError):
            return redirect_uri == client.redirect_uris

class AuthorizationManager:
    """Manages user authorizations and codes"""
    
    @staticmethod
    def create_authorization_code(user_id, client_id, scope_names, redirect_uri):
        """Create an authorization code"""
        code = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        
        # Validate scopes
        valid, scopes = ScopeManager.validate_scopes(scope_names)
        if not valid:
            return None, scopes
        
        scope_ids = [scope.id for scope in scopes]
        
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            scope_ids=json.dumps(scope_ids),
            redirect_uri=redirect_uri,
            expires_at=expires_at
        )
        
        db.session.add(auth_code)
        db.session.commit()
        
        return auth_code, None
    
    @staticmethod
    def exchange_code_for_authorization(code, client_id, redirect_uri):
        """Exchange authorization code for user authorization"""
        auth_code = AuthorizationCode.query.filter_by(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            used=False
        ).first()
        
        if not auth_code:
            return None, "Invalid authorization code"
        
        if auth_code.expires_at < datetime.datetime.utcnow():
            return None, "Authorization code expired"
        
        # Mark code as used
        auth_code.used = True
        
        # Create or update user authorization
        authorization = UserAuthorization.query.filter_by(
            user_id=auth_code.user_id,
            client_id=client_id,
            is_active=True
        ).first()
        
        if authorization:
            # Update existing authorization with new scopes
            authorization.scope_ids = auth_code.scope_ids
            authorization.granted_at = datetime.datetime.utcnow()
        else:
            # Create new authorization
            authorization = UserAuthorization(
                user_id=auth_code.user_id,
                client_id=client_id,
                scope_ids=auth_code.scope_ids
            )
            db.session.add(authorization)
        
        db.session.commit()
        
        return authorization, None
    
    @staticmethod
    def get_user_authorization(user_id, client_id):
        """Get user's authorization for a client"""
        return UserAuthorization.query.filter_by(
            user_id=user_id,
            client_id=client_id,
            is_active=True
        ).first()
    
    @staticmethod
    def revoke_authorization(user_id, client_id):
        """Revoke user's authorization for a client"""
        # Find all authorizations for this user/client combination
        authorizations = UserAuthorization.query.filter_by(
            user_id=user_id,
            client_id=client_id
        ).all()
        
        print(f"DEBUG: Found {len(authorizations)} authorization(s) for user {user_id}, client {client_id}")
        
        revoked_count = 0
        for authorization in authorizations:
            print(f"DEBUG: Authorization ID {authorization.id}, is_active: {authorization.is_active}")
            if authorization.is_active:
                authorization.is_active = False
                revoked_count += 1
                print(f"DEBUG: Revoked authorization ID {authorization.id}")
        
        if revoked_count > 0:
            db.session.commit()
            print(f"DEBUG: Committed {revoked_count} revocation(s)")
            return True
        
        print("DEBUG: No active authorizations found to revoke")
        return False
    
    @staticmethod
    def get_authorized_scopes(user_id, client_id):
        """Get scopes authorized by user for client"""
        authorization = AuthorizationManager.get_user_authorization(user_id, client_id)
        if not authorization:
            return []
        
        try:
            scope_ids = json.loads(authorization.scope_ids)
            scopes = DataScope.query.filter(DataScope.id.in_(scope_ids)).all()
            return [scope.name for scope in scopes]
        except (json.JSONDecodeError, TypeError):
            return []
    
    @staticmethod
    def update_last_used(user_id, client_id):
        """Update last used timestamp for authorization"""
        authorization = AuthorizationManager.get_user_authorization(user_id, client_id)
        if authorization:
            authorization.last_used = datetime.datetime.utcnow()
            db.session.commit()
