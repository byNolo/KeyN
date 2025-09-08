#!/usr/bin/env python3
"""
Setup script for KeyN OAuth system
Creates the database tables and initializes demo client credentials
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_server.app import create_app, db
from auth_server.app.models import User, ClientApplication, DataScope
from auth_server.app.oauth_utils import ClientManager, ScopeManager
import json

def setup_oauth_system():
    """Set up the OAuth system with demo client"""
    app = create_app()
    
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        
        print("Initializing default scopes...")
        ScopeManager.initialize_default_scopes()
        
        print("Creating demo client...")
        
        # Check if demo client already exists
        existing_client = ClientApplication.query.filter_by(name="KeyN OAuth Demo Client").first()
        if existing_client:
            print(f"Demo client already exists with ID: {existing_client.client_id}")
            print(f"Client Secret: {existing_client.client_secret}")
            return
        
        # Get first admin user to assign as creator
        admin_user = User.query.first()
        if not admin_user:
            print("ERROR: No users found. Please create an admin user first.")
            return
        
        # Create demo client
        redirect_uris = [
            "http://localhost:5001/oauth/callback",
            "https://demo-keyn.bynolo.ca/oauth/callback"
        ]
        
        client = ClientManager.create_client(
            name="KeyN OAuth Demo Client",
            description="Demo application showing OAuth integration with KeyN",
            website_url="https://demo-keyn.bynolo.ca",
            redirect_uris=redirect_uris,
            created_by_user_id=admin_user.id
        )
        
        print("✅ Demo client created successfully!")
        print(f"   Client ID: {client.client_id}")
        print(f"   Client Secret: {client.client_secret}")
        print(f"   Redirect URIs: {json.loads(client.redirect_uris)}")
        
        # Display available scopes
        scopes = DataScope.query.filter_by(is_active=True).all()
        print(f"\n📋 Available scopes ({len(scopes)}):")
        for scope in scopes:
            print(f"   • {scope.name}: {scope.display_name}")
        
        print("\n🔧 To use the demo client:")
        print("1. Set these environment variables in your demo client:")
        print(f"   KEYN_CLIENT_ID={client.client_id}")
        print(f"   KEYN_CLIENT_SECRET={client.client_secret}")
        print("2. Run the demo client with: python demo_client/oauth_app.py")
        print("3. Visit http://localhost:5001 to test the OAuth flow")

if __name__ == "__main__":
    setup_oauth_system()
