#!/usr/bin/env python3
"""
Client management script for KeyN OAuth system
"""

import sys
import os
import argparse
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_server.app import create_app, db
from auth_server.app.models import User, ClientApplication, DataScope, UserAuthorization
from auth_server.app.oauth_utils import ClientManager, ScopeManager

def list_clients():
    """List all registered clients"""
    clients = ClientApplication.query.all()
    if not clients:
        print("No clients registered.")
        return
    
    print(f"{'ID':<10} {'Name':<30} {'Created By':<15} {'Active':<6}")
    print("-" * 70)
    for client in clients:
        creator = User.query.get(client.created_by)
        creator_name = creator.username if creator else "Unknown"
        status = "Yes" if client.is_active else "No"
        print(f"{client.client_id[:8]+'...':<10} {client.name[:28]:<30} {creator_name:<15} {status:<6}")

def show_client(client_id):
    """Show detailed client information"""
    client = ClientApplication.query.filter_by(client_id=client_id).first()
    if not client:
        print(f"Client {client_id} not found.")
        return
    
    creator = User.query.get(client.created_by)
    redirect_uris = json.loads(client.redirect_uris) if client.redirect_uris else []
    
    print(f"Client Details:")
    print(f"  ID: {client.client_id}")
    print(f"  Secret: {client.client_secret}")
    print(f"  Name: {client.name}")
    print(f"  Description: {client.description or 'None'}")
    print(f"  Website: {client.website_url or 'None'}")
    print(f"  Created by: {creator.username if creator else 'Unknown'}")
    print(f"  Created at: {client.created_at}")
    print(f"  Active: {'Yes' if client.is_active else 'No'}")
    print(f"  Redirect URIs:")
    for uri in redirect_uris:
        print(f"    • {uri}")
    
    # Show authorizations
    authorizations = UserAuthorization.query.filter_by(client_id=client_id, is_active=True).count()
    print(f"  Active Authorizations: {authorizations}")

def create_client(name, description, website_url, redirect_uris, creator_username):
    """Create a new client"""
    creator = User.query.filter_by(username=creator_username).first()
    if not creator:
        print(f"User {creator_username} not found.")
        return
    
    try:
        client = ClientManager.create_client(
            name=name,
            description=description,
            website_url=website_url,
            redirect_uris=redirect_uris,
            created_by_user_id=creator.id
        )
        
        print("✅ Client created successfully!")
        print(f"   Client ID: {client.client_id}")
        print(f"   Client Secret: {client.client_secret}")
        print("   Keep the client secret secure!")
        
    except Exception as e:
        print(f"❌ Failed to create client: {e}")

def deactivate_client(client_id):
    """Deactivate a client"""
    client = ClientApplication.query.filter_by(client_id=client_id).first()
    if not client:
        print(f"Client {client_id} not found.")
        return
    
    client.is_active = False
    db.session.commit()
    print(f"✅ Client {client_id} deactivated.")

def list_scopes():
    """List all available scopes"""
    scopes = DataScope.query.all()
    print(f"{'Name':<20} {'Display Name':<25} {'Active':<6}")
    print("-" * 55)
    for scope in scopes:
        status = "Yes" if scope.is_active else "No"
        print(f"{scope.name:<20} {scope.display_name:<25} {status:<6}")

def list_authorizations(username=None):
    """List user authorizations"""
    if username:
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"User {username} not found.")
            return
        authorizations = UserAuthorization.query.filter_by(user_id=user.id, is_active=True).all()
    else:
        authorizations = UserAuthorization.query.filter_by(is_active=True).all()
    
    if not authorizations:
        print("No active authorizations found.")
        return
    
    print(f"{'User':<20} {'Client':<30} {'Granted':<20} {'Last Used':<20}")
    print("-" * 95)
    for auth in authorizations:
        user = User.query.get(auth.user_id)
        client = ClientApplication.query.filter_by(client_id=auth.client_id).first()
        username = user.username if user else "Unknown"
        client_name = client.name if client else "Unknown"
        granted = auth.granted_at.strftime("%Y-%m-%d %H:%M") if auth.granted_at else "Unknown"
        last_used = auth.last_used.strftime("%Y-%m-%d %H:%M") if auth.last_used else "Never"
        
        print(f"{username:<20} {client_name[:28]:<30} {granted:<20} {last_used:<20}")

def main():
    parser = argparse.ArgumentParser(description="KeyN OAuth Client Management")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List clients
    subparsers.add_parser("list", help="List all clients")
    
    # Show client details
    show_parser = subparsers.add_parser("show", help="Show client details")
    show_parser.add_argument("client_id", help="Client ID")
    
    # Create client
    create_parser = subparsers.add_parser("create", help="Create a new client")
    create_parser.add_argument("name", help="Client name")
    create_parser.add_argument("creator", help="Creator username")
    create_parser.add_argument("--description", default="", help="Client description")
    create_parser.add_argument("--website", default="", help="Client website URL")
    create_parser.add_argument("--redirect-uris", nargs="+", required=True, help="Redirect URIs")
    
    # Deactivate client
    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate a client")
    deactivate_parser.add_argument("client_id", help="Client ID")
    
    # List scopes
    subparsers.add_parser("scopes", help="List all available scopes")
    
    # List authorizations
    auth_parser = subparsers.add_parser("authorizations", help="List user authorizations")
    auth_parser.add_argument("--user", help="Filter by username")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    app = create_app()
    with app.app_context():
        if args.command == "list":
            list_clients()
        elif args.command == "show":
            show_client(args.client_id)
        elif args.command == "create":
            create_client(
                args.name, 
                args.description, 
                args.website,
                args.redirect_uris,
                args.creator
            )
        elif args.command == "deactivate":
            deactivate_client(args.client_id)
        elif args.command == "scopes":
            list_scopes()
        elif args.command == "authorizations":
            list_authorizations(args.user)

if __name__ == "__main__":
    main()
