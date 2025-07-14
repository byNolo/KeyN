#!/usr/bin/env python3
"""
Database migration script to add IP banning and device tracking tables.
Run this to update your existing database with the new features.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_server.app import create_app, db
from auth_server.app.models import User, RefreshToken, IPBan, DeviceBan, LoginAttempt

def migrate_database():
    """Create new tables and update existing ones"""
    app = create_app()
    
    with app.app_context():
        print("Creating new tables...")
        
        # Create all tables (will only create missing ones)
        db.create_all()
        
        print("✅ Database updated successfully!")
        print("\nNew tables added:")
        print("- IPBan: Track banned IP addresses")
        print("- DeviceBan: Track banned device fingerprints") 
        print("- LoginAttempt: Track all login attempts for analysis")
        print("\nNew features available:")
        print("- Proper IP detection (works with Cloudflare)")
        print("- IP address banning")
        print("- Device fingerprinting and banning")
        print("- Rate limiting based on failed attempts")
        print("- Comprehensive login attempt logging")

if __name__ == "__main__":
    migrate_database()
