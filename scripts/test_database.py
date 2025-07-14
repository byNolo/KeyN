#!/usr/bin/env python3

import os
import sys
from dotenv import load_dotenv

# Add parent directory to path
sys.path.append('/home/sam/KeyN/Dev/KeyN')

# Load environment variables
load_dotenv('/home/sam/KeyN/Dev/KeyN/.env')

# Test database connection
from auth_server.app import create_app
from auth_server.app.models import User, db

app = create_app()

print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

with app.app_context():
    try:
        # Test if we can query users
        users = User.query.all()
        print(f"✅ Found {len(users)} users in database")
        
        # Test if we can create a user
        from werkzeug.security import generate_password_hash
        test_user = User(
            username='testuser', 
            email='test@example.com',
            password_hash=generate_password_hash('testpass')
        )
        
        db.session.add(test_user)
        db.session.commit()
        print("✅ Successfully created test user")
        
        # Clean up
        db.session.delete(test_user)
        db.session.commit()
        print("✅ Successfully deleted test user")
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        import traceback
        traceback.print_exc()
