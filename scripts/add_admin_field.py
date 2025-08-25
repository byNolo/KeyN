#!/usr/bin/env python3
"""
Migration script to add is_admin field to User model
Run this after updating the User model to add admin functionality
"""

import sys
import os

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from auth_server.app import create_app, db
from auth_server.app.models import User

def add_admin_field():
    """Add is_admin field to existing User table"""
    app = create_app()
    
    with app.app_context():
        try:
            # Check if the column already exists
            inspector = db.inspect(db.engine)
            columns = [column['name'] for column in inspector.get_columns('user')]
            
            if 'is_admin' not in columns:
                print("Adding is_admin column to User table...")
                
                # Add the column using raw SQL
                with db.engine.connect() as conn:
                    conn.execute(db.text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
                    conn.commit()
                
                print("✓ Successfully added is_admin column")
                
                # Optionally, make the first user an admin
                first_user = User.query.first()
                if first_user:
                    print(f"Making first user '{first_user.username}' an admin...")
                    first_user.is_admin = True
                    db.session.commit()
                    print(f"✓ User '{first_user.username}' is now an admin")
                else:
                    print("No users found in database")
                    
            else:
                print("✓ is_admin column already exists")
                
                # Check if there are any admins
                admin_count = User.query.filter_by(is_admin=True).count()
                if admin_count == 0:
                    first_user = User.query.first()
                    if first_user:
                        print(f"No admins found. Making first user '{first_user.username}' an admin...")
                        first_user.is_admin = True
                        db.session.commit()
                        print(f"✓ User '{first_user.username}' is now an admin")
                else:
                    print(f"✓ Found {admin_count} admin user(s)")
                    
        except Exception as e:
            print(f"✗ Error during migration: {e}")
            return False
            
    return True

if __name__ == "__main__":
    print("KeyN Admin Field Migration")
    print("=" * 30)
    
    if add_admin_field():
        print("\n✓ Migration completed successfully!")
        print("\nNOTE: Make sure to restart your auth server for changes to take effect.")
        print("You can now access the admin panel at /admin (admin users only)")
    else:
        print("\n✗ Migration failed!")
        sys.exit(1)
