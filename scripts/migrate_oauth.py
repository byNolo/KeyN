#!/usr/bin/env python3
"""
Database migration script for KeyN OAuth system
Adds new columns and tables for OAuth functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_server.app import create_app, db
from auth_server.app.models import User, ClientApplication, DataScope, UserAuthorization, AuthorizationCode
import sqlite3

def migrate_database():
    """Migrate the database to support OAuth functionality"""
    app = create_app()
    
    with app.app_context():
        # Get database path
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
        else:
            print("ERROR: Only SQLite databases are supported for migration")
            return
        
        print(f"Migrating database: {db_path}")
        
        # Connect directly to SQLite to add columns
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            # Add new columns to user table
            new_user_columns = [
                ('first_name', 'VARCHAR(100)'),
                ('last_name', 'VARCHAR(100)'),
                ('display_name', 'VARCHAR(200)'),
                ('bio', 'TEXT'),
                ('website', 'VARCHAR(500)'),
                ('location', 'VARCHAR(200)'),
                ('date_of_birth', 'DATE')
            ]
            
            for column_name, column_type in new_user_columns:
                try:
                    cursor.execute(f"ALTER TABLE user ADD COLUMN {column_name} {column_type}")
                    print(f"✅ Added column {column_name} to user table")
                except sqlite3.OperationalError as e:
                    if "duplicate column name" in str(e).lower():
                        print(f"⚠️  Column {column_name} already exists in user table")
                    else:
                        print(f"❌ Error adding column {column_name}: {e}")
            
            # Add missing columns to login_attempt table if they don't exist
            login_attempt_columns = [
                ('username_attempted', 'VARCHAR(150)'),
                ('success', 'BOOLEAN DEFAULT 0'),
                ('timestamp', 'DATETIME DEFAULT CURRENT_TIMESTAMP'),
                ('failure_reason', 'VARCHAR(255)')
            ]
            
            for column_name, column_type in login_attempt_columns:
                try:
                    cursor.execute(f"ALTER TABLE login_attempt ADD COLUMN {column_name} {column_type}")
                    print(f"✅ Added column {column_name} to login_attempt table")
                except sqlite3.OperationalError as e:
                    if "duplicate column name" in str(e).lower():
                        print(f"⚠️  Column {column_name} already exists in login_attempt table")
                    else:
                        print(f"❌ Error adding column {column_name}: {e}")
            
            conn.commit()
            conn.close()
            
            # Now create all tables using SQLAlchemy
            print("Creating new OAuth tables...")
            db.create_all()
            
            print("✅ Database migration completed successfully!")
            
        except Exception as e:
            conn.rollback()
            conn.close()
            print(f"❌ Migration failed: {e}")
            raise

if __name__ == "__main__":
    migrate_database()
