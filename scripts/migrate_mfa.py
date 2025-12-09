#!/usr/bin/env python3
"""
Multi-Factor Authentication (MFA) migration script for KeyN

Creates the MFA-related tables if they do not already exist:
- mfa_secret: Stores encrypted TOTP secrets for users
- mfa_backup_code: Stores hashed backup codes for MFA recovery
- mfa_trusted_device: Tracks devices that can skip MFA for a limited time

Safe to run multiple times (idempotent). Only supports SQLite (current deployment model).

Usage:
  python scripts/migrate_mfa.py

After running, you can verify:
  sqlite3 instance/keyn_auth.db ".schema mfa_secret"
  sqlite3 instance/keyn_auth.db ".schema mfa_backup_code"
  sqlite3 instance/keyn_auth.db ".schema mfa_trusted_device"
"""

import sys
import os
import sqlite3
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_server.app import create_app, db  # noqa: E402


def table_exists(cursor, name: str) -> bool:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cursor.fetchone() is not None


def index_exists(cursor, name: str) -> bool:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (name,))
    return cursor.fetchone() is not None


def migrate_mfa():
    app = create_app()
    with app.app_context():
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if not db_uri.startswith('sqlite:///'):
            print("Error: This migration script only supports SQLite databases.")
            print(f"Current database URI: {db_uri}")
            return 1

        db_path = db_uri.replace('sqlite:///', '')
        if not os.path.exists(db_path):
            print(f"Error: Database file not found at {db_path}")
            return 1

        print(f"Using database: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Track changes
        changes_made = False

        # Create mfa_secret table
        if not table_exists(cursor, 'mfa_secret'):
            print("Creating mfa_secret table...")
            cursor.execute("""
                CREATE TABLE mfa_secret (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    encrypted_secret VARCHAR(255) NOT NULL,
                    created_at DATETIME NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT 1,
                    last_used DATETIME,
                    FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
                )
            """)
            changes_made = True
            print("✓ Created mfa_secret table")
        else:
            print("✓ mfa_secret table already exists")

        # Create index on user_id for mfa_secret
        if not index_exists(cursor, 'ix_mfa_secret_user_id'):
            print("Creating index on mfa_secret.user_id...")
            cursor.execute("CREATE INDEX ix_mfa_secret_user_id ON mfa_secret (user_id)")
            changes_made = True
            print("✓ Created index ix_mfa_secret_user_id")
        else:
            print("✓ Index ix_mfa_secret_user_id already exists")

        # Create mfa_backup_code table
        if not table_exists(cursor, 'mfa_backup_code'):
            print("Creating mfa_backup_code table...")
            cursor.execute("""
                CREATE TABLE mfa_backup_code (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    code_hash VARCHAR(255) NOT NULL,
                    used BOOLEAN NOT NULL DEFAULT 0,
                    used_at DATETIME,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
                )
            """)
            changes_made = True
            print("✓ Created mfa_backup_code table")
        else:
            print("✓ mfa_backup_code table already exists")

        # Create index on user_id for mfa_backup_code
        if not index_exists(cursor, 'ix_mfa_backup_code_user_id'):
            print("Creating index on mfa_backup_code.user_id...")
            cursor.execute("CREATE INDEX ix_mfa_backup_code_user_id ON mfa_backup_code (user_id)")
            changes_made = True
            print("✓ Created index ix_mfa_backup_code_user_id")
        else:
            print("✓ Index ix_mfa_backup_code_user_id already exists")

        # Create mfa_trusted_device table
        if not table_exists(cursor, 'mfa_trusted_device'):
            print("Creating mfa_trusted_device table...")
            cursor.execute("""
                CREATE TABLE mfa_trusted_device (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    device_fingerprint VARCHAR(128) NOT NULL,
                    device_name VARCHAR(255),
                    ip_address VARCHAR(64),
                    user_agent VARCHAR(512),
                    trusted_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL,
                    last_used DATETIME,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
                )
            """)
            changes_made = True
            print("✓ Created mfa_trusted_device table")
        else:
            print("✓ mfa_trusted_device table already exists")

        # Create index on user_id for mfa_trusted_device
        if not index_exists(cursor, 'ix_mfa_trusted_device_user_id'):
            print("Creating index on mfa_trusted_device.user_id...")
            cursor.execute("CREATE INDEX ix_mfa_trusted_device_user_id ON mfa_trusted_device (user_id)")
            changes_made = True
            print("✓ Created index ix_mfa_trusted_device_user_id")
        else:
            print("✓ Index ix_mfa_trusted_device_user_id already exists")

        if changes_made:
            conn.commit()
            print("\n✓ Migration completed successfully!")
            print("\nMFA tables created:")
            print("  - mfa_secret: TOTP secret storage")
            print("  - mfa_backup_code: Backup codes for recovery")
            print("  - mfa_trusted_device: Trusted device tracking")
        else:
            print("\n✓ All MFA tables already exist. No changes needed.")

        conn.close()
        return 0


if __name__ == '__main__':
    try:
        exit_code = migrate_mfa()
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n✗ Migration failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
