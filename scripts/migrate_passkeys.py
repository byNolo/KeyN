#!/usr/bin/env python3
"""
Passkey / WebAuthn migration script for KeyN

Creates the passkey_credential table if it does not already exist.
Safe to run multiple times (idempotent). Only supports SQLite (current deployment model).

Fields (mirrors auth_server.app.models.PasskeyCredential):
  id INTEGER PRIMARY KEY
  user_id INTEGER NOT NULL (FK -> user.id)
  credential_id VARCHAR(255) UNIQUE NOT NULL (base64url credential ID)
  public_key TEXT NOT NULL (base64url encoded COSE key)
  sign_count INTEGER DEFAULT 0
  transports VARCHAR(255) NULL (comma-separated transports)
  created_at DATETIME
  last_used DATETIME NULL
  friendly_name VARCHAR(255) NULL

Usage:
  python scripts/migrate_passkeys.py

After running, you can verify:
  sqlite3 instance/keyn_auth.db ".schema passkey_credential"
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


def migrate_passkeys():
    app = create_app()
    with app.app_context():
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if not db_uri.startswith('sqlite:///'):
            print("❌ This migration script currently supports only SQLite.")
            print(f"   Detected URI: {db_uri}")
            return 1

        db_path = db_uri.replace('sqlite:///', '')
        print(f"📦 Database path: {db_path}")

        if not os.path.exists(db_path):
            print("⚠️  Database file does not exist yet. Creating all tables via SQLAlchemy ...")
            db.create_all()
            print("✅ All tables created (including passkey_credential). Migration complete.")
            return 0

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            if table_exists(cursor, 'passkey_credential'):
                print("ℹ️  Table 'passkey_credential' already exists. Nothing to do.")
            else:
                print("🛠  Creating 'passkey_credential' table...")
                cursor.execute(
                    """
                    CREATE TABLE passkey_credential (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        credential_id VARCHAR(255) NOT NULL UNIQUE,
                        public_key TEXT NOT NULL,
                        sign_count INTEGER DEFAULT 0,
                        transports VARCHAR(255),
                        created_at DATETIME,
                        last_used DATETIME,
                        friendly_name VARCHAR(255),
                        FOREIGN KEY(user_id) REFERENCES user (id)
                    )
                    """
                )
                print("✅ Table created.")

            # Ensure index on user_id for faster lookups
            if not index_exists(cursor, 'idx_passkey_user_id'):
                print("🛠  Creating index idx_passkey_user_id...")
                cursor.execute("CREATE INDEX idx_passkey_user_id ON passkey_credential (user_id)")
                print("✅ Index created.")
            else:
                print("ℹ️  Index idx_passkey_user_id already exists.")

            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"❌ Migration failed: {e}")
            raise
        finally:
            conn.close()

        # Let SQLAlchemy pick up the model metadata (no-op if already correct)
        db.create_all()
        print("🎉 Passkey migration completed successfully at", datetime.utcnow().isoformat(), 'UTC')
        return 0


if __name__ == '__main__':
    raise SystemExit(migrate_passkeys())
