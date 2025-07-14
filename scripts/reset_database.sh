#!/bin/bash

# KeyN Database Reset Script
# This script recreates the database with proper permissions

echo "🔄 Resetting KeyN Database..."

# Stop auth server
pkill -f "auth_server" 2>/dev/null

# Backup old database
if [ -f "/home/sam/KeyN/Dev/KeyN/auth_server/instance/keyn_auth.db" ]; then
    cp /home/sam/KeyN/Dev/KeyN/auth_server/instance/keyn_auth.db /home/sam/KeyN/Dev/KeyN/auth_server/instance/keyn_auth.db.backup
    echo "📦 Database backed up"
fi

# Remove old database
rm -f /home/sam/KeyN/Dev/KeyN/auth_server/instance/keyn_auth.db

# Recreate database
cd /home/sam/KeyN/Dev/KeyN
/home/sam/KeyN/Dev/KeyN/venv/bin/python -c "
from auth_server.app import create_app
from auth_server.app.models import db

app = create_app()
with app.app_context():
    db.create_all()
    print('✅ Database tables created')
"

# Set proper permissions
chmod 664 /home/sam/KeyN/Dev/KeyN/auth_server/instance/keyn_auth.db
chmod 775 /home/sam/KeyN/Dev/KeyN/auth_server/instance/

echo "✅ Database reset complete!"
echo "📍 Database location: /home/sam/KeyN/Dev/KeyN/auth_server/instance/keyn_auth.db"
