#!/bin/bash

# Stop all KeyN services

echo "🛑 Stopping KeyN Services..."

pkill -f "python.*run.py"
pkill -f "python.*app.py" 
pkill -f "python.*oauth_app.py"
pkill -f "python.*ui_site"
pkill -f "python.*demo_client"
pkill -f "python.*auth_server"

echo "✅ All KeyN services stopped"

# Show remaining processes (if any)
REMAINING=$(ps aux | grep -E "(run\.py|app\.py)" | grep -v grep)
if [ ! -z "$REMAINING" ]; then
    echo "⚠️  Remaining Python processes:"
    echo "$REMAINING"
else
    echo "🎯 All KeyN processes terminated successfully"
fi
