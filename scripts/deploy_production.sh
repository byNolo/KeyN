#!/bin/bash

# KeyN Production Deployment Script
# This script starts all KeyN services for production testing

echo "🔐 KeyN Production Deployment"
echo "============================="
echo ""

# Configuration from environment variables
KEYN_DIR="${KEYN_PROJECT_DIR:-/home/sam/KeyN/Dev/KeyN}"
VENV_PATH="${KEYN_VENV_PATH:-$KEYN_DIR/venv}"
AUTH_URL="${KEYN_AUTH_SERVER_URL:-https://auth-keyn.nolanbc.ca}"
UI_URL="${KEYN_UI_SITE_URL:-https://keyn.nolanbc.ca}"
DEMO_URL="${KEYN_DEMO_CLIENT_URL:-https://demo-keyn.nolanbc.ca}"

# Kill any existing processes
echo "Stopping existing services..."
pkill -f "python.*run.py" 2>/dev/null
pkill -f "python.*app.py" 2>/dev/null
pkill -f "python.*ui_site" 2>/dev/null
pkill -f "python.*demo_client" 2>/dev/null
sleep 2

# Start services
echo "Starting KeyN services..."

# Create logs directory if it doesn't exist
mkdir -p "$KEYN_DIR/logs"

# Auth Server (port 6000)
echo "📡 Starting Auth Server on port 6000..."
cd "$KEYN_DIR/auth_server"
nohup "$VENV_PATH/bin/python" run.py > ../logs/auth_server.log 2>&1 &
AUTH_PID=$!
echo "Auth Server PID: $AUTH_PID"

# UI Site (port 6001) 
echo "🌐 Starting UI Site on port 6001..."
cd "$KEYN_DIR/ui_site"
nohup "$VENV_PATH/bin/python" app.py > ../logs/ui_site.log 2>&1 &
UI_PID=$!
echo "UI Site PID: $UI_PID"

# Demo Client (port 6002)
echo "🎮 Starting Demo Client on port 6002..."
cd "$KEYN_DIR/demo_client"
nohup "$VENV_PATH/bin/python" app.py > ../logs/demo_client.log 2>&1 &
DEMO_PID=$!
echo "Demo Client PID: $DEMO_PID"

# Wait a moment for services to start
sleep 3

echo ""
echo "🚀 KeyN Services Started!"
echo "========================="
echo ""
echo "Local Services (accessed via Cloudflare Tunnel):"
echo "🏠 KeyN UI Site:    localhost:6001 → $UI_URL"
echo "🔐 Auth Server:     localhost:6000 → $AUTH_URL"
echo "🎮 Demo Client:     localhost:6002 → $DEMO_URL"
echo ""
echo "Process IDs:"
echo "Auth Server: $AUTH_PID"
echo "UI Site:     $UI_PID"
echo "Demo Client: $DEMO_PID"
echo ""
echo "To stop services: ./scripts/stop_keyn_services.sh"
echo "To view logs:     tail -f logs/[service].log"
echo ""

# Check if services are running
echo "Checking service status..."
sleep 2

if ss -tln | grep -q ":6000"; then
    echo "✅ Auth Server (port 6000) is running"
else
    echo "❌ Auth Server (port 6000) failed to start"
fi

if ss -tln | grep -q ":6001"; then
    echo "✅ UI Site (port 6001) is running"
else
    echo "❌ UI Site (port 6001) failed to start"
fi

if ss -tln | grep -q ":6002"; then
    echo "✅ Demo Client (port 6002) is running"
else
    echo "❌ Demo Client (port 6002) failed to start"
fi
