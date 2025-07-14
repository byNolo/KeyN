#!/bin/bash

# KeyN Production Deployment Script
# This script starts all KeyN services for production testing

echo "🔐 KeyN Production Deployment"
echo "============================="
echo ""

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
mkdir -p /home/sam/KeyN/Dev/KeyN/logs

# Auth Server (port 6000)
echo "📡 Starting Auth Server on port 6000..."
cd /home/sam/KeyN/Dev/KeyN/auth_server
nohup /home/sam/KeyN/Dev/KeyN/venv/bin/python run.py > ../logs/auth_server.log 2>&1 &
AUTH_PID=$!
echo "Auth Server PID: $AUTH_PID"

# UI Site (port 6001) 
echo "🌐 Starting UI Site on port 6001..."
cd /home/sam/KeyN/Dev/KeyN/ui_site
nohup /home/sam/KeyN/Dev/KeyN/venv/bin/python app.py > ../logs/ui_site.log 2>&1 &
UI_PID=$!
echo "UI Site PID: $UI_PID"

# Demo Client (port 6002)
echo "🎮 Starting Demo Client on port 6002..."
cd /home/sam/KeyN/Dev/KeyN/demo_client
nohup /home/sam/KeyN/Dev/KeyN/venv/bin/python app.py > ../logs/demo_client.log 2>&1 &
DEMO_PID=$!
echo "Demo Client PID: $DEMO_PID"

# Wait a moment for services to start
sleep 3

echo ""
echo "🚀 KeyN Services Started!"
echo "========================="
echo ""
echo "Local Services (accessed via Cloudflare Tunnel):"
echo "🏠 KeyN UI Site:    localhost:6001 → https://keyn.nolanbc.ca"
echo "🔐 Auth Server:     localhost:6000 → https://auth-keyn.nolanbc.ca"
echo "🎮 Demo Client:     localhost:6002 → https://demo-keyn.nolanbc.ca"
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

echo ""
echo "🎯 Next Steps:"
echo "1. Configure your Cloudflare Tunnel with the ingress rules:"
echo "   ./scripts/setup_cloudflare_tunnel.sh"
echo "2. Add DNS CNAME records in Cloudflare dashboard"
echo "3. Test the SSO flow at https://demo-keyn.nolanbc.ca"
echo ""
echo "🌩️ Cloudflare Tunnel Configuration:"
echo "Run: ./scripts/setup_cloudflare_tunnel.sh for complete setup instructions"
