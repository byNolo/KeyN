#!/bin/bash

# KeyN Cloudflare Tunnel Configuration Generatecho "🌐 DNS Configuration (Add to Cloudflare DNS):"
echo "auth-keyn.nolanbc.ca  CNAME  YOUR_TUNNEL_ID.cfargotunnel.com"
echo "keyn.nolanbc.ca       CNAME  YOUR_TUNNEL_ID.cfargotunnel.com"
echo "demo-keyn.nolanbc.ca  CNAME  YOUR_TUNNEL_ID.cfargotunnel.com"
echo ""

echo "🚀 Cloudflare Tunnel Commands:"
echo "# Route DNS (if using CLI)"
echo "cloudflared tunnel route dns YOUR_TUNNEL_NAME auth-keyn.nolanbc.ca"
echo "cloudflared tunnel route dns YOUR_TUNNEL_NAME keyn.nolanbc.ca"
echo "cloudflared tunnel route dns YOUR_TUNNEL_NAME demo-keyn.nolanbc.ca"️ KeyN Cloudflare Tunnel Configuration"
echo "========================================"
echo ""

# Check if services are running
echo "Checking KeyN services status..."
if ss -tln | grep -q ":6000"; then
    echo "✅ Auth Server (port 6000) is running"
else
    echo "❌ Auth Server (port 6000) is NOT running"
    echo "   Run: ./scripts/deploy_production.sh"
fi

if ss -tln | grep -q ":6001"; then
    echo "✅ UI Site (port 6001) is running"
else
    echo "❌ UI Site (port 6001) is NOT running"
    echo "   Run: ./scripts/deploy_production.sh"
fi

if ss -tln | grep -q ":6002"; then
    echo "✅ Demo Client (port 6002) is running"
else
    echo "❌ Demo Client (port 6002) is NOT running"
    echo "   Run: ./scripts/deploy_production.sh"
fi

echo ""
echo "📋 Cloudflare Tunnel Configuration"
echo "Add this to your tunnel.yml or Cloudflare Zero Trust dashboard:"
echo ""

cat << 'EOF'
# tunnel.yml configuration
tunnel: YOUR_TUNNEL_ID
credentials-file: /path/to/credentials.json

ingress:
  # KeyN Auth Server
  - hostname: auth-keyn.nolanbc.ca
    service: http://localhost:6000
    
  # KeyN UI Site  
  - hostname: keyn.nolanbc.ca
    service: http://localhost:6001
    
  # KeyN Demo Client
  - hostname: demo-keyn.nolanbc.ca
    service: http://localhost:6002
    
  # Catch-all (required)
  - service: http_status:404
EOF

echo ""
echo "🌐 DNS Configuration (Add to Cloudflare DNS):"
echo "keyn-auth.nolanbc.ca  CNAME  YOUR_TUNNEL_ID.cfargotunnel.com"
echo "keyn.nolanbc.ca       CNAME  YOUR_TUNNEL_ID.cfargotunnel.com"
echo "keyn-demo.nolanbc.ca  CNAME  YOUR_TUNNEL_ID.cfargotunnel.com"
echo ""

echo "🚀 Cloudflare Tunnel Commands:"
echo "# Route DNS (if using CLI)"
echo "cloudflared tunnel route dns YOUR_TUNNEL_NAME keyn-auth.nolanbc.ca"
echo "cloudflared tunnel route dns YOUR_TUNNEL_NAME keyn.nolanbc.ca"
echo "cloudflared tunnel route dns YOUR_TUNNEL_NAME keyn-demo.nolanbc.ca"
echo ""
echo "# Run the tunnel"
echo "cloudflared tunnel run YOUR_TUNNEL_NAME"
echo ""

echo "🎯 Test URLs (after tunnel is configured):"
echo "https://keyn.nolanbc.ca          - KeyN UI Site"
echo "https://auth-keyn.nolanbc.ca     - Auth Server"
echo "https://demo-keyn.nolanbc.ca     - Demo Client"
echo ""

echo "📝 Notes:"
echo "- Replace YOUR_TUNNEL_ID and YOUR_TUNNEL_NAME with your actual values"
echo "- Cloudflare provides automatic HTTPS/SSL"
echo "- No firewall configuration needed"
echo "- Services run on localhost ports, exposed via tunnel"
