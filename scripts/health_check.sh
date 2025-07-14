#!/bin/bash

# KeyN Health Check Script
# Monitors service health and can auto-restart if needed

echo "🔍 KeyN Health Check - $(date)"
echo "========================================"

# Configuration
KEYN_DIR="${KEYN_PROJECT_DIR:-/home/sam/KeyN/Dev/KeyN}"
HEALTH_LOG="$KEYN_DIR/logs/health_check.log"
AUTO_RESTART=${1:-false}  # Pass 'true' as first argument to enable auto-restart

# Health check URLs from environment or defaults
AUTH_HEALTH_URL="${KEYN_HEALTH_CHECK_AUTH_URL:-https://auth-keyn.nolanbc.ca/health}"
UI_SITE_URL="${KEYN_HEALTH_CHECK_UI_URL:-https://keyn.nolanbc.ca}"
DEMO_CLIENT_URL="${KEYN_HEALTH_CHECK_DEMO_URL:-https://demo-keyn.nolanbc.ca}"

# Ensure logs directory exists
mkdir -p "$KEYN_DIR/logs"

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$HEALTH_LOG"
}

# Function to check if a port is listening
check_port() {
    local port=$1
    local service_name=$2
    
    if ss -tln | grep -q ":$port"; then
        echo "✅ $service_name (port $port): Running"
        log_message "SUCCESS: $service_name running on port $port"
        return 0
    else
        echo "❌ $service_name (port $port): Down"
        log_message "ERROR: $service_name not running on port $port"
        return 1
    fi
}

# Function to check HTTP endpoint
check_endpoint() {
    local url=$1
    local service_name=$2
    local timeout=${3:-10}
    
    if curl -s --max-time $timeout "$url" > /dev/null 2>&1; then
        echo "✅ $service_name: Accessible"
        log_message "SUCCESS: $service_name accessible at $url"
        return 0
    else
        echo "❌ $service_name: Not accessible"
        log_message "ERROR: $service_name not accessible at $url"
        return 1
    fi
}

# Check local services
services_down=0

echo "📊 Local Services Status:"
check_port 6000 "Auth Server" || ((services_down++))
check_port 6001 "UI Site" || ((services_down++))
check_port 6002 "Demo Client" || ((services_down++))

echo ""
echo "🌐 External Endpoints:"

# Check external endpoints (if tunnel is running)
check_endpoint "$AUTH_HEALTH_URL" "KeyN Auth Health"
auth_health_status=$?

check_endpoint "$UI_SITE_URL" "KeyN UI Site"
ui_status=$?

check_endpoint "$DEMO_CLIENT_URL" "Demo Client"
demo_status=$?

echo ""
echo "📈 System Resources:"

# Check disk space for logs and database
db_size=$(du -h "$KEYN_DIR/auth_server/instance/keyn_auth.db" 2>/dev/null | cut -f1 || echo "N/A")
log_dir_size=$(du -sh "$KEYN_DIR/logs" 2>/dev/null | cut -f1 || echo "N/A")

echo "💾 Database size: $db_size"
echo "📝 Logs directory size: $log_dir_size"

# Check memory usage of KeyN processes
echo "🧠 KeyN Process Memory Usage:"
ps aux | grep -E "(run\.py|app\.py)" | grep -v grep | awk '{print "   " $11 ": " $6/1024 "MB (PID: " $2 ")"}'

echo ""
echo "📋 Summary:"
total_issues=$((services_down + auth_health_status + ui_status + demo_status))

if [ $total_issues -eq 0 ]; then
    echo "🎉 All services are healthy!"
    log_message "SUCCESS: All services healthy"
else
    echo "⚠️  Found $total_issues issue(s)"
    log_message "WARNING: Found $total_issues issues"
    
    # Auto-restart if enabled and local services are down
    if [ "$AUTO_RESTART" = "true" ] && [ $services_down -gt 0 ]; then
        echo ""
        echo "🔄 Auto-restart enabled, restarting services..."
        log_message "INFO: Auto-restarting services due to $services_down local service(s) down"
        
        cd "$KEYN_DIR"
        ./scripts/deploy_production.sh
        
        # Wait and re-check
        sleep 10
        echo ""
        echo "🔍 Re-checking after restart..."
        check_port 6000 "Auth Server"
        check_port 6001 "UI Site" 
        check_port 6002 "Demo Client"
    fi
fi

echo ""
echo "📄 Recent health log (last 5 entries):"
tail -5 "$HEALTH_LOG" 2>/dev/null || echo "No health log entries yet"

# Cleanup old log entries (keep last 1000 lines)
if [ -f "$HEALTH_LOG" ]; then
    tail -1000 "$HEALTH_LOG" > "$HEALTH_LOG.tmp" && mv "$HEALTH_LOG.tmp" "$HEALTH_LOG"
fi

echo ""
echo "💡 Usage:"
echo "   ./scripts/health_check.sh        - Check health only"
echo "   ./scripts/health_check.sh true   - Check health and auto-restart if needed"
echo "   tail -f $HEALTH_LOG              - Monitor health log"
