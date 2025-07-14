#!/bin/bash

# KeyN Cron Setup Helper
# Sets up automated health checks and log management

KEYN_DIR="${KEYN_PROJECT_DIR:-/home/sam/KeyN/Dev/KeyN}"
CRON_FILE="/tmp/keyn_cron_jobs"

echo "⏰ KeyN Automated Maintenance Setup"
echo "==================================="

# Check if scripts exist and are executable
if [ ! -x "$KEYN_DIR/scripts/health_check.sh" ]; then
    echo "❌ Health check script not found or not executable"
    echo "   Run: chmod +x $KEYN_DIR/scripts/health_check.sh"
    exit 1
fi

if [ ! -x "$KEYN_DIR/scripts/manage_logs.sh" ]; then
    echo "❌ Log management script not found or not executable"
    echo "   Run: chmod +x $KEYN_DIR/scripts/manage_logs.sh"
    exit 1
fi

echo "📋 Available cron job options:"
echo ""
echo "1. Health check every 5 minutes"
echo "2. Health check with auto-restart every 5 minutes"
echo "3. Log rotation daily at 2 AM"
echo "4. Weekly log cleanup (Sundays at 3 AM)"
echo "5. All of the above (recommended)"
echo "6. Remove all KeyN cron jobs"
echo ""

read -p "Choose an option (1-6): " choice

# Create cron entries based on choice
> "$CRON_FILE"

case $choice in
    1|5)
        echo "# KeyN health check every 5 minutes" >> "$CRON_FILE"
        echo "*/5 * * * * $KEYN_DIR/scripts/health_check.sh >> $KEYN_DIR/logs/cron.log 2>&1" >> "$CRON_FILE"
        ;;
    2)
        echo "# KeyN health check with auto-restart every 5 minutes" >> "$CRON_FILE"
        echo "*/5 * * * * $KEYN_DIR/scripts/health_check.sh true >> $KEYN_DIR/logs/cron.log 2>&1" >> "$CRON_FILE"
        ;;
esac

case $choice in
    3|5)
        echo "# KeyN log rotation daily at 2 AM" >> "$CRON_FILE"
        echo "0 2 * * * $KEYN_DIR/scripts/manage_logs.sh >> $KEYN_DIR/logs/cron.log 2>&1" >> "$CRON_FILE"
        ;;
esac

case $choice in
    4|5)
        echo "# KeyN weekly cleanup on Sundays at 3 AM" >> "$CRON_FILE"
        echo "0 3 * * 0 find $KEYN_DIR/logs/archive -name '*.gz' -mtime +30 -delete" >> "$CRON_FILE"
        ;;
esac

if [ "$choice" = "6" ]; then
    # Remove KeyN cron jobs
    echo "🗑️  Removing existing KeyN cron jobs..."
    crontab -l 2>/dev/null | grep -v "KeyN\|$KEYN_DIR" | crontab -
    echo "✅ KeyN cron jobs removed"
    rm -f "$CRON_FILE"
    exit 0
fi

if [ ! -s "$CRON_FILE" ]; then
    echo "❌ No cron jobs selected"
    rm -f "$CRON_FILE"
    exit 1
fi

echo ""
echo "📝 Cron jobs to be added:"
cat "$CRON_FILE"
echo ""

read -p "Add these cron jobs? (y/N): " confirm

if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    # Backup existing cron
    crontab -l 2>/dev/null > /tmp/cron_backup
    
    # Remove existing KeyN cron jobs and add new ones
    (crontab -l 2>/dev/null | grep -v "KeyN\|$KEYN_DIR"; cat "$CRON_FILE") | crontab -
    
    echo "✅ Cron jobs added successfully!"
    echo ""
    echo "📋 Current crontab:"
    crontab -l | grep -A5 -B5 "KeyN\|$KEYN_DIR"
    echo ""
    echo "💡 To view cron logs: tail -f $KEYN_DIR/logs/cron.log"
    echo "💡 To remove cron jobs: $0 and select option 6"
    echo "💡 Cron backup saved to: /tmp/cron_backup"
    
    # Create logs directory if needed
    mkdir -p "$KEYN_DIR/logs"
    
else
    echo "❌ Cron jobs not added"
fi

rm -f "$CRON_FILE"
