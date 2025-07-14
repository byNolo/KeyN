#!/bin/bash

# KeyN Log Management Script
# Handles log rotation, archiving, and cleanup

KEYN_DIR="${KEYN_PROJECT_DIR:-/home/sam/KeyN/Dev/KeyN}"
LOGS_DIR="$KEYN_DIR/logs"
ARCHIVE_DIR="$LOGS_DIR/archive"
MAX_LOG_SIZE="50M"
KEEP_DAYS=30

echo "📝 KeyN Log Management - $(date)"
echo "=================================="

# Create directories if they don't exist
mkdir -p "$ARCHIVE_DIR"

# Function to rotate a log file
rotate_log() {
    local log_file=$1
    local service_name=$2
    
    if [ -f "$log_file" ]; then
        local file_size=$(du -h "$log_file" | cut -f1)
        local size_bytes=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null)
        
        echo "📄 $service_name log: $file_size"
        
        # Check if log file is larger than max size (50MB = 52428800 bytes)
        if [ "$size_bytes" -gt 52428800 ]; then
            echo "   🔄 Rotating large log file..."
            
            # Create timestamped archive
            local timestamp=$(date '+%Y%m%d_%H%M%S')
            local archive_name="${log_file##*/}.${timestamp}"
            
            # Compress and move to archive
            gzip -c "$log_file" > "$ARCHIVE_DIR/$archive_name.gz"
            
            # Truncate original log (keep file handle for running processes)
            > "$log_file"
            
            echo "   ✅ Archived to: $archive_name.gz"
        else
            echo "   ✅ Size OK (under $MAX_LOG_SIZE)"
        fi
    else
        echo "📄 $service_name log: Not found"
    fi
}

# Function to clean old archives
cleanup_old_archives() {
    echo ""
    echo "🧹 Cleaning archives older than $KEEP_DAYS days..."
    
    local deleted_count=0
    
    # Find and delete archives older than KEEP_DAYS
    if [ -d "$ARCHIVE_DIR" ]; then
        while IFS= read -r -d '' file; do
            rm "$file"
            ((deleted_count++))
            echo "   🗑️  Deleted: $(basename "$file")"
        done < <(find "$ARCHIVE_DIR" -name "*.gz" -mtime +$KEEP_DAYS -type f -print0 2>/dev/null)
    fi
    
    if [ $deleted_count -eq 0 ]; then
        echo "   ✅ No old archives to clean"
    else
        echo "   ✅ Cleaned $deleted_count old archive(s)"
    fi
}

# Function to show log statistics
show_log_stats() {
    echo ""
    echo "📊 Log Directory Statistics:"
    echo "   Total size: $(du -sh "$LOGS_DIR" | cut -f1)"
    echo "   Active logs: $(find "$LOGS_DIR" -name "*.log" -type f | wc -l)"
    echo "   Archived logs: $(find "$ARCHIVE_DIR" -name "*.gz" -type f 2>/dev/null | wc -l)"
    echo ""
}

# Main log rotation
echo "🔄 Checking log files for rotation..."

rotate_log "$LOGS_DIR/auth_server.log" "Auth Server"
rotate_log "$LOGS_DIR/ui_site.log" "UI Site"
rotate_log "$LOGS_DIR/demo_client.log" "Demo Client"
rotate_log "$LOGS_DIR/health_check.log" "Health Check"

# Clean old archives
cleanup_old_archives

# Show statistics
show_log_stats

echo "📋 Recent log activity:"
echo "   Auth Server (last 3 lines):"
tail -3 "$LOGS_DIR/auth_server.log" 2>/dev/null | sed 's/^/      /' || echo "      No recent activity"

echo "   Health Check (last 2 lines):"
tail -2 "$LOGS_DIR/health_check.log" 2>/dev/null | sed 's/^/      /' || echo "      No recent activity"

echo ""
echo "💡 Usage:"
echo "   ./scripts/manage_logs.sh                    - Rotate logs and cleanup"
echo "   find $ARCHIVE_DIR -name '*.gz' -ls          - List all archived logs"
echo "   zcat $ARCHIVE_DIR/auth_server.log.*.gz      - View archived log content"

echo ""
echo "✅ Log management complete!"
