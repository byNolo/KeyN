#!/bin/bash

# KeyN Database Update Script
# Runs all necessary database migrations

echo "🔐 KeyN Database Update"
echo "======================="
echo ""

KEYN_DIR="${KEYN_PROJECT_DIR:-/home/sam/KeyN/Dev/KeyN}"
VENV_PATH="${KEYN_VENV_PATH:-$KEYN_DIR/venv}"

cd "$KEYN_DIR"

echo "Running database migrations..."
echo ""

# Run MFA migration
echo "📱 Migrating MFA tables..."
"$VENV_PATH/bin/python" scripts/migrate_mfa.py
MFA_EXIT=$?

if [ $MFA_EXIT -eq 0 ]; then
    echo ""
    echo "✅ Database update completed successfully!"
else
    echo ""
    echo "❌ Database update failed with exit code: $MFA_EXIT"
    exit 1
fi

echo ""
echo "Database is now up to date!"
