#!/bin/bash
# ============================================================
# reset.sh — PenTrix Lab Reset Script
# ============================================================
# Wipes all student data (submissions, uploaded files, logs)
# and re-seeds the database to a fresh state.
#
# Usage:
#   docker exec pentrix_web bash /app/reset.sh
#   OR run from host: ./reset.sh (if mounted)
# ============================================================

set -e

echo "============================================="
echo "  PenTrix Lab — Full Reset"
echo "============================================="

DB_PATH="/app/data/pentrix.db"

# 1. Stop if DB doesn't exist
if [ ! -f "$DB_PATH" ]; then
    echo "[!] Database not found at $DB_PATH"
    echo "[*] Running initial seed instead..."
    cd /app && python seed.py
    echo "[✓] Fresh database seeded."
    exit 0
fi

echo "[*] Clearing student submissions..."
sqlite3 "$DB_PATH" "DELETE FROM submissions;"

echo "[*] Clearing hint unlocks..."
sqlite3 "$DB_PATH" "DELETE FROM hint_unlocks;"

echo "[*] Clearing access logs..."
sqlite3 "$DB_PATH" "DELETE FROM access_logs;"

echo "[*] Clearing approval requests..."
sqlite3 "$DB_PATH" "DELETE FROM approval_requests;"

echo "[*] Resetting user-created content..."
# Remove non-seed users (keep IDs 1-6)
sqlite3 "$DB_PATH" "DELETE FROM users WHERE id > 6;"
# Remove user-created posts (keep seed posts)
sqlite3 "$DB_PATH" "DELETE FROM posts WHERE id > 5;"
# Remove user-created comments
sqlite3 "$DB_PATH" "DELETE FROM comments WHERE id > 3;"
# Remove user-created messages (keep seed messages)
sqlite3 "$DB_PATH" "DELETE FROM messages WHERE id > 5;"
# Remove user-created tickets
sqlite3 "$DB_PATH" "DELETE FROM tickets WHERE id > 3;"
# Remove uploaded files records
sqlite3 "$DB_PATH" "DELETE FROM files;"

echo "[*] Cleaning uploaded files..."
rm -rf /app/uploads/*
rm -rf /app/static/uploads/*
mkdir -p /app/uploads /app/static/uploads

echo "[*] Recreating flag files and backups..."
cd /app && python -c "
from seed import create_flag_files, create_backup_files
create_flag_files()
create_backup_files()
print('[✓] Flag files and backups recreated.')
"

echo "[*] Re-seeding flags and hints..."
cd /app && python -c "
from db import get_db, init_db
from flags import get_all_flags, HINTS
import sqlite3

db_path = '/app/data/pentrix.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

# Clear and re-seed flags
c.execute('DELETE FROM flags')
c.execute('DELETE FROM hints')

flags = get_all_flags()
for fid, fval in flags.items():
    desc = fid
    chapter = fid.split('-')[0]
    c.execute('INSERT OR IGNORE INTO flags (flag_id, flag_value, description, chapter, points) VALUES (?,?,?,?,?)',
              [fid, fval, desc, chapter, 100])

for fid, tiers in HINTS.items():
    for tier, content in tiers.items():
        cost = {1: 0, 2: 25, 3: 50}.get(tier, 0)
        c.execute('INSERT OR IGNORE INTO hints (flag_id, tier, content, points_cost) VALUES (?,?,?,?)',
                  [fid, tier, content, cost])

conn.commit()
conn.close()
print('[✓] Flags and hints re-seeded.')
"

echo "[*] Resetting sessions table..."
sqlite3 "$DB_PATH" "DELETE FROM sessions;"

echo ""
echo "============================================="
echo "  ✓ PenTrix Lab has been fully reset!"
echo "  ✓ 6 default users preserved"
echo "  ✓ All submissions cleared"
echo "  ✓ All hints re-locked"
echo "  ✓ Uploaded files removed"
echo "============================================="
echo ""
echo "Default Credentials:"
echo "  admin    / admin"
echo "  alice    / password123"
echo "  bob      / letmein"
echo "  charlie  / qwerty"
echo "  hr_manager / hr2024"
echo "  dev_user / dev_secret"
echo ""
