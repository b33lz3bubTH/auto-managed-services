#!/bin/sh
set -e

USERLIST_FILE="/etc/pgbouncer/userlist.txt"
CONFIG_FILE="/etc/pgbouncer/pgbouncer.ini"

# Wait for userlist.txt to be created by golang service (max 30 seconds)
echo "Waiting for userlist.txt to be created..."
for i in $(seq 1 30); do
    if [ -f "$USERLIST_FILE" ]; then
        echo "✓ userlist.txt found"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "✗ Timeout waiting for userlist.txt"
        exit 1
    fi
    sleep 1
done

# Verify userlist.txt has content and is readable
if [ ! -s "$USERLIST_FILE" ]; then
    echo "✗ userlist.txt is empty"
    exit 1
fi
if [ ! -r "$USERLIST_FILE" ]; then
    echo "✗ userlist.txt is not readable"
    exit 1
fi

echo "Starting pgbouncer with config: $CONFIG_FILE"
exec pgbouncer "$CONFIG_FILE"
