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

# Store initial checksum
LAST_CHECKSUM=$(md5sum "$USERLIST_FILE" | cut -d' ' -f1)

# Background watcher that reloads pgbouncer when userlist.txt changes
watch_userlist() {
    while true; do
        sleep 5
        if [ -f "$USERLIST_FILE" ]; then
            CURRENT_CHECKSUM=$(md5sum "$USERLIST_FILE" | cut -d' ' -f1)
            if [ "$CURRENT_CHECKSUM" != "$LAST_CHECKSUM" ]; then
                echo "✓ userlist.txt changed, reloading pgbouncer..."
                LAST_CHECKSUM="$CURRENT_CHECKSUM"
                # Send SIGHUP to pgbouncer to reload auth file
                pkill -HUP pgbouncer 2>/dev/null || true
            fi
        fi
    done
}

# Start watcher in background
watch_userlist &

echo "Starting pgbouncer with config: $CONFIG_FILE"
exec pgbouncer "$CONFIG_FILE"
