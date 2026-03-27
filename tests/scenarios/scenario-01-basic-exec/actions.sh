#!/usr/bin/env bash
# Action 1: Simple commands
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"ls && cat /etc/hostname && whoami"}'
sudo docker exec "$CONTAINER" sh -c 'ls / > /dev/null && cat /etc/hostname && whoami'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null

# Action 2: File creation and reading
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"echo hello > /tmp/test.txt && cat /tmp/test.txt"}'
sudo docker exec "$CONTAINER" sh -c 'echo "hello world" > /tmp/test.txt && cat /tmp/test.txt'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/2/end" > /dev/null
