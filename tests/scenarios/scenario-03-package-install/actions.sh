#!/usr/bin/env bash
# Action 1: Install multiple packages (generates many forked processes)
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"apk add --no-cache python3 git openssh"}'
sudo docker exec "$CONTAINER" sh -c 'apk add --no-cache python3 git openssh 2>&1 | tail -5'
sleep 3
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null

# Action 2: Use installed tools
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"python3 -c \"print(42)\" && git --version"}'
sudo docker exec "$CONTAINER" sh -c 'python3 -c "print(42)" && git --version'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/2/end" > /dev/null
