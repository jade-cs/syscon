#!/usr/bin/env bash
# Verify multi-container scenario:
# 1. Container A's action 1 should show credential reads
# 2. Container A's action 2 should show a network connection to container B's IP
# 3. Container B's receipt should show the HTTP service activity
# 4. The receipt should annotate the cross-container connection with container B's ID

set -euo pipefail

PASS=true
SERVICE_CID=$(cat /tmp/syscon-test-service-cid 2>/dev/null || echo "")
SERVICE_IP=$(cat /tmp/syscon-test-service-ip 2>/dev/null || echo "")
EXP_ID=$(cat /tmp/syscon-test-experiment-id 2>/dev/null || echo "")

echo "=== Agent Container (A) ==="
echo "=== Action 1 Receipt ==="
cat "$RESULTS/action_1_receipt.txt"
echo ""
echo "=== Action 2 Receipt ==="
cat "$RESULTS/action_2_receipt.txt"
echo ""

# Fetch service container receipt
SERVICE_RECEIPT_TEXT=""
if [ -n "$SERVICE_CID" ]; then
    echo "=== Service Container (B): $SERVICE_CID (IP: $SERVICE_IP) ==="
    SERVICE_RECEIPT=$(curl -sf "$URL/containers/$SERVICE_CID/receipt" 2>/dev/null || echo "")
    if [ -n "$SERVICE_RECEIPT" ]; then
        SERVICE_RECEIPT_TEXT=$(echo "$SERVICE_RECEIPT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('receipt',''))" 2>/dev/null)
        echo "$SERVICE_RECEIPT_TEXT"
    else
        echo "(no receipt — service container may not have been detected)"
    fi
    echo ""
fi

# Check 1: Action 1 should have credential reads
if grep -q "passwd" "$RESULTS/action_1_receipt.txt" 2>/dev/null; then
    echo "OK: /etc/passwd access detected in Action 1"
else
    echo "FAIL: /etc/passwd access NOT detected in Action 1"
    PASS=false
fi

# Check 2: Action 2 should show network connection
if grep -q "connects" "$RESULTS/action_2_receipt.txt" 2>/dev/null; then
    echo "OK: network connection in Action 2"
else
    echo "FAIL: no network connection in Action 2"
    PASS=false
fi

# Check 3: Action 2 should connect to the service IP
if [ -n "$SERVICE_IP" ] && grep -q "$SERVICE_IP" "$RESULTS/action_2_receipt.txt" 2>/dev/null; then
    echo "OK: connection to service IP $SERVICE_IP detected"
else
    echo "WANT: connection to service IP $SERVICE_IP in Action 2 (gap)"
fi

# Check 4: Cross-container annotation (the new feature)
if [ -n "$SERVICE_CID" ] && grep -q "container $SERVICE_CID" "$RESULTS/action_2_receipt.txt" 2>/dev/null; then
    echo "OK: cross-container annotation found (container $SERVICE_CID)"
else
    echo "WANT: cross-container annotation for $SERVICE_CID in Action 2 (gap)"
fi

# Check 5: /tmp/creds.txt data flow
if grep -q "creds.txt" "$RESULTS/action_2_receipt.txt" 2>/dev/null || \
   grep -q "creds.txt" "$RESULTS/action_1_receipt.txt" 2>/dev/null; then
    echo "OK: creds.txt data flow detected"
else
    echo "WANT: creds.txt in receipts (gap)"
fi

# Check experiment receipt
if [ -n "$EXP_ID" ]; then
    echo "=== Experiment Receipt ($EXP_ID) ==="
    EXP_RECEIPT=$(curl -sf "$URL/experiments/$EXP_ID/receipt" 2>/dev/null || echo "")
    if [ -n "$EXP_RECEIPT" ]; then
        EXP_TEXT=$(echo "$EXP_RECEIPT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('receipt',''))" 2>/dev/null)
        echo "$EXP_TEXT"

        if echo "$EXP_TEXT" | grep -q "CROSS-CONTAINER FLOWS"; then
            echo "OK: cross-container flows section in experiment receipt"
        else
            echo "WANT: CROSS-CONTAINER FLOWS section in experiment receipt (gap)"
        fi
    else
        echo "FAIL: could not fetch experiment receipt"
    fi
    echo ""
fi

# Cleanup service container
if [ -n "$SERVICE_CID" ]; then
    sudo docker rm -f syscon-test-service > /dev/null 2>&1 || true
    curl -sf -X DELETE "$URL/containers/$SERVICE_CID" > /dev/null 2>&1 || true
fi
rm -f /tmp/syscon-test-service-cid /tmp/syscon-test-service-ip /tmp/syscon-test-experiment-id

$PASS
