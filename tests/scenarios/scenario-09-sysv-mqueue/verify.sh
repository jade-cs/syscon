#!/usr/bin/env bash
# Verify that SysV message queue IPC was detected.
FAIL=0

ACTION1="$RESULTS/action_1_receipt.txt"
if [ ! -s "$ACTION1" ]; then echo "FAIL: Action 1 receipt is empty"; exit 1; fi

echo "=== Action 1 Receipt ==="
cat "$ACTION1"
echo ""

# Check that sender and receiver processes were tracked
if grep -q "sender" "$ACTION1"; then
    echo "OK: sender process detected"
else
    echo "FAIL: sender process not in receipt"
    FAIL=1
fi
if grep -q "receiver" "$ACTION1"; then
    echo "OK: receiver process detected"
else
    echo "FAIL: receiver process not in receipt"
    FAIL=1
fi

# Check for mqueue taint edge between sender and receiver
if grep -q "mqueue" "$ACTION1"; then
    echo "OK: mqueue taint edge detected"
else
    echo "FAIL: no mqueue edge in receipt"
    FAIL=1
fi

# Check the graph for IPC edges
GRAPH="$RESULTS/graph.dot"
if [ -f "$GRAPH" ] && grep -q "mqueue" "$GRAPH"; then
    echo "OK: mqueue edges found in graph"
else
    echo "FAIL: no mqueue edges in graph"
    FAIL=1
fi

exit $FAIL
