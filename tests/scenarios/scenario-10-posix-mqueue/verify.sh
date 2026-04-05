#!/usr/bin/env bash
# Verify socketpair covert channel detection.
FAIL=0

ACTION1="$RESULTS/action_1_receipt.txt"
if [ ! -s "$ACTION1" ]; then echo "FAIL: Action 1 receipt is empty"; exit 1; fi

echo "=== Action 1 Receipt ==="
cat "$ACTION1"
echo ""

# Check sockpair process was tracked
if grep -q "sockpair" "$ACTION1"; then
    echo "OK: sockpair process detected"
else
    echo "FAIL: sockpair process not in receipt"
    FAIL=1
fi

# Check that /etc/passwd was read (the exfiltrated file)
if grep -q "/etc/passwd" "$ACTION1"; then
    echo "OK: sensitive file read detected"
else
    echo "FAIL: /etc/passwd read not detected"
    FAIL=1
fi

# Check network exfiltration
if grep -q "connects" "$ACTION1"; then
    echo "OK: network exfiltration detected"
else
    echo "FAIL: network connection not detected"
    FAIL=1
fi

exit $FAIL
