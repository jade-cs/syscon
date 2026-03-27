#!/usr/bin/env bash
# Verify that the receipt shows process events
if [ ! -s "$RECEIPT" ]; then
    echo "Receipt is empty"
    exit 1
fi
echo "Receipt length: $(wc -c < "$RECEIPT") bytes"
echo "Receipt preview:"
head -20 "$RECEIPT"
# Should have at least a header line
grep -q "Post-Action Receipt" "$RECEIPT" || grep -q "PROCESSES" "$RECEIPT" || grep -q "syscall events" "$RECEIPT"
