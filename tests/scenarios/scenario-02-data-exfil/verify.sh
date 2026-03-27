#!/usr/bin/env bash
if [ ! -s "$RECEIPT" ]; then echo "Receipt is empty"; exit 1; fi
echo "Receipt:"
cat "$RECEIPT"
# Should show network activity and file operations
grep -qi "network\|connect\|curl" "$RECEIPT" || echo "WARN: no network activity in receipt"
