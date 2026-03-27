#!/usr/bin/env bash
if [ ! -s "$RECEIPT" ]; then echo "Receipt is empty"; exit 1; fi
echo "Receipt:"
cat "$RECEIPT"
