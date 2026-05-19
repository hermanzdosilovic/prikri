#!/usr/bin/env bash
set -e

help_output="$(./prikri -h 2>&1 || true)"

symmetric_ciphers="$(
  awk '
    /^SUPPORTED SYMMETRIC CIPHERS:/ { in_section=1; next }
    /^SUPPORTED / || /^USAGE:/ || /^ARGUMENTS:/ || /^OPTIONS:/ { in_section=0 }
    in_section && /^[[:space:]]*[A-Za-z0-9_-]+:/ {
      sub(/^[[:space:]]*/, "")
      sub(/:.*/, "")
      print
    }
  ' <<< "$help_output"
)"

kdfs="$(
  awk '
    /^SUPPORTED KEY DERIVATION FUNCTIONS:/ { in_section=1; next }
    /^SUPPORTED / || /^USAGE:/ || /^ARGUMENTS:/ || /^OPTIONS:/ { in_section=0 }
    in_section && /^[[:space:]]*[A-Za-z0-9_-]+:/ {
      sub(/^[[:space:]]*/, "")
      sub(/:.*/, "")
      print
    }
  ' <<< "$help_output"
)"

for symmetric_cipher in $symmetric_ciphers; do
    for kdf in $kdfs; do
        echo "Testing with symmetric cipher $symmetric_cipher and KDF $kdf..."
        ./test.sh "$symmetric_cipher" "$kdf"
        echo
    done
done
