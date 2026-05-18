#!/usr/bin/env bash
set -e

SYMMETRIC_CIPHER="${1:-aes-256-cbc}"

echo "This is my password for testing purposes." > password.txt

dd if=/dev/urandom of=./random.bin bs=1M count=8 status=none # Creates a random 8MB file named random.bin

./prikri e random.bin -s "$SYMMETRIC_CIPHER" -p password.txt # Creates random.bin.enc

./prikri d random.bin.enc -s "$SYMMETRIC_CIPHER" -p password.txt # Creates random.bin.enc.dec

cmp random.bin random.bin.enc.dec && \
    echo "Test PASSED: decrypted file matches original." || \
    echo "Test FAILED: decrypted file does not match original."

rm *.bin *.enc *.dec password.txt
