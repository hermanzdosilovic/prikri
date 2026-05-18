#!/usr/bin/env bash
set -e

echo "This is my password for testing purposes." > password.txt

./prikri e Makefile -p password.txt # Creates Makefile.enc

./prikri d Makefile.enc -p password.txt # Creates Makefile.enc.dec

cmp Makefile Makefile.enc.dec && \
    echo "Test PASSED: decrypted file matches original." || \
    echo "Test FAILED: decrypted file does not match original."
