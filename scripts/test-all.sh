#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER="${1:-http://localhost:8080}"

echo "=== Atrium - Test Suite ==="
echo "Server: $SERVER"
echo ""

echo "Running mTLS tests..."
echo "===================="
bash "$SCRIPT_DIR/test-mtls.sh" "$SERVER" || true
echo ""

echo "Running DPoP tests..."
echo "===================="
bash "$SCRIPT_DIR/test-dpop.sh" "$SERVER" || true
echo ""

echo "=== All Tests Complete ==="
