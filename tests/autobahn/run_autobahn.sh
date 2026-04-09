#!/bin/bash
# Signet Autobahn Compliance Test Runner
# Copyright 2026 Signet Authors
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../../build"

echo "=== Signet Autobahn Compliance Test ==="
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required to run Autobahn tests"
    echo "Install Docker and try again"
    exit 1
fi

# Check if test client exists
if [ ! -f "${BUILD_DIR}/tests/signet_autobahn_client" ]; then
    echo "Error: signet_autobahn_client not found"
    echo "Build with: cmake -DSIGNET_BUILD_AUTOBAHN=ON .. && make"
    exit 1
fi

# Create directories
mkdir -p "${SCRIPT_DIR}/reports"

# Start Autobahn fuzzing server
echo "Starting Autobahn fuzzing server..."
docker run -d --rm \
    --name signet_autobahn_server \
    -v "${SCRIPT_DIR}:/config" \
    -v "${SCRIPT_DIR}/reports:/reports" \
    -p 9001:9001 \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingserver -s /config/fuzzingserver.json

# Wait for server to start
echo "Waiting for server to start..."
sleep 3

# Run test client
echo ""
echo "Running Signet test client..."
echo ""

"${BUILD_DIR}/tests/signet_autobahn_client" "$@"
EXIT_CODE=$?

# Stop server
echo ""
echo "Stopping Autobahn server..."
docker stop signet_autobahn_server 2>/dev/null || true

# Open report if available
if [ -f "${SCRIPT_DIR}/reports/server/index.html" ]; then
    echo ""
    echo "Report available at: ${SCRIPT_DIR}/reports/server/index.html"

    # Try to open in browser (Linux/macOS)
    if command -v xdg-open &> /dev/null; then
        xdg-open "${SCRIPT_DIR}/reports/server/index.html" 2>/dev/null || true
    elif command -v open &> /dev/null; then
        open "${SCRIPT_DIR}/reports/server/index.html" 2>/dev/null || true
    fi
fi

exit $EXIT_CODE
