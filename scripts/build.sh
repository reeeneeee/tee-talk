#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== tee-talk Reproducible Build ==="
echo "Building from: $REPO_ROOT"
echo ""

docker build \
    -f "$REPO_ROOT/Dockerfile.build" \
    -t tee-talk-build \
    "$REPO_ROOT"

# Extract binary
docker create --name tee-talk-extract tee-talk-build 2>/dev/null && true
docker cp tee-talk-extract:/tee-talk "$REPO_ROOT/tee-talk"
docker rm tee-talk-extract

SHA384=$(sha384sum "$REPO_ROOT/tee-talk" | cut -d' ' -f1)
SHA256=$(sha256sum "$REPO_ROOT/tee-talk" | cut -d' ' -f1)

echo ""
echo "=== Build Complete ==="
echo "Binary:  $REPO_ROOT/tee-talk"
echo "SHA-384: $SHA384"
echo "SHA-256: $SHA256"
echo ""
echo "The SHA-256 is what gets embedded in the attestation report."
echo "Any builder using the same source should get identical hashes."
