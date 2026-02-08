#!/bin/bash
# Upload a tee-talk disk image to GCP as a Confidential VM-compatible image.
#
# Requirements:
#   - gcloud CLI (authenticated)
#   - gsutil
#   - disk.raw from scripts/build-image.sh
#
# Usage:
#   ./scripts/upload-image.sh [image-name]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DISK_RAW="${REPO_ROOT}/disk.raw"
if [ ! -f "$DISK_RAW" ]; then
    echo "Error: disk.raw not found at $DISK_RAW"
    echo "Run scripts/build-image.sh first."
    exit 1
fi

PROJECT_ID="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
BUCKET="${GCP_BUCKET:-${PROJECT_ID}-tee-talk-images}"
DATE_TAG=$(date +%Y%m%d)
IMAGE_NAME="${1:-tee-talk-verified-${DATE_TAG}}"

echo "=== tee-talk Image Upload ==="
echo "Project: $PROJECT_ID"
echo "Bucket:  gs://$BUCKET"
echo "Image:   $IMAGE_NAME"
echo ""

# Create bucket if it doesn't exist
if ! gsutil ls "gs://$BUCKET" &>/dev/null; then
    echo "Creating bucket gs://$BUCKET..."
    gsutil mb -p "$PROJECT_ID" -l us-central1 "gs://$BUCKET"
fi

# GCP requires disk images as tar.gz with oldgnu format
echo "[1/3] Compressing disk.raw (GCP oldgnu tar format)..."
TARBALL="${REPO_ROOT}/disk.raw.tar.gz"
tar --format=oldgnu -Sczf "$TARBALL" -C "$REPO_ROOT" disk.raw

echo "[2/3] Uploading to gs://$BUCKET/${IMAGE_NAME}.tar.gz..."
gsutil cp "$TARBALL" "gs://$BUCKET/${IMAGE_NAME}.tar.gz"

echo "[3/3] Creating GCP image..."
gcloud compute images create "$IMAGE_NAME" \
    --project="$PROJECT_ID" \
    --source-uri="gs://$BUCKET/${IMAGE_NAME}.tar.gz" \
    --guest-os-features=SEV_SNP_CAPABLE,UEFI_COMPATIBLE,GVNIC \
    --description="tee-talk verified image (dm-verity, reproducible build)"

# Clean up tarball
rm -f "$TARBALL"

echo ""
echo "=== Upload Complete ==="
echo "Image: $IMAGE_NAME"
echo ""
echo "Deploy with:"
echo "  ./deploy/deploy-verified.sh $IMAGE_NAME"
