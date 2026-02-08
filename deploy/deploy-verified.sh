#!/bin/bash
# Deploy tee-talk to a GCP Confidential VM from a verified image.
#
# Unlike deploy.sh (which uses a stock Ubuntu image + startup script that
# builds from source), this uses a pre-built image with dm-verity. The binary
# is already installed — no compilation on the VM, no startup script.
#
# Usage:
#   ./deploy/deploy-verified.sh <image-name>
#
# The image-name comes from scripts/upload-image.sh output.

set -euo pipefail

IMAGE_NAME="${1:-}"
if [ -z "$IMAGE_NAME" ]; then
    echo "Usage: $0 <image-name>"
    echo ""
    echo "  image-name: GCP image from scripts/upload-image.sh"
    echo "              e.g. tee-talk-verified-20250206"
    exit 1
fi

PROJECT_ID="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${GCP_ZONE:-us-central1-a}"
INSTANCE_NAME="${INSTANCE_NAME:-tee-talk-verified}"
MACHINE_TYPE="${MACHINE_TYPE:-n2d-standard-4}"

echo "=== tee-talk Verified Deployment ==="
echo "Project:  $PROJECT_ID"
echo "Zone:     $ZONE"
echo "Instance: $INSTANCE_NAME"
echo "Machine:  $MACHINE_TYPE"
echo "Image:    $IMAGE_NAME"
echo ""

# Check if instance already exists
if gcloud compute instances describe "$INSTANCE_NAME" --zone="$ZONE" &>/dev/null; then
    echo "Instance $INSTANCE_NAME already exists."
    read -p "Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing instance..."
        gcloud compute instances delete "$INSTANCE_NAME" --zone="$ZONE" --quiet
    else
        echo "Aborted."
        exit 1
    fi
fi

# Create firewall rule if it doesn't exist
if ! gcloud compute firewall-rules describe allow-tee-talk &>/dev/null; then
    echo "Creating firewall rule for port 9999..."
    gcloud compute firewall-rules create allow-tee-talk \
        --allow tcp:9999 \
        --target-tags=tee-talk \
        --description="Allow tee-talk connections"
fi

# Create Confidential VM from verified image
echo "Creating Confidential VM with SEV-SNP from verified image..."
gcloud compute instances create "$INSTANCE_NAME" \
    --machine-type="$MACHINE_TYPE" \
    --min-cpu-platform="AMD Milan" \
    --zone="$ZONE" \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image="$IMAGE_NAME" \
    --image-project="$PROJECT_ID" \
    --tags=tee-talk \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --boot-disk-size=10GB

echo ""
echo "Waiting for instance to start..."
sleep 10

# Get external IP
EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "=== Deployment Complete ==="
echo "Instance:    $INSTANCE_NAME"
echo "External IP: $EXTERNAL_IP"
echo ""
echo "Verification chain:"
echo "  SEV-SNP      → OVMF firmware integrity (AMD hardware-signed)"
echo "  Secure Boot  → kernel integrity"
echo "  dm-verity    → filesystem integrity (including tee-talk binary)"
echo "  Self-measure → SHA-256(/proc/self/exe) in attestation report"
echo ""
echo "The model (llama3.2) will be pulled on first boot."
echo "This may take a few minutes. Then connect with:"
echo ""
echo "  EXPECTED_BINARY_HASH=<sha256> cargo run -- connect -a $EXTERNAL_IP:9999"
echo ""
echo "Or skip attestation verification:"
echo ""
echo "  cargo run -- connect -a $EXTERNAL_IP:9999 --trust-server"
