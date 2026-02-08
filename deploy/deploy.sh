#!/bin/bash
# Deploy TEE Talk to Google Cloud Confidential VM

set -e

PROJECT_ID="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${GCP_ZONE:-us-central1-a}"
INSTANCE_NAME="${INSTANCE_NAME:-tee-talk-tee}"
MACHINE_TYPE="${MACHINE_TYPE:-n2d-standard-4}"

echo "=== TEE Talk GCP Deployment ==="
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo "Instance: $INSTANCE_NAME"
echo "Machine Type: $MACHINE_TYPE"
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
    echo "Creating firewall rule..."
    gcloud compute firewall-rules create allow-tee-talk \
        --allow tcp:9999 \
        --target-tags=tee-talk \
        --description="Allow TEE Talk connections"
fi

# Create the Confidential VM
echo "Creating Confidential VM with AMD SEV-SNP..."
gcloud compute instances create "$INSTANCE_NAME" \
    --machine-type="$MACHINE_TYPE" \
    --min-cpu-platform="AMD Milan" \
    --zone="$ZONE" \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image-project=ubuntu-os-cloud \
    --image-family=ubuntu-2404-lts-amd64 \
    --tags=tee-talk \
    --metadata-from-file=startup-script="$(dirname "$0")/startup.sh" \
    --boot-disk-size=50GB

echo ""
echo "Waiting for instance to start..."
sleep 10

# Get external IP
EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "=== Deployment Complete ==="
echo "Instance: $INSTANCE_NAME"
echo "External IP: $EXTERNAL_IP"
echo ""
echo "The startup script will:"
echo "  1. Install Rust and dependencies"
echo "  2. Install Ollama and pull llama3.2 model"
echo "  3. Build and start the tee-talk server"
echo ""
echo "This may take 10-15 minutes. Monitor progress with:"
echo "  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE -- tail -f /var/log/startup.log"
echo ""
echo "Once ready, connect from your machine with:"
echo "  cargo run -- connect -a $EXTERNAL_IP:9999"
