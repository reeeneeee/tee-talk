#!/bin/bash
# Startup script for TEE Talk TEE server on GCP Confidential VM

LOG_FILE="/var/log/startup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== TEE Talk TEE Server Startup ==="
echo "Date: $(date)"
echo ""

# Update system
echo "[1/6] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "[2/6] Installing build dependencies..."
apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl

# Install Rust
echo "[3/6] Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source /root/.cargo/env

# Install Ollama
echo "[4/6] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
systemctl enable ollama
systemctl start ollama

# Wait for Ollama to be ready
echo "Waiting for Ollama to start..."
sleep 5

# Pull a small model for CPU inference
echo "[5/6] Pulling LLM model (llama3.2)..."
ollama pull llama3.2:latest

# Clone and build tee-talk
echo "[6/6] Building tee-talk..."
cd /opt
if [ -d "tee-talk" ]; then
    cd tee-talk
    git pull
else
    git clone https://github.com/YOUR_USERNAME/tee-talk.git
    cd tee-talk
fi

# Build with real TEE attestation
source /root/.cargo/env
cargo build --release --features real-tee

# Create systemd service
cat > /etc/systemd/system/tee-talk.service << 'EOF'
[Unit]
Description=TEE Talk TEE Server
After=network.target ollama.service

[Service]
Type=simple
ExecStart=/opt/tee-talk/target/release/tee-talk server --bind 0.0.0.0:9999 --real-attestation
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable tee-talk
systemctl start tee-talk

echo ""
echo "=== Startup Complete ==="
echo "TEE Talk server is running on port 9999"
echo "Attestation mode: REAL (SEV-SNP)"
echo ""
echo "Check status with: systemctl status tee-talk"
echo "View logs with: journalctl -u tee-talk -f"
