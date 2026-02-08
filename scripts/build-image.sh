#!/bin/bash
# Build a dm-verity-protected GCP disk image for tee-talk.
#
# Requirements:
#   - Linux (loop devices, mount, chroot)
#   - sudo / root
#   - Packages: debootstrap, cryptsetup, dosfstools, parted, grub-efi-amd64-bin,
#               e2fsprogs, mount, qemu-utils (for qemu-img)
#   - The tee-talk binary (from scripts/build.sh)
#   - Ollama binary (downloaded automatically)
#
# Output:
#   - disk.raw              — bootable GCP disk image
#   - verity-manifest.json  — root hash + verity params
#
# Usage:
#   sudo ./scripts/build-image.sh [path-to-tee-talk-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$(mktemp -d)"

# Binary path: argument or default location from build.sh
BINARY="${1:-$REPO_ROOT/tee-talk}"
if [ ! -f "$BINARY" ]; then
    echo "Error: tee-talk binary not found at $BINARY"
    echo "Run scripts/build.sh first, or pass the binary path as an argument."
    exit 1
fi

BINARY_SHA256=$(sha256sum "$BINARY" | cut -d' ' -f1)
echo "=== tee-talk Verified Image Build ==="
echo "Binary: $BINARY"
echo "Binary SHA-256: $BINARY_SHA256"
echo "Work dir: $WORK_DIR"
echo ""

# -------------------------------------------------------
# Check dependencies
# -------------------------------------------------------
for cmd in debootstrap veritysetup parted mkfs.fat mkfs.ext4 grub-install losetup; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found. Install required packages:"
        echo "  apt-get install debootstrap cryptsetup dosfstools parted grub-efi-amd64-bin e2fsprogs"
        exit 1
    fi
done

# -------------------------------------------------------
# Image layout
# -------------------------------------------------------
# Partition 1: EFI System Partition (ESP) — 512 MiB
# Partition 2: Root filesystem (read-only, verity-protected) — 4 GiB
# Partition 3: Verity hash partition — 128 MiB
# Partition 4: Data (model weights, writable) — rest
IMAGE_SIZE_MB=8192
ESP_SIZE_MB=512
ROOT_SIZE_MB=4096
VERITY_SIZE_MB=128
IMAGE="$WORK_DIR/disk.raw"

echo "[1/8] Creating ${IMAGE_SIZE_MB}M raw disk image..."
dd if=/dev/zero of="$IMAGE" bs=1M count=$IMAGE_SIZE_MB status=progress

echo "[2/8] Partitioning..."
parted -s "$IMAGE" -- \
    mklabel gpt \
    mkpart ESP fat32 1MiB "${ESP_SIZE_MB}MiB" \
    set 1 esp on \
    mkpart root ext4 "${ESP_SIZE_MB}MiB" "$((ESP_SIZE_MB + ROOT_SIZE_MB))MiB" \
    mkpart verity "$((ESP_SIZE_MB + ROOT_SIZE_MB))MiB" "$((ESP_SIZE_MB + ROOT_SIZE_MB + VERITY_SIZE_MB))MiB" \
    mkpart data ext4 "$((ESP_SIZE_MB + ROOT_SIZE_MB + VERITY_SIZE_MB))MiB" 100%

# Attach loop device
LOOP=$(losetup --find --show --partscan "$IMAGE")
echo "Loop device: $LOOP"

cleanup() {
    echo "Cleaning up..."
    umount -R "$WORK_DIR/mnt" 2>/dev/null || true
    losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$WORK_DIR/mnt"
}
trap cleanup EXIT

# Format partitions
echo "[3/8] Formatting partitions..."
mkfs.fat -F 32 "${LOOP}p1"
mkfs.ext4 -L root "${LOOP}p2"
mkfs.ext4 -L data "${LOOP}p4"

# Mount root
mkdir -p "$WORK_DIR/mnt"
mount "${LOOP}p2" "$WORK_DIR/mnt"
mkdir -p "$WORK_DIR/mnt/boot/efi"
mount "${LOOP}p1" "$WORK_DIR/mnt/boot/efi"

ROOT="$WORK_DIR/mnt"

# -------------------------------------------------------
# Install base system
# -------------------------------------------------------
echo "[4/8] Installing base system with debootstrap (Ubuntu 24.04)..."
debootstrap --variant=minbase noble "$ROOT" http://archive.ubuntu.com/ubuntu

# Mount pseudo-filesystems for chroot
mount --bind /dev "$ROOT/dev"
mount --bind /dev/pts "$ROOT/dev/pts"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"

# Configure apt sources
cat > "$ROOT/etc/apt/sources.list" << 'EOF'
deb http://archive.ubuntu.com/ubuntu noble main restricted universe
deb http://archive.ubuntu.com/ubuntu noble-updates main restricted universe
deb http://archive.ubuntu.com/ubuntu noble-security main restricted universe
EOF

# Install kernel, bootloader, and essentials
# shim-signed: Microsoft-signed EFI shim (trusted by GCP Secure Boot)
# grub-efi-amd64-signed: Canonical-signed GRUB (trusted by the shim)
# linux-image-generic: Canonical-signed kernel (trusted by GRUB)
chroot "$ROOT" bash -c "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
        linux-image-generic \
        grub-efi-amd64-signed \
        shim-signed \
        cryptsetup-initramfs \
        systemd \
        systemd-sysv \
        openssh-server \
        curl \
        ca-certificates \
        netplan.io \
        isc-dhcp-client
"

# -------------------------------------------------------
# Network configuration (DHCP on all ethernet interfaces)
# -------------------------------------------------------
mkdir -p "$ROOT/etc/netplan"
cat > "$ROOT/etc/netplan/01-dhcp.yaml" << 'EOF'
network:
  version: 2
  ethernets:
    id0:
      match:
        name: "en*"
      dhcp4: true
EOF

# Generate SSH host keys so sshd can start
chroot "$ROOT" ssh-keygen -A

# Set root password for serial console debugging
chroot "$ROOT" bash -c 'echo "root:teetalk" | chpasswd'

# -------------------------------------------------------
# GCP guest agent (handles SSH key injection from metadata)
# -------------------------------------------------------
chroot "$ROOT" bash -c "
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    echo 'deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt google-compute-engine-noble-stable main' > /etc/apt/sources.list.d/google-cloud.list
    apt-get update
    apt-get install -y google-guest-agent
"

# -------------------------------------------------------
# dm-verity initramfs integration
# -------------------------------------------------------
# dm-mod.create on the kernel cmdline runs before modules load,
# so dm-verity (a module) isn't available yet. Instead, we use a
# custom initramfs script that runs after modules load but before
# root is mounted.

# 1. Ensure dm-verity module is in the initramfs
echo "dm-mod" >> "$ROOT/etc/initramfs-tools/modules"
echo "dm-verity" >> "$ROOT/etc/initramfs-tools/modules"

# 2. Hook to copy veritysetup into the initramfs
mkdir -p "$ROOT/etc/initramfs-tools/hooks"
cat > "$ROOT/etc/initramfs-tools/hooks/dm-verity" << 'HOOKEOF'
#!/bin/sh
set -e
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/sbin/veritysetup
copy_exec /usr/sbin/dmsetup
manual_add_modules dm-mod dm-verity
HOOKEOF
chmod +x "$ROOT/etc/initramfs-tools/hooks/dm-verity"

# 3. local-top script to open the verity device before root mount
#    Reads verity params from kernel cmdline: verity.data= verity.hash= verity.roothash= etc.
mkdir -p "$ROOT/etc/initramfs-tools/scripts/local-top"
cat > "$ROOT/etc/initramfs-tools/scripts/local-top/dm-verity" << 'SCRIPTEOF'
#!/bin/sh
set -e
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac

# Parse verity params from kernel cmdline
VERITY_DATA=""
VERITY_HASH=""
VERITY_ROOTHASH=""

for x in $(cat /proc/cmdline); do
    case "$x" in
        verity.data=*) VERITY_DATA="${x#verity.data=}" ;;
        verity.hash=*) VERITY_HASH="${x#verity.hash=}" ;;
        verity.roothash=*) VERITY_ROOTHASH="${x#verity.roothash=}" ;;
    esac
done

if [ -z "$VERITY_DATA" ] || [ -z "$VERITY_HASH" ] || [ -z "$VERITY_ROOTHASH" ]; then
    echo "dm-verity: missing parameters, skipping"
    exit 0
fi

# Wait for devices to appear
echo "dm-verity: waiting for $VERITY_DATA and $VERITY_HASH..."
for i in $(seq 1 30); do
    [ -b "$VERITY_DATA" ] && [ -b "$VERITY_HASH" ] && break
    sleep 0.5
done

if [ ! -b "$VERITY_DATA" ] || [ ! -b "$VERITY_HASH" ]; then
    echo "dm-verity: devices not found!"
    exit 1
fi

# Load modules
modprobe dm-mod 2>/dev/null || true
modprobe dm-verity 2>/dev/null || true

# Open verity device — creates /dev/dm-0
echo "dm-verity: opening $VERITY_DATA with roothash $VERITY_ROOTHASH"
veritysetup open "$VERITY_DATA" vroot "$VERITY_HASH" "$VERITY_ROOTHASH"
echo "dm-verity: /dev/dm-0 created"
SCRIPTEOF
chmod +x "$ROOT/etc/initramfs-tools/scripts/local-top/dm-verity"

# Rebuild initramfs with our hooks
chroot "$ROOT" update-initramfs -u

# -------------------------------------------------------
# Install tee-talk
# -------------------------------------------------------
echo "[5/8] Installing tee-talk binary..."
cp "$BINARY" "$ROOT/usr/local/bin/tee-talk"
chmod 755 "$ROOT/usr/local/bin/tee-talk"

# Create systemd service for tee-talk
cat > "$ROOT/etc/systemd/system/tee-talk.service" << 'EOF'
[Unit]
Description=tee-talk TEE Server
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
ExecStart=/usr/local/bin/tee-talk server --bind 0.0.0.0:9999
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

chroot "$ROOT" systemctl enable tee-talk.service

# -------------------------------------------------------
# Install Ollama
# -------------------------------------------------------
echo "[6/8] Installing Ollama (CPU-only)..."
# Download Ollama binary directly (the install script needs systemd running)
OLLAMA_VERSION="0.5.4"
curl -fsSL "https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/ollama-linux-amd64.tgz" \
    -o "$WORK_DIR/ollama.tgz"
# Extract only the ollama binary and CPU runner — skip CUDA/ROCm libs (~4GB)
tar -xzf "$WORK_DIR/ollama.tgz" -C "$ROOT/usr/local" \
    --exclude='lib/ollama/runners/cuda*' \
    --exclude='lib/ollama/runners/rocm*' \
    --exclude='lib/ollama/libcublas*' \
    --exclude='lib/ollama/libcudart*' \
    --exclude='lib/ollama/libcublasLt*'

# Create ollama systemd service
cat > "$ROOT/etc/systemd/system/ollama.service" << 'EOF'
[Unit]
Description=Ollama LLM Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=5
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=HOME=/data
Environment=OLLAMA_MODELS=/data/ollama

[Install]
WantedBy=multi-user.target
EOF

chroot "$ROOT" systemctl enable ollama.service

# Create a first-boot service to pull the model (model goes on data partition)
cat > "$ROOT/etc/systemd/system/ollama-pull-model.service" << 'EOF'
[Unit]
Description=Pull Ollama model on first boot
After=ollama.service data.mount
Wants=ollama.service
ConditionPathExists=!/data/.model-pulled

[Service]
Type=oneshot
Environment=HOME=/data
Environment=OLLAMA_MODELS=/data/ollama
ExecStart=/bin/bash -c 'sleep 10 && /usr/local/bin/ollama pull llama3.2:latest && /usr/local/bin/ollama pull nomic-embed-text && touch /data/.model-pulled'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Mount data partition at /data
echo "LABEL=data /data ext4 defaults 0 2" >> "$ROOT/etc/fstab"
mkdir -p "$ROOT/data"

chroot "$ROOT" systemctl enable ollama-pull-model.service

# -------------------------------------------------------
# Configure GRUB (verity params added after veritysetup)
# -------------------------------------------------------
echo "[7/8] Installing GRUB bootloader..."

# Set up basic GRUB config (we'll patch the cmdline after veritysetup)
cat > "$ROOT/etc/default/grub" << EOF
GRUB_DEFAULT=0
GRUB_TIMEOUT=1
GRUB_CMDLINE_LINUX="console=ttyS0,115200n8 ro"
GRUB_TERMINAL="serial console"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
EOF

# Install signed bootloader chain for Secure Boot:
#   UEFI firmware → shimx64.efi (Microsoft-signed) → grubx64.efi (Canonical-signed) → kernel (Canonical-signed)
#
# GCP Secure Boot trusts Microsoft's UEFI CA. The shim is signed by Microsoft
# and contains Canonical's key, which trusts the signed GRUB and kernel.
mkdir -p "$ROOT/boot/efi/EFI/BOOT"

# Copy the signed shim as the default bootloader (BOOTX64.EFI is what UEFI loads)
cp "$ROOT/usr/lib/shim/shimx64.efi.signed" "$ROOT/boot/efi/EFI/BOOT/BOOTX64.EFI"
# Copy the signed GRUB (the shim loads grubx64.efi from the same directory)
cp "$ROOT/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed" "$ROOT/boot/efi/EFI/BOOT/grubx64.efi"

# Also install to the ubuntu-specific path (some UEFI implementations look here)
mkdir -p "$ROOT/boot/efi/EFI/ubuntu"
cp "$ROOT/usr/lib/shim/shimx64.efi.signed" "$ROOT/boot/efi/EFI/ubuntu/shimx64.efi"
cp "$ROOT/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed" "$ROOT/boot/efi/EFI/ubuntu/grubx64.efi"

# Detect the kernel version installed (needed for the GRUB config)
KERNEL_VERSION=$(chroot "$ROOT" bash -c 'ls /boot/vmlinuz-*' | sed 's|/boot/vmlinuz-||' | sort -V | tail -1)
echo "Kernel version: $KERNEL_VERSION"

# Don't generate grub.cfg on the root partition — we can't modify it
# after veritysetup without invalidating the hash. Instead, the ESP
# grub.cfg will contain the full boot entry (written after veritysetup).

# -------------------------------------------------------
# Unmount and apply dm-verity
# -------------------------------------------------------
echo "[8/8] Applying dm-verity to root filesystem..."

# Unmount everything inside chroot
umount "$ROOT/dev/pts" 2>/dev/null || true
umount "$ROOT/dev" 2>/dev/null || true
umount "$ROOT/proc" 2>/dev/null || true
umount "$ROOT/sys" 2>/dev/null || true
umount "$ROOT/boot/efi"
umount "$ROOT"

# Run veritysetup on root partition → hash partition
# This makes the root filesystem tamper-evident
VERITY_OUTPUT=$(veritysetup format "${LOOP}p2" "${LOOP}p3" 2>&1)
echo "$VERITY_OUTPUT"

ROOT_HASH=$(echo "$VERITY_OUTPUT" | grep "Root hash:" | awk '{print $NF}')
HASH_ALGORITHM=$(echo "$VERITY_OUTPUT" | grep "Hash algorithm:" | awk '{print $NF}')
DATA_BLOCKS=$(echo "$VERITY_OUTPUT" | grep "Data blocks:" | awk '{print $NF}')
DATA_BLOCK_SIZE=$(echo "$VERITY_OUTPUT" | grep "Data block size:" | awk '{print $NF}')
HASH_BLOCK_SIZE=$(echo "$VERITY_OUTPUT" | grep "Hash block size:" | awk '{print $NF}')
SALT=$(echo "$VERITY_OUTPUT" | grep "Salt:" | awk '{print $NF}')
UUID=$(echo "$VERITY_OUTPUT" | grep "UUID:" | awk '{print $NF}')

echo ""
echo "Root hash: $ROOT_HASH"

# Write a FULL grub.cfg directly in the ESP.
# We cannot modify the root partition after veritysetup — doing so would
# invalidate the hash. So the ESP contains the complete boot config.
mkdir -p "$WORK_DIR/esp"
mount "${LOOP}p1" "$WORK_DIR/esp"

# Our initramfs local-top script reads verity.* params from the cmdline
# and calls veritysetup to create /dev/dm-0 before root is mounted.
VERITY_CMDLINE="verity.data=/dev/nvme0n1p2 verity.hash=/dev/nvme0n1p3 verity.roothash=$ROOT_HASH"

mkdir -p "$WORK_DIR/esp/EFI/BOOT"
cat > "$WORK_DIR/esp/EFI/BOOT/grub.cfg" << GRUBEOF
set timeout=1
set default=0

menuentry "tee-talk (dm-verity)" {
    search --no-floppy --label root --set=root
    linux /boot/vmlinuz-${KERNEL_VERSION} root=/dev/dm-0 ro console=ttyS0,115200n8 ${VERITY_CMDLINE}
    initrd /boot/initrd.img-${KERNEL_VERSION}
}
GRUBEOF

# Also write to the ubuntu path in case the shim looks there
mkdir -p "$WORK_DIR/esp/EFI/ubuntu"
cp "$WORK_DIR/esp/EFI/BOOT/grub.cfg" "$WORK_DIR/esp/EFI/ubuntu/grub.cfg"

echo "Wrote GRUB config with verity params in ESP"
cat "$WORK_DIR/esp/EFI/BOOT/grub.cfg"

umount "$WORK_DIR/esp"

# Detach loop device
losetup -d "$LOOP"
trap - EXIT

# -------------------------------------------------------
# Output
# -------------------------------------------------------
cp "$WORK_DIR/disk.raw" "$REPO_ROOT/disk.raw"

# Write verity manifest
cat > "$REPO_ROOT/verity-manifest.json" << EOF
{
  "root_hash": "$ROOT_HASH",
  "hash_algorithm": "$HASH_ALGORITHM",
  "data_blocks": $DATA_BLOCKS,
  "data_block_size": $DATA_BLOCK_SIZE,
  "hash_block_size": $HASH_BLOCK_SIZE,
  "salt": "$SALT",
  "uuid": "$UUID",
  "binary_sha256": "$BINARY_SHA256"
}
EOF

echo ""
echo "=== Image Build Complete ==="
echo "Image:      $REPO_ROOT/disk.raw"
echo "Manifest:   $REPO_ROOT/verity-manifest.json"
echo "Root hash:  $ROOT_HASH"
echo "Binary SHA: $BINARY_SHA256"
echo ""
echo "Next: upload with scripts/upload-image.sh"

# Clean up work dir
rm -rf "$WORK_DIR"
