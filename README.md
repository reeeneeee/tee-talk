# TEE Talk

End-to-end encrypted LLM chat inside a hardware-isolated [Trusted Execution Environment](https://cloud.google.com/confidential-computing). Your prompts are encrypted before leaving your device and decrypted only inside the TEE.

Inspired by [Moxie Marlinspike's Confer architecture](https://signal.org/blog/private-ai/).

## Talk to it

### Download (easiest)

Download the latest binary from [Releases](https://github.com/reeeneeee/tee-talk/releases) and run it:

```bash
./tee-talk
```

That's it. Opens a web UI in your browser, connected to the public TEE server with end-to-end encryption.

### SMS

Text **HELLO** to **+1 (970) 717-2021**

No app, no account. SMS is not end-to-end encrypted (your carrier can see messages), but the AI runs inside the TEE.

### Terminal (end-to-end encrypted)

```bash
git clone https://github.com/reeeneeee/tee-talk.git
cd tee-talk
cargo run -- connect -a 34.60.196.117:9999
```

The client performs a [Noise_XX](https://noiseprotocol.org/) handshake, verifies the AMD SEV-SNP attestation report, and establishes an encrypted channel. Everything you type is encrypted before it leaves your machine.

### Web UI (end-to-end encrypted)

```bash
cargo run -- connect -a 34.60.196.117:9999 --web
```

Opens a local web UI at `http://localhost:8080`. The browser talks to a local server on your machine; the connection to the TEE is still end-to-end encrypted.

### Skip attestation

If you just want to chat and don't care about verifying the TEE:

```bash
cargo run -- connect -a 34.60.196.117:9999 --trust-server
```

The connection is still end-to-end encrypted via Noise protocol — you just skip the hardware attestation check.

## Verify it

You can cryptographically verify that the server is running the exact binary built from this source code. See [VERIFY.md](VERIFY.md) for the full verification chain.

Quick version:

```bash
# Build the binary yourself and get its SHA-256
./scripts/build.sh

# Connect and verify the TEE is running that exact binary
EXPECTED_BINARY_HASH=65f2218dda0b63a6829feca96a1968912d6050bb98a040af002711fd5d19277d \
  cargo run -- connect -a 34.60.196.117:9999
```

The expected hashes are in [VERIFICATION.toml](VERIFICATION.toml).

## Local demo

Run both client and server locally with mock attestation (no TEE hardware needed):

```bash
# Make sure Ollama is running
ollama pull llama3.2
ollama serve

# Run the demo
cargo run
```

## How it works

```
You                          TEE (AMD SEV-SNP)
 │                                │
 ├─ Noise_XX handshake ──────────┤
 │  (encrypted channel)          │
 ├─ Verify attestation ◄─────────┤ Hardware-signed report
 │  - AMD cert chain             │
 │  - Public key binding         │
 │  - Binary hash                │
 │                                │
 ├─ Encrypt prompt ──────────────► Decrypt inside TEE
 │                                │  ↓
 │                                │ LLM (llama3.2)
 │                                │  ↓
 ◄─ Decrypt response ────────────┤ Encrypt response
```

| Property | How |
|---|---|
| Encryption in transit | Noise_XX with forward secrecy |
| Encryption at rest | AMD SEV-SNP memory encryption |
| Code integrity | Reproducible build + binary self-measurement in attestation report |
| No MITM | Public key bound to hardware-signed report |
| Filesystem integrity | dm-verity root hash in kernel cmdline |

## Run your own server

Requires a Linux machine (or GCP VM) with Docker and sudo.

```bash
# 0. Decrypt readings.txt (embedded in binary at compile time)
gpg -d readings.txt.gpg > readings.txt

# 1. Reproducible binary build (Docker)
./scripts/build.sh

# 2. Build dm-verity disk image (needs sudo, debootstrap, cryptsetup, etc.)
sudo ./scripts/build-image.sh

# 3. Upload to GCP as a Confidential VM image
./scripts/upload-image.sh tee-talk-verified-v1

# 4. Deploy a Confidential VM from the image
./deploy/deploy-verified.sh tee-talk-verified-v1
```

The model (llama3.2) is pulled automatically on first boot.

### Deploying updates

After changing the Rust code:

```bash
# Rebuild binary (new SHA-256)
./scripts/build.sh

# Rebuild disk image (new verity root hash)
sudo ./scripts/build-image.sh

# Delete old VM, upload new image, deploy
gcloud compute instances delete tee-talk-verified --zone=us-central1-a --quiet
./scripts/upload-image.sh tee-talk-verified-vN
./deploy/deploy-verified.sh tee-talk-verified-vN
```

Then update `VERIFICATION.toml` with the new binary and verity hashes from the build output, and update the server IP in the README and website if it changed.

Changes to the website (`site/`) or README don't require a rebuild — just push to GitHub and redeploy on Vercel.

See [VERIFY.md](VERIFY.md) for details on the verification chain.

## References

- [Signal: Private AI](https://signal.org/blog/private-ai/)
- [AMD SEV-SNP Specification](https://www.amd.com/en/developer/sev.html)
- [Google Cloud Confidential VMs](https://cloud.google.com/confidential-computing)
- [Noise Protocol Framework](https://noiseprotocol.org/)
