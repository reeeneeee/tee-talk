# Development Log

## 2026-01-28: Initial Implementation

### Phase 1: Proof of Concept (Complete)
- Created basic Rust project with Noise protocol encryption
- Implemented mock TEE server with simulated attestation
- Added Ollama integration for real LLM responses
- Tested end-to-end encrypted chat flow locally

**Files created:**
- `src/main.rs` - Entry point with interactive chat
- `src/noise.rs` - Noise_XX protocol wrapper using `snow` crate
- `src/attestation.rs` - Mock attestation (SHA256 measurement)
- `src/client.rs` - Encrypted client with attestation verification
- `src/tee.rs` - Simulated TEE server calling Ollama

### Phase 2: Real TEE Support (In Progress)
- Updated `Cargo.toml` with real attestation dependencies
- Rewrote `attestation.rs` to support both mock and real AMD SEV-SNP
- Added feature flag `real-tee` for server-side hardware attestation

**Key changes:**
- Attestation report now uses JSON serialization for flexibility
- Report includes `is_real` flag to distinguish mock vs hardware
- Measurement upgraded from SHA256 (32 bytes) to SHA384 (48 bytes) to match AMD spec
- `report_data` field (64 bytes) contains SHA256 hash of Noise public key

### Completed:
- [x] Create `src/certs.rs` for AMD certificate chain verification
- [x] Update `src/client.rs` with real report verification
- [x] Update `src/tee.rs` to use real attestation when feature enabled
- [x] Add CLI arguments for server/client modes (clap)
- [x] Create deployment scripts for GCP Confidential VM

### Files created in this phase:
- `src/certs.rs` - AMD KDS certificate fetching and verification
- `deploy/deploy.sh` - GCP Confidential VM deployment script
- `deploy/startup.sh` - VM startup script (installs Rust, Ollama, builds server)

### CLI Usage:
```bash
# Demo mode (default) - runs server + client locally with mock attestation
cargo run

# Server mode - for running on Confidential VM
cargo run -- server --bind 0.0.0.0:9999 --real-attestation

# Client mode - connect to remote TEE
cargo run -- connect -a <IP>:9999
```

### 2026-01-28: Deployed to Real TEE

Successfully deployed to GCP Confidential VM with AMD SEV-SNP:
- Instance: `tee-talk-tee` (n2d-standard-4, AMD Milan)
- IP: `34.67.216.203:9999`
- Real hardware attestation working via `/dev/sev-guest`

Fixed `sev-snp-utilities` API:
- Changed from `request_with_data()` to `request_raw()`
- Added `Requester` trait import

### 2026-01-29: Full Attestation Verification Implemented

Implemented complete cryptographic verification of AMD SEV-SNP attestation reports:

**1. Measurement Verification**
- Added `verify_measurement()` function
- Supports `EXPECTED_MEASUREMENT` env var for real attestation
- Falls back to mock measurement for demo mode
- Real attestation fails without explicit expected measurement

**2. Certificate Chain Verification**
- ARK (AMD Root Key) self-signature verification
- ASK (AMD SEV Signing Key) signed by ARK
- VCEK (Versioned Chip Endorsement Key) signed by ASK
- Uses RSA-PSS with SHA-384 (not PKCS#1 v1.5)
- Validates issuer DN contains "Advanced Micro Devices"

**3. Report Signature Verification**
- ECDSA P-384 signature over report body (0x2A0 bytes)
- AMD uses little-endian signature format (r||s with padding)
- Converts to big-endian for crypto library

**Dependencies added:**
- `rsa` crate for RSA-PSS verification

**Testing:**
```bash
# Connect with expected measurement
EXPECTED_MEASUREMENT=7978085287e721f166390efe75bc235c41a5119a65c81c69c3ea03e6621f3f62ac60188e1e963aa5746c813a8ea14705 \
cargo run -- connect -a 34.67.216.203:9999
```

### Next steps:
- [ ] Add binary self-measurement (hash of executable in attestation)
- [ ] Add transparency log integration (Sigstore) for measurement verification
- [ ] Add streaming responses for better UX
- [ ] Reproducible builds for deterministic binary hashes
