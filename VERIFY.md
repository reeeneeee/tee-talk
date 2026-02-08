# Verifying tee-talk

This document explains how to independently verify that the tee-talk binary
running inside a TEE matches the public source code.

## Verification chain

```
Source code
  → Reproducible Docker build → binary SHA-256
  → Custom VM image with dm-verity → root hash in kernel cmdline

GCP Confidential VM boots:
  SEV-SNP measurement   → proves OVMF firmware integrity (AMD hardware-signed)
  Secure Boot           → proves kernel integrity
  dm-verity             → proves filesystem integrity (including binary)
  Binary self-measurement → SHA-256(/proc/self/exe) in report_data[32..64]

Client connects:
  AMD cert chain (ARK → ASK → VCEK) → report is hardware-signed
  Public key binding                 → no MITM (report bound to this handshake)
  Binary hash                        → matches expected from VERIFICATION.toml
```

## 1. Reproduce the binary

Clone the repo and run the reproducible build:

```
git clone https://github.com/irenawang/tee-talk.git
cd tee-talk
./scripts/build.sh
```

This builds inside a pinned Docker image (Rust 1.85.0, deterministic flags)
and prints the SHA-384 and SHA-256 of the resulting binary. Compare against
the values in `VERIFICATION.toml`:

```
[binary]
sha384 = "..."
sha256 = "..."
```

The SHA-256 is what the running binary embeds in `report_data[32..64]` of the
AMD SEV-SNP attestation report.

## 2. Connect and verify

```
# Full verification (checks attestation + binary hash):
EXPECTED_BINARY_HASH=<sha256 from step 1> \
  cargo run -- connect -a <server>:9999

# Skip attestation but keep encryption:
cargo run -- connect -a <server>:9999 --trust-server
```

When connecting without `--trust-server`, the client automatically:

1. Completes a Noise_XX handshake (end-to-end encrypted, forward-secret)
2. Receives the TEE's attestation report inside the handshake payload
3. Verifies the AMD certificate chain (ARK → ASK → VCEK)
4. Checks that the report is signed by the chip's VCEK
5. Checks that the Noise public key is bound to the report (`report_data[0..32]`)
6. Checks that the binary hash matches your expected value (`report_data[32..64]`)
7. Checks the TEE measurement against `EXPECTED_MEASUREMENT` (if set)

If any check fails, the connection is aborted before any messages are sent.

## 3. What each check proves

| Check | What it proves |
|---|---|
| AMD cert chain | The report was signed by real AMD hardware, not forged |
| Report signature | The report contents have not been tampered with |
| Public key binding | No man-in-the-middle — the encrypted channel terminates inside the TEE |
| Binary hash | The code running in the TEE matches the reproducible build |
| TEE measurement | The firmware/launch state matches the expected configuration |

## 4. What `--trust-server` does

Skips all attestation checks. The Noise protocol handshake still completes,
so the connection is still end-to-end encrypted — you just don't have
cryptographic proof of what's on the other end.

Use this for local testing or when connecting to a server you operate yourself.

## 5. Environment variables

| Variable | Purpose |
|---|---|
| `EXPECTED_BINARY_HASH` | SHA-256 of the binary (hex). Checked against `report_data[32..64]` |
| `EXPECTED_MEASUREMENT` | SHA-384 TEE measurement (hex). Checked against the report's measurement field |

Both are optional. If unset, the client prints the values it received but
does not reject the connection.

## GCP-specific notes

On GCP Confidential VMs, the SEV-SNP `LAUNCH_DIGEST` only covers the OVMF
firmware — it does not directly measure the kernel or filesystem. Kernel
integrity comes from Secure Boot; filesystem integrity comes from dm-verity.
The binary self-measurement in `report_data[32..64]` closes the gap: it is
hardware-signed by AMD, and since the binary runs inside memory-encrypted TEE
memory on a dm-verity-protected filesystem, a tampered binary cannot produce
the expected hash.
