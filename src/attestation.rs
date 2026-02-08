//! Attestation module supporting both mock and real AMD SEV-SNP attestation.
//!
//! In mock mode (default): Uses simulated attestation for local testing.
//! In real mode (--features real-tee): Uses hardware SEV-SNP attestation.

use sha2::{Sha256, Sha384, Digest};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "server"))]
use crate::certs::SIMULATED_TEE_CODE;

/// Compute SHA-256 of the running binary via /proc/self/exe (Linux only).
/// Returns zeros on platforms where this isn't available.
#[cfg(feature = "server")]
fn self_measurement() -> [u8; 32] {
    #[cfg(target_os = "linux")]
    {
        if let Ok(bytes) = std::fs::read("/proc/self/exe") {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            return hasher.finalize().into();
        }
    }
    [0u8; 32]
}

/// Simulated TEE code/firmware that gets measured (mock mode)
#[cfg(feature = "server")]
const SIMULATED_TEE_CODE: &[u8] = b"tee-talk-v0.1.0";

/// AMD SEV-SNP attestation report (real or mock)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Version of the attestation report format
    pub version: u32,
    /// Hash of the code running in the TEE (measurement) - 48 bytes, hex encoded
    pub measurement: String,
    /// User-provided data (64 bytes) - we put the public key hash here, hex encoded
    pub report_data: String,
    /// The raw report bytes (for signature verification), hex encoded
    pub raw_report: String,
    /// Signature over the report (ECDSA P-384), hex encoded
    pub signature: String,
    /// Chip ID for fetching VCEK certificate, hex encoded
    pub chip_id: String,
    /// Whether this is a real hardware attestation
    pub is_real: bool,
}

impl AttestationReport {
    /// Generate a mock attestation report (for local testing)
    #[cfg(feature = "server")]
    pub fn generate_mock(public_key: &[u8]) -> Self {
        // Create report_data: [0..32] = SHA-256(public_key), [32..64] = SHA-256(binary)
        let mut report_data = [0u8; 64];
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let pk_hash = hasher.finalize();
        report_data[..32].copy_from_slice(&pk_hash);
        report_data[32..64].copy_from_slice(&self_measurement());

        // Compute measurement (hash of "TEE code")
        let mut measurement = [0u8; 48];
        let mut hasher = Sha384::new();
        hasher.update(SIMULATED_TEE_CODE);
        measurement.copy_from_slice(&hasher.finalize());

        // Create mock raw report
        let mut raw_report = Vec::new();
        raw_report.extend_from_slice(&1u32.to_le_bytes()); // version
        raw_report.extend_from_slice(&measurement);
        raw_report.extend_from_slice(&report_data);

        // Create mock signature
        let mut sig_hasher = Sha384::new();
        sig_hasher.update(&raw_report);
        sig_hasher.update(b"mock-signing-key");
        let signature = sig_hasher.finalize().to_vec();

        // Mock chip ID
        let chip_id = vec![0u8; 64];

        AttestationReport {
            version: 1,
            measurement: hex::encode(measurement),
            report_data: hex::encode(report_data),
            raw_report: hex::encode(raw_report),
            signature: hex::encode(signature),
            chip_id: hex::encode(chip_id),
            is_real: false,
        }
    }

    /// Generate a real SEV-SNP attestation report (requires real-tee feature)
    #[cfg(feature = "real-tee")]
    pub fn generate_real(public_key: &[u8]) -> Result<Self> {
        use sev_snp_utilities::{AttestationReport as SevReport, Requester};

        // Create report_data: [0..32] = SHA-256(public_key), [32..64] = SHA-256(binary)
        let mut report_data = [0u8; 64];
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let pk_hash = hasher.finalize();
        report_data[..32].copy_from_slice(&pk_hash);
        report_data[32..64].copy_from_slice(&self_measurement());

        // Request attestation from hardware using request_raw
        let raw_bytes = SevReport::request_raw(&report_data)
            .map_err(|e| anyhow::anyhow!("Failed to get SEV-SNP report: {}", e))?;

        // Parse the raw report to extract fields
        // SEV-SNP report structure offsets:
        // 0x000: version (4 bytes)
        // 0x090: measurement (48 bytes)
        // 0x050: report_data (64 bytes)
        // 0x1A0: chip_id (64 bytes)

        let version = u32::from_le_bytes(raw_bytes[0..4].try_into().unwrap());
        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&raw_bytes[0x090..0x0C0]);
        let mut rd = [0u8; 64];
        rd.copy_from_slice(&raw_bytes[0x050..0x090]);
        let chip_id = raw_bytes[0x1A0..0x1E0].to_vec();

        Ok(AttestationReport {
            version,
            measurement: hex::encode(measurement),
            report_data: hex::encode(rd),
            raw_report: hex::encode(&raw_bytes[..0x2A0]), // Report body
            signature: hex::encode(&raw_bytes[0x2A0..]),   // Signature
            chip_id: hex::encode(chip_id),
            is_real: true,
        })
    }

    /// Get measurement as bytes
    pub fn measurement_bytes(&self) -> Result<[u8; 48]> {
        let bytes = hex::decode(&self.measurement)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid measurement length"))
    }

    /// Get report_data as bytes
    pub fn report_data_bytes(&self) -> Result<[u8; 64]> {
        let bytes = hex::decode(&self.report_data)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid report_data length"))
    }

    /// Get the binary self-measurement hash from report_data[32..64] as hex
    pub fn binary_hash(&self) -> Result<String> {
        let rd = self.report_data_bytes()?;
        Ok(hex::encode(&rd[32..64]))
    }

    /// Serialize report for transmission
    #[cfg(feature = "server")]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialization failed")
    }

    /// Deserialize report from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// Verify an attestation report
///
/// For mock reports: checks the mock signature
/// For real reports: should verify against AMD certificate chain (see certs.rs)
pub fn verify_mock_report(report: &AttestationReport, expected_public_key: &[u8]) -> Result<()> {
    if report.is_real {
        anyhow::bail!("Use verify_real_report for real attestation reports");
    }

    // Verify public key binding
    let mut hasher = Sha256::new();
    hasher.update(expected_public_key);
    let expected_pk_hash: [u8; 32] = hasher.finalize().into();

    let report_data = report.report_data_bytes()?;
    if report_data[..32] != expected_pk_hash {
        anyhow::bail!("Public key mismatch: report not bound to this handshake");
    }

    // Verify measurement matches expected TEE code
    let mut hasher = Sha384::new();
    hasher.update(SIMULATED_TEE_CODE);
    let expected_measurement: [u8; 48] = hasher.finalize().into();

    let measurement = report.measurement_bytes()?;
    if measurement != expected_measurement {
        anyhow::bail!("Measurement mismatch: TEE code has been tampered with");
    }

    // Verify mock signature
    let raw_report = hex::decode(&report.raw_report)?;
    let mut sig_hasher = Sha384::new();
    sig_hasher.update(&raw_report);
    sig_hasher.update(b"mock-signing-key");
    let expected_sig = sig_hasher.finalize().to_vec();

    let signature = hex::decode(&report.signature)?;
    if signature != expected_sig {
        anyhow::bail!("Invalid mock attestation signature");
    }

    Ok(())
}
