//! AMD certificate chain verification for SEV-SNP attestation.
//!
//! Certificate chain: VCEK (chip) → ASK (intermediate) → ARK (root)
//! - VCEK: Versioned Chip Endorsement Key (unique per CPU)
//! - ASK: AMD SEV Signing Key (intermediate CA)
//! - ARK: AMD Root Key (trust anchor)

use anyhow::{Context, Result};
use der::Decode;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha384};
use x509_cert::Certificate;

/// AMD Key Distribution Service endpoints
#[allow(dead_code)]
const AMD_KDS_VCEK: &str = "https://kdsintf.amd.com/vcek/v1";
const AMD_KDS_CERT_CHAIN: &str = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain";

/// Fetch the VCEK certificate for a specific chip
#[allow(dead_code)]
pub async fn fetch_vcek(chip_id: &[u8], reported_tcb: u64) -> Result<Vec<u8>> {
    let chip_id_hex = hex::encode(chip_id);

    // TCB version components (from the attestation report)
    let tcb_bytes = reported_tcb.to_le_bytes();

    let url = format!(
        "{}/Milan/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        AMD_KDS_VCEK,
        chip_id_hex,
        tcb_bytes[0], // Boot loader SPL
        tcb_bytes[1], // TEE SPL
        tcb_bytes[6], // SNP SPL
        tcb_bytes[7], // Microcode SPL
    );

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch VCEK: {} - {}", response.status(), url);
    }

    Ok(response.bytes().await?.to_vec())
}

/// Fetch the AMD certificate chain (ASK + ARK)
pub async fn fetch_cert_chain() -> Result<(Vec<u8>, Vec<u8>)> {
    let client = reqwest::Client::new();
    let response = client.get(AMD_KDS_CERT_CHAIN).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch cert chain: {}", response.status());
    }

    let pem_data = response.text().await?;

    // Parse PEM to extract ASK and ARK certificates
    // The response contains two certificates concatenated
    let certs: Vec<&str> = pem_data
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .collect();

    if certs.len() < 2 {
        anyhow::bail!("Expected 2 certificates in chain, got {}", certs.len());
    }

    let ask_pem = format!("{}-----END CERTIFICATE-----", certs[0]);
    let ark_pem = format!("{}-----END CERTIFICATE-----", certs[1]);

    Ok((ask_pem.into_bytes(), ark_pem.into_bytes()))
}

/// Parse a DER-encoded X.509 certificate
pub fn parse_der_certificate(der_bytes: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der_bytes)
        .context("Failed to parse DER-encoded certificate")
}

/// Parse a PEM-encoded X.509 certificate
pub fn parse_pem_certificate(pem_bytes: &[u8]) -> Result<Certificate> {
    use x509_cert::der::DecodePem;
    let pem_str = std::str::from_utf8(pem_bytes)
        .context("PEM data is not valid UTF-8")?;
    Certificate::from_pem(pem_str)
        .context("Failed to parse PEM-encoded certificate")
}

/// Extract the P-384 public key from a certificate (for VCEK)
fn extract_p384_public_key(cert: &Certificate) -> Result<VerifyingKey> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let key_bytes = spki.subject_public_key.as_bytes()
        .ok_or_else(|| anyhow::anyhow!("Public key has unused bits"))?;

    VerifyingKey::from_sec1_bytes(key_bytes)
        .context("Failed to parse P-384 public key from certificate")
}

/// Extract RSA public key from a certificate (for ARK/ASK)
fn extract_rsa_public_key(cert: &Certificate) -> Result<rsa::RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let key_bytes = spki.subject_public_key.as_bytes()
        .ok_or_else(|| anyhow::anyhow!("Public key has unused bits"))?;

    rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
        .context("Failed to parse RSA public key from certificate")
}

/// Verify a certificate's RSA-PSS signature (for ARK/ASK chain)
///
/// AMD ARK and ASK use RSA-4096 with RSA-PSS padding and SHA-384
fn verify_rsa_cert_signature(cert: &Certificate, issuer_key: &rsa::RsaPublicKey) -> Result<()> {
    use der::Encode;
    use rsa::signature::Verifier;
    use rsa::pss::{Signature, VerifyingKey};
    use sha2::Sha384;

    // Get the TBS (to-be-signed) certificate bytes
    let tbs_bytes = cert.tbs_certificate.to_der()
        .context("Failed to encode TBS certificate")?;

    // Get the signature bytes
    let sig_bytes = cert.signature.as_bytes()
        .ok_or_else(|| anyhow::anyhow!("Signature has unused bits"))?;

    let signature = Signature::try_from(sig_bytes)
        .context("Failed to parse RSA-PSS signature")?;

    let verifying_key = VerifyingKey::<Sha384>::new(issuer_key.clone());
    verifying_key.verify(&tbs_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("RSA-PSS certificate signature verification failed"))
}

/// Verify the AMD certificate chain (ARK → ASK → VCEK)
///
/// Returns the VCEK's public key for use in report signature verification
pub fn verify_certificate_chain(
    vcek_der: &[u8],
    ask_pem: &[u8],
    ark_pem: &[u8],
) -> Result<VerifyingKey> {
    // Parse all certificates
    let vcek = parse_der_certificate(vcek_der)
        .context("Failed to parse VCEK certificate")?;
    let ask = parse_pem_certificate(ask_pem)
        .context("Failed to parse ASK certificate")?;
    let ark = parse_pem_certificate(ark_pem)
        .context("Failed to parse ARK certificate")?;

    // 1. Verify ARK is from AMD (issuer DN check)
    let ark_issuer = ark.tbs_certificate.issuer.to_string();
    if !ark_issuer.contains("AMD") && !ark_issuer.contains("Advanced Micro Devices") {
        anyhow::bail!(
            "Invalid certificate: ARK issuer DN does not contain 'AMD' or 'Advanced Micro Devices'\n\
             Got: {}", ark_issuer
        );
    }

    // 2. Verify ARK is self-signed (RSA-4096)
    let ark_key = extract_rsa_public_key(&ark)
        .context("Failed to extract ARK public key")?;
    verify_rsa_cert_signature(&ark, &ark_key)
        .context("ARK is not properly self-signed")?;
    println!("[Certs] ARK self-signature verified");

    // 3. Verify ASK is signed by ARK (RSA-4096)
    verify_rsa_cert_signature(&ask, &ark_key)
        .context("ASK is not signed by ARK")?;
    println!("[Certs] ASK signature verified (signed by ARK)");

    // 4. Verify VCEK is signed by ASK (RSA-4096 signature over ECDSA cert)
    let ask_key = extract_rsa_public_key(&ask)
        .context("Failed to extract ASK public key")?;
    verify_rsa_cert_signature(&vcek, &ask_key)
        .context("VCEK is not signed by ASK")?;
    println!("[Certs] VCEK signature verified (signed by ASK)");

    // 5. Extract and return VCEK public key
    let vcek_key = extract_p384_public_key(&vcek)
        .context("Failed to extract VCEK public key")?;

    Ok(vcek_key)
}

/// Parse TCB version from raw attestation report
///
/// TCB is at offset 0x180-0x188 in the report
pub fn parse_tcb_from_report(raw_report: &[u8]) -> Result<u64> {
    if raw_report.len() < 0x188 {
        anyhow::bail!("Report too short to contain TCB version");
    }

    let tcb_bytes: [u8; 8] = raw_report[0x180..0x188].try_into()
        .map_err(|_| anyhow::anyhow!("Failed to extract TCB bytes"))?;

    Ok(u64::from_le_bytes(tcb_bytes))
}

/// Verify attestation report signature using VCEK public key
///
/// AMD SEV-SNP reports use ECDSA P-384:
/// - Report body: first 0x2A0 (672) bytes
/// - Signature structure (512 bytes total):
///   - r component: bytes 0-71 (only first 48 used for P-384)
///   - s component: bytes 72-143 (only first 48 used for P-384)
///   - reserved: bytes 144-511
pub fn verify_report_signature_with_key(
    report: &crate::attestation::AttestationReport,
    vcek_key: &VerifyingKey,
) -> Result<()> {
    if !report.is_real {
        anyhow::bail!("Cannot verify mock report with real verification");
    }

    // Extract report body (first 0x2A0 bytes = 672 bytes)
    let raw_report = hex::decode(&report.raw_report)
        .context("Failed to decode raw report")?;
    if raw_report.len() < 0x2A0 {
        anyhow::bail!("Report too short: expected at least 672 bytes");
    }
    let report_body = &raw_report[..0x2A0];

    // Extract signature from AMD's padded format
    let sig_bytes = hex::decode(&report.signature)
        .context("Failed to decode signature")?;
    if sig_bytes.len() < 144 {
        anyhow::bail!("Signature too short: expected at least 144 bytes");
    }

    // AMD SEV-SNP signature format (little-endian):
    // - r: bytes 0-47 (48 bytes for P-384, rest is padding)
    // - s: bytes 72-119 (48 bytes for P-384, rest is padding)
    // The crypto library expects big-endian, so we need to reverse
    let mut r = [0u8; 48];
    let mut s = [0u8; 48];
    r.copy_from_slice(&sig_bytes[..48]);
    s.copy_from_slice(&sig_bytes[72..120]);

    // Reverse from little-endian to big-endian
    r.reverse();
    s.reverse();

    let mut sig_concat = [0u8; 96];
    sig_concat[..48].copy_from_slice(&r);
    sig_concat[48..].copy_from_slice(&s);

    let signature = Signature::from_slice(&sig_concat)
        .context("Failed to parse ECDSA signature")?;

    // Verify signature over the report body
    vcek_key.verify(report_body, &signature)
        .map_err(|_| anyhow::anyhow!("Report signature verification failed"))?;

    Ok(())
}

/// Verify the public key binding in the attestation report
pub fn verify_public_key_binding(
    report: &crate::attestation::AttestationReport,
    expected_public_key: &[u8],
) -> Result<()> {
    use sha2::Sha256;

    let mut hasher = Sha256::new();
    hasher.update(expected_public_key);
    let expected_hash: [u8; 32] = hasher.finalize().into();

    let report_data = report.report_data_bytes()?;
    if report_data[..32] != expected_hash {
        anyhow::bail!(
            "Public key binding failed: report not bound to this handshake\n\
             Expected: {}\n\
             Got: {}",
            hex::encode(expected_hash),
            hex::encode(&report_data[..32])
        );
    }

    Ok(())
}

/// Default mock measurement (SHA-384 of "tee-talk-v0.1.0")
pub(crate) const SIMULATED_TEE_CODE: &[u8] = b"tee-talk-v0.1.0";

/// Verify the measurement in the attestation report
///
/// For real attestation: requires `expected_measurement` parameter or `EXPECTED_MEASUREMENT` env var
/// For mock attestation: falls back to default mock measurement if none provided
pub fn verify_measurement(
    report: &crate::attestation::AttestationReport,
    expected_measurement: Option<&[u8]>,
) -> Result<()> {
    let report_measurement = report.measurement_bytes()?;

    // Determine expected measurement
    let expected: [u8; 48] = if let Some(m) = expected_measurement {
        // Explicit parameter takes priority
        m.try_into().map_err(|_| anyhow::anyhow!("Expected measurement must be 48 bytes"))?
    } else if let Ok(env_val) = std::env::var("EXPECTED_MEASUREMENT") {
        // Fall back to environment variable
        let bytes = hex::decode(&env_val)
            .map_err(|_| anyhow::anyhow!("EXPECTED_MEASUREMENT must be valid hex"))?;
        bytes.try_into()
            .map_err(|_| anyhow::anyhow!("EXPECTED_MEASUREMENT must be 48 bytes (96 hex chars)"))?
    } else if !report.is_real {
        // For mock attestation, use default measurement
        let mut hasher = Sha384::new();
        hasher.update(SIMULATED_TEE_CODE);
        hasher.finalize().into()
    } else {
        // Real attestation requires explicit measurement
        anyhow::bail!(
            "Real attestation requires expected measurement.\n\
             Set EXPECTED_MEASUREMENT env var or provide measurement parameter."
        );
    };

    if report_measurement != expected {
        anyhow::bail!(
            "Measurement mismatch: TEE code does not match expected value.\n\
             Expected: {}\n\
             Got: {}",
            hex::encode(expected),
            hex::encode(report_measurement)
        );
    }

    Ok(())
}

/// Verify the binary self-measurement in report_data[32..64]
///
/// Compares against EXPECTED_BINARY_HASH env var (hex-encoded SHA-256).
/// If the env var is not set, prints a warning and skips.
pub fn verify_binary_hash(
    report: &crate::attestation::AttestationReport,
) -> Result<()> {
    let binary_hash = report.binary_hash()?;

    if let Ok(expected) = std::env::var("EXPECTED_BINARY_HASH") {
        if binary_hash != expected {
            anyhow::bail!(
                "Binary hash mismatch: the running binary does not match the expected build.\n\
                 Expected: {}\n\
                 Got:      {}",
                expected,
                binary_hash
            );
        }
        println!("[Certs] Binary hash verified: {}", &binary_hash[..16]);
    } else {
        println!("[Certs] Binary hash: {} (no EXPECTED_BINARY_HASH set, skipping check)", &binary_hash[..16]);
    }

    Ok(())
}

/// Full attestation verification
///
/// If `trust_server` is true, skips all verification but still completes the
/// Noise handshake — the connection is encrypted regardless.
pub async fn verify_attestation(
    report: &crate::attestation::AttestationReport,
    expected_public_key: &[u8],
    trust_server: bool,
) -> Result<()> {
    if trust_server {
        println!("[Certs] --trust-server: skipping attestation verification");
        println!("[Certs] Connection is still end-to-end encrypted via Noise protocol");
        return Ok(());
    }

    println!("[Certs] Verifying attestation report...");

    // 1. Verify public key binding (report is bound to this handshake)
    verify_public_key_binding(report, expected_public_key)?;
    println!("[Certs] Public key binding verified");

    // 2. Verify measurement (TEE code hash)
    verify_measurement(report, None)?;
    println!("[Certs] Measurement verified");

    // 3. Verify binary self-measurement from report_data[32..64]
    verify_binary_hash(report)?;

    if report.is_real {
        // 4. Fetch AMD certificate chain (ASK + ARK)
        println!("[Certs] Fetching AMD certificate chain...");
        let (ask_pem, ark_pem) = fetch_cert_chain().await?;
        println!("[Certs] Certificate chain fetched");

        // 5. Parse TCB and fetch VCEK for this chip
        let raw_report = hex::decode(&report.raw_report)
            .context("Failed to decode raw report")?;
        let tcb = parse_tcb_from_report(&raw_report)?;
        let chip_id = hex::decode(&report.chip_id)
            .context("Failed to decode chip_id")?;

        println!("[Certs] Fetching VCEK certificate...");
        let vcek_der = fetch_vcek(&chip_id, tcb).await?;
        println!("[Certs] VCEK certificate fetched");

        // 6. Verify certificate chain and get VCEK public key
        let vcek_key = verify_certificate_chain(&vcek_der, &ask_pem, &ark_pem)?;
        println!("[Certs] Certificate chain verified");

        // 7. Verify report signature
        verify_report_signature_with_key(report, &vcek_key)?;
        println!("[Certs] Report signature verified");
    } else {
        // Mock verification
        crate::attestation::verify_mock_report(report, expected_public_key)?;
    }

    println!("[Certs] Attestation verified successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Tests that use EXPECTED_MEASUREMENT env var may have race conditions
    // when run in parallel. Use `cargo test -- --test-threads=1` if tests fail.

    // ===========================================
    // Measurement Verification Tests
    // ===========================================

    #[test]
    fn test_verify_measurement_mock_uses_default() {
        // Create a mock report with the expected default measurement
        let public_key = b"test-public-key";
        let report = crate::attestation::AttestationReport::generate_mock(public_key);

        // Should pass without EXPECTED_MEASUREMENT env var
        std::env::remove_var("EXPECTED_MEASUREMENT");
        let result = verify_measurement(&report, None);
        assert!(result.is_ok(), "Mock measurement should use default");
    }

    #[test]
    fn test_verify_measurement_with_valid_env() {
        let public_key = b"test-public-key";
        let report = crate::attestation::AttestationReport::generate_mock(public_key);

        // Compute expected measurement
        let mut hasher = Sha384::new();
        hasher.update(SIMULATED_TEE_CODE);
        let expected: [u8; 48] = hasher.finalize().into();

        std::env::set_var("EXPECTED_MEASUREMENT", hex::encode(expected));
        let result = verify_measurement(&report, None);
        std::env::remove_var("EXPECTED_MEASUREMENT");

        assert!(result.is_ok(), "Valid EXPECTED_MEASUREMENT should pass");
    }

    #[test]
    fn test_verify_measurement_with_invalid_env() {
        let public_key = b"test-public-key";
        let report = crate::attestation::AttestationReport::generate_mock(public_key);

        // Set wrong measurement (all zeros)
        let wrong_measurement = hex::encode([0u8; 48]);
        std::env::set_var("EXPECTED_MEASUREMENT", wrong_measurement);
        let result = verify_measurement(&report, None);
        std::env::remove_var("EXPECTED_MEASUREMENT");

        assert!(result.is_err(), "Wrong measurement should fail");
        assert!(
            result.unwrap_err().to_string().contains("Measurement mismatch"),
            "Error should mention measurement mismatch"
        );
    }

    #[test]
    fn test_verify_measurement_with_explicit_param() {
        let public_key = b"test-public-key";
        let report = crate::attestation::AttestationReport::generate_mock(public_key);

        // Compute correct measurement
        let mut hasher = Sha384::new();
        hasher.update(SIMULATED_TEE_CODE);
        let expected: [u8; 48] = hasher.finalize().into();

        let result = verify_measurement(&report, Some(&expected));
        assert!(result.is_ok(), "Explicit correct measurement should pass");

        // Try wrong measurement
        let wrong = [0u8; 48];
        let result = verify_measurement(&report, Some(&wrong));
        assert!(result.is_err(), "Explicit wrong measurement should fail");
    }

    // ===========================================
    // Certificate Parsing Tests
    // ===========================================

    #[test]
    fn test_parse_der_certificate_invalid() {
        let invalid_der = b"not a valid certificate";
        let result = parse_der_certificate(invalid_der);
        assert!(result.is_err(), "Invalid DER should fail to parse");
    }

    #[test]
    fn test_parse_pem_certificate_missing_headers() {
        let invalid_pem = b"just some random data without PEM headers";
        let result = parse_pem_certificate(invalid_pem);
        assert!(result.is_err(), "Invalid PEM should fail to parse");
    }

    #[test]
    fn test_parse_pem_certificate_invalid_utf8() {
        let invalid_utf8: &[u8] = &[0xFF, 0xFE, 0x00, 0x01];
        let result = parse_pem_certificate(invalid_utf8);
        assert!(result.is_err(), "Invalid UTF-8 should fail");
        assert!(
            result.unwrap_err().to_string().contains("UTF-8"),
            "Error should mention UTF-8"
        );
    }

    // ===========================================
    // TCB Parsing Tests
    // ===========================================

    #[test]
    fn test_parse_tcb_from_report_valid() {
        // Create a report buffer large enough
        let mut report = vec![0u8; 0x200];
        // Set TCB at offset 0x180
        let tcb_value: u64 = 0x0102030405060708;
        report[0x180..0x188].copy_from_slice(&tcb_value.to_le_bytes());

        let result = parse_tcb_from_report(&report);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tcb_value);
    }

    #[test]
    fn test_parse_tcb_from_report_too_short() {
        let short_report = vec![0u8; 0x100]; // Too short
        let result = parse_tcb_from_report(&short_report);
        assert!(result.is_err(), "Short report should fail TCB parsing");
    }

    // ===========================================
    // Signature Verification Tests
    // ===========================================

    #[test]
    fn test_verify_report_signature_mock_rejected() {
        let public_key = b"test-public-key";
        let report = crate::attestation::AttestationReport::generate_mock(public_key);

        // Use the P-384 generator point as a valid test key
        let generator_hex = "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
        let key_bytes = hex::decode(generator_hex).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes).unwrap();

        let result = verify_report_signature_with_key(&report, &verifying_key);
        assert!(result.is_err(), "Mock report should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("mock"),
            "Error should mention mock"
        );
    }

    // ===========================================
    // Integration-style Tests
    // ===========================================

    #[test]
    fn test_verify_measurement_real_requires_explicit() {
        // Create a mock report but mark it as "real" to test the requirement
        let public_key = b"test-public-key";
        let mut report = crate::attestation::AttestationReport::generate_mock(public_key);
        report.is_real = true;

        // Clear any env var
        std::env::remove_var("EXPECTED_MEASUREMENT");

        let result = verify_measurement(&report, None);
        assert!(result.is_err(), "Real attestation should require explicit measurement");
        assert!(
            result.unwrap_err().to_string().contains("requires expected measurement"),
            "Error should explain requirement"
        );
    }
}
