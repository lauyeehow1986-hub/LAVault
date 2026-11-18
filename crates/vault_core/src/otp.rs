use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Result, VaultError};
use crate::identity::TotpSecret;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Default for OtpAlgorithm {
    fn default() -> Self {
        Self::Sha1
    }
}

fn compute_hmac(alg: OtpAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match alg {
        OtpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key)
                .map_err(|e| VaultError::Crypto(format!("HMAC-SHA1 key error: {e}")))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| VaultError::Crypto(format!("HMAC-SHA256 key error: {e}")))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key)
                .map_err(|e| VaultError::Crypto(format!("HMAC-SHA512 key error: {e}")))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Compute HOTP per RFC 4226 Section 5.3.
pub fn hotp_rfc4226(secret: &[u8], counter: u64, digits: u32, alg: OtpAlgorithm) -> Result<String> {
    if !(6..=8).contains(&digits) {
        return Err(VaultError::InvalidInput(format!(
            "OTP digits must be 6..=8, got {digits}"
        )));
    }
    let mac = compute_hmac(alg, secret, &counter.to_be_bytes())?;
    let offset = (mac[mac.len() - 1] & 0x0F) as usize;
    let binary = u32::from_be_bytes([
        mac[offset] & 0x7F,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    let modulus = 10u32.pow(digits);
    let otp = binary % modulus;
    Ok(format!("{:0width$}", otp, width = digits as usize))
}

/// Compute TOTP per RFC 6238 Section 4.
pub fn totp_rfc6238(
    secret: &[u8],
    unix_time: u64,
    step_seconds: u64,
    t0: u64,
    digits: u32,
    alg: OtpAlgorithm,
) -> Result<String> {
    if step_seconds == 0 {
        return Err(VaultError::InvalidInput(
            "TOTP step_seconds must be > 0".into(),
        ));
    }
    if unix_time < t0 {
        return Err(VaultError::InvalidInput(
            "unix_time must be >= t0".into(),
        ));
    }
    let counter = (unix_time - t0) / step_seconds;
    hotp_rfc4226(secret, counter, digits, alg)
}

/// Decode a Base32 TOTP secret (case-insensitive, whitespace/padding-tolerant) into a zeroized `TotpSecret`.
pub fn decode_base32_secret(secret_b32: &str) -> Result<TotpSecret> {
    let normalized: String = secret_b32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(VaultError::InvalidInput("empty Base32 TOTP secret".into()));
    }
    let raw = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|e| VaultError::InvalidInput(format!("invalid Base32 TOTP secret: {e}")))?;
    Ok(TotpSecret::from_bytes(raw))
}

/// Compute TOTP code and remaining seconds in the current window from a Base32 secret.
pub fn totp_from_base32(
    secret_b32: &str,
    unix_time: u64,
    step_seconds: u64,
    digits: u32,
    alg: OtpAlgorithm,
) -> Result<(String, u64)> {
    let secret = decode_base32_secret(secret_b32)?;
    let code = totp_rfc6238(secret.as_bytes(), unix_time, step_seconds, 0, digits, alg)?;
    let remaining = step_seconds - (unix_time % step_seconds);
    Ok((code, remaining))
}
