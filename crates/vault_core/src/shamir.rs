use std::collections::HashSet;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::identity::ShamirShare;

struct Gf256Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

static GF256: OnceLock<Gf256Tables> = OnceLock::new();

fn tables() -> &'static Gf256Tables {
    GF256.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;
            let x_times_2 = (x << 1) ^ if (x & 0x80) != 0 { 0x11B } else { 0 };
            x = x_times_2 ^ x;
        }
        log[0] = 0;
        Gf256Tables { exp, log }
    })
}

#[inline]
pub fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline]
pub fn gf256_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

#[inline]
pub fn gf256_div(a: u8, b: u8) -> Result<u8> {
    if b == 0 {
        return Err(VaultError::Quorum("division by zero in GF(256)".into()));
    }
    if a == 0 {
        return Ok(0);
    }
    let t = tables();
    Ok(t.exp[t.log[a as usize] as usize + 255 - t.log[b as usize] as usize])
}

/// 16-hex-character (8-byte) SHA-256 commitment matching `mcp_vault_dev_server.py`.
pub fn secret_commitment(secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"LAVAULT-SHAMIR-V1:");
    hasher.update(secret);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// 8-hex-character share checksum matching `mcp_vault_dev_server.py`.
pub fn share_checksum(index: u8, data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([index]);
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(&digest[..4])
}

pub fn slip39_uri(share: &ShamirShare) -> String {
    let csum = share_checksum(share.index(), share.data());
    format!(
        "lavault-share://v1/{}-of-{}/idx-{}/{}.{}",
        share.threshold_k(),
        share.total_n(),
        share.index(),
        hex::encode(share.data()),
        csum
    )
}

/// Parse and checksum-verify a `lavault-share://v1/<K>-of-<N>/idx-<idx>/<hex>.<csum>` URI.
pub fn parse_slip39_uri(uri: &str) -> Result<ShamirShare> {
    let body = uri
        .trim()
        .strip_prefix("lavault-share://v1/")
        .ok_or_else(|| {
            VaultError::InvalidInput("share URI must start with lavault-share://v1/".into())
        })?;
    let parts: Vec<&str> = body.split('/').collect();
    if parts.len() != 3 {
        return Err(VaultError::InvalidInput(
            "invalid share URI layout; expected <K>-of-<N>/idx-<idx>/<hex>.<csum>".into(),
        ));
    }
    let (k_str, n_str) = parts[0]
        .split_once("-of-")
        .ok_or_else(|| VaultError::InvalidInput("invalid <K>-of-<N> quorum segment".into()))?;
    let k: u8 = k_str
        .parse()
        .map_err(|_| VaultError::InvalidInput("invalid K value in share URI".into()))?;
    let n: u8 = n_str
        .parse()
        .map_err(|_| VaultError::InvalidInput("invalid N value in share URI".into()))?;
    validate_params(k, n)?;

    let idx_str = parts[1]
        .strip_prefix("idx-")
        .ok_or_else(|| VaultError::InvalidInput("invalid idx-<idx> segment".into()))?;
    let idx: u8 = idx_str
        .parse()
        .map_err(|_| VaultError::InvalidInput("invalid share index".into()))?;
    if idx == 0 || idx > n {
        return Err(VaultError::Quorum(format!(
            "share index {idx} out of range 1..={n}"
        )));
    }

    let (hex_data, csum) = parts[2]
        .split_once('.')
        .ok_or_else(|| VaultError::InvalidInput("missing .<checksum> suffix".into()))?;
    let data = hex::decode(hex_data.trim())
        .map_err(|e| VaultError::InvalidInput(format!("invalid share hex payload: {e}")))?;
    let expected_csum = share_checksum(idx, &data);
    if expected_csum != csum.trim().to_ascii_lowercase() {
        return Err(VaultError::AuthFailed(format!(
            "guardian share idx-{idx} checksum mismatch"
        )));
    }
    Ok(ShamirShare::new(idx, k, n, data))
}

fn validate_params(threshold_k: u8, total_n: u8) -> Result<()> {
    if threshold_k == 0 || threshold_k > total_n {
        return Err(VaultError::Quorum(format!(
            "invalid Shamir parameters: K={threshold_k}, N={total_n} (require 1 <= K <= N <= 255)"
        )));
    }
    Ok(())
}

/// Split `secret` into `total_n` shares requiring `threshold_k` shares using OS CSPRNG.
pub fn shamir_split_secret_random(
    secret: &[u8],
    threshold_k: u8,
    total_n: u8,
) -> Result<Vec<ShamirShare>> {
    shamir_split_inner(secret, threshold_k, total_n, None)
}

/// Deterministic split matching `mcp_vault_dev_server.py` for cross-language reference vector parity.
pub fn shamir_split_secret_deterministic(
    secret: &[u8],
    threshold_k: u8,
    total_n: u8,
    seed: &[u8],
) -> Result<Vec<ShamirShare>> {
    shamir_split_inner(secret, threshold_k, total_n, Some(seed))
}

fn shamir_split_inner(
    secret: &[u8],
    threshold_k: u8,
    total_n: u8,
    deterministic_seed: Option<&[u8]>,
) -> Result<Vec<ShamirShare>> {
    validate_params(threshold_k, total_n)?;
    if secret.is_empty() {
        return Err(VaultError::InvalidInput(
            "cannot split an empty secret".into(),
        ));
    }

    let mut shares_bytes = vec![vec![0u8; secret.len()]; total_n as usize];
    let mut coeffs = vec![0u8; threshold_k as usize];

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        coeffs[0] = secret_byte;
        for coeff_idx in 1..(threshold_k as usize) {
            if let Some(seed) = deterministic_seed {
                let mut hasher = Sha256::new();
                hasher.update(seed);
                hasher.update((byte_idx as u32).to_be_bytes());
                hasher.update((coeff_idx as u32).to_be_bytes());
                let h = hasher.finalize();
                coeffs[coeff_idx] = if h[0] != 0 { h[0] } else { 1 };
            } else {
                let mut rnd = [0u8; 1];
                loop {
                    getrandom::getrandom(&mut rnd)
                        .map_err(|e| VaultError::Crypto(format!("getrandom failed: {e}")))?;
                    if rnd[0] != 0 {
                        break;
                    }
                }
                coeffs[coeff_idx] = rnd[0];
            }
        }

        for share_num in 1..=total_n {
            let x = share_num;
            let mut y = 0u8;
            for &c in coeffs.iter().rev() {
                y = gf256_add(gf256_mul(y, x), c);
            }
            shares_bytes[(share_num - 1) as usize][byte_idx] = y;
        }
    }
    coeffs.zeroize();

    Ok(shares_bytes
        .into_iter()
        .enumerate()
        .map(|(i, raw)| ShamirShare::new((i + 1) as u8, threshold_k, total_n, raw))
        .collect())
}

/// Reconstruct secret from `K` or more GF(256) Shamir shares via Lagrange interpolation at x = 0.
pub fn shamir_reconstruct_secret(
    shares: &[ShamirShare],
    expected_commitment: Option<&str>,
) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(VaultError::Quorum("no Shamir shares provided".into()));
    }

    let k = shares[0].threshold_k() as usize;
    if k == 0 {
        return Err(VaultError::Quorum("invalid threshold_k = 0".into()));
    }
    if shares.len() < k {
        return Err(VaultError::Quorum(format!(
            "insufficient shares for quorum: provided {}, require at least K={k}",
            shares.len()
        )));
    }

    let selected = &shares[..k];
    let secret_len = selected[0].data().len();
    if secret_len == 0 {
        return Err(VaultError::Quorum("empty share payload".into()));
    }

    let mut seen = HashSet::with_capacity(k);
    let mut xs = Vec::with_capacity(k);
    for s in selected {
        if s.index() == 0 {
            return Err(VaultError::Quorum("share index 0 is invalid".into()));
        }
        if s.data().len() != secret_len {
            return Err(VaultError::Quorum("share lengths do not match".into()));
        }
        if !seen.insert(s.index()) {
            return Err(VaultError::Quorum(
                "duplicate share indices detected in quorum".into(),
            ));
        }
        xs.push(s.index());
    }

    let mut lagrange_weights = Vec::with_capacity(k);
    for i in 0..k {
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..k {
            if i == j {
                continue;
            }
            num = gf256_mul(num, xs[j]);
            den = gf256_mul(den, gf256_add(xs[j], xs[i]));
        }
        lagrange_weights.push(gf256_div(num, den)?);
    }

    let mut reconstructed = vec![0u8; secret_len];
    for byte_idx in 0..secret_len {
        let mut val = 0u8;
        for i in 0..k {
            val = gf256_add(val, gf256_mul(selected[i].data()[byte_idx], lagrange_weights[i]));
        }
        reconstructed[byte_idx] = val;
    }

    if let Some(expected) = expected_commitment {
        let actual = secret_commitment(&reconstructed);
        if actual != expected {
            reconstructed.zeroize();
            return Err(VaultError::AuthFailed(format!(
                "Shamir reconstruction commitment mismatch: expected {expected}, got {actual}"
            )));
        }
    }

    Ok(reconstructed)
}
