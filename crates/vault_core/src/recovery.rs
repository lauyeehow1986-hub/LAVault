use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::identity::{
    stretch_master_password, DerivedIdentityKeys, MasterIdentitySeed, ShamirShare, VaultPassword,
};
use crate::shamir::{
    secret_commitment, shamir_reconstruct_secret, shamir_split_secret_random, slip39_uri,
};

const RKF_MAGIC: &[u8; 8] = b"LAVRKF1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianShareCapsule {
    pub guardian_id: String,
    pub share_index: u8,
    pub threshold_k: u8,
    pub total_n: u8,
    pub share_hex: String,
    pub secret_commitment: String,
    pub slip39_uri: String,
    pub signature_hex: String,
}

impl GuardianShareCapsule {
    fn signing_payload(&self) -> Vec<u8> {
        format!(
            "LAVAULT-GUARDIAN-V1|{}|{}|{}|{}|{}|{}",
            self.guardian_id,
            self.share_index,
            self.threshold_k,
            self.total_n,
            self.share_hex,
            self.secret_commitment
        )
        .into_bytes()
    }
}

/// Option 1: Export 256-bit `MasterIdentitySeed` as a 24-word BIP-0039 mnemonic phrase.
pub fn export_bip39_mnemonic(seed: &MasterIdentitySeed) -> Result<String> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, seed.as_bytes())
        .map_err(|e| VaultError::Crypto(format!("BIP-39 mnemonic creation failed: {e}")))?;
    Ok(mnemonic.to_string())
}

/// Option 1: Recover 256-bit `MasterIdentitySeed` from a 24-word BIP-0039 mnemonic phrase.
pub fn import_bip39_mnemonic(phrase: &str) -> Result<MasterIdentitySeed> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| VaultError::InvalidInput(format!("invalid BIP-39 mnemonic: {e}")))?;
    let mut entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        entropy.zeroize();
        return Err(VaultError::InvalidInput(format!(
            "expected 24-word (32-byte) mnemonic, got {} bytes",
            entropy.len()
        )));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&entropy);
    entropy.zeroize();
    let seed = MasterIdentitySeed::from_bytes(buf);
    buf.zeroize();
    Ok(seed)
}

/// Option 2: Export an Argon2id + XChaCha20-Poly1305 encrypted `.rkf` recovery keyfile.
pub fn export_rkf_keyfile(
    seed: &MasterIdentitySeed,
    password: &VaultPassword,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut salt)
        .map_err(|e| VaultError::Crypto(format!("getrandom salt failed: {e}")))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| VaultError::Crypto(format!("getrandom nonce failed: {e}")))?;

    let kek = stretch_master_password(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_bytes().into());

    let mut aad = Vec::with_capacity(8 + 16 + 24);
    aad.extend_from_slice(RKF_MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: seed.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("RKF encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(aad.len() + ciphertext.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Option 2: Decrypt an `.rkf` recovery keyfile back into a `MasterIdentitySeed`.
pub fn import_rkf_keyfile(rkf_bytes: &[u8], password: &VaultPassword) -> Result<MasterIdentitySeed> {
    if rkf_bytes.len() < 8 + 16 + 24 + 32 + 16 {
        return Err(VaultError::InvalidInput("RKF keyfile truncated".into()));
    }
    if &rkf_bytes[..8] != RKF_MAGIC {
        return Err(VaultError::InvalidInput("invalid RKF magic header".into()));
    }
    let salt = &rkf_bytes[8..24];
    let nonce_bytes = &rkf_bytes[24..48];
    let aad = &rkf_bytes[..48];
    let ciphertext = &rkf_bytes[48..];

    let kek = stretch_master_password(password, salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_bytes().into());

    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthFailed("RKF decryption failed (wrong password or tampered)".into()))?;

    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(VaultError::Crypto("invalid seed length in RKF".into()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let seed = MasterIdentitySeed::from_bytes(buf);
    buf.zeroize();
    Ok(seed)
}

/// Option 3: Export M-of-N Ed25519-signed Shamir GF(256) capsules for designated Recovery Guardians.
pub fn export_guardian_capsules(
    seed: &MasterIdentitySeed,
    keys: &DerivedIdentityKeys,
    guardian_ids: &[String],
    threshold_k: u8,
) -> Result<Vec<GuardianShareCapsule>> {
    if guardian_ids.is_empty() || guardian_ids.len() > 255 {
        return Err(VaultError::InvalidInput(
            "guardian count must be between 1 and 255".into(),
        ));
    }
    let total_n = guardian_ids.len() as u8;
    let shares = shamir_split_secret_random(seed.as_bytes(), threshold_k, total_n)?;
    let commitment = secret_commitment(seed.as_bytes());

    let mut capsules = Vec::with_capacity(guardian_ids.len());
    for (guardian_id, share) in guardian_ids.iter().zip(shares.iter()) {
        let mut cap = GuardianShareCapsule {
            guardian_id: guardian_id.clone(),
            share_index: share.index(),
            threshold_k,
            total_n,
            share_hex: hex::encode(share.data()),
            secret_commitment: commitment.clone(),
            slip39_uri: slip39_uri(share),
            signature_hex: String::new(),
        };
        let sig = keys.ed25519_signing().sign(&cap.signing_payload());
        cap.signature_hex = hex::encode(sig.to_bytes());
        capsules.push(cap);
    }
    Ok(capsules)
}

/// Option 3: Verify signatures and reconstruct `MasterIdentitySeed` from M-of-N guardian capsules.
pub fn recover_seed_from_guardian_capsules(
    capsules: &[GuardianShareCapsule],
    owner_verifying_key: &VerifyingKey,
) -> Result<MasterIdentitySeed> {
    if capsules.is_empty() {
        return Err(VaultError::Quorum("no guardian capsules supplied".into()));
    }

    let expected_commitment = &capsules[0].secret_commitment;
    let mut shares = Vec::with_capacity(capsules.len());

    for cap in capsules {
        let sig_bytes = hex::decode(&cap.signature_hex)
            .map_err(|_| VaultError::AuthFailed("invalid guardian signature hex".into()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| VaultError::AuthFailed("invalid guardian signature length".into()))?;
        let signature = Signature::from_bytes(&sig_arr);
        owner_verifying_key
            .verify(&cap.signing_payload(), &signature)
            .map_err(|_| {
                VaultError::AuthFailed(format!(
                    "guardian capsule signature verification failed for {}",
                    cap.guardian_id
                ))
            })?;

        let raw_share = hex::decode(&cap.share_hex)
            .map_err(|_| VaultError::InvalidInput("invalid guardian share hex".into()))?;
        shares.push(ShamirShare::new(
            cap.share_index,
            cap.threshold_k,
            cap.total_n,
            raw_share,
        ));
    }

    let mut seed_bytes = shamir_reconstruct_secret(&shares, Some(expected_commitment))?;
    if seed_bytes.len() != 32 {
        seed_bytes.zeroize();
        return Err(VaultError::Quorum(
            "reconstructed guardian seed is not 32 bytes".into(),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&seed_bytes);
    seed_bytes.zeroize();
    let seed = MasterIdentitySeed::from_bytes(buf);
    buf.zeroize();
    Ok(seed)
}
