use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, VaultError};

pub const INFO_X25519_KEK: &[u8] = b"local-auth-vault/v1/x25519-kek";
pub const INFO_ED25519_SIG: &[u8] = b"local-auth-vault/v1/ed25519-sig";
pub const INFO_VAULT_DB_KEY: &[u8] = b"local-auth-vault/v1/vault-db-key";
pub const INFO_XTS_AES_512: &[u8] = b"local-auth-vault/v1/xts-aes-512";

/// 256-bit root seed generated via OS CSPRNG.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterIdentitySeed([u8; 32]);

impl MasterIdentitySeed {
    pub fn generate() -> Result<Self> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)
            .map_err(|e| VaultError::Crypto(format!("getrandom failed: {e}")))?;
        Ok(Self(buf))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 256-bit Data Encryption Key for files and virtual volumes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey([u8; 32]);

impl DataEncryptionKey {
    pub fn generate() -> Result<Self> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)
            .map_err(|e| VaultError::Crypto(format!("getrandom failed: {e}")))?;
        Ok(Self(buf))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 256-bit Key Encryption Key / Database Key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Single GF(256) Shamir secret share.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    index: u8,
    threshold_k: u8,
    total_n: u8,
    data: Vec<u8>,
}

impl ShamirShare {
    pub fn new(index: u8, threshold_k: u8, total_n: u8, data: Vec<u8>) -> Self {
        Self {
            index,
            threshold_k,
            total_n,
            data,
        }
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn threshold_k(&self) -> u8 {
        self.threshold_k
    }

    pub fn total_n(&self) -> u8 {
        self.total_n
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Raw TOTP/HOTP shared secret bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// User master password/PIN wrapper wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultPassword(String);

impl VaultPassword {
    pub fn new(password: String) -> Self {
        Self(password)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Deterministic identity key hierarchy derived from `MasterIdentitySeed`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedIdentityKeys {
    x25519_secret: X25519StaticSecret,
    #[zeroize(skip)]
    ed25519_signing: SigningKey,
    vault_db_key: KeyEncryptionKey,
}

impl DerivedIdentityKeys {
    pub fn from_seed(seed: &MasterIdentitySeed) -> Result<Self> {
        let salt = b"lavault-identity-v1";
        let x_bytes: [u8; 32] = hkdf_sha256(seed.as_bytes(), salt, INFO_X25519_KEK, 32)?
            .try_into()
            .map_err(|_| VaultError::Crypto("invalid x25519 key length".into()))?;
        let ed_bytes: [u8; 32] = hkdf_sha256(seed.as_bytes(), salt, INFO_ED25519_SIG, 32)?
            .try_into()
            .map_err(|_| VaultError::Crypto("invalid ed25519 key length".into()))?;
        let db_bytes: [u8; 32] = hkdf_sha256(seed.as_bytes(), salt, INFO_VAULT_DB_KEY, 32)?
            .try_into()
            .map_err(|_| VaultError::Crypto("invalid vault db key length".into()))?;

        let mut x_mut = x_bytes;
        let x25519_secret = X25519StaticSecret::from(x_mut);
        x_mut.zeroize();

        let mut ed_mut = ed_bytes;
        let ed25519_signing = SigningKey::from_bytes(&ed_mut);
        ed_mut.zeroize();

        Ok(Self {
            x25519_secret,
            ed25519_signing,
            vault_db_key: KeyEncryptionKey::from_bytes(db_bytes),
        })
    }

    pub fn from_raw_parts(
        mut x25519_bytes: [u8; 32],
        mut ed25519_bytes: [u8; 32],
        vault_db_key: KeyEncryptionKey,
    ) -> Self {
        let x25519_secret = X25519StaticSecret::from(x25519_bytes);
        let ed25519_signing = SigningKey::from_bytes(&ed25519_bytes);
        x25519_bytes.zeroize();
        ed25519_bytes.zeroize();
        Self {
            x25519_secret,
            ed25519_signing,
            vault_db_key,
        }
    }

    pub fn x25519_secret(&self) -> &X25519StaticSecret {
        &self.x25519_secret
    }

    pub fn x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.x25519_secret)
    }

    pub fn x25519_public_bytes(&self) -> [u8; 32] {
        self.x25519_public().to_bytes()
    }

    pub fn ed25519_signing(&self) -> &SigningKey {
        &self.ed25519_signing
    }

    pub fn ed25519_verifying(&self) -> VerifyingKey {
        self.ed25519_signing.verifying_key()
    }

    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519_signing.verifying_key().to_bytes()
    }

    pub fn vault_db_key(&self) -> &KeyEncryptionKey {
        &self.vault_db_key
    }
}

/// RFC 5869 HKDF-SHA256 extract + expand.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| VaultError::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

/// Stretch a user master password/PIN using Argon2id (RFC 9106: m=65536 KiB, t=3, p=4).
pub fn stretch_master_password(password: &VaultPassword, salt: &[u8]) -> Result<KeyEncryptionKey> {
    if salt.len() < 8 {
        return Err(VaultError::InvalidInput(
            "Argon2id salt must be at least 8 bytes".into(),
        ));
    }
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| VaultError::Crypto(format!("Argon2id params error: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_str().as_bytes(), salt, &mut out)
        .map_err(|e| VaultError::Crypto(format!("Argon2id hashing failed: {e}")))?;
    let key = KeyEncryptionKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// Combine an Argon2id-stretched password key with a hardware-keystore secret via HKDF-SHA256.
pub fn combine_hardware_and_password_key(
    password_key: &KeyEncryptionKey,
    hardware_secret: &[u8],
) -> Result<KeyEncryptionKey> {
    let mut ikm = Vec::with_capacity(32 + hardware_secret.len());
    ikm.extend_from_slice(password_key.as_bytes());
    ikm.extend_from_slice(hardware_secret);
    let okm = hkdf_sha256(
        &ikm,
        b"lavault-hw-pw-combine-v1",
        INFO_VAULT_DB_KEY,
        32,
    );
    ikm.zeroize();
    let okm = okm?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    let kek = KeyEncryptionKey::from_bytes(out);
    out.zeroize();
    Ok(kek)
}
