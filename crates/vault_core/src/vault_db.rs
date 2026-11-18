use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, VaultError};
use crate::identity::{KeyEncryptionKey, VaultPassword};
use crate::otp::{totp_from_base32, OtpAlgorithm};

const SENTINEL_PLAINTEXT: &[u8] = b"LAVAULT-SQLITE-SENTINEL-V1";

#[derive(Debug, Clone)]
pub struct NewVaultEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp_secret_base32: Option<String>,
    pub totp_algorithm: OtpAlgorithm,
    pub totp_digits: u32,
    pub totp_period_secs: u64,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
    pub url: Option<String>,
    pub updated_at: i64,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedVaultEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: VaultPassword,
    pub totp_code: Option<String>,
    pub totp_remaining_secs: Option<u64>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SecretEntryBlob {
    password: String,
    totp_secret_base32: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxCompatEntry {
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub otp_secret_base32: Option<String>,
    pub otp_algorithm: OtpAlgorithm,
    pub otp_digits: u32,
    pub otp_period_secs: u64,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxCompatDocument {
    pub format_version: String,
    pub kdf: String,
    pub cipher: String,
    pub entries: Vec<KdbxCompatEntry>,
}

pub struct PasswordTotpVault {
    conn: Connection,
    db_key: KeyEncryptionKey,
}

impl PasswordTotpVault {
    pub fn open_or_create(path: &Path, db_key: &KeyEncryptionKey) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Storage(format!("SQLite open failed: {e}")))?;
        Self::init_with_conn(conn, db_key)
    }

    pub fn open_in_memory(db_key: &KeyEncryptionKey) -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| VaultError::Storage(format!("SQLite memory open failed: {e}")))?;
        Self::init_with_conn(conn, db_key)
    }

    fn init_with_conn(conn: Connection, db_key: &KeyEncryptionKey) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                has_totp INTEGER NOT NULL,
                totp_alg TEXT NOT NULL,
                totp_digits INTEGER NOT NULL,
                totp_period INTEGER NOT NULL,
                url TEXT,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                updated_at INTEGER NOT NULL
             );",
        )
        .map_err(|e| VaultError::Storage(format!("SQLite schema error: {e}")))?;

        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT v FROM vault_meta WHERE k = 'sentinel'",
                [],
                |row| row.get(0),
            )
            .ok();

        if let Some(blob) = existing {
            if blob.len() < 24 + 16 {
                return Err(VaultError::AuthFailed("corrupt vault sentinel".into()));
            }
            let nonce = &blob[..24];
            let ct = &blob[24..];
            let cipher = XChaCha20Poly1305::new(db_key.as_bytes().into());
            let pt = cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ct,
                        aad: b"vault_meta:sentinel",
                    },
                )
                .map_err(|_| {
                    VaultError::AuthFailed("vault unlock failed: invalid db_key".into())
                })?;
            if pt.as_slice() != SENTINEL_PLAINTEXT {
                return Err(VaultError::AuthFailed("vault sentinel mismatch".into()));
            }
        } else {
            let mut nonce = [0u8; 24];
            getrandom::getrandom(&mut nonce)
                .map_err(|e| VaultError::Crypto(format!("getrandom failed: {e}")))?;
            let cipher = XChaCha20Poly1305::new(db_key.as_bytes().into());
            let ct = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: SENTINEL_PLAINTEXT,
                        aad: b"vault_meta:sentinel",
                    },
                )
                .map_err(|e| VaultError::Crypto(format!("sentinel encrypt failed: {e}")))?;
            let mut combined = Vec::with_capacity(24 + ct.len());
            combined.extend_from_slice(&nonce);
            combined.extend_from_slice(&ct);
            conn.execute(
                "INSERT INTO vault_meta (k, v) VALUES ('sentinel', ?1)",
                params![combined],
            )
            .map_err(|e| VaultError::Storage(format!("sentinel write failed: {e}")))?;
        }

        Ok(Self {
            conn,
            db_key: db_key.clone(),
        })
    }

    pub fn add_entry(&mut self, entry: NewVaultEntry) -> Result<String> {
        let mut id_bytes = [0u8; 16];
        getrandom::getrandom(&mut id_bytes)
            .map_err(|e| VaultError::Crypto(format!("getrandom id failed: {e}")))?;
        let id = hex::encode(id_bytes);
        self.upsert_entry_with_id(&id, entry)?;
        Ok(id)
    }

    pub fn upsert_entry_with_id(&mut self, id: &str, entry: NewVaultEntry) -> Result<()> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::Crypto(format!("getrandom nonce failed: {e}")))?;

        let blob = SecretEntryBlob {
            password: entry.password,
            totp_secret_base32: entry.totp_secret_base32.clone(),
            notes: entry.notes,
        };
        let mut serialized = ciborium_encode_secret(&blob)?;

        let cipher = XChaCha20Poly1305::new(self.db_key.as_bytes().into());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &serialized,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|e| VaultError::Crypto(format!("entry encrypt failed: {e}")))?;
        serialized.zeroize();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let has_totp = if entry.totp_secret_base32.is_some() { 1 } else { 0 };
        let alg_str = alg_to_str(entry.totp_algorithm);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO vault_entries
                 (id, title, username, has_totp, totp_alg, totp_digits, totp_period, url, nonce, ciphertext, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    id,
                    entry.title,
                    entry.username,
                    has_totp,
                    alg_str,
                    entry.totp_digits as i64,
                    entry.totp_period_secs as i64,
                    entry.url,
                    nonce.to_vec(),
                    ct,
                    now
                ],
            )
            .map_err(|e| VaultError::Storage(format!("insert entry failed: {e}")))?;

        Ok(())
    }

    pub fn list_summaries(&self) -> Result<Vec<VaultEntrySummary>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, title, username, has_totp, url, updated_at FROM vault_entries ORDER BY title ASC",
            )
            .map_err(|e| VaultError::Storage(format!("prepare failed: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(VaultEntrySummary {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    username: r.get(2)?,
                    has_totp: r.get::<_, i64>(3)? != 0,
                    url: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            })
            .map_err(|e| VaultError::Storage(format!("query failed: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| VaultError::Storage(format!("row decode failed: {e}")))?);
        }
        Ok(out)
    }

    pub fn search(&self, query: &str) -> Result<Vec<VaultEntrySummary>> {
        let q = format!("%{}%", query.to_lowercase());
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, title, username, has_totp, url, updated_at FROM vault_entries
                 WHERE lower(title) LIKE ?1 OR lower(username) LIKE ?1
                 ORDER BY title ASC",
            )
            .map_err(|e| VaultError::Storage(format!("search prepare failed: {e}")))?;
        let rows = stmt
            .query_map(params![q], |r| {
                Ok(VaultEntrySummary {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    username: r.get(2)?,
                    has_totp: r.get::<_, i64>(3)? != 0,
                    url: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            })
            .map_err(|e| VaultError::Storage(format!("search query failed: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| VaultError::Storage(format!("row decode failed: {e}")))?);
        }
        Ok(out)
    }

    pub fn unlock_entry_at(&self, id: &str, unix_time: u64) -> Result<UnlockedVaultEntry> {
        type RowTuple = (
            String,
            String,
            String,
            i64,
            i64,
            Option<String>,
            Vec<u8>,
            Vec<u8>,
        );
        let row: RowTuple = self
            .conn
            .query_row(
                "SELECT title, username, totp_alg, totp_digits, totp_period, url, nonce, ciphertext
                 FROM vault_entries WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .map_err(|e| VaultError::Storage(format!("entry '{id}' not found: {e}")))?;

        let (title, username, alg_str, digits, period, url, nonce, ct) = row;
        if nonce.len() != 24 {
            return Err(VaultError::Storage("invalid entry nonce length".into()));
        }
        let cipher = XChaCha20Poly1305::new(self.db_key.as_bytes().into());
        let mut pt = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| VaultError::AuthFailed("entry decryption failed".into()))?;

        let secret_blob: SecretEntryBlob = ciborium::de::from_reader(pt.as_slice())
            .map_err(|e| VaultError::Storage(format!("entry CBOR decode failed: {e}")))?;
        pt.zeroize();

        let alg = str_to_alg(&alg_str)?;
        let (totp_code, totp_remaining_secs) = match &secret_blob.totp_secret_base32 {
            Some(b32) => {
                let (code, rem) =
                    totp_from_base32(b32, unix_time, period as u64, digits as u32, alg)?;
                (Some(code), Some(rem))
            }
            None => (None, None),
        };

        Ok(UnlockedVaultEntry {
            id: id.to_string(),
            title,
            username,
            password: VaultPassword::new(secret_blob.password.clone()),
            totp_code,
            totp_remaining_secs,
            url,
            notes: secret_blob.notes.clone(),
        })
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM vault_entries WHERE id = ?1", params![id])
            .map_err(|e| VaultError::Storage(format!("delete entry failed: {e}")))?;
        if changed == 0 {
            return Err(VaultError::Storage(format!("entry '{id}' not found")));
        }
        Ok(())
    }

    pub fn export_kdbx_compatible(&self) -> Result<KdbxCompatDocument> {
        let summaries = self.list_summaries()?;
        let mut entries = Vec::with_capacity(summaries.len());
        for s in summaries {
            let (alg_str, digits, period, nonce, ct): (String, i64, i64, Vec<u8>, Vec<u8>) = self
                .conn
                .query_row(
                    "SELECT totp_alg, totp_digits, totp_period, nonce, ciphertext FROM vault_entries WHERE id = ?1",
                    params![s.id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .map_err(|e| VaultError::Storage(format!("export row failed: {e}")))?;
            let cipher = XChaCha20Poly1305::new(self.db_key.as_bytes().into());
            let mut pt = cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: s.id.as_bytes(),
                    },
                )
                .map_err(|_| VaultError::AuthFailed("export decrypt failed".into()))?;
            let blob: SecretEntryBlob = ciborium::de::from_reader(pt.as_slice())
                .map_err(|e| VaultError::Storage(format!("export decode failed: {e}")))?;
            pt.zeroize();

            entries.push(KdbxCompatEntry {
                uuid: s.id,
                title: s.title,
                username: s.username,
                password: blob.password.clone(),
                otp_secret_base32: blob.totp_secret_base32.clone(),
                otp_algorithm: str_to_alg(&alg_str)?,
                otp_digits: digits as u32,
                otp_period_secs: period as u64,
                url: s.url,
                notes: blob.notes.clone(),
            });
        }

        Ok(KdbxCompatDocument {
            format_version: "KDBX-4.1-COMPAT".to_string(),
            kdf: "Argon2id-RFC9106".to_string(),
            cipher: "XChaCha20-Poly1305".to_string(),
            entries,
        })
    }
}

fn ciborium_encode_secret(blob: &SecretEntryBlob) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(blob, &mut out)
        .map_err(|e| VaultError::Crypto(format!("entry CBOR encode failed: {e}")))?;
    Ok(out)
}

fn alg_to_str(alg: OtpAlgorithm) -> &'static str {
    match alg {
        OtpAlgorithm::Sha1 => "SHA1",
        OtpAlgorithm::Sha256 => "SHA256",
        OtpAlgorithm::Sha512 => "SHA512",
    }
}

fn str_to_alg(s: &str) -> Result<OtpAlgorithm> {
    match s {
        "SHA1" => Ok(OtpAlgorithm::Sha1),
        "SHA256" => Ok(OtpAlgorithm::Sha256),
        "SHA512" => Ok(OtpAlgorithm::Sha512),
        other => Err(VaultError::Storage(format!("unknown OTP algorithm: {other}"))),
    }
}
