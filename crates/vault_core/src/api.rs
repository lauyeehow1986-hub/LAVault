use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::anyhow;
use zeroize::Zeroize;

use crate::identity::{
    combine_hardware_and_password_key, stretch_master_password, DerivedIdentityKeys,
    MasterIdentitySeed, VaultPassword,
};
use crate::otp::{totp_rfc6238, OtpAlgorithm};
use crate::recovery::{
    export_bip39_mnemonic, export_guardian_capsules, export_rkf_keyfile, import_bip39_mnemonic,
    GuardianShareCapsule,
};
use crate::transport::{
    decode_bcur_payload, fulfill_unlock_challenge, UnlockChallenge, BLE_GATT_SERVICE_UUID,
    MDNS_SERVICE_TYPE, MDNS_TCP_PORT,
};
use crate::vault_db::{NewVaultEntry, PasswordTotpVault, VaultEntrySummary};
use crate::vlt::inspect_vlt_header;

struct ActiveSession {
    seed: MasterIdentitySeed,
    keys: DerivedIdentityKeys,
    vault: PasswordTotpVault,
}

static SESSIONS: OnceLock<Mutex<HashMap<String, ActiveSession>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<String, ActiveSession>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone)]
pub struct SessionInfoDto {
    pub session_id: String,
    pub x25519_public_bytes: Vec<u8>,
    pub ed25519_public_bytes: Vec<u8>,
    pub x25519_public_hex: String,
    pub ed25519_public_hex: String,
}

#[derive(Debug, Clone)]
pub struct VaultEntryInputDto {
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

#[derive(Debug, Clone)]
pub struct VaultEntrySummaryDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
    pub url: Option<String>,
    pub updated_at: i64,
}

impl From<VaultEntrySummary> for VaultEntrySummaryDto {
    fn from(s: VaultEntrySummary) -> Self {
        Self {
            id: s.id,
            title: s.title,
            username: s.username,
            has_totp: s.has_totp,
            url: s.url,
            updated_at: s.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnlockedVaultEntryDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub totp_remaining_secs: Option<u64>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GuardianCapsuleDto {
    pub guardian_id: String,
    pub share_index: u8,
    pub threshold_k: u8,
    pub total_n: u8,
    pub slip39_uri: String,
    pub signature_hex: String,
}

impl From<GuardianShareCapsule> for GuardianCapsuleDto {
    fn from(c: GuardianShareCapsule) -> Self {
        Self {
            guardian_id: c.guardian_id,
            share_index: c.share_index,
            threshold_k: c.threshold_k,
            total_n: c.total_n,
            slip39_uri: c.slip39_uri,
            signature_hex: c.signature_hex,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryKitDto {
    pub bip39_24_words: String,
    pub rkf_bytes: Vec<u8>,
    pub guardian_capsules: Vec<GuardianCapsuleDto>,
}

#[derive(Debug, Clone)]
pub struct VltInspectDto {
    pub version: u32,
    pub cipher: String,
    pub direct_slot_count: usize,
    pub quorum_threshold_k: u8,
    pub quorum_total_n: u8,
    pub header_sha256_hex: String,
    pub signature_valid: bool,
}

#[derive(Debug, Clone)]
pub struct TransportConfigDto {
    pub mdns_service: String,
    pub tls13_port: u16,
    pub ble_gatt_service_uuid: String,
}

pub fn get_transport_config() -> TransportConfigDto {
    TransportConfigDto {
        mdns_service: MDNS_SERVICE_TYPE.to_string(),
        tls13_port: MDNS_TCP_PORT,
        ble_gatt_service_uuid: BLE_GATT_SERVICE_UUID.to_string(),
    }
}

pub fn verify_totp_vector_for_test() -> anyhow::Result<String> {
    Ok(totp_rfc6238(b"12345678901234567890", 59, 30, 0, 8, OtpAlgorithm::Sha1)?)
}

pub fn create_identity_and_vault(
    db_path: String,
    master_password: String,
    hardware_secret: Vec<u8>,
) -> anyhow::Result<SessionInfoDto> {
    let mut pw = VaultPassword::new(master_password);
    let pw_key = stretch_master_password(&pw, b"lavault-app-salt-v1")?;
    pw.zeroize();
    let combined_db_key = combine_hardware_and_password_key(&pw_key, &hardware_secret)?;

    let vault = PasswordTotpVault::open_or_create(Path::new(&db_path), &combined_db_key)?;
    let seed = vault.load_or_create_identity_seed()?;
    let keys = DerivedIdentityKeys::from_seed(&seed)?;

    let mut id_bytes = [0u8; 16];
    getrandom::getrandom(&mut id_bytes)
        .map_err(|e| anyhow!("getrandom session id failed: {e}"))?;
    let session_id = hex::encode(id_bytes);

    let x_pub = keys.x25519_public_bytes();
    let ed_pub = keys.ed25519_public_bytes();
    let info = SessionInfoDto {
        session_id: session_id.clone(),
        x25519_public_bytes: x_pub.to_vec(),
        ed25519_public_bytes: ed_pub.to_vec(),
        x25519_public_hex: hex::encode(x_pub),
        ed25519_public_hex: hex::encode(ed_pub),
    };

    let mut guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    guard.insert(session_id, ActiveSession { seed, keys, vault });
    Ok(info)
}

pub fn recover_identity_from_bip39(
    db_path: String,
    mnemonic_24_words: String,
    master_password: String,
    hardware_secret: Vec<u8>,
) -> anyhow::Result<SessionInfoDto> {
    let seed = import_bip39_mnemonic(&mnemonic_24_words)?;
    let keys = DerivedIdentityKeys::from_seed(&seed)?;

    let mut pw = VaultPassword::new(master_password);
    let pw_key = stretch_master_password(&pw, b"lavault-app-salt-v1")?;
    pw.zeroize();
    let combined_db_key = combine_hardware_and_password_key(&pw_key, &hardware_secret)?;
    let vault = PasswordTotpVault::open_or_create(Path::new(&db_path), &combined_db_key)?;
    vault.store_identity_seed(&seed)?;

    let mut id_bytes = [0u8; 16];
    getrandom::getrandom(&mut id_bytes)
        .map_err(|e| anyhow!("getrandom session id failed: {e}"))?;
    let session_id = hex::encode(id_bytes);

    let x_pub = keys.x25519_public_bytes();
    let ed_pub = keys.ed25519_public_bytes();
    let info = SessionInfoDto {
        session_id: session_id.clone(),
        x25519_public_bytes: x_pub.to_vec(),
        ed25519_public_bytes: ed_pub.to_vec(),
        x25519_public_hex: hex::encode(x_pub),
        ed25519_public_hex: hex::encode(ed_pub),
    };

    let mut guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    guard.insert(session_id, ActiveSession { seed, keys, vault });
    Ok(info)
}

pub fn lock_session(session_id: String) -> anyhow::Result<()> {
    let mut guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    guard.remove(&session_id);
    Ok(())
}

pub fn add_vault_entry(session_id: String, entry: VaultEntryInputDto) -> anyhow::Result<String> {
    let mut guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get_mut(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    Ok(sess.vault.add_entry(NewVaultEntry {
        title: entry.title,
        username: entry.username,
        password: entry.password,
        totp_secret_base32: entry.totp_secret_base32,
        totp_algorithm: entry.totp_algorithm,
        totp_digits: entry.totp_digits,
        totp_period_secs: entry.totp_period_secs,
        url: entry.url,
        notes: entry.notes,
    })?)
}

pub fn list_vault_entries(session_id: String) -> anyhow::Result<Vec<VaultEntrySummaryDto>> {
    let guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    Ok(sess
        .vault
        .list_summaries()?
        .into_iter()
        .map(VaultEntrySummaryDto::from)
        .collect())
}

pub fn search_vault_entries(session_id: String, query: String) -> anyhow::Result<Vec<VaultEntrySummaryDto>> {
    let guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    Ok(sess
        .vault
        .search(&query)?
        .into_iter()
        .map(VaultEntrySummaryDto::from)
        .collect())
}

pub fn unlock_vault_entry_at(
    session_id: String,
    entry_id: String,
    unix_time: u64,
) -> anyhow::Result<UnlockedVaultEntryDto> {
    let guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    let unlocked = sess.vault.unlock_entry_at(&entry_id, unix_time)?;
    Ok(UnlockedVaultEntryDto {
        id: unlocked.id.clone(),
        title: unlocked.title.clone(),
        username: unlocked.username.clone(),
        password: unlocked.password.as_str().to_string(),
        totp_code: unlocked.totp_code.clone(),
        totp_remaining_secs: unlocked.totp_remaining_secs,
        url: unlocked.url.clone(),
        notes: unlocked.notes.clone(),
    })
}

pub fn delete_vault_entry(session_id: String, entry_id: String) -> anyhow::Result<()> {
    let mut guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get_mut(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    Ok(sess.vault.delete_entry(&entry_id)?)
}

pub fn approve_bcur_unlock_request(session_id: String, ur_req: String) -> anyhow::Result<String> {
    let guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    let challenge = UnlockChallenge::from_bcur(&ur_req)?;
    let resp = fulfill_unlock_challenge(&challenge, &challenge.slot_id, &sess.keys)?;
    Ok(resp.to_bcur()?)
}

pub fn export_recovery_kit(
    session_id: String,
    rkf_password: String,
    guardian_ids: Vec<String>,
    threshold_k: u8,
) -> anyhow::Result<RecoveryKitDto> {
    let guard = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    let sess = guard
        .get(&session_id)
        .ok_or_else(|| anyhow!("session locked or unknown"))?;
    let bip39_24_words = export_bip39_mnemonic(&sess.seed)?;
    let mut pw = VaultPassword::new(rkf_password);
    let rkf_bytes = export_rkf_keyfile(&sess.seed, &pw)?;
    pw.zeroize();
    let capsules =
        export_guardian_capsules(&sess.seed, &sess.keys, &guardian_ids, threshold_k)?;
    Ok(RecoveryKitDto {
        bip39_24_words,
        rkf_bytes,
        guardian_capsules: capsules.into_iter().map(GuardianCapsuleDto::from).collect(),
    })
}

pub fn inspect_vlt_file(path: String) -> anyhow::Result<VltInspectDto> {
    let raw = std::fs::read(&path)?;
    let info = inspect_vlt_header(&raw)?;
    Ok(VltInspectDto {
        version: info.version,
        cipher: format!("{:?}", info.cipher),
        direct_slot_count: info.direct_slot_count,
        quorum_threshold_k: info.quorum_threshold_k,
        quorum_total_n: info.quorum_total_n,
        header_sha256_hex: info.header_sha256_hex,
        signature_valid: info.signature_valid,
    })
}

pub fn decode_bcur_summary(ur_string: String) -> anyhow::Result<String> {
    let (ur_type, bytes) = decode_bcur_payload(&ur_string)?;
    Ok(format!("ur:{ur_type} ({} bytes CBOR)", bytes.len()))
}
