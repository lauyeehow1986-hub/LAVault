use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_kw::KekAes256;
use bip39::Language;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, VaultError};
use crate::identity::{hkdf_sha256, DataEncryptionKey, DerivedIdentityKeys};
use crate::vlt::{encode_canonical_cbor, parse_vlt_parts, DirectWrapMethod};

pub const MDNS_SERVICE_TYPE: &str = "_localauth._tcp.local.";
pub const MDNS_TCP_PORT: u16 = 53319;
pub const BLE_GATT_SERVICE_UUID: &str = "0000fffd-0000-1000-8000-00805f9b34fb";
pub const BLE_GATT_CHALLENGE_CHAR_UUID: &str = "0000fffe-0000-1000-8000-00805f9b34fb";
pub const BLE_GATT_RESPONSE_CHAR_UUID: &str = "0000ffff-0000-1000-8000-00805f9b34fb";

const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
const VOWELS: &[u8] = b"aeoiu";

struct BytewordsTable {
    words: Vec<String>,
    map: HashMap<String, u8>,
}

static BYTEWORDS: OnceLock<BytewordsTable> = OnceLock::new();

fn bytewords_table() -> &'static BytewordsTable {
    BYTEWORDS.get_or_init(|| {
        let mut words = Vec::with_capacity(256);
        let mut map = HashMap::with_capacity(256);
        for i in 0..256usize {
            let w = String::from_utf8(vec![
                CONSONANTS[i / 20],
                VOWELS[(i / 4) % 5],
                CONSONANTS[(i * 3 + 7) % 20],
                VOWELS[i % 5],
            ])
            .expect("ASCII byteword");
            map.insert(w.clone(), i as u8);
            words.push(w);
        }
        BytewordsTable { words, map }
    })
}

/// Encode CBOR bytes into `ur:<type>/<bytewords>` with trailing big-endian CRC32 (matches MCP server).
pub fn encode_bcur_payload(ur_type: &str, cbor_bytes: &[u8]) -> String {
    let table = bytewords_table();
    let crc = crc32fast::hash(cbor_bytes);
    let mut out = format!("ur:{}/", ur_type.to_ascii_lowercase());
    out.reserve((cbor_bytes.len() + 4) * 4);
    for &b in cbor_bytes {
        out.push_str(&table.words[b as usize]);
    }
    for &b in &crc.to_be_bytes() {
        out.push_str(&table.words[b as usize]);
    }
    out
}

/// Decode and CRC32-verify a `ur:<type>/<bytewords>` optical QR string.
pub fn decode_bcur_payload(ur_string: &str) -> Result<(String, Vec<u8>)> {
    let lower = ur_string.trim().to_ascii_lowercase();
    let rest = lower
        .strip_prefix("ur:")
        .ok_or_else(|| VaultError::InvalidInput("invalid UR prefix: must start with 'ur:'".into()))?;
    let (ur_type, encoded) = rest
        .split_once('/')
        .ok_or_else(|| VaultError::InvalidInput("missing '/' separator in UR".into()))?;
    if encoded.len() < 16 || encoded.len() % 4 != 0 {
        return Err(VaultError::InvalidInput("invalid Bytewords length".into()));
    }

    let table = bytewords_table();
    let mut raw = Vec::with_capacity(encoded.len() / 4);
    for chunk in encoded.as_bytes().chunks_exact(4) {
        let token = std::str::from_utf8(chunk)
            .map_err(|_| VaultError::InvalidInput("invalid UTF-8 byteword".into()))?;
        let byte = table
            .map
            .get(token)
            .ok_or_else(|| VaultError::InvalidInput(format!("unknown Byteword token: {token}")))?;
        raw.push(*byte);
    }

    let split_at = raw.len() - 4;
    let payload = &raw[..split_at];
    let expected_crc = u32::from_be_bytes(
        raw[split_at..]
            .try_into()
            .map_err(|_| VaultError::InvalidInput("bad CRC len".into()))?,
    );
    let actual_crc = crc32fast::hash(payload);
    if expected_crc != actual_crc {
        return Err(VaultError::AuthFailed(format!(
            "BC-UR CRC32 integrity failure: expected {expected_crc:#x}, got {actual_crc:#x}"
        )));
    }

    Ok((ur_type.to_string(), payload.to_vec()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultipartUrPart {
    seq_num: u32,
    seq_len: u32,
    total_len: u32,
    message_crc32: u32,
    is_parity: bool,
    fragment: Vec<u8>,
}

/// Encode large CBOR payloads as multipart `ur:<type>/<seq>-<len>/<bytewords>` frames plus an XOR fountain parity frame.
pub fn encode_bcur_multipart(
    ur_type: &str,
    payload: &[u8],
    max_fragment_bytes: usize,
) -> Result<Vec<String>> {
    if max_fragment_bytes == 0 {
        return Err(VaultError::InvalidInput(
            "max_fragment_bytes must be > 0".into(),
        ));
    }
    let table = bytewords_table();
    let msg_crc = crc32fast::hash(payload);
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[]]
    } else {
        payload.chunks(max_fragment_bytes).collect()
    };
    let seq_len = chunks.len() as u32;
    let padded_len = chunks.iter().map(|c| c.len()).max().unwrap_or(0);
    let mut parity = vec![0u8; padded_len];

    let mut frames = Vec::with_capacity(chunks.len() + 1);
    for (idx, chunk) in chunks.iter().enumerate() {
        for (i, &b) in chunk.iter().enumerate() {
            parity[i] ^= b;
        }
        let part = MultipartUrPart {
            seq_num: (idx + 1) as u32,
            seq_len,
            total_len: payload.len() as u32,
            message_crc32: msg_crc,
            is_parity: false,
            fragment: chunk.to_vec(),
        };
        let cbor = encode_canonical_cbor(&part)?;
        let crc = crc32fast::hash(&cbor);
        let mut bw = String::with_capacity((cbor.len() + 4) * 4);
        for &b in &cbor {
            bw.push_str(&table.words[b as usize]);
        }
        for &b in &crc.to_be_bytes() {
            bw.push_str(&table.words[b as usize]);
        }
        frames.push(format!(
            "ur:{}/{}-{}/{}",
            ur_type.to_ascii_lowercase(),
            idx + 1,
            seq_len,
            bw
        ));
    }

    // Add 1 XOR fountain parity packet (recovers any single dropped fragment)
    if seq_len > 1 {
        let parity_part = MultipartUrPart {
            seq_num: seq_len + 1,
            seq_len,
            total_len: payload.len() as u32,
            message_crc32: msg_crc,
            is_parity: true,
            fragment: parity,
        };
        let cbor = encode_canonical_cbor(&parity_part)?;
        let crc = crc32fast::hash(&cbor);
        let mut bw = String::with_capacity((cbor.len() + 4) * 4);
        for &b in &cbor {
            bw.push_str(&table.words[b as usize]);
        }
        for &b in &crc.to_be_bytes() {
            bw.push_str(&table.words[b as usize]);
        }
        frames.push(format!(
            "ur:{}/{}-{}/{}",
            ur_type.to_ascii_lowercase(),
            seq_len + 1,
            seq_len,
            bw
        ));
    }

    Ok(frames)
}

/// Decode multipart `ur:<type>/<seq>-<len>/<bytewords>` frames (with single-erasure XOR fountain recovery).
pub fn decode_bcur_multipart(frames: &[String]) -> Result<(String, Vec<u8>)> {
    if frames.is_empty() {
        return Err(VaultError::InvalidInput("no multipart UR frames".into()));
    }
    let table = bytewords_table();
    let mut ur_type_out = String::new();
    let mut seq_len = 0u32;
    let mut total_len = 0usize;
    let mut expected_crc = 0u32;
    let mut fragments: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut parity_buf: Option<Vec<u8>> = None;

    for f in frames {
        let lower = f.trim().to_ascii_lowercase();
        let rest = lower
            .strip_prefix("ur:")
            .ok_or_else(|| VaultError::InvalidInput("missing ur: prefix".into()))?;
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() != 3 {
            return Err(VaultError::InvalidInput("expected ur:type/seq-len/body".into()));
        }
        ur_type_out = parts[0].to_string();
        let encoded = parts[2];
        if encoded.len() < 16 || encoded.len() % 4 != 0 {
            return Err(VaultError::InvalidInput("invalid multipart bytewords".into()));
        }
        let mut raw = Vec::with_capacity(encoded.len() / 4);
        for chunk in encoded.as_bytes().chunks_exact(4) {
            let token = std::str::from_utf8(chunk)
                .map_err(|_| VaultError::InvalidInput("invalid UTF-8 byteword".into()))?;
            let b = table
                .map
                .get(token)
                .ok_or_else(|| VaultError::InvalidInput(format!("unknown byteword {token}")))?;
            raw.push(*b);
        }
        let split_at = raw.len() - 4;
        let cbor = &raw[..split_at];
        let frame_crc = u32::from_be_bytes(raw[split_at..].try_into().unwrap());
        if frame_crc != crc32fast::hash(cbor) {
            return Err(VaultError::AuthFailed("multipart frame CRC32 mismatch".into()));
        }
        let part: MultipartUrPart = ciborium::de::from_reader(cbor)
            .map_err(|e| VaultError::InvalidInput(format!("multipart CBOR decode failed: {e}")))?;
        seq_len = part.seq_len;
        total_len = part.total_len as usize;
        expected_crc = part.message_crc32;
        if part.is_parity {
            parity_buf = Some(part.fragment);
        } else {
            fragments.insert(part.seq_num, part.fragment);
        }
    }

    if fragments.len() as u32 + 1 == seq_len {
        if let Some(mut recovered) = parity_buf {
            let mut missing_idx = None;
            for idx in 1..=seq_len {
                if let Some(frag) = fragments.get(&idx) {
                    for (i, &b) in frag.iter().enumerate() {
                        recovered[i] ^= b;
                    }
                } else {
                    missing_idx = Some(idx);
                }
            }
            if let Some(idx) = missing_idx {
                fragments.insert(idx, recovered);
            }
        }
    }

    if (fragments.len() as u32) < seq_len {
        return Err(VaultError::InvalidInput(format!(
            "incomplete multipart UR: have {} of {} fragments",
            fragments.len(),
            seq_len
        )));
    }

    let mut reassembled = Vec::with_capacity(total_len);
    for idx in 1..=seq_len {
        let frag = fragments
            .get(&idx)
            .ok_or_else(|| VaultError::InvalidInput(format!("missing fragment {idx}")))?;
        reassembled.extend_from_slice(frag);
    }
    reassembled.truncate(total_len);

    if crc32fast::hash(&reassembled) != expected_crc {
        return Err(VaultError::AuthFailed(
            "reassembled multipart UR CRC32 mismatch".into(),
        ));
    }

    Ok((ur_type_out, reassembled))
}

/// 8-word one-time verifier fallback (when no webcam is available) derived from SHA-256 of nonce.
pub fn encode_8word_verifier(challenge_nonce: &[u8]) -> String {
    let wordlist = Language::English.word_list();
    let digest = Sha256::digest(challenge_nonce);
    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let hi = digest[i * 2] as usize;
        let lo = digest[i * 2 + 1] as usize;
        let idx = ((hi << 8) | lo) % wordlist.len();
        words.push(wordlist[idx]);
    }
    words.join(" ")
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Spake2Result {
    pub shared_key: [u8; 32],
    pub sas_6digit: String,
}

pub struct Spake2Pairing {
    state: Spake2<Ed25519Group>,
}

impl Spake2Pairing {
    pub fn start_initiator(id_a: &str, id_b: &str, pin: &str) -> (Self, Vec<u8>) {
        let (state, msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(pin.as_bytes()),
            &Identity::new(id_a.as_bytes()),
            &Identity::new(id_b.as_bytes()),
        );
        (Self { state }, msg)
    }

    pub fn start_responder(id_a: &str, id_b: &str, pin: &str) -> (Self, Vec<u8>) {
        let (state, msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(pin.as_bytes()),
            &Identity::new(id_a.as_bytes()),
            &Identity::new(id_b.as_bytes()),
        );
        (Self { state }, msg)
    }

    pub fn finish(self, peer_msg: &[u8]) -> Result<Spake2Result> {
        let raw = self
            .state
            .finish(peer_msg)
            .map_err(|e| VaultError::AuthFailed(format!("SPAKE2 exchange failed: {e:?}")))?;
        let digest: [u8; 32] = Sha256::digest(&raw).into();
        let sas_num = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
        Ok(Spake2Result {
            shared_key: digest,
            sas_6digit: format!("{sas_num:06}"),
        })
    }
}

/// Generate a self-signed Ed25519 TLS 1.3 certificate + PKCS#8 private key DER for pinned mTLS.
pub fn generate_pinned_ed25519_tls_identity(common_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| VaultError::Crypto(format!("rcgen Ed25519 keygen failed: {e}")))?;
    let params = rcgen::CertificateParams::new(vec![common_name.to_string(), "localhost".into()])
        .map_err(|e| VaultError::Crypto(format!("rcgen params failed: {e}")))?;
    let cert = params
        .self_signed(&kp)
        .map_err(|e| VaultError::Crypto(format!("rcgen self_signed failed: {e}")))?;
    let cert_der = cert.der().to_vec();
    let key_der = kp.serialize_der();
    let _ = &mut kp;
    Ok((cert_der, key_der))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockChallenge {
    pub req_id: String,
    pub requester_name: String,
    pub header_sha256: String,
    pub slot_id: String,
    pub wrap_method: DirectWrapMethod,
    pub slot_ephemeral_pk: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub pc_response_epk: Vec<u8>,
    pub challenge_nonce: Vec<u8>,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockResponse {
    pub req_id: String,
    pub responder_id: String,
    pub responder_epk: Vec<u8>,
    pub encrypted_dek: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UnlockChallenge {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        encode_canonical_cbor(self)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes)
            .map_err(|e| VaultError::InvalidInput(format!("UnlockChallenge CBOR decode failed: {e}")))
    }

    pub fn to_bcur(&self) -> Result<String> {
        let cbor = self.to_cbor()?;
        Ok(encode_bcur_payload("lavault-req", &cbor))
    }

    pub fn from_bcur(ur: &str) -> Result<Self> {
        let (ur_type, cbor) = decode_bcur_payload(ur)?;
        if ur_type != "lavault-req" {
            return Err(VaultError::InvalidInput(format!(
                "expected ur:lavault-req, got ur:{ur_type}"
            )));
        }
        Self::from_cbor(&cbor)
    }
}

impl UnlockResponse {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        encode_canonical_cbor(self)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes)
            .map_err(|e| VaultError::InvalidInput(format!("UnlockResponse CBOR decode failed: {e}")))
    }

    pub fn to_bcur(&self) -> Result<String> {
        let cbor = self.to_cbor()?;
        Ok(encode_bcur_payload("lavault-res", &cbor))
    }

    pub fn from_bcur(ur: &str) -> Result<Self> {
        let (ur_type, cbor) = decode_bcur_payload(ur)?;
        if ur_type != "lavault-res" {
            return Err(VaultError::InvalidInput(format!(
                "expected ur:lavault-res, got ur:{ur_type}"
            )));
        }
        Self::from_cbor(&cbor)
    }

    fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"LAVAULT-UNLOCK-RES-V1|");
        h.update(self.req_id.as_bytes());
        h.update(b"|");
        h.update(self.responder_id.as_bytes());
        h.update(b"|");
        h.update(&self.responder_epk);
        h.update(&self.encrypted_dek);
        h.finalize().into()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralResponseSecret(StaticSecret);

impl EphemeralResponseSecret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }
}

pub fn build_unlock_challenge_for_vlt(
    vlt_container: &[u8],
    slot_id: &str,
    requester_name: &str,
) -> Result<(UnlockChallenge, EphemeralResponseSecret)> {
    let (header, header_sha256, sig_valid, _) = parse_vlt_parts(vlt_container)?;
    if !sig_valid {
        return Err(VaultError::AuthFailed(
            "cannot build unlock challenge for .vlt with invalid signature".into(),
        ));
    }
    let slot = header
        .direct_slots
        .iter()
        .find(|s| s.recipient_id == slot_id)
        .ok_or_else(|| {
            VaultError::AuthFailed(format!("slot '{slot_id}' not found in .vlt header"))
        })?;

    let mut req_id_bytes = [0u8; 8];
    let mut challenge_nonce = [0u8; 16];
    let mut pc_esk_bytes = [0u8; 32];
    getrandom::getrandom(&mut req_id_bytes)
        .map_err(|e| VaultError::Crypto(format!("getrandom req_id failed: {e}")))?;
    getrandom::getrandom(&mut challenge_nonce)
        .map_err(|e| VaultError::Crypto(format!("getrandom nonce failed: {e}")))?;
    getrandom::getrandom(&mut pc_esk_bytes)
        .map_err(|e| VaultError::Crypto(format!("getrandom pc_esk failed: {e}")))?;

    let pc_esk = StaticSecret::from(pc_esk_bytes);
    pc_esk_bytes.zeroize();
    let pc_epk = X25519PublicKey::from(&pc_esk);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let challenge = UnlockChallenge {
        req_id: format!("req_{}", hex::encode(req_id_bytes)),
        requester_name: requester_name.to_string(),
        header_sha256: hex::encode(header_sha256),
        slot_id: slot_id.to_string(),
        wrap_method: slot.wrap_method,
        slot_ephemeral_pk: slot.ephemeral_pk.clone(),
        wrapped_dek: slot.wrapped_dek.clone(),
        pc_response_epk: pc_epk.to_bytes().to_vec(),
        challenge_nonce: challenge_nonce.to_vec(),
        created_at_unix: now,
    };

    Ok((challenge, EphemeralResponseSecret(pc_esk)))
}

pub fn fulfill_unlock_challenge(
    challenge: &UnlockChallenge,
    responder_id: &str,
    responder_keys: &DerivedIdentityKeys,
) -> Result<UnlockResponse> {
    // 1. Unwrap the DEK from the slot using responder's static X25519 key
    let slot_epk_arr: [u8; 32] = challenge
        .slot_ephemeral_pk
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidInput("invalid slot epk len".into()))?;
    let slot_epk = X25519PublicKey::from(slot_epk_arr);
    let shared = responder_keys.x25519_secret().diffie_hellman(&slot_epk);
    let pk_bytes = responder_keys.x25519_public_bytes();
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&slot_epk_arr);
    salt[32..].copy_from_slice(&pk_bytes);
    let mut kek = hkdf_sha256(
        shared.as_bytes(),
        &salt,
        b"local-auth-vault/v1/direct-slot",
        32,
    )?;

    let mut dek = match challenge.wrap_method {
        DirectWrapMethod::Aes256Kw => {
            let arr: [u8; 32] = kek.as_slice().try_into().unwrap();
            KekAes256::from(arr)
                .unwrap_vec(&challenge.wrapped_dek)
                .map_err(|_| VaultError::AuthFailed("AES-256-KW slot unwrap failed".into()))?
        }
        DirectWrapMethod::XChaCha20Poly1305 => {
            if challenge.wrapped_dek.len() < 24 + 16 {
                return Err(VaultError::InvalidInput("wrapped_dek truncated".into()));
            }
            let nonce = &challenge.wrapped_dek[..24];
            let ct = &challenge.wrapped_dek[24..];
            let mut aad = Vec::with_capacity(96);
            aad.extend_from_slice(b"local-auth-vault/v1/direct-slot");
            aad.extend_from_slice(&slot_epk_arr);
            aad.extend_from_slice(&pk_bytes);
            let cipher = XChaCha20Poly1305::new(kek.as_slice().into());
            cipher
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
                .map_err(|_| VaultError::AuthFailed("XChaCha slot unwrap failed".into()))?
        }
    };
    kek.zeroize();

    // 2. Re-encrypt DEK to PC's ephemeral response public key
    let pc_epk_arr: [u8; 32] = challenge
        .pc_response_epk
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidInput("invalid pc_response_epk len".into()))?;
    let pc_epk = X25519PublicKey::from(pc_epk_arr);

    let mut resp_esk_bytes = [0u8; 32];
    getrandom::getrandom(&mut resp_esk_bytes)
        .map_err(|e| VaultError::Crypto(format!("getrandom resp_esk failed: {e}")))?;
    let resp_esk = StaticSecret::from(resp_esk_bytes);
    resp_esk_bytes.zeroize();
    let resp_epk = X25519PublicKey::from(&resp_esk);
    let resp_shared = resp_esk.diffie_hellman(&pc_epk);

    let mut sess_salt = [0u8; 64];
    sess_salt[..32].copy_from_slice(resp_epk.as_bytes());
    sess_salt[32..].copy_from_slice(&pc_epk_arr);
    let mut sess_key = hkdf_sha256(
        resp_shared.as_bytes(),
        &sess_salt,
        b"local-auth-vault/v1/unlock-response",
        32,
    )?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| VaultError::Crypto(format!("getrandom resp nonce failed: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sess_key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &dek,
                aad: challenge.req_id.as_bytes(),
            },
        )
        .map_err(|e| VaultError::Crypto(format!("response encrypt failed: {e}")))?;
    dek.zeroize();
    sess_key.zeroize();

    let mut encrypted_dek = Vec::with_capacity(12 + ct.len());
    encrypted_dek.extend_from_slice(&nonce_bytes);
    encrypted_dek.extend_from_slice(&ct);

    let mut response = UnlockResponse {
        req_id: challenge.req_id.clone(),
        responder_id: responder_id.to_string(),
        responder_epk: resp_epk.to_bytes().to_vec(),
        encrypted_dek,
        signature: Vec::new(),
    };
    let digest = response.signing_digest();
    let sig = responder_keys.ed25519_signing().sign(&digest);
    response.signature = sig.to_bytes().to_vec();
    Ok(response)
}

pub fn verify_and_extract_unlock_dek(
    response: &UnlockResponse,
    pc_ephem: &EphemeralResponseSecret,
    expected_responder_vk: &VerifyingKey,
) -> Result<DataEncryptionKey> {
    let sig_arr: [u8; 64] = response
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::AuthFailed("invalid response signature len".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    expected_responder_vk
        .verify(&response.signing_digest(), &sig)
        .map_err(|_| VaultError::AuthFailed("UnlockResponse Ed25519 signature invalid".into()))?;

    let resp_epk_arr: [u8; 32] = response
        .responder_epk
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidInput("invalid responder_epk len".into()))?;
    let resp_epk = X25519PublicKey::from(resp_epk_arr);
    let shared = pc_ephem.0.diffie_hellman(&resp_epk);
    let pc_epk = X25519PublicKey::from(&pc_ephem.0);

    let mut sess_salt = [0u8; 64];
    sess_salt[..32].copy_from_slice(&resp_epk_arr);
    sess_salt[32..].copy_from_slice(pc_epk.as_bytes());
    let mut sess_key = hkdf_sha256(
        shared.as_bytes(),
        &sess_salt,
        b"local-auth-vault/v1/unlock-response",
        32,
    )?;

    if response.encrypted_dek.len() < 12 + 16 {
        return Err(VaultError::InvalidInput("encrypted_dek truncated".into()));
    }
    let nonce = &response.encrypted_dek[..12];
    let ct = &response.encrypted_dek[12..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sess_key));
    let mut pt = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: response.req_id.as_bytes(),
            },
        )
        .map_err(|_| VaultError::AuthFailed("UnlockResponse DEK decryption failed".into()))?;
    sess_key.zeroize();

    if pt.len() != 32 {
        pt.zeroize();
        return Err(VaultError::AuthFailed("invalid DEK length".into()));
    }
    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(&pt);
    pt.zeroize();
    let dek = DataEncryptionKey::from_bytes(dek_arr);
    dek_arr.zeroize();
    Ok(dek)
}

/// Application-layer X25519 + ChaCha20-Poly1305 framing for BLE GATT channel.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BleSessionCipher {
    session_key: [u8; 32],
}

impl BleSessionCipher {
    pub fn from_ephemeral_pair(local_keys: &DerivedIdentityKeys, peer_x25519_pk: &[u8]) -> Self {
        let mut pk_arr = [0u8; 32];
        if peer_x25519_pk.len() == 32 {
            pk_arr.copy_from_slice(peer_x25519_pk);
        }
        let peer_pk = X25519PublicKey::from(pk_arr);
        let shared = local_keys.x25519_secret().diffie_hellman(&peer_pk);
        let derived = hkdf_sha256(
            shared.as_bytes(),
            b"lavault-ble-gatt-v1",
            b"local-auth-vault/v1/ble-gatt-session",
            32,
        )
        .expect("32-byte HKDF");
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&derived);
        Self { session_key }
    }

    pub fn encrypt_response(&self, resp: &UnlockResponse) -> Result<Vec<u8>> {
        let cbor = resp.to_cbor()?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::Crypto(format!("getrandom ble nonce failed: {e}")))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.session_key));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &cbor,
                    aad: BLE_GATT_SERVICE_UUID.as_bytes(),
                },
            )
            .map_err(|e| VaultError::Transport(format!("BLE encrypt failed: {e}")))?;
        let mut packet = Vec::with_capacity(12 + ct.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ct);
        Ok(packet)
    }

    pub fn decrypt_response(&self, packet: &[u8]) -> Result<UnlockResponse> {
        if packet.len() < 12 + 16 {
            return Err(VaultError::Transport("BLE packet truncated".into()));
        }
        let nonce = &packet[..12];
        let ct = &packet[12..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.session_key));
        let pt = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: BLE_GATT_SERVICE_UUID.as_bytes(),
                },
            )
            .map_err(|_| VaultError::AuthFailed("BLE GATT packet authentication failed".into()))?;
        UnlockResponse::from_cbor(&pt)
    }
}
