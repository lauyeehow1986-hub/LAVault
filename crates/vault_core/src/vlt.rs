use std::path::Path;

use aes_gcm::{
    aead::{Aead as GcmAead, KeyInit as GcmKeyInit, Payload as GcmPayload},
    Aes256Gcm, Nonce as GcmNonce,
};
use aes_kw::KekAes256;
use chacha20poly1305::{
    aead::Payload,
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::identity::{
    hkdf_sha256, DataEncryptionKey, DerivedIdentityKeys, KeyEncryptionKey, ShamirShare,
};
use crate::shamir::{
    secret_commitment, shamir_reconstruct_secret, shamir_split_secret_random, share_checksum,
};

pub const VLT_MAGIC: &[u8; 8] = b"LAVAULT1";
pub const STREAM_CHUNK_SIZE: usize = 65536;
const INFO_DIRECT_SLOT: &[u8] = b"local-auth-vault/v1/direct-slot";
const INFO_QUORUM_SHARE_SLOT: &[u8] = b"local-auth-vault/v1/quorum-share-slot";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadCipher {
    ChaCha20Poly1305,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectWrapMethod {
    Aes256Kw,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone)]
pub struct VltOptions {
    pub cipher: PayloadCipher,
    pub wrap_method: DirectWrapMethod,
    pub direct_recipients: Vec<(String, [u8; 32])>,
    pub quorum_members: Vec<(String, [u8; 32])>,
    pub quorum_threshold_k: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectRecipientSlot {
    pub slot_type: String,
    pub recipient_id: String,
    pub recipient_pk: Vec<u8>,
    pub ephemeral_pk: Vec<u8>,
    pub wrap_method: DirectWrapMethod,
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumMemberSlot {
    pub member_id: String,
    pub share_index: u8,
    pub member_pk: Vec<u8>,
    pub ephemeral_pk: Vec<u8>,
    pub wrapped_share: Vec<u8>,
    pub share_checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirQuorumSlot {
    pub slot_type: String,
    pub threshold_k: u8,
    pub total_n: u8,
    pub wrapped_dek_under_group: Vec<u8>,
    pub secret_commitment: String,
    pub member_shares: Vec<QuorumMemberSlot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VltHeader {
    pub version: u32,
    pub magic: String,
    pub cipher: PayloadCipher,
    pub chunk_size_bytes: u32,
    pub owner_ed25519_pk: Vec<u8>,
    pub direct_slots: Vec<DirectRecipientSlot>,
    pub quorum_slot: Option<ShamirQuorumSlot>,
}

#[derive(Debug, Clone)]
pub struct VltHeaderInfo {
    pub version: u32,
    pub cipher: PayloadCipher,
    pub chunk_size_bytes: u32,
    pub direct_slot_count: usize,
    pub quorum_threshold_k: u8,
    pub quorum_total_n: u8,
    pub header_sha256_hex: String,
    pub signature_valid: bool,
}

/// Encode any `Serialize` value into RFC 8949 Section 4.2.1 canonical deterministic CBOR
/// (sorting map keys by their bytewise deterministic CBOR encodings).
pub fn encode_canonical_cbor<T: Serialize>(val: &T) -> Result<Vec<u8>> {
    let value = Value::serialized(val)
        .map_err(|e| VaultError::Crypto(format!("CBOR value conversion failed: {e}")))?;
    let canonical = canonicalize_cbor_value(value)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut out)
        .map_err(|e| VaultError::Crypto(format!("CBOR serialization failed: {e}")))?;
    Ok(out)
}

fn canonicalize_cbor_value(val: Value) -> Result<Value> {
    match val {
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonicalize_cbor_value(item)?);
            }
            Ok(Value::Array(out))
        }
        Value::Map(entries) => {
            let mut encoded_pairs = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let ck = canonicalize_cbor_value(k)?;
                let cv = canonicalize_cbor_value(v)?;
                let mut k_bytes = Vec::new();
                ciborium::ser::into_writer(&ck, &mut k_bytes)
                    .map_err(|e| VaultError::Crypto(format!("CBOR key encode failed: {e}")))?;
                encoded_pairs.push((k_bytes, ck, cv));
            }
            encoded_pairs.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(Value::Map(
                encoded_pairs
                    .into_iter()
                    .map(|(_, ck, cv)| (ck, cv))
                    .collect(),
            ))
        }
        Value::Tag(t, inner) => Ok(Value::Tag(t, Box::new(canonicalize_cbor_value(*inner)?))),
        other => Ok(other),
    }
}

fn derive_ephemeral_slot_kek(
    shared_secret: &[u8],
    epk: &[u8; 32],
    pk: &[u8; 32],
    info: &[u8],
) -> Result<KeyEncryptionKey> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(pk);
    let okm = hkdf_sha256(shared_secret, &salt, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    let kek = KeyEncryptionKey::from_bytes(key);
    key.zeroize();
    Ok(kek)
}

fn wrap_bytes_for_recipient(
    plaintext_key: &[u8],
    recipient_pk_bytes: &[u8; 32],
    wrap_method: DirectWrapMethod,
    info: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut esk_bytes = [0u8; 32];
    getrandom::getrandom(&mut esk_bytes)
        .map_err(|e| VaultError::Crypto(format!("getrandom esk failed: {e}")))?;
    let esk = StaticSecret::from(esk_bytes);
    esk_bytes.zeroize();

    let epk = X25519PublicKey::from(&esk);
    let recipient_pk = X25519PublicKey::from(*recipient_pk_bytes);
    let shared = esk.diffie_hellman(&recipient_pk);

    let epk_bytes = epk.to_bytes();
    let kek = derive_ephemeral_slot_kek(shared.as_bytes(), &epk_bytes, recipient_pk_bytes, info)?;

    let wrapped = match wrap_method {
        DirectWrapMethod::Aes256Kw => {
            let kw = KekAes256::from(*kek.as_bytes());
            kw.wrap_vec(plaintext_key)
                .map_err(|e| VaultError::Crypto(format!("AES-256-KW wrap failed: {e:?}")))?
        }
        DirectWrapMethod::XChaCha20Poly1305 => {
            let mut nonce_bytes = [0u8; 24];
            getrandom::getrandom(&mut nonce_bytes)
                .map_err(|e| VaultError::Crypto(format!("getrandom wrap nonce failed: {e}")))?;
            let cipher = XChaCha20Poly1305::new(kek.as_bytes().into());
            let mut aad = Vec::with_capacity(info.len() + 64);
            aad.extend_from_slice(info);
            aad.extend_from_slice(&epk_bytes);
            aad.extend_from_slice(recipient_pk_bytes);
            let ct = cipher
                .encrypt(
                    XNonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext_key,
                        aad: &aad,
                    },
                )
                .map_err(|e| VaultError::Crypto(format!("XChaCha wrap failed: {e}")))?;
            let mut combined = Vec::with_capacity(24 + ct.len());
            combined.extend_from_slice(&nonce_bytes);
            combined.extend_from_slice(&ct);
            combined
        }
    };

    Ok((epk_bytes.to_vec(), wrapped))
}

fn unwrap_bytes_with_recipient(
    wrapped: &[u8],
    epk_bytes: &[u8],
    recipient_keys: &DerivedIdentityKeys,
    wrap_method: DirectWrapMethod,
    info: &[u8],
) -> Result<Vec<u8>> {
    let epk_arr: [u8; 32] = epk_bytes
        .try_into()
        .map_err(|_| VaultError::InvalidInput("invalid ephemeral public key length".into()))?;
    let epk = X25519PublicKey::from(epk_arr);
    let shared = recipient_keys.x25519_secret().diffie_hellman(&epk);
    let pk_bytes = recipient_keys.x25519_public_bytes();
    let kek = derive_ephemeral_slot_kek(shared.as_bytes(), &epk_arr, &pk_bytes, info)?;

    match wrap_method {
        DirectWrapMethod::Aes256Kw => {
            let kw = KekAes256::from(*kek.as_bytes());
            kw.unwrap_vec(wrapped)
                .map_err(|_| VaultError::AuthFailed("AES-256-KW integrity unwrap failed".into()))
        }
        DirectWrapMethod::XChaCha20Poly1305 => {
            if wrapped.len() < 24 + 16 {
                return Err(VaultError::InvalidInput("wrapped slot truncated".into()));
            }
            let nonce = &wrapped[..24];
            let ct = &wrapped[24..];
            let mut aad = Vec::with_capacity(info.len() + 64);
            aad.extend_from_slice(info);
            aad.extend_from_slice(&epk_arr);
            aad.extend_from_slice(&pk_bytes);
            let cipher = XChaCha20Poly1305::new(kek.as_bytes().into());
            cipher
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
                .map_err(|_| VaultError::AuthFailed("XChaCha slot unwrap failed".into()))
        }
    }
}

fn build_header_and_seal_with_dek(
    plaintext: &[u8],
    dek: &DataEncryptionKey,
    owner: &DerivedIdentityKeys,
    opts: &VltOptions,
) -> Result<Vec<u8>> {
    if opts.direct_recipients.is_empty() && opts.quorum_members.is_empty() {
        return Err(VaultError::InvalidInput(
            "at least one direct recipient or quorum group is required".into(),
        ));
    }

    let mut direct_slots = Vec::with_capacity(opts.direct_recipients.len());
    for (id, pk) in &opts.direct_recipients {
        let (epk, wrapped_dek) =
            wrap_bytes_for_recipient(dek.as_bytes(), pk, opts.wrap_method, INFO_DIRECT_SLOT)?;
        direct_slots.push(DirectRecipientSlot {
            slot_type: "direct_x25519".to_string(),
            recipient_id: id.clone(),
            recipient_pk: pk.to_vec(),
            ephemeral_pk: epk,
            wrap_method: opts.wrap_method,
            wrapped_dek,
        });
    }

    let quorum_slot = if !opts.quorum_members.is_empty() {
        let total_n = u8::try_from(opts.quorum_members.len())
            .map_err(|_| VaultError::InvalidInput("too many quorum members".into()))?;
        let k = opts.quorum_threshold_k;
        if k == 0 || k > total_n {
            return Err(VaultError::Quorum(format!(
                "invalid quorum threshold {k} for {total_n} members"
            )));
        }

        let mut group_kek_bytes = [0u8; 32];
        getrandom::getrandom(&mut group_kek_bytes)
            .map_err(|e| VaultError::Crypto(format!("getrandom GroupKEK failed: {e}")))?;

        let kw = KekAes256::from(group_kek_bytes);
        let wrapped_dek_under_group = kw
            .wrap_vec(dek.as_bytes())
            .map_err(|e| VaultError::Crypto(format!("GroupKEK wrap failed: {e:?}")))?;

        let shares = shamir_split_secret_random(&group_kek_bytes, k, total_n)?;
        let commitment = secret_commitment(&group_kek_bytes);
        group_kek_bytes.zeroize();

        let mut member_slots = Vec::with_capacity(opts.quorum_members.len());
        for ((member_id, member_pk), share) in opts.quorum_members.iter().zip(shares.iter()) {
            let mut share_payload = Vec::with_capacity(1 + share.data().len());
            share_payload.push(share.index());
            share_payload.extend_from_slice(share.data());

            let (epk, wrapped_share) = wrap_bytes_for_recipient(
                &share_payload,
                member_pk,
                DirectWrapMethod::XChaCha20Poly1305,
                INFO_QUORUM_SHARE_SLOT,
            )?;
            share_payload.zeroize();

            member_slots.push(QuorumMemberSlot {
                member_id: member_id.clone(),
                share_index: share.index(),
                member_pk: member_pk.to_vec(),
                ephemeral_pk: epk,
                wrapped_share,
                share_checksum: share_checksum(share.index(), share.data()),
            });
        }

        Some(ShamirQuorumSlot {
            slot_type: "shamir_quorum".to_string(),
            threshold_k: k,
            total_n,
            wrapped_dek_under_group,
            secret_commitment: commitment,
            member_shares: member_slots,
        })
    } else {
        None
    };

    let header = VltHeader {
        version: 1,
        magic: "LAVAULT1".to_string(),
        cipher: opts.cipher,
        chunk_size_bytes: STREAM_CHUNK_SIZE as u32,
        owner_ed25519_pk: owner.ed25519_public_bytes().to_vec(),
        direct_slots,
        quorum_slot,
    };

    let header_cbor = encode_canonical_cbor(&header)?;
    let header_sha256: [u8; 32] = Sha256::digest(&header_cbor).into();
    let sig = owner.ed25519_signing().sign(&header_sha256);

    let mut out = Vec::with_capacity(8 + 4 + header_cbor.len() + 64 + plaintext.len() + 1024);
    out.extend_from_slice(VLT_MAGIC);
    out.extend_from_slice(&(header_cbor.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_cbor);
    out.extend_from_slice(&sig.to_bytes());

    encrypt_stream_chunks(plaintext, dek, opts.cipher, &header_sha256, &mut out)?;
    Ok(out)
}

pub fn encrypt_bytes_to_vlt(
    plaintext: &[u8],
    owner: &DerivedIdentityKeys,
    opts: &VltOptions,
) -> Result<Vec<u8>> {
    let dek = DataEncryptionKey::generate()?;
    build_header_and_seal_with_dek(plaintext, &dek, owner, opts)
}

fn stream_chunk_nonce(chunk_index: u64, is_final: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // 11-byte big-endian chunk index (u64 sits in bytes 3..11) + 1-byte final flag
    nonce[3..11].copy_from_slice(&chunk_index.to_be_bytes());
    nonce[11] = if is_final { 0x01 } else { 0x00 };
    nonce
}

fn encrypt_stream_chunks(
    plaintext: &[u8],
    dek: &DataEncryptionKey,
    cipher_kind: PayloadCipher,
    header_aad: &[u8; 32],
    out: &mut Vec<u8>,
) -> Result<()> {
    let total_chunks = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(STREAM_CHUNK_SIZE)
    };

    for idx in 0..total_chunks {
        let start = idx * STREAM_CHUNK_SIZE;
        let end = ((idx + 1) * STREAM_CHUNK_SIZE).min(plaintext.len());
        let chunk = &plaintext[start..end];
        let is_final = idx + 1 == total_chunks;
        let nonce_bytes = stream_chunk_nonce(idx as u64, is_final);

        let ct = match cipher_kind {
            PayloadCipher::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(dek.as_bytes()));
                cipher
                    .encrypt(
                        Nonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: chunk,
                            aad: header_aad,
                        },
                    )
                    .map_err(|e| VaultError::Crypto(format!("STREAM ChaCha encrypt failed: {e}")))?
            }
            PayloadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(dek.as_bytes().into());
                cipher
                    .encrypt(
                        GcmNonce::from_slice(&nonce_bytes),
                        GcmPayload {
                            msg: chunk,
                            aad: header_aad,
                        },
                    )
                    .map_err(|e| VaultError::Crypto(format!("STREAM AES-GCM encrypt failed: {e}")))?
            }
        };

        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
    }

    Ok(())
}

fn decrypt_stream_chunks(
    payload_bytes: &[u8],
    dek: &DataEncryptionKey,
    cipher_kind: PayloadCipher,
    header_aad: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let mut chunk_index = 0u64;
    let mut plaintext = Vec::new();

    if payload_bytes.is_empty() {
        return Err(VaultError::InvalidInput("empty .vlt payload stream".into()));
    }

    while offset < payload_bytes.len() {
        if offset + 4 > payload_bytes.len() {
            return Err(VaultError::InvalidInput("truncated chunk length".into()));
        }
        let ct_len = u32::from_be_bytes(
            payload_bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidInput("bad chunk length".into()))?,
        ) as usize;
        offset += 4;
        if offset + ct_len > payload_bytes.len() {
            return Err(VaultError::InvalidInput("truncated chunk ciphertext".into()));
        }
        let ct = &payload_bytes[offset..offset + ct_len];
        offset += ct_len;

        let is_final = offset == payload_bytes.len();
        let nonce_bytes = stream_chunk_nonce(chunk_index, is_final);

        let pt = match cipher_kind {
            PayloadCipher::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(dek.as_bytes()));
                cipher
                    .decrypt(
                        Nonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: ct,
                            aad: header_aad,
                        },
                    )
                    .map_err(|_| VaultError::AuthFailed("STREAM chunk authentication failed".into()))?
            }
            PayloadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(dek.as_bytes().into());
                cipher
                    .decrypt(
                        GcmNonce::from_slice(&nonce_bytes),
                        GcmPayload {
                            msg: ct,
                            aad: header_aad,
                        },
                    )
                    .map_err(|_| VaultError::AuthFailed("STREAM chunk authentication failed".into()))?
            }
        };

        plaintext.extend_from_slice(&pt);
        chunk_index += 1;
    }

    Ok(plaintext)
}

pub fn parse_vlt_parts(container: &[u8]) -> Result<(VltHeader, [u8; 32], bool, &[u8])> {
    if container.len() < 8 + 4 + 64 {
        return Err(VaultError::InvalidInput(".vlt container too small".into()));
    }
    if &container[..8] != VLT_MAGIC {
        return Err(VaultError::InvalidInput("invalid .vlt magic header".into()));
    }
    let header_len = u32::from_be_bytes(
        container[8..12]
            .try_into()
            .map_err(|_| VaultError::InvalidInput("bad header len".into()))?,
    ) as usize;
    let header_end = 12 + header_len;
    if header_end + 64 > container.len() {
        return Err(VaultError::InvalidInput("truncated .vlt header".into()));
    }
    let header_cbor = &container[12..header_end];
    let sig_bytes: [u8; 64] = container[header_end..header_end + 64]
        .try_into()
        .map_err(|_| VaultError::InvalidInput("bad signature len".into()))?;
    let payload = &container[header_end + 64..];

    let header: VltHeader = ciborium::de::from_reader(header_cbor)
        .map_err(|e| VaultError::InvalidInput(format!("invalid .vlt CBOR header: {e}")))?;

    let header_sha256: [u8; 32] = Sha256::digest(header_cbor).into();
    let owner_pk_arr: [u8; 32] = header
        .owner_ed25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidInput("invalid owner Ed25519 key length".into()))?;
    let verifying = VerifyingKey::from_bytes(&owner_pk_arr)
        .map_err(|e| VaultError::AuthFailed(format!("invalid owner Ed25519 key: {e}")))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let sig_valid = verifying.verify(&header_sha256, &sig).is_ok();

    Ok((header, header_sha256, sig_valid, payload))
}

pub fn inspect_vlt_header(container: &[u8]) -> Result<VltHeaderInfo> {
    let (header, header_sha256, signature_valid, _) = parse_vlt_parts(container)?;
    let (quorum_threshold_k, quorum_total_n) = match &header.quorum_slot {
        Some(q) => (q.threshold_k, q.total_n),
        None => (0, 0),
    };
    Ok(VltHeaderInfo {
        version: header.version,
        cipher: header.cipher,
        chunk_size_bytes: header.chunk_size_bytes,
        direct_slot_count: header.direct_slots.len(),
        quorum_threshold_k,
        quorum_total_n,
        header_sha256_hex: hex::encode(header_sha256),
        signature_valid,
    })
}

pub fn unwrap_dek_direct(
    header: &VltHeader,
    recipient_id: &str,
    recipient_keys: &DerivedIdentityKeys,
) -> Result<DataEncryptionKey> {
    let slot = header
        .direct_slots
        .iter()
        .find(|s| s.recipient_id == recipient_id)
        .ok_or_else(|| {
            VaultError::AuthFailed(format!("no direct slot for recipient '{recipient_id}'"))
        })?;

    let mut dek_vec = unwrap_bytes_with_recipient(
        &slot.wrapped_dek,
        &slot.ephemeral_pk,
        recipient_keys,
        slot.wrap_method,
        INFO_DIRECT_SLOT,
    )?;
    if dek_vec.len() != 32 {
        dek_vec.zeroize();
        return Err(VaultError::AuthFailed("unwrapped DEK is not 32 bytes".into()));
    }
    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(&dek_vec);
    dek_vec.zeroize();
    let dek = DataEncryptionKey::from_bytes(dek_arr);
    dek_arr.zeroize();
    Ok(dek)
}

pub fn decrypt_bytes_with_dek(container: &[u8], dek: &DataEncryptionKey) -> Result<Vec<u8>> {
    let (header, header_sha256, sig_valid, payload) = parse_vlt_parts(container)?;
    if !sig_valid {
        return Err(VaultError::AuthFailed(
            "header Ed25519 signature verification failed".into(),
        ));
    }
    decrypt_stream_chunks(payload, dek, header.cipher, &header_sha256)
}

pub fn decrypt_bytes_with_direct_slot(
    container: &[u8],
    recipient_id: &str,
    recipient_keys: &DerivedIdentityKeys,
) -> Result<Vec<u8>> {
    let (header, header_sha256, sig_valid, payload) = parse_vlt_parts(container)?;
    if !sig_valid {
        return Err(VaultError::AuthFailed(
            "header Ed25519 signature verification failed".into(),
        ));
    }
    let dek = unwrap_dek_direct(&header, recipient_id, recipient_keys)?;
    decrypt_stream_chunks(payload, &dek, header.cipher, &header_sha256)
}

pub fn unwrap_dek_quorum(
    header: &VltHeader,
    members: &[(&str, &DerivedIdentityKeys)],
) -> Result<DataEncryptionKey> {
    let qslot = header
        .quorum_slot
        .as_ref()
        .ok_or_else(|| VaultError::Quorum("container has no shamir_quorum slot".into()))?;

    let mut shares = Vec::with_capacity(members.len());
    for (member_id, member_keys) in members {
        let mslot = qslot
            .member_shares
            .iter()
            .find(|m| m.member_id == *member_id)
            .ok_or_else(|| {
                VaultError::Quorum(format!("no quorum share for member '{member_id}'"))
            })?;

        let mut plain_share = unwrap_bytes_with_recipient(
            &mslot.wrapped_share,
            &mslot.ephemeral_pk,
            member_keys,
            DirectWrapMethod::XChaCha20Poly1305,
            INFO_QUORUM_SHARE_SLOT,
        )?;
        if plain_share.len() < 2 {
            plain_share.zeroize();
            return Err(VaultError::Quorum("corrupt quorum share length".into()));
        }
        let idx = plain_share[0];
        let share_data = plain_share[1..].to_vec();
        plain_share.zeroize();
        shares.push(ShamirShare::new(
            idx,
            qslot.threshold_k,
            qslot.total_n,
            share_data,
        ));
    }

    let mut group_kek_vec =
        shamir_reconstruct_secret(&shares, Some(&qslot.secret_commitment))?;
    let group_kek_arr: [u8; 32] = group_kek_vec
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Quorum("reconstructed GroupKEK is not 32 bytes".into()))?;
    group_kek_vec.zeroize();

    let kw = KekAes256::from(group_kek_arr);
    let mut dek_vec = kw
        .unwrap_vec(&qslot.wrapped_dek_under_group)
        .map_err(|_| VaultError::AuthFailed("GroupKEK DEK unwrap failed".into()))?;
    if dek_vec.len() != 32 {
        dek_vec.zeroize();
        return Err(VaultError::AuthFailed("unwrapped DEK is not 32 bytes".into()));
    }
    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(&dek_vec);
    dek_vec.zeroize();
    let dek = DataEncryptionKey::from_bytes(dek_arr);
    dek_arr.zeroize();
    Ok(dek)
}

pub fn decrypt_bytes_with_quorum_slots(
    container: &[u8],
    members: &[(&str, &DerivedIdentityKeys)],
) -> Result<Vec<u8>> {
    let (header, header_sha256, sig_valid, payload) = parse_vlt_parts(container)?;
    if !sig_valid {
        return Err(VaultError::AuthFailed(
            "header Ed25519 signature verification failed".into(),
        ));
    }
    let dek = unwrap_dek_quorum(&header, members)?;
    decrypt_stream_chunks(payload, &dek, header.cipher, &header_sha256)
}

/// Add a 1-of-N direct recipient to an existing `.vlt` container (re-seals header + AAD).
pub fn add_direct_recipient_to_vlt(
    container: &[u8],
    authorizer_id: &str,
    authorizer_keys: &DerivedIdentityKeys,
    new_recipient_id: &str,
    new_recipient_pk: [u8; 32],
) -> Result<Vec<u8>> {
    let (header, header_sha256, sig_valid, payload) = parse_vlt_parts(container)?;
    if !sig_valid {
        return Err(VaultError::AuthFailed("invalid .vlt header signature".into()));
    }
    let dek = unwrap_dek_direct(&header, authorizer_id, authorizer_keys)?;
    let plaintext = decrypt_stream_chunks(payload, &dek, header.cipher, &header_sha256)?;

    let mut recipients: Vec<(String, [u8; 32])> = header
        .direct_slots
        .iter()
        .filter(|s| s.recipient_id != new_recipient_id)
        .filter_map(|s| {
            let pk: [u8; 32] = s.recipient_pk.as_slice().try_into().ok()?;
            Some((s.recipient_id.clone(), pk))
        })
        .collect();
    recipients.push((new_recipient_id.to_string(), new_recipient_pk));

    let (quorum_members, quorum_threshold_k) = match &header.quorum_slot {
        Some(q) => (
            q.member_shares
                .iter()
                .filter_map(|m| {
                    let pk: [u8; 32] = m.member_pk.as_slice().try_into().ok()?;
                    Some((m.member_id.clone(), pk))
                })
                .collect(),
            q.threshold_k,
        ),
        None => (Vec::new(), 0),
    };

    let wrap_method = header
        .direct_slots
        .first()
        .map(|s| s.wrap_method)
        .unwrap_or(DirectWrapMethod::Aes256Kw);

    let opts = VltOptions {
        cipher: header.cipher,
        wrap_method,
        direct_recipients: recipients,
        quorum_members,
        quorum_threshold_k,
    };

    build_header_and_seal_with_dek(&plaintext, &dek, authorizer_keys, &opts)
}

/// Remove a 1-of-N direct recipient and rotate the DEK so the removed peer loses future decryption.
pub fn remove_direct_recipient_from_vlt(
    container: &[u8],
    owner_keys: &DerivedIdentityKeys,
    recipient_id_to_remove: &str,
) -> Result<Vec<u8>> {
    let (header, header_sha256, sig_valid, payload) = parse_vlt_parts(container)?;
    if !sig_valid {
        return Err(VaultError::AuthFailed("invalid .vlt header signature".into()));
    }

    let owner_pk = owner_keys.x25519_public_bytes();
    let owner_slot = header
        .direct_slots
        .iter()
        .find(|s| s.recipient_pk == owner_pk.as_slice())
        .ok_or_else(|| VaultError::AuthFailed("owner direct slot not found".into()))?;

    let old_dek = unwrap_dek_direct(&header, &owner_slot.recipient_id, owner_keys)?;
    let plaintext = decrypt_stream_chunks(payload, &old_dek, header.cipher, &header_sha256)?;

    let recipients: Vec<(String, [u8; 32])> = header
        .direct_slots
        .iter()
        .filter(|s| s.recipient_id != recipient_id_to_remove)
        .filter_map(|s| {
            let pk: [u8; 32] = s.recipient_pk.as_slice().try_into().ok()?;
            Some((s.recipient_id.clone(), pk))
        })
        .collect();

    if recipients.is_empty() && header.quorum_slot.is_none() {
        return Err(VaultError::InvalidInput(
            "cannot remove the last recipient from container".into(),
        ));
    }

    let (quorum_members, quorum_threshold_k) = match &header.quorum_slot {
        Some(q) => (
            q.member_shares
                .iter()
                .filter_map(|m| {
                    let pk: [u8; 32] = m.member_pk.as_slice().try_into().ok()?;
                    Some((m.member_id.clone(), pk))
                })
                .collect(),
            q.threshold_k,
        ),
        None => (Vec::new(), 0),
    };

    let wrap_method = header
        .direct_slots
        .first()
        .map(|s| s.wrap_method)
        .unwrap_or(DirectWrapMethod::Aes256Kw);

    let opts = VltOptions {
        cipher: header.cipher,
        wrap_method,
        direct_recipients: recipients,
        quorum_members,
        quorum_threshold_k,
    };

    encrypt_bytes_to_vlt(&plaintext, owner_keys, &opts)
}

pub fn encrypt_directory_to_vlt(
    src_dir: &Path,
    dest_vlt: &Path,
    owner: &DerivedIdentityKeys,
    opts: &VltOptions,
) -> Result<()> {
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        builder.mode(tar::HeaderMode::Deterministic);
        builder.append_dir_all(".", src_dir)?;
        builder.finish()?;
    }
    let compressed = zstd::stream::encode_all(tar_buf.as_slice(), 3)?;
    let vlt_bytes = encrypt_bytes_to_vlt(&compressed, owner, opts)?;
    std::fs::write(dest_vlt, vlt_bytes)?;
    Ok(())
}

fn unpack_zstd_tar(compressed: &[u8], dest_dir: &Path) -> Result<()> {
    let tar_bytes = zstd::stream::decode_all(compressed)?;
    std::fs::create_dir_all(dest_dir)?;
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    archive.unpack(dest_dir)?;
    Ok(())
}

pub fn decrypt_directory_from_vlt(
    src_vlt: &Path,
    dest_dir: &Path,
    recipient_id: &str,
    recipient_keys: &DerivedIdentityKeys,
) -> Result<()> {
    let vlt_bytes = std::fs::read(src_vlt)?;
    let compressed = decrypt_bytes_with_direct_slot(&vlt_bytes, recipient_id, recipient_keys)?;
    unpack_zstd_tar(&compressed, dest_dir)
}

pub fn decrypt_directory_from_vlt_with_dek(
    src_vlt: &Path,
    dest_dir: &Path,
    dek: &DataEncryptionKey,
) -> Result<()> {
    let vlt_bytes = std::fs::read(src_vlt)?;
    let compressed = decrypt_bytes_with_dek(&vlt_bytes, dek)?;
    unpack_zstd_tar(&compressed, dest_dir)
}
