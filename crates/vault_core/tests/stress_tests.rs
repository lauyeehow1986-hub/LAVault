use std::time::Instant;
use tempfile::tempdir;
use vault_core::identity::{DerivedIdentityKeys, KeyEncryptionKey, MasterIdentitySeed};
use vault_core::otp::{totp_from_base32, totp_rfc6238, OtpAlgorithm};
use vault_core::transport::{
    build_unlock_challenge_for_vlt, decode_bcur_multipart, encode_bcur_multipart,
    fulfill_unlock_challenge, verify_and_extract_unlock_dek, Spake2Pairing, UnlockChallenge,
    UnlockResponse,
};
use vault_core::vault_db::{NewVaultEntry, PasswordTotpVault};
use vault_core::vlt::{
    decrypt_bytes_with_direct_slot, decrypt_bytes_with_quorum_slots, encrypt_bytes_to_vlt,
    DirectWrapMethod, PayloadCipher, VltOptions,
};

#[test]
fn stress_totp_10k_generations_and_boundary_rollovers() {
    let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let start = Instant::now();
    for i in 0..10_000u64 {
        let t = 1_700_000_000 + i;
        let (code, rem) =
            totp_from_base32(secret_b32, t, 30, 6, OtpAlgorithm::Sha1).expect("TOTP");
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&rem));
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs_f64() < 5.0, "10k TOTPs took too long: {elapsed:?}");

    // Verify exact rollover boundary at T=59 -> T=60
    let (c59, r59) = totp_from_base32(secret_b32, 59, 30, 8, OtpAlgorithm::Sha1).unwrap();
    let (c60, r60) = totp_from_base32(secret_b32, 60, 30, 8, OtpAlgorithm::Sha1).unwrap();
    assert_eq!(c59, "94287082");
    assert_eq!(r59, 1);
    assert_eq!(r60, 30);
    assert_ne!(c59, c60);
    assert_eq!(
        totp_rfc6238(b"12345678901234567890", 60, 30, 0, 8, OtpAlgorithm::Sha1).unwrap(),
        c60
    );
}

#[test]
fn stress_vlt_and_qr_unlocker_50_rounds_1_of_n_and_2_of_3_quorum() {
    let owner = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([1u8; 32])).unwrap();
    let phone = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([2u8; 32])).unwrap();
    let g1 = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([3u8; 32])).unwrap();
    let g2 = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([4u8; 32])).unwrap();
    let g3 = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([5u8; 32])).unwrap();

    for round in 0..50usize {
        let payload = vec![(round % 251) as u8; 4096 + round * 1024];
        let vlt = encrypt_bytes_to_vlt(
            &payload,
            &owner,
            &VltOptions {
                cipher: if round % 2 == 0 {
                    PayloadCipher::ChaCha20Poly1305
                } else {
                    PayloadCipher::Aes256Gcm
                },
                wrap_method: if round % 2 == 0 {
                    DirectWrapMethod::Aes256Kw
                } else {
                    DirectWrapMethod::XChaCha20Poly1305
                },
                direct_recipients: vec![
                    ("owner".into(), owner.x25519_public_bytes()),
                    ("phone".into(), phone.x25519_public_bytes()),
                ],
                quorum_members: vec![
                    ("g1".into(), g1.x25519_public_bytes()),
                    ("g2".into(), g2.x25519_public_bytes()),
                    ("g3".into(), g3.x25519_public_bytes()),
                ],
                quorum_threshold_k: 2,
            },
        )
        .unwrap();

        // Air-gapped QR challenge/response cycle
        let (challenge, ephem) =
            build_unlock_challenge_for_vlt(&vlt, "phone", "StressPC").unwrap();
        let req_ur = challenge.to_bcur().unwrap();
        let parsed_req = UnlockChallenge::from_bcur(&req_ur).unwrap();
        let resp = fulfill_unlock_challenge(&parsed_req, "phone", &phone).unwrap();
        let res_ur = resp.to_bcur().unwrap();
        let parsed_res = UnlockResponse::from_bcur(&res_ur).unwrap();
        let dek = verify_and_extract_unlock_dek(&parsed_res, &ephem, &phone.ed25519_verifying())
            .unwrap();
        assert_ne!(dek.as_bytes(), &[0u8; 32]);

        // Verify direct decrypt & quorum decrypt
        assert_eq!(
            decrypt_bytes_with_direct_slot(&vlt, "phone", &phone).unwrap(),
            payload
        );
        assert_eq!(
            decrypt_bytes_with_quorum_slots(&vlt, &[("g1", &g1), ("g3", &g3)]).unwrap(),
            payload
        );
    }
}

#[test]
fn stress_bcur_multipart_erasure_and_spake2_50_rounds() {
    for round in 0..50usize {
        let data = vec![(round * 7 % 256) as u8; 512 + round * 13];
        let mut frames = encode_bcur_multipart("lavault-req", &data, 96).unwrap();
        // Drop one data fragment and rely on XOR fountain parity frame to recover
        frames.remove(round % (frames.len() - 1));
        let (ur_type, recovered) = decode_bcur_multipart(&frames).unwrap();
        assert_eq!(ur_type, "lavault-req");
        assert_eq!(recovered, data);

        let pin = format!("{:06}", (round * 19391) % 1_000_000);
        let (pc, m1) = Spake2Pairing::start_initiator("pc", "phone", &pin);
        let (ph, m2) = Spake2Pairing::start_responder("pc", "phone", &pin);
        let r1 = pc.finish(&m2).unwrap();
        let r2 = ph.finish(&m1).unwrap();
        assert_eq!(r1.shared_key, r2.shared_key);
        assert_eq!(r1.sas_6digit, r2.sas_6digit);
    }
}

#[test]
fn stress_vault_db_100_entries_unlock_and_delete() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("stress_vault.db");
    let db_key = KeyEncryptionKey::from_bytes([0x88; 32]);
    let mut vault = PasswordTotpVault::open_or_create(&db_path, &db_key).unwrap();

    let mut ids = Vec::with_capacity(100);
    for i in 0..100 {
        let id = vault
            .add_entry(NewVaultEntry {
                title: format!("Service-{i:03}"),
                username: format!("user{i}@lavault.local"),
                password: format!("Pass-{i:03}-Secret!"),
                totp_secret_base32: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
                totp_algorithm: OtpAlgorithm::Sha1,
                totp_digits: 6,
                totp_period_secs: 30,
                url: None,
                notes: None,
            })
            .unwrap();
        ids.push(id);
    }

    assert_eq!(vault.list_summaries().unwrap().len(), 100);
    for (i, id) in ids.iter().enumerate() {
        let unlocked = vault.unlock_entry_at(id, 1_700_000_000 + i as u64).unwrap();
        assert_eq!(unlocked.password.as_str(), format!("Pass-{i:03}-Secret!"));
        assert_eq!(unlocked.totp_code.as_ref().unwrap().len(), 6);
    }
    for id in ids {
        vault.delete_entry(&id).unwrap();
    }
    assert!(vault.list_summaries().unwrap().is_empty());
}
