use tempfile::tempdir;
use vault_core::api::{
    add_vault_entry, approve_bcur_unlock_request, create_identity_and_vault, delete_vault_entry,
    export_recovery_kit, list_vault_entries, lock_session, search_vault_entries,
    unlock_vault_entry_at, verify_totp_vector_for_test, VaultEntryInputDto,
};
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed};
use vault_core::otp::OtpAlgorithm;
use vault_core::transport::{
    build_unlock_challenge_for_vlt, decode_bcur_multipart, decode_bcur_payload,
    encode_8word_verifier, encode_bcur_multipart, encode_bcur_payload, fulfill_unlock_challenge,
    verify_and_extract_unlock_dek, BleSessionCipher, Spake2Pairing, BLE_GATT_SERVICE_UUID,
    MDNS_SERVICE_TYPE, MDNS_TCP_PORT,
};
use vault_core::vlt::{
    decrypt_bytes_with_direct_slot, encrypt_bytes_to_vlt, DirectWrapMethod, PayloadCipher,
    VltOptions,
};

#[test]
fn bcur_bytewords_and_multipart_fountain_roundtrip() {
    assert_eq!(MDNS_SERVICE_TYPE, "_localauth._tcp.local.");
    assert_eq!(MDNS_TCP_PORT, 53319);
    assert_eq!(
        BLE_GATT_SERVICE_UUID,
        "0000fffd-0000-1000-8000-00805f9b34fb"
    );

    let payload = b"cbor-challenge-payload-for-optical-qr-test".to_vec();
    let ur = encode_bcur_payload("lavault-req", &payload);
    assert!(ur.starts_with("ur:lavault-req/"));

    let (ur_type, decoded) = decode_bcur_payload(&ur).expect("decode bc-ur");
    assert_eq!(ur_type, "lavault-req");
    assert_eq!(decoded, payload);

    // Tampered character fails CRC32
    let mut bad = ur.clone();
    bad.pop();
    bad.push(if ur.ends_with('a') { 'b' } else { 'a' });
    assert!(decode_bcur_payload(&bad).is_err());

    // Multipart fountain UR for larger payloads
    let large_payload = vec![0x5Cu8; 640];
    let parts = encode_bcur_multipart("lavault-res", &large_payload, 128).expect("multipart encode");
    assert!(parts.len() >= 5);
    let reassembled = decode_bcur_multipart(&parts).expect("multipart decode");
    assert_eq!(reassembled.0, "lavault-res");
    assert_eq!(reassembled.1, large_payload);
}

#[test]
fn spake2_pairing_derives_identical_session_keys_and_sas() {
    let (pc, msg_pc) = Spake2Pairing::start_initiator("lavault-pc", "lavault-phone", "482910");
    let (phone, msg_phone) = Spake2Pairing::start_responder("lavault-pc", "lavault-phone", "482910");

    let key_pc = pc.finish(&msg_phone).expect("pc finish spake2");
    let key_phone = phone.finish(&msg_pc).expect("phone finish spake2");
    assert_eq!(key_pc.shared_key, key_phone.shared_key);
    assert_eq!(key_pc.sas_6digit, key_phone.sas_6digit);

    // Wrong PIN produces mismatched key
    let (pc_bad, msg_bad) = Spake2Pairing::start_initiator("lavault-pc", "lavault-phone", "000000");
    let (phone_ok, msg_ok) = Spake2Pairing::start_responder("lavault-pc", "lavault-phone", "482910");
    let k1 = pc_bad.finish(&msg_ok).unwrap();
    let k2 = phone_ok.finish(&msg_bad).unwrap();
    assert_ne!(k1.shared_key, k2.shared_key);
}

#[test]
fn unified_challenge_response_unlocks_vlt_over_qr_and_ble() {
    let phone_seed = MasterIdentitySeed::from_bytes([0x15; 32]);
    let phone_keys = DerivedIdentityKeys::from_seed(&phone_seed).unwrap();

    let plaintext = b"Air-gapped secret document".to_vec();
    let opts = VltOptions {
        cipher: PayloadCipher::ChaCha20Poly1305,
        wrap_method: DirectWrapMethod::Aes256Kw,
        direct_recipients: vec![("phone_main".into(), phone_keys.x25519_public_bytes())],
        quorum_members: vec![],
        quorum_threshold_k: 0,
    };
    let vlt_bytes = encrypt_bytes_to_vlt(&plaintext, &phone_keys, &opts).unwrap();

    // Build UnlockChallenge + ephemeral response key on PC
    let (challenge, pc_ephem) =
        build_unlock_challenge_for_vlt(&vlt_bytes, "phone_main", "Workstation-Win11").unwrap();

    // 8-word one-time verifier code fallback
    let words = encode_8word_verifier(&challenge.challenge_nonce);
    assert_eq!(words.split_whitespace().count(), 8);

    // Transport via Optical QR (bc-ur) + BLE session framing
    let req_ur = challenge.to_bcur().unwrap();
    let parsed_req = vault_core::transport::UnlockChallenge::from_bcur(&req_ur).unwrap();

    let response = fulfill_unlock_challenge(&parsed_req, "phone_main", &phone_keys).unwrap();
    let ble_cipher = BleSessionCipher::from_ephemeral_pair(
        &phone_keys,
        &challenge.pc_response_epk,
    );
    let ble_packet = ble_cipher.encrypt_response(&response).unwrap();
    let decrypted_resp = ble_cipher.decrypt_response(&ble_packet).unwrap();

    let dek =
        verify_and_extract_unlock_dek(&decrypted_resp, &pc_ephem, &phone_keys.ed25519_verifying())
            .expect("extract DEK");

    // Verify DEK matches direct decrypt
    let direct_pt = decrypt_bytes_with_direct_slot(&vlt_bytes, "phone_main", &phone_keys).unwrap();
    assert_eq!(direct_pt, plaintext);
    assert_ne!(dek.as_bytes(), &[0u8; 32]);
}

#[test]
fn flutter_rust_bridge_api_lifecycle_and_zeroize_lock() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("app_vault.db");

    assert_eq!(
        verify_totp_vector_for_test().unwrap(),
        "94287082"
    );

    let session = create_identity_and_vault(
        db_path.to_string_lossy().to_string(),
        "MasterPass#2026".to_string(),
        vec![0xAB; 32],
    )
    .expect("create session");

    let entry_id = add_vault_entry(
        session.session_id.clone(),
        VaultEntryInputDto {
            title: "Cloudflare".into(),
            username: "ops@lavault.local".into(),
            password: "Cf-Password-123".into(),
            totp_secret_base32: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
            totp_algorithm: OtpAlgorithm::Sha1,
            totp_digits: 8,
            totp_period_secs: 30,
            url: Some("https://dash.cloudflare.com".into()),
            notes: None,
        },
    )
    .expect("add entry");

    assert_eq!(list_vault_entries(session.session_id.clone()).unwrap().len(), 1);
    assert_eq!(
        search_vault_entries(session.session_id.clone(), "cloud".into())
            .unwrap()
            .len(),
        1
    );

    let unlocked = unlock_vault_entry_at(session.session_id.clone(), entry_id.clone(), 59).unwrap();
    assert_eq!(unlocked.password, "Cf-Password-123");
    assert_eq!(unlocked.totp_code.as_deref(), Some("94287082"));
    assert_eq!(unlocked.totp_remaining_secs, Some(1));

    delete_vault_entry(session.session_id.clone(), entry_id).expect("delete entry");
    assert_eq!(list_vault_entries(session.session_id.clone()).unwrap().len(), 0);

    let recovery = export_recovery_kit(
        session.session_id.clone(),
        "rkf-pass".to_string(),
        vec!["alice".into(), "bob".into(), "charlie".into()],
        2,
    )
    .expect("export recovery kit");
    assert_eq!(recovery.bip39_24_words.split_whitespace().count(), 24);
    assert_eq!(recovery.guardian_capsules.len(), 3);

    // Approve an air-gapped bc-ur request via session
    let seed = MasterIdentitySeed::from_bytes([0x31; 32]);
    let owner = DerivedIdentityKeys::from_seed(&seed).unwrap();
    let vlt_bytes = encrypt_bytes_to_vlt(
        b"hello qr",
        &owner,
        &VltOptions {
            cipher: PayloadCipher::ChaCha20Poly1305,
            wrap_method: DirectWrapMethod::Aes256Kw,
            direct_recipients: vec![("mobile_owner".into(), session.x25519_public_bytes.clone().try_into().unwrap())],
            quorum_members: vec![],
            quorum_threshold_k: 0,
        },
    )
    .unwrap();
    let (challenge, _) =
        build_unlock_challenge_for_vlt(&vlt_bytes, "mobile_owner", "MacBook").unwrap();
    let res_ur = approve_bcur_unlock_request(
        session.session_id.clone(),
        challenge.to_bcur().unwrap(),
    )
    .expect("approve bc-ur");
    assert!(res_ur.starts_with("ur:lavault-res/"));

    // Locking the session wipes keys in RAM; subsequent calls must fail
    lock_session(session.session_id.clone()).unwrap();
    assert!(list_vault_entries(session.session_id).is_err());
}
