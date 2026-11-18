use tempfile::tempdir;
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed};
use vault_core::vlt::{
    add_direct_recipient_to_vlt, decrypt_bytes_with_direct_slot, decrypt_bytes_with_quorum_slots,
    decrypt_directory_from_vlt, encrypt_bytes_to_vlt, encrypt_directory_to_vlt,
    inspect_vlt_header, remove_direct_recipient_from_vlt, DirectWrapMethod, PayloadCipher,
    VltOptions, VLT_MAGIC,
};

fn make_identity(tag: u8) -> DerivedIdentityKeys {
    let seed = MasterIdentitySeed::from_bytes([tag; 32]);
    DerivedIdentityKeys::from_seed(&seed).unwrap()
}

#[test]
fn vlt_1_of_n_direct_aes_kw_and_xchacha_multi_chunk_roundtrip() {
    let owner = make_identity(1);
    let peer_b = make_identity(2);
    let intruder = make_identity(99);

    // 150 KB payload spans 3 x 64 KB STREAM chunks
    let plaintext: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();

    for (cipher, wrap_method) in [
        (PayloadCipher::ChaCha20Poly1305, DirectWrapMethod::Aes256Kw),
        (PayloadCipher::Aes256Gcm, DirectWrapMethod::XChaCha20Poly1305),
    ] {
        let opts = VltOptions {
            cipher,
            wrap_method,
            direct_recipients: vec![
                ("owner".into(), owner.x25519_public_bytes()),
                ("peer_b".into(), peer_b.x25519_public_bytes()),
            ],
            quorum_members: vec![],
            quorum_threshold_k: 0,
        };

        let container = encrypt_bytes_to_vlt(&plaintext, &owner, &opts).expect("encrypt .vlt");
        assert!(container.starts_with(VLT_MAGIC));

        let info = inspect_vlt_header(&container).expect("inspect .vlt");
        assert_eq!(info.direct_slot_count, 2);
        assert!(info.signature_valid);

        let dec_owner = decrypt_bytes_with_direct_slot(&container, "owner", &owner).unwrap();
        let dec_peer = decrypt_bytes_with_direct_slot(&container, "peer_b", &peer_b).unwrap();
        assert_eq!(dec_owner, plaintext);
        assert_eq!(dec_peer, plaintext);

        assert!(decrypt_bytes_with_direct_slot(&container, "peer_b", &intruder).is_err());
    }
}

#[test]
fn vlt_k_of_n_shamir_quorum_unlock_and_tamper_aad_rejection() {
    let owner = make_identity(10);
    let alice = make_identity(11);
    let bob = make_identity(12);
    let charlie = make_identity(13);

    let plaintext = b"Confidential board resolution and vault keys".to_vec();
    let opts = VltOptions {
        cipher: PayloadCipher::ChaCha20Poly1305,
        wrap_method: DirectWrapMethod::Aes256Kw,
        direct_recipients: vec![("owner".into(), owner.x25519_public_bytes())],
        quorum_members: vec![
            ("alice".into(), alice.x25519_public_bytes()),
            ("bob".into(), bob.x25519_public_bytes()),
            ("charlie".into(), charlie.x25519_public_bytes()),
        ],
        quorum_threshold_k: 2,
    };

    let container = encrypt_bytes_to_vlt(&plaintext, &owner, &opts).unwrap();
    let info = inspect_vlt_header(&container).unwrap();
    assert_eq!(info.quorum_threshold_k, 2);
    assert_eq!(info.quorum_total_n, 3);

    // 1 member fails
    assert!(
        decrypt_bytes_with_quorum_slots(&container, &[("alice", &alice)]).is_err()
    );

    // Any 2 of 3 members succeed
    let recovered = decrypt_bytes_with_quorum_slots(
        &container,
        &[("bob", &bob), ("charlie", &charlie)],
    )
    .expect("2-of-3 quorum unlock");
    assert_eq!(recovered, plaintext);

    // Tampering with ciphertext or header invalidates verification & AAD
    let mut tampered = container.clone();
    let last_idx = tampered.len() - 1;
    tampered[last_idx] ^= 0x01;
    assert!(decrypt_bytes_with_direct_slot(&tampered, "owner", &owner).is_err());
}

#[test]
fn vlt_directory_archive_and_recipient_add_remove() {
    let owner = make_identity(20);
    let friend = make_identity(21);

    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("docs");
    std::fs::create_dir_all(src_dir.join("nested")).unwrap();
    std::fs::write(src_dir.join("readme.txt"), b"hello lavault").unwrap();
    std::fs::write(src_dir.join("nested/secret.bin"), &[7u8; 4096]).unwrap();

    let vlt_path = dir.path().join("docs.vlt");
    let opts = VltOptions {
        cipher: PayloadCipher::ChaCha20Poly1305,
        wrap_method: DirectWrapMethod::Aes256Kw,
        direct_recipients: vec![("owner".into(), owner.x25519_public_bytes())],
        quorum_members: vec![],
        quorum_threshold_k: 0,
    };
    encrypt_directory_to_vlt(&src_dir, &vlt_path, &owner, &opts).expect("encrypt dir");

    let mut vlt_bytes = std::fs::read(&vlt_path).unwrap();
    assert!(decrypt_bytes_with_direct_slot(&vlt_bytes, "friend", &friend).is_err());

    // Add friend recipient using owner unlock
    vlt_bytes = add_direct_recipient_to_vlt(
        &vlt_bytes,
        "owner",
        &owner,
        "friend",
        friend.x25519_public_bytes(),
    )
    .expect("add recipient");
    std::fs::write(&vlt_path, &vlt_bytes).unwrap();

    let out_dir = dir.path().join("restored");
    decrypt_directory_from_vlt(&vlt_path, &out_dir, "friend", &friend).expect("friend decrypt dir");
    assert_eq!(
        std::fs::read(out_dir.join("readme.txt")).unwrap(),
        b"hello lavault"
    );
    assert_eq!(
        std::fs::read(out_dir.join("nested/secret.bin")).unwrap(),
        vec![7u8; 4096]
    );

    // Remove friend recipient
    let updated = remove_direct_recipient_from_vlt(&vlt_bytes, &owner, "friend").unwrap();
    assert!(decrypt_bytes_with_direct_slot(&updated, "friend", &friend).is_err());
    assert!(decrypt_bytes_with_direct_slot(&updated, "owner", &owner).is_ok());
}
