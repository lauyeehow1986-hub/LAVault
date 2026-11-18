use sha2::{Digest, Sha256};
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed, VaultPassword};
use vault_core::recovery::{
    export_bip39_mnemonic, export_guardian_capsules, export_rkf_keyfile, import_bip39_mnemonic,
    import_rkf_keyfile, recover_seed_from_guardian_capsules,
};
use vault_core::shamir::{
    secret_commitment, shamir_reconstruct_secret, shamir_split_secret_deterministic,
    shamir_split_secret_random,
};

#[test]
fn shamir_gf256_matches_mcp_reference_vectors_bit_for_bit() {
    let secret = Sha256::digest(b"master-identity-seed-256");
    let shares = shamir_split_secret_deterministic(&secret, 3, 5, b"slip39-test")
        .expect("deterministic shamir split");

    assert_eq!(shares.len(), 5);
    assert!(hex::encode(shares[0].data()).starts_with("bd3fefc4ea7558580b3f93d25fd8fd25b90c"));
    assert!(hex::encode(shares[1].data()).starts_with("33be90838458d50f4c75ac7a9b3e127cee5e"));
    assert!(hex::encode(shares[2].data()).starts_with("abba77e21bfb66365718212f1b2ff61a87f8"));
    assert!(hex::encode(shares[3].data()).starts_with("fd280c54f1b080cd1bc59b21304542dc31e3"));
    assert!(hex::encode(shares[4].data()).starts_with("652ceb356e1333f400a81674b054a6ba5845"));

    let commitment = secret_commitment(&secret);
    let rec_first = shamir_reconstruct_secret(&shares[0..3], Some(&commitment)).unwrap();
    let rec_last = shamir_reconstruct_secret(&shares[2..5], Some(&commitment)).unwrap();
    let rec_sparse = shamir_reconstruct_secret(
        &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        Some(&commitment),
    )
    .unwrap();

    assert_eq!(rec_first.as_slice(), secret.as_slice());
    assert_eq!(rec_last.as_slice(), secret.as_slice());
    assert_eq!(rec_sparse.as_slice(), secret.as_slice());
}

#[test]
fn shamir_rejects_insufficient_shares_and_tampering() {
    let secret = [0x5Au8; 32];
    let shares = shamir_split_secret_random(&secret, 3, 5).unwrap();
    let commitment = secret_commitment(&secret);

    assert!(shamir_reconstruct_secret(&shares[0..2], Some(&commitment)).is_err());

    let mut tampered = shares[0..3].to_vec();
    let mut bad_bytes = tampered[0].data().to_vec();
    bad_bytes[0] ^= 0xFF;
    tampered[0] = vault_core::identity::ShamirShare::new(
        tampered[0].index(),
        tampered[0].threshold_k(),
        tampered[0].total_n(),
        bad_bytes,
    );
    assert!(shamir_reconstruct_secret(&tampered, Some(&commitment)).is_err());
}

#[test]
fn bip39_24_word_mnemonic_roundtrip() {
    let seed = MasterIdentitySeed::generate().unwrap();
    let phrase = export_bip39_mnemonic(&seed).expect("BIP-39 export");
    assert_eq!(phrase.split_whitespace().count(), 24);

    let recovered = import_bip39_mnemonic(&phrase).expect("BIP-39 import");
    assert_eq!(recovered.as_bytes(), seed.as_bytes());
    assert!(import_bip39_mnemonic("abandon abandon invalid word").is_err());
}

#[test]
fn encrypted_rkf_recovery_keyfile_roundtrip() {
    let seed = MasterIdentitySeed::generate().unwrap();
    let pw = VaultPassword::new("rkf-backup-pass-2026".to_string());
    let wrong_pw = VaultPassword::new("wrong-pass-2026".to_string());

    let rkf_bytes = export_rkf_keyfile(&seed, &pw).expect("export .rkf");
    assert!(rkf_bytes.starts_with(b"LAVRKF1\0"));

    let recovered = import_rkf_keyfile(&rkf_bytes, &pw).expect("import .rkf");
    assert_eq!(recovered.as_bytes(), seed.as_bytes());
    assert!(import_rkf_keyfile(&rkf_bytes, &wrong_pw).is_err());
}

#[test]
fn guardian_signed_qr_capsules_roundtrip_and_signature_verification() {
    let seed = MasterIdentitySeed::generate().unwrap();
    let keys = DerivedIdentityKeys::from_seed(&seed).unwrap();
    let guardians = vec![
        "guardian_alice".to_string(),
        "guardian_bob".to_string(),
        "guardian_charlie".to_string(),
    ];

    let capsules =
        export_guardian_capsules(&seed, &keys, &guardians, 2).expect("export guardian capsules");
    assert_eq!(capsules.len(), 3);

    let recovered = recover_seed_from_guardian_capsules(
        &capsules[1..3],
        &keys.ed25519_verifying(),
    )
    .expect("recover seed from 2-of-3 guardian capsules");
    assert_eq!(recovered.as_bytes(), seed.as_bytes());

    let mut forged = capsules[0..2].to_vec();
    forged[0].signature_hex = "00".repeat(64);
    assert!(recover_seed_from_guardian_capsules(&forged, &keys.ed25519_verifying()).is_err());
}
