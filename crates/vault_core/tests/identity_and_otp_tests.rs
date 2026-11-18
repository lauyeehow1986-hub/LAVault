use vault_core::identity::{
    combine_hardware_and_password_key, hkdf_sha256, stretch_master_password, DataEncryptionKey,
    DerivedIdentityKeys, KeyEncryptionKey, MasterIdentitySeed, ShamirShare, TotpSecret,
    VaultPassword, INFO_ED25519_SIG, INFO_VAULT_DB_KEY, INFO_X25519_KEK,
};
use vault_core::otp::{hotp_rfc4226, totp_from_base32, totp_rfc6238, OtpAlgorithm};
use zeroize::Zeroize;

#[test]
fn secret_structs_zeroize_explicitly() {
    let mut seed = MasterIdentitySeed::from_bytes([0xAA; 32]);
    assert_eq!(seed.as_bytes(), &[0xAA; 32]);
    seed.zeroize();
    assert_eq!(seed.as_bytes(), &[0u8; 32]);

    let mut dek = DataEncryptionKey::from_bytes([0xBB; 32]);
    dek.zeroize();
    assert_eq!(dek.as_bytes(), &[0u8; 32]);

    let mut kek = KeyEncryptionKey::from_bytes([0xCC; 32]);
    kek.zeroize();
    assert_eq!(kek.as_bytes(), &[0u8; 32]);

    let mut share = ShamirShare::new(1, 2, 3, vec![0xDD; 32]);
    share.zeroize();
    assert!(share.data().iter().all(|&b| b == 0));

    let mut totp = TotpSecret::from_bytes(b"12345678901234567890".to_vec());
    totp.zeroize();
    assert!(totp.as_bytes().iter().all(|&b| b == 0));

    let mut pw = VaultPassword::new("correct-horse-battery-staple".to_string());
    pw.zeroize();
    assert!(pw.as_str().is_empty());
}

#[test]
fn generate_master_seed_is_random_and_non_zero() {
    let s1 = MasterIdentitySeed::generate().expect("CSPRNG seed generation");
    let s2 = MasterIdentitySeed::generate().expect("CSPRNG seed generation");
    assert_ne!(s1.as_bytes(), &[0u8; 32]);
    assert_ne!(s1.as_bytes(), s2.as_bytes());
}

#[test]
fn hkdf_rfc5869_test_case_1_matches_mcp_reference() {
    let ikm = [0x0Bu8; 22];
    let salt: Vec<u8> = (0x00u8..0x0D).collect();
    let info: Vec<u8> = (0xF0u8..0xFA).collect();
    let okm = hkdf_sha256(&ikm, &salt, &info, 42).expect("HKDF expand");
    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn identity_subkey_derivation_is_deterministic_and_domain_separated() {
    assert_eq!(INFO_X25519_KEK, b"local-auth-vault/v1/x25519-kek");
    assert_eq!(INFO_ED25519_SIG, b"local-auth-vault/v1/ed25519-sig");
    assert_eq!(INFO_VAULT_DB_KEY, b"local-auth-vault/v1/vault-db-key");

    let seed = MasterIdentitySeed::from_bytes([0x42; 32]);
    let keys_a = DerivedIdentityKeys::from_seed(&seed).expect("derive keys");
    let keys_b = DerivedIdentityKeys::from_seed(&seed).expect("derive keys");

    assert_eq!(keys_a.x25519_public_bytes(), keys_b.x25519_public_bytes());
    assert_eq!(keys_a.ed25519_public_bytes(), keys_b.ed25519_public_bytes());
    assert_eq!(keys_a.vault_db_key().as_bytes(), keys_b.vault_db_key().as_bytes());
    assert_ne!(
        &keys_a.x25519_public_bytes(),
        keys_a.vault_db_key().as_bytes()
    );
}

#[test]
fn argon2id_and_hardware_key_combination() {
    let pw = VaultPassword::new("LaVault-Test-Passphrase-2026!".to_string());
    let salt = [0x11u8; 16];
    let stretched = stretch_master_password(&pw, &salt).expect("Argon2id stretch");
    let hw_secret = [0x99u8; 32];
    let combined_a =
        combine_hardware_and_password_key(&stretched, &hw_secret).expect("HKDF combine");
    let combined_b =
        combine_hardware_and_password_key(&stretched, &hw_secret).expect("HKDF combine");
    let combined_diff =
        combine_hardware_and_password_key(&stretched, &[0x98u8; 32]).expect("HKDF combine");
    assert_eq!(combined_a.as_bytes(), combined_b.as_bytes());
    assert_ne!(combined_a.as_bytes(), combined_diff.as_bytes());
}

#[test]
fn hotp_rfc4226_appendix_d_vectors() {
    let secret = b"12345678901234567890";
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, exp) in expected.iter().enumerate() {
        let code = hotp_rfc4226(secret, counter as u64, 6, OtpAlgorithm::Sha1).expect("HOTP");
        assert_eq!(code, *exp);
    }
}

#[test]
fn totp_rfc6238_official_vectors() {
    let s1 = b"12345678901234567890";
    let s256 = b"12345678901234567890123456789012";
    let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";

    assert_eq!(
        totp_rfc6238(s1, 59, 30, 0, 8, OtpAlgorithm::Sha1).unwrap(),
        "94287082"
    );
    assert_eq!(
        totp_rfc6238(s256, 59, 30, 0, 8, OtpAlgorithm::Sha256).unwrap(),
        "46119246"
    );
    assert_eq!(
        totp_rfc6238(s512, 59, 30, 0, 8, OtpAlgorithm::Sha512).unwrap(),
        "90693936"
    );

    assert_eq!(
        totp_rfc6238(s1, 1111111109, 30, 0, 8, OtpAlgorithm::Sha1).unwrap(),
        "07081804"
    );
    assert_eq!(
        totp_rfc6238(s256, 1111111109, 30, 0, 8, OtpAlgorithm::Sha256).unwrap(),
        "68084774"
    );
    assert_eq!(
        totp_rfc6238(s512, 1111111109, 30, 0, 8, OtpAlgorithm::Sha512).unwrap(),
        "25091201"
    );
}

#[test]
fn totp_base32_and_remaining_seconds() {
    // Base32 of "12345678901234567890" is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    let (code, remaining) =
        totp_from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, 30, 8, OtpAlgorithm::Sha1)
            .expect("Base32 TOTP");
    assert_eq!(code, "94287082");
    assert_eq!(remaining, 1); // 59 % 30 == 29 -> 1 second left
}
