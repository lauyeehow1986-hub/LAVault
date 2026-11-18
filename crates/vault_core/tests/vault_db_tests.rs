use tempfile::tempdir;
use vault_core::identity::{DerivedIdentityKeys, KeyEncryptionKey, MasterIdentitySeed};
use vault_core::otp::OtpAlgorithm;
use vault_core::vault_db::{NewVaultEntry, PasswordTotpVault};

#[test]
fn vault_db_crud_search_live_totp_and_wrong_key_rejection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("lavault.db");

    let seed = MasterIdentitySeed::from_bytes([0x33; 32]);
    let keys = DerivedIdentityKeys::from_seed(&seed).unwrap();
    let db_key = keys.vault_db_key();
    let wrong_key = KeyEncryptionKey::from_bytes([0x99; 32]);

    {
        let mut vault = PasswordTotpVault::open_or_create(&db_path, db_key).expect("create vault");
        let id1 = vault
            .add_entry(NewVaultEntry {
                title: "GitHub Work".into(),
                username: "alice@example.com".into(),
                password: "S3cur3-GitHub-Password!".into(),
                totp_secret_base32: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
                totp_algorithm: OtpAlgorithm::Sha1,
                totp_digits: 8,
                totp_period_secs: 30,
                url: Some("https://github.com".into()),
                notes: Some("2FA enabled".into()),
            })
            .expect("add entry 1");

        vault
            .add_entry(NewVaultEntry {
                title: "AWS Console".into(),
                username: "root-admin".into(),
                password: "Aws-Root-Password-999".into(),
                totp_secret_base32: None,
                totp_algorithm: OtpAlgorithm::Sha1,
                totp_digits: 6,
                totp_period_secs: 30,
                url: None,
                notes: None,
            })
            .expect("add entry 2");

        let unlocked = vault
            .unlock_entry_at(&id1, 59)
            .expect("unlock entry with live TOTP");
        assert_eq!(unlocked.password.as_str(), "S3cur3-GitHub-Password!");
        assert_eq!(unlocked.totp_code.as_deref(), Some("94287082"));
        assert_eq!(unlocked.totp_remaining_secs, Some(1));

        let matches = vault.search("github").expect("search");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].title, "GitHub Work");
    }

    // Wrong key must fail authentication
    assert!(PasswordTotpVault::open_or_create(&db_path, &wrong_key).is_err());

    // Reopen with correct key and verify persistence, KDBX-compatible export, and delete
    let mut reopened = PasswordTotpVault::open_or_create(&db_path, db_key).expect("reopen");
    let all = reopened.list_summaries().unwrap();
    assert_eq!(all.len(), 2);

    let kdbx_doc = reopened.export_kdbx_compatible().expect("kdbx export");
    assert_eq!(kdbx_doc.format_version, "KDBX-4.1-COMPAT");
    assert_eq!(kdbx_doc.entries.len(), 2);

    reopened.delete_entry(&all[0].id).unwrap();
    assert_eq!(reopened.list_summaries().unwrap().len(), 1);
}
