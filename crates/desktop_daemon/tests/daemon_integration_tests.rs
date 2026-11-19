use tempfile::tempdir;
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed};
use vault_core::transport::generate_pinned_ed25519_tls_identity;

use desktop_daemon::cli::{execute_cli_command, Cli, Commands, RecipientsAction};
use desktop_daemon::mount::{MountSessionConfig, VirtualDriveManager};
use desktop_daemon::wifi::{run_pinned_tls13_unlock_roundtrip, PinnedTlsPeer};

fn make_keys(tag: u8) -> DerivedIdentityKeys {
    let seed = MasterIdentitySeed::from_bytes([tag; 32]);
    DerivedIdentityKeys::from_seed(&seed).unwrap()
}

#[test]
fn cli_lock_unlock_and_recipient_management_1_of_n_and_2_of_3_quorum() {
    let dir = tempdir().unwrap();
    let owner = make_keys(1);
    let peer = make_keys(2);

    let owner_seed_hex = hex::encode([1u8; 32]);
    let peer_pk_hex = hex::encode(peer.x25519_public_bytes());

    let src_file = dir.path().join("secret_report.txt");
    let vlt_file = dir.path().join("secret_report.txt.vlt");
    let out_file = dir.path().join("restored_report.txt");
    std::fs::write(&src_file, b"Quarterly confidential audit findings").unwrap();

    // Lock with 1-of-N owner + 2-of-3 quorum
    let g1 = make_keys(11);
    let g2 = make_keys(12);
    let g3 = make_keys(13);

    let lock_cli = Cli {
        command: Commands::Lock {
            path: src_file.clone(),
            output: Some(vlt_file.clone()),
            seed_hex: Some(owner_seed_hex.clone()),
            recipients: vec![],
            quorum_k: 2,
            quorum_members: vec![
                format!("g1:{}", hex::encode(g1.x25519_public_bytes())),
                format!("g2:{}", hex::encode(g2.x25519_public_bytes())),
                format!("g3:{}", hex::encode(g3.x25519_public_bytes())),
            ],
        },
    };
    execute_cli_command(lock_cli).expect("cli lock");
    assert!(vlt_file.exists());

    // Unlock via 2-of-3 quorum (g2 + g3)
    let quorum_out = dir.path().join("quorum_restored.txt");
    execute_cli_command(Cli {
        command: Commands::Unlock {
            file: vlt_file.clone(),
            output: Some(quorum_out.clone()),
            slot: "owner".into(),
            seed_hex: None,
            quorum_seeds: vec![
                format!("g2:{}", hex::encode([12u8; 32])),
                format!("g3:{}", hex::encode([13u8; 32])),
            ],
        },
    })
    .expect("cli 2-of-3 quorum unlock");
    assert_eq!(
        std::fs::read(&quorum_out).unwrap(),
        b"Quarterly confidential audit findings"
    );

    // Add peer recipient
    let add_cli = Cli {
        command: Commands::Recipients {
            action: RecipientsAction::Add {
                file: vlt_file.clone(),
                id: "peer_phone".into(),
                pubkey_hex: peer_pk_hex,
                owner_seed_hex: owner_seed_hex.clone(),
                authorizer_id: "owner".into(),
            },
        },
    };
    execute_cli_command(add_cli).expect("cli recipients add");

    // Unlock as peer
    let peer_seed_hex = hex::encode([2u8; 32]);
    let unlock_cli = Cli {
        command: Commands::Unlock {
            file: vlt_file.clone(),
            output: Some(out_file.clone()),
            slot: "peer_phone".into(),
            seed_hex: Some(peer_seed_hex),
            quorum_seeds: vec![],
        },
    };
    execute_cli_command(unlock_cli).expect("cli unlock as peer");
    assert_eq!(
        std::fs::read(&out_file).unwrap(),
        b"Quarterly confidential audit findings"
    );

    // Remove peer recipient -> peer can no longer unlock
    let rm_cli = Cli {
        command: Commands::Recipients {
            action: RecipientsAction::Remove {
                file: vlt_file.clone(),
                id: "peer_phone".into(),
                owner_seed_hex: owner_seed_hex.clone(),
            },
        },
    };
    execute_cli_command(rm_cli).expect("cli recipients remove");

    let unlock_removed = Cli {
        command: Commands::Unlock {
            file: vlt_file,
            output: Some(dir.path().join("should_fail.txt")),
            slot: "peer_phone".into(),
            seed_hex: Some(hex::encode([2u8; 32])),
            quorum_seeds: vec![],
        },
    };
    assert!(execute_cli_command(unlock_removed).is_err());
    let _ = owner;
}

#[tokio::test]
async fn wifi_pinned_mutual_tls13_unlock_roundtrip_over_loopback() {
    let phone_keys = make_keys(44);
    let (pc_cert, pc_key) = generate_pinned_ed25519_tls_identity("lavault-pc").unwrap();
    let (phone_cert, phone_key) = generate_pinned_ed25519_tls_identity("lavault-phone").unwrap();

    let vlt = vault_core::vlt::encrypt_bytes_to_vlt(
        b"TLS 1.3 pinned unlock payload",
        &phone_keys,
        &vault_core::vlt::VltOptions {
            cipher: vault_core::vlt::PayloadCipher::ChaCha20Poly1305,
            wrap_method: vault_core::vlt::DirectWrapMethod::Aes256Kw,
            direct_recipients: vec![("phone_main".into(), phone_keys.x25519_public_bytes())],
            quorum_members: vec![],
            quorum_threshold_k: 0,
        },
    )
    .unwrap();

    let pc_peer = PinnedTlsPeer {
        cert_der: pc_cert.clone(),
        key_der: pc_key,
        expected_remote_cert_der: phone_cert.clone(),
    };
    let phone_peer = PinnedTlsPeer {
        cert_der: phone_cert,
        key_der: phone_key,
        expected_remote_cert_der: pc_cert,
    };

    let dek = run_pinned_tls13_unlock_roundtrip(
        &vlt,
        "phone_main",
        "Test-PC",
        pc_peer,
        phone_peer,
        &phone_keys,
    )
    .await
    .expect("mutual pinned TLS 1.3 unlock");
    assert_ne!(dek.as_bytes(), &[0u8; 32]);
}

#[test]
fn virtual_drive_manager_mount_and_disconnect_zeroize() {
    let dir = tempdir().unwrap();
    let backing = dir.path().join("encrypted_vol");
    let mount_point = dir.path().join("mount_pt");

    let mut mgr = VirtualDriveManager::new(MountSessionConfig {
        vault_dir: backing,
        mount_point,
        proximity_timeout_secs: 60,
    });

    mgr.mount_with_key(&[0x55u8; 32]).expect("mount volume");
    assert!(mgr.is_mounted());
    mgr.write_virtual_file("secret.txt", b"mounted drive data")
        .unwrap();
    assert_eq!(
        mgr.read_virtual_file("secret.txt").unwrap(),
        b"mounted drive data"
    );

    mgr.on_phone_disconnect();
    assert!(!mgr.is_mounted());
    assert!(mgr.read_virtual_file("secret.txt").is_err());
}

#[test]
fn stress_cli_command_runs_benchmark_and_generates_qr_html() {
    let dir = tempdir().unwrap();
    let qr_html = dir.path().join("stress_qr.html");
    execute_cli_command(Cli {
        command: Commands::Stress {
            rounds: 15,
            totp_iterations: 500,
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            digits: 6,
            live_totp_secs: 0,
            qr_html_out: Some(qr_html.clone()),
        },
    })
    .expect("lavault stress command should succeed");

    let html = std::fs::read_to_string(&qr_html).expect("stress html file created");
    assert!(html.contains("<svg"), "HTML report should embed scannable SVG QR");
    assert!(
        html.contains("JBSWY3DPEHPK3PXP"),
        "HTML report should display the Base32 TOTP secret"
    );
}

#[test]
fn phone_test_qr_challenge_fulfill_and_decrypt_end_to_end() {
    let dir = tempdir().unwrap();
    let phone_keys = make_keys(77);
    let pc_owner_keys = make_keys(1);

    let phone_x25519_hex = hex::encode(phone_keys.x25519_public_bytes());
    let phone_ed25519_hex = hex::encode(phone_keys.ed25519_verifying().to_bytes());
    let qr_html = dir.path().join("phone_test_qr.html");
    let vlt_out = dir.path().join("phone_test.txt.vlt");

    let session = desktop_daemon::qr::prepare_phone_test_session(
        &phone_x25519_hex,
        Some(&phone_ed25519_hex),
        Some(&pc_owner_keys),
        b"LaVault phone stress payload #1",
        &vlt_out,
        &qr_html,
    )
    .expect("prepare phone test session");

    // Also test X25519-only mode (no Ed25519 key copied from phone UI)
    let session_x_only = desktop_daemon::qr::prepare_phone_test_session(
        &phone_x25519_hex,
        None,
        Some(&pc_owner_keys),
        b"LaVault X25519-only payload",
        &dir.path().join("xonly.vlt"),
        &dir.path().join("xonly.html"),
    )
    .expect("prepare phone x25519-only session");
    let x_challenge =
        vault_core::transport::UnlockChallenge::from_bcur(&session_x_only.ur_request).unwrap();
    let x_response =
        vault_core::transport::fulfill_unlock_challenge(&x_challenge, "phone", &phone_keys)
            .unwrap();
    let x_decrypted = session_x_only
        .complete_with_ur_response(&x_response.to_bcur().unwrap())
        .expect("complete X25519-only phone decryption");
    assert_eq!(x_decrypted, b"LaVault X25519-only payload");

    assert!(vlt_out.exists());
    let html = std::fs::read_to_string(&qr_html).unwrap();
    assert!(html.contains("<svg"));
    assert!(html.contains("ur:lavault-req/"));
    assert!(session.ur_request.starts_with("ur:lavault-req/"));

    let terminal_qr = desktop_daemon::qr::render_terminal_qr(&session.ur_request).unwrap();
    assert!(terminal_qr.lines().count() > 10);

    // Simulate the phone scanning `ur:lavault-req/...`, unlocking, and displaying `ur:lavault-res/...`
    let challenge = vault_core::transport::UnlockChallenge::from_bcur(&session.ur_request).unwrap();
    let response =
        vault_core::transport::fulfill_unlock_challenge(&challenge, "phone", &phone_keys).unwrap();
    let ur_response = response.to_bcur().unwrap();

    let decrypted = session
        .complete_with_ur_response(&ur_response)
        .expect("complete phone test decryption");
    assert_eq!(decrypted, b"LaVault phone stress payload #1");
}
