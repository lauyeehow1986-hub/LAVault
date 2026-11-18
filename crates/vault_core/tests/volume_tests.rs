use tempfile::tempdir;
use vault_core::volume::{
    OverlayEncryptedVolume, XtsBlockContainer, XtsVolumeKey, OVERLAY_BLOCK_SIZE,
};
use zeroize::Zeroize;

#[test]
fn xts_aes_256_rejects_identical_subkeys_per_nist_sp800_38e() {
    let mut bad = [0x42u8; 64];
    assert!(XtsVolumeKey::from_bytes(&bad).is_err());
    bad.zeroize();

    let key = XtsVolumeKey::derive_from_seed(b"master-volume-seed", b"xts-salt")
        .expect("derive valid 512-bit XTS key");
    assert_ne!(&key.as_bytes()[..32], &key.as_bytes()[32..]);
}

#[test]
fn xts_sector_container_read_write_roundtrip() {
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("secure_disk.xts");
    let key = XtsVolumeKey::derive_from_seed(b"volume-seed-001", b"salt-001").unwrap();

    let mut container =
        XtsBlockContainer::create_or_open(&img_path, key, 16, 4096).expect("create XTS volume");
    let sector0 = vec![0xABu8; 4096];
    let sector5 = (0..4096).map(|i| (i % 256) as u8).collect::<Vec<_>>();

    container.write_sector(0, &sector0).unwrap();
    container.write_sector(5, &sector5).unwrap();

    let read0 = container.read_sector(0).unwrap();
    let read5 = container.read_sector(5).unwrap();
    assert_eq!(read0, sector0);
    assert_eq!(read5, sector5);

    // Raw ciphertext on disk must differ from plaintext
    let raw_disk = std::fs::read(&img_path).unwrap();
    assert_ne!(&raw_disk[..4096], sector0.as_slice());

    container.lock_and_zeroize();
    assert!(container.read_sector(0).is_err());
}

#[test]
fn overlay_volume_32kb_blocks_and_aes_siv_filenames_with_lock_on_disconnect() {
    let dir = tempdir().unwrap();
    let backing_dir = dir.path().join("vault_backing");
    let mut master_key = [0x77u8; 32];

    let mut vol =
        OverlayEncryptedVolume::mount(&backing_dir, &master_key).expect("mount overlay volume");
    master_key.zeroize();

    // Multi-block payload (> 2 x 32 KB blocks)
    let payload: Vec<u8> = (0..(OVERLAY_BLOCK_SIZE * 2 + 1234))
        .map(|i| (i % 251) as u8)
        .collect();
    vol.write_file("payroll_2026.csv", &payload)
        .expect("write encrypted file");
    vol.write_file("notes.txt", b"zero cloud secrets")
        .expect("write second file");

    // Backing filenames on disk are encrypted via AES-SIV (plaintext names never appear)
    let disk_names: Vec<String> = std::fs::read_dir(&backing_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(!disk_names.iter().any(|n| n.contains("payroll")));
    assert!(!disk_names.iter().any(|n| n.contains("notes")));

    let list = vol.list_files().unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.contains(&"payroll_2026.csv".to_string()));
    assert!(list.contains(&"notes.txt".to_string()));

    let read_back = vol.read_file("payroll_2026.csv").unwrap();
    assert_eq!(read_back, payload);

    vol.rename_file("notes.txt", "notes_archived.txt").unwrap();
    assert_eq!(
        vol.read_file("notes_archived.txt").unwrap(),
        b"zero cloud secrets"
    );

    vol.delete_file("notes_archived.txt").unwrap();
    assert_eq!(vol.list_files().unwrap(), vec!["payroll_2026.csv".to_string()]);

    // Immediate unmount + RAM zeroize on phone disconnect
    vol.unmount_and_zeroize();
    assert!(!vol.is_mounted());
    assert!(vol.read_file("payroll_2026.csv").is_err());
}
