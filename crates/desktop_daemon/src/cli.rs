use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed, VaultPassword};
use vault_core::otp::{totp_from_base32, OtpAlgorithm};
use vault_core::recovery::{import_bip39_mnemonic, import_rkf_keyfile};
use vault_core::shamir::{parse_slip39_uri, shamir_reconstruct_secret};
use vault_core::transport::{
    build_unlock_challenge_for_vlt, decode_bcur_multipart, encode_8word_verifier,
    encode_bcur_multipart, fulfill_unlock_challenge, verify_and_extract_unlock_dek,
    verify_and_extract_unlock_dek_optional_vk, UnlockChallenge, UnlockResponse,
};
use vault_core::vlt::{
    add_direct_recipient_to_vlt, decrypt_bytes_with_dek, decrypt_bytes_with_direct_slot,
    decrypt_bytes_with_quorum_slots, decrypt_directory_from_vlt,
    decrypt_directory_from_vlt_with_dek, encrypt_bytes_to_vlt, encrypt_directory_to_vlt,
    remove_direct_recipient_from_vlt, DirectWrapMethod, PayloadCipher, VltOptions,
};

use crate::mount::{MountSessionConfig, VirtualDriveManager};
use crate::qr::{
    prepare_phone_test_session, run_qr_challenge_prompt, save_stress_qr_html,
    write_unlock_qr_html,
};
use crate::wifi::run_lan_unlock_blocking;

#[derive(Debug, Parser)]
#[command(name = "lavault", about = "LaVault Zero-Cloud File & Virtual Volume Unlocker")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Encrypt a file or directory into a multi-user `.vlt` container
    Lock {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        seed_hex: Option<String>,
        /// Additional 1-of-N direct recipients formatted as `id:x25519_hex`
        #[arg(short, long)]
        recipients: Vec<String>,
        /// K-of-N Shamir threshold (0 to disable quorum slot)
        #[arg(long, default_value_t = 0)]
        quorum_k: u8,
        /// Quorum members formatted as `id:x25519_hex`
        #[arg(long)]
        quorum_members: Vec<String>,
    },
    /// Unlock and decrypt a `.vlt` file or directory
    Unlock {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "owner")]
        slot: String,
        #[arg(long)]
        seed_hex: Option<String>,
        /// Quorum member seeds formatted as `member_id:seed_hex`
        #[arg(long)]
        quorum_seeds: Vec<String>,
        /// Listen on local Wi-Fi LAN for 1-tap phone approval (no copy-paste)
        #[arg(long, default_value_t = false)]
        wifi: bool,
        /// TCP port for `--wifi` unlock listener
        #[arg(long, default_value_t = 53319)]
        port: u16,
        /// Treat encrypted `.vlt` payload as a compressed folder archive
        #[arg(long, default_value_t = false)]
        dir: bool,
        /// Write scannable HTML QR unlock page to this path (default: unlock_qr.html)
        #[arg(long)]
        qr_html: Option<PathBuf>,
        /// Supply `ur:lavault-res/...` directly without interactive stdin prompt
        #[arg(long)]
        qr_res: Option<String>,
    },
    /// Mount an encrypted virtual volume directory (locks key in RAM and wipes on disconnect)
    Mount {
        vault_dir: PathBuf,
        mount_point: PathBuf,
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
        #[arg(long)]
        master_key_hex: Option<String>,
    },
    /// Manage authorized 1-of-N recipients on a `.vlt` file
    Recipients {
        #[command(subcommand)]
        action: RecipientsAction,
    },
    /// Start SPAKE2 + mDNS device pairing with the mobile authenticator
    Pair {
        #[arg(long)]
        pin: String,
        #[arg(long, default_value = "LaVault-Desktop")]
        device_name: String,
    },
    /// Run offline + live wall-clock TOTP and .vlt Unlocker stress benchmarks
    Stress {
        #[arg(long, default_value_t = 50)]
        rounds: usize,
        #[arg(long, default_value_t = 10_000)]
        totp_iterations: usize,
        #[arg(long)]
        totp_secret: Option<String>,
        #[arg(long, default_value_t = 6)]
        digits: u32,
        #[arg(long, default_value_t = 0)]
        live_totp_secs: u64,
        #[arg(long)]
        qr_html_out: Option<PathBuf>,
    },
    /// End-to-end Phone <-> PC Unlocker test generating QR (.html + terminal) and decrypting from phone response
    PhoneTest {
        #[arg(long)]
        phone_x25519: String,
        #[arg(long)]
        phone_ed25519: Option<String>,
        #[arg(long, default_value = "LaVault phone stress test secret!")]
        payload: String,
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        iterations: usize,
        #[arg(long)]
        batch_res: Vec<String>,
        #[arg(long, default_value_t = false)]
        no_wait: bool,
    },
    /// Verify Triple Recovery backups (24-word BIP-39, .rkf hex/pass, or K-of-N guardian share URIs)
    VerifyRecovery {
        #[arg(long)]
        bip39: Option<String>,
        #[arg(long)]
        rkf_hex: Option<String>,
        #[arg(long)]
        rkf_pass: Option<String>,
        #[arg(long, num_args = 1..)]
        shares: Vec<String>,
        #[arg(long)]
        expected_x25519: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum RecipientsAction {
    Add {
        file: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        pubkey_hex: String,
        #[arg(long)]
        owner_seed_hex: String,
        #[arg(long, default_value = "owner")]
        authorizer_id: String,
    },
    Remove {
        file: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        owner_seed_hex: String,
    },
}

fn keys_from_seed_hex(seed_hex: Option<String>) -> Result<DerivedIdentityKeys> {
    let seed = if let Some(hex_str) = seed_hex {
        let raw = hex::decode(hex_str.trim())?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("seed_hex must be 32 bytes (64 hex chars)"))?;
        MasterIdentitySeed::from_bytes(arr)
    } else {
        MasterIdentitySeed::generate()?
    };
    Ok(DerivedIdentityKeys::from_seed(&seed)?)
}

fn parse_recipient_arg(s: &str) -> Result<(String, [u8; 32])> {
    let (id, hex_pk) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("recipient must be formatted as id:hex_pubkey"))?;
    let raw = hex::decode(hex_pk.trim())?;
    let pk: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("X25519 public key must be 32 bytes"))?;
    Ok((id.to_string(), pk))
}

pub fn execute_cli_command(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Lock {
            path,
            output,
            seed_hex,
            recipients,
            quorum_k,
            quorum_members,
        } => {
            let owner = keys_from_seed_hex(seed_hex)?;
            let mut direct_recipients = vec![("owner".to_string(), owner.x25519_public_bytes())];
            for r in recipients {
                direct_recipients.push(parse_recipient_arg(&r)?);
            }
            let mut q_members = Vec::new();
            for q in quorum_members {
                q_members.push(parse_recipient_arg(&q)?);
            }
            let opts = VltOptions {
                cipher: PayloadCipher::ChaCha20Poly1305,
                wrap_method: DirectWrapMethod::Aes256Kw,
                direct_recipients,
                quorum_members: q_members,
                quorum_threshold_k: quorum_k,
            };

            let out_path = output.unwrap_or_else(|| {
                let mut p = path.as_os_str().to_os_string();
                p.push(".vlt");
                PathBuf::from(p)
            });

            if path.is_dir() {
                encrypt_directory_to_vlt(&path, &out_path, &owner, &opts)?;
            } else {
                let data = std::fs::read(&path)?;
                let vlt_bytes = encrypt_bytes_to_vlt(&data, &owner, &opts)?;
                std::fs::write(&out_path, vlt_bytes)?;
            }
            println!("Locked -> {}", out_path.display());
        }
        Commands::Unlock {
            file,
            output,
            slot,
            seed_hex,
            quorum_seeds,
            wifi,
            port,
            dir,
            qr_html,
            qr_res,
        } => {
            let raw = std::fs::read(&file)?;
            let is_dir_vlt = dir || file.to_string_lossy().ends_with(".dir.vlt");
            if !quorum_seeds.is_empty() {
                let mut member_keys = Vec::with_capacity(quorum_seeds.len());
                for item in quorum_seeds {
                    let (id, sh) = item
                        .split_once(':')
                        .ok_or_else(|| anyhow!("quorum_seeds entry must be id:seed_hex"))?;
                    let keys = keys_from_seed_hex(Some(sh.to_string()))?;
                    member_keys.push((id.to_string(), keys));
                }
                let refs: Vec<(&str, &DerivedIdentityKeys)> = member_keys
                    .iter()
                    .map(|(id, k)| (id.as_str(), k))
                    .collect();
                let pt = decrypt_bytes_with_quorum_slots(&raw, &refs)?;
                let out_path = output.unwrap_or_else(|| file.with_extension("unlocked"));
                std::fs::write(&out_path, pt)?;
                println!("Unlocked (quorum) -> {}", out_path.display());
            } else if let Some(sh) = seed_hex {
                let keys = keys_from_seed_hex(Some(sh))?;
                let out_path = output.unwrap_or_else(|| file.with_extension("unlocked"));
                if is_dir_vlt && out_path.extension().is_none() {
                    decrypt_directory_from_vlt(&file, &out_path, &slot, &keys)?;
                } else {
                    let pt = decrypt_bytes_with_direct_slot(&raw, &slot, &keys)?;
                    std::fs::write(&out_path, pt)?;
                }
                println!("Unlocked -> {}", out_path.display());
            } else {
                let target_label = file
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| file.display().to_string());
                let (challenge, ephem) =
                    build_unlock_challenge_for_vlt(&raw, &slot, "LaVault-PC")?;
                let out_path = output.unwrap_or_else(|| {
                    if is_dir_vlt {
                        file.with_extension("unlocked_dir")
                    } else {
                        file.with_extension("unlocked")
                    }
                });
                let html_path = qr_html.unwrap_or_else(|| PathBuf::from("unlock_qr.html"));

                let dek = if wifi {
                    let outcome = run_lan_unlock_blocking(
                        port,
                        challenge,
                        ephem,
                        target_label,
                        &html_path,
                    )?;
                    println!("Phone approval received from responder '{}'.", outcome.responder_id);
                    outcome.dek
                } else {
                    let ur_req = challenge.to_bcur()?;
                    let verifier = encode_8word_verifier(&challenge.challenge_nonce);
                    write_unlock_qr_html(&ur_req, &verifier, &target_label, None, &html_path)?;
                    println!("Saved scannable QR unlock page -> {}", html_path.display());
                    run_qr_challenge_prompt(&challenge, &verifier)?;

                    let res_str = if let Some(r) = qr_res {
                        r
                    } else {
                        loop {
                            print!("\nPaste ur:lavault-res/... from phone (or 'quit' to abort): ");
                            io::stdout().flush()?;
                            let mut line = String::new();
                            if io::stdin().read_line(&mut line)? == 0 {
                                return Err(anyhow!("EOF reached before receiving phone response"));
                            }
                            let trimmed = line.trim();
                            if trimmed.eq_ignore_ascii_case("quit") {
                                return Err(anyhow!("Unlock aborted by user"));
                            }
                            if !trimmed.is_empty() {
                                break trimmed.to_string();
                            }
                        }
                    };
                    let response = UnlockResponse::from_bcur(res_str.trim())?;
                    verify_and_extract_unlock_dek_optional_vk(&response, &ephem, None)?
                };

                if is_dir_vlt {
                    decrypt_directory_from_vlt_with_dek(&file, &out_path, &dek)?;
                    println!("Unlocked directory -> {}", out_path.display());
                } else {
                    let pt = decrypt_bytes_with_dek(&raw, &dek)?;
                    std::fs::write(&out_path, pt)?;
                    println!("Unlocked -> {}", out_path.display());
                }
            }
        }
        Commands::Mount {
            vault_dir,
            mount_point,
            timeout_secs,
            master_key_hex,
        } => {
            let mut mgr = VirtualDriveManager::new(MountSessionConfig {
                vault_dir,
                mount_point,
                proximity_timeout_secs: timeout_secs,
            });
            let key_bytes: [u8; 32] = if let Some(h) = master_key_hex {
                hex::decode(h.trim())?
                    .try_into()
                    .map_err(|_| anyhow!("master_key_hex must be 32 bytes"))?
            } else {
                let mut k = [0u8; 32];
                // Ephemeral session key if no key supplied
                k.copy_from_slice(
                    keys_from_seed_hex(None)?
                        .vault_db_key()
                        .as_bytes(),
                );
                k
            };
            mgr.mount_with_key(&key_bytes)?;
            println!(
                "Mounted encrypted volume (backend: {}).",
                mgr.backend_name()
            );
        }
        Commands::Recipients { action } => match action {
            RecipientsAction::Add {
                file,
                id,
                pubkey_hex,
                owner_seed_hex,
                authorizer_id,
            } => {
                let owner = keys_from_seed_hex(Some(owner_seed_hex))?;
                let pk: [u8; 32] = hex::decode(pubkey_hex.trim())?
                    .try_into()
                    .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;
                let raw = std::fs::read(&file)?;
                let updated =
                    add_direct_recipient_to_vlt(&raw, &authorizer_id, &owner, &id, pk)?;
                std::fs::write(&file, updated)?;
                println!("Added recipient '{id}' to {}", file.display());
            }
            RecipientsAction::Remove {
                file,
                id,
                owner_seed_hex,
            } => {
                let owner = keys_from_seed_hex(Some(owner_seed_hex))?;
                let raw = std::fs::read(&file)?;
                let updated = remove_direct_recipient_from_vlt(&raw, &owner, &id)?;
                std::fs::write(&file, updated)?;
                println!("Removed recipient '{id}' and rotated DEK on {}", file.display());
            }
        },
        Commands::Pair { pin, device_name } => {
            println!(
                "Starting SPAKE2 pairing for '{device_name}' with PIN length {} over {} port {}",
                pin.len(),
                vault_core::transport::MDNS_SERVICE_TYPE,
                vault_core::transport::MDNS_TCP_PORT
            );
        }
        Commands::Stress {
            rounds,
            totp_iterations,
            totp_secret,
            digits,
            live_totp_secs,
            qr_html_out,
        } => {
            let secret = totp_secret.unwrap_or_else(|| "JBSWY3DPEHPK3PXP".to_string());
            let totp_start = Instant::now();
            let algs = [OtpAlgorithm::Sha1, OtpAlgorithm::Sha256, OtpAlgorithm::Sha512];
            for i in 0..totp_iterations {
                let ts = 1_700_000_000u64 + (i as u64) * 30;
                let _ = totp_from_base32(&secret, ts, 30, digits, algs[i % 3])?;
            }
            let (b1, _) = totp_from_base32(&secret, 59, 30, digits, OtpAlgorithm::Sha1)?;
            let (b2, _) = totp_from_base32(&secret, 60, 30, digits, OtpAlgorithm::Sha1)?;
            assert_ne!(b1, b2, "boundary rollover check failed");
            let totp_ms = totp_start.elapsed().as_secs_f64() * 1000.0;
            println!(
                "[TOTP Stress] {totp_iterations} RFC 6238 generations ({digits}-digit, SHA1/256/512) passed in {totp_ms:.1} ms ({:.0} ops/s)",
                (totp_iterations as f64) / (totp_ms / 1000.0).max(0.001)
            );

            let owner = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([1u8; 32]))?;
            let phone = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::from_bytes([2u8; 32]))?;
            let vlt_start = Instant::now();
            let mut last_ur_req = String::new();

            for r in 0..rounds {
                let payload = format!("LaVault Stress Payload #{r:04}").into_bytes();
                let vlt = encrypt_bytes_to_vlt(
                    &payload,
                    &owner,
                    &VltOptions {
                        cipher: PayloadCipher::ChaCha20Poly1305,
                        wrap_method: DirectWrapMethod::Aes256Kw,
                        direct_recipients: vec![("phone".into(), phone.x25519_public_bytes())],
                        quorum_members: vec![],
                        quorum_threshold_k: 0,
                    },
                )?;
                let (challenge, ephem) = build_unlock_challenge_for_vlt(&vlt, "phone", "StressPC")?;
                let ur = challenge.to_bcur()?;
                last_ur_req = ur.clone();

                let frames = encode_bcur_multipart("lavault-req", &challenge.to_cbor()?, 80)?;
                let subset: Vec<String> = if frames.len() > 2 {
                    frames.into_iter().skip(1).collect() // drop frame 0 -> XOR fountain recovery
                } else {
                    frames
                };
                let (ur_type, recovered_bytes) = decode_bcur_multipart(&subset)?;
                if ur_type != "lavault-req" {
                    return Err(anyhow!("unexpected UR type '{ur_type}' in round {r}"));
                }
                let parsed = UnlockChallenge::from_cbor(&recovered_bytes)?;
                let response = fulfill_unlock_challenge(&parsed, "phone", &phone)?;
                let dek =
                    verify_and_extract_unlock_dek(&response, &ephem, &phone.ed25519_verifying())?;
                let decrypted = decrypt_bytes_with_dek(&vlt, &dek)?;
                if decrypted != payload {
                    return Err(anyhow!("decrypted payload mismatch on stress round {r}"));
                }
            }
            let vlt_ms = vlt_start.elapsed().as_secs_f64() * 1000.0;
            println!(
                "[Unlocker Stress] {rounds} full .vlt + bc-ur fountain + QR challenge/decrypt cycles passed in {vlt_ms:.1} ms ({:.1} rounds/s)",
                (rounds as f64) / (vlt_ms / 1000.0).max(0.001)
            );

            if let Some(html_path) = qr_html_out {
                save_stress_qr_html(&secret, &last_ur_req, &html_path)?;
                println!("Saved QR parity & sample unlocker sheet -> {}", html_path.display());
            }

            if live_totp_secs > 0 {
                println!(
                    "\n=== Live TOTP Parity Mode ({live_totp_secs}s, {digits} digits) ==="
                );
                println!("Add or open this exact Base32 Secret in Phone App -> Vault + TOTP tab: {secret}");
                let deadline = Instant::now() + std::time::Duration::from_secs(live_totp_secs);
                let mut last_tick_sec = 0u64;
                while Instant::now() < deadline {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now != last_tick_sec {
                        last_tick_sec = now;
                        let (code, rem) =
                            totp_from_base32(&secret, now, 30, digits, OtpAlgorithm::Sha1)?;
                        println!("[UTC {now}] {digits}-digit TOTP: {code}  |  {rem:02}s remaining");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
        Commands::PhoneTest {
            phone_x25519,
            phone_ed25519,
            payload,
            out_dir,
            iterations,
            batch_res,
            no_wait,
        } => {
            for iter in 1..=iterations {
                let iter_payload = format!("{payload} [round {iter}/{iterations}]");
                let vlt_path = out_dir.join(format!("phone_test_{iter}.vlt"));
                let html_path = out_dir.join(format!("phone_test_{iter}.html"));
                let session = prepare_phone_test_session(
                    &phone_x25519,
                    phone_ed25519.as_deref(),
                    None,
                    iter_payload.as_bytes(),
                    &vlt_path,
                    &html_path,
                )?;

                println!("\n=== Phone Unlocker Test Round {iter}/{iterations} ===");
                println!("1. Open browser file: {}", session.html_path.display());
                println!("   (or scan the terminal QR below in Android/iOS Unlocker tab -> Scan PC Unlock QR)");
                run_qr_challenge_prompt(
                    &UnlockChallenge::from_bcur(&session.ur_request)?,
                    &session.verifier_8words,
                )?;

                if let Some(res) = batch_res.get(iter - 1) {
                    let started = Instant::now();
                    let pt = session.complete_with_ur_response(res)?;
                    println!(
                        "PASS Round {iter}: Verified Ed25519 signature + unwrapped DEK + decrypted {} bytes in {:.2} ms -> {:?}",
                        pt.len(),
                        started.elapsed().as_secs_f64() * 1000.0,
                        String::from_utf8_lossy(&pt)
                    );
                } else if !no_wait {
                    loop {
                        print!("\nPaste ur:lavault-res/... from phone (or 'quit' to abort): ");
                        io::stdout().flush()?;
                        let mut line = String::new();
                        if io::stdin().read_line(&mut line)? == 0 {
                            return Err(anyhow!("EOF reached before receiving phone response"));
                        }
                        let trimmed = line.trim();
                        if trimmed.eq_ignore_ascii_case("quit") {
                            return Err(anyhow!("Phone test aborted by user"));
                        }
                        if trimmed.is_empty() {
                            continue;
                        }
                        let started = Instant::now();
                        match session.complete_with_ur_response(trimmed) {
                            Ok(pt) => {
                                println!(
                                    "PASS Round {iter}: Verified phone Ed25519 signature + unwrapped DEK + decrypted {} bytes in {:.2} ms!\nPlaintext: {:?}",
                                    pt.len(),
                                    started.elapsed().as_secs_f64() * 1000.0,
                                    String::from_utf8_lossy(&pt)
                                );
                                break;
                            }
                            Err(e) => {
                                println!("Verification failed ({e}). Try pasting the full ur:lavault-res/... string again.");
                            }
                        }
                    }
                }
            }
        }
        Commands::VerifyRecovery {
            bip39,
            rkf_hex,
            rkf_pass,
            shares,
            expected_x25519,
        } => {
            let (mode, seed) = if let Some(phrase) = bip39 {
                ("BIP-0039 24-word mnemonic", import_bip39_mnemonic(&phrase)?)
            } else if let Some(hex_str) = rkf_hex {
                let pass = rkf_pass.ok_or_else(|| {
                    anyhow!("--rkf-pass is required when verifying a .rkf recovery keyfile")
                })?;
                let rkf_bytes = hex::decode(hex_str.trim())?;
                let pw = VaultPassword::new(pass);
                ("Encrypted .rkf Keyfile", import_rkf_keyfile(&rkf_bytes, &pw)?)
            } else if !shares.is_empty() {
                let parsed: Vec<_> = shares
                    .iter()
                    .map(|u| parse_slip39_uri(u))
                    .collect::<vault_core::error::Result<Vec<_>>>()?;
                let raw_seed = shamir_reconstruct_secret(&parsed, None)?;
                let arr: [u8; 32] = raw_seed
                    .try_into()
                    .map_err(|_| anyhow!("reconstructed seed must be 32 bytes"))?;
                (
                    "K-of-N Shamir Guardian Shares",
                    MasterIdentitySeed::from_bytes(arr),
                )
            } else {
                return Err(anyhow!(
                    "supply one of --bip39 \"...\", --rkf-hex ... --rkf-pass ..., or --shares ..."
                ));
            };

            let keys = DerivedIdentityKeys::from_seed(&seed)?;
            let recovered_x = hex::encode(keys.x25519_public_bytes());
            let recovered_ed = hex::encode(keys.ed25519_public_bytes());
            println!("Recovery Method   : {mode}");
            println!("Recovered X25519  : {recovered_x}");
            println!("Recovered Ed25519 : {recovered_ed}");

            if let Some(expected) = expected_x25519 {
                if !recovered_x.eq_ignore_ascii_case(expected.trim()) {
                    return Err(anyhow!(
                        "MISMATCH: expected X25519 {}, got {}",
                        expected.trim(),
                        recovered_x
                    ));
                }
                println!("MATCH: Recovered X25519 key matches phone this_device 100%!");
            }
        }
    }
    Ok(())
}
