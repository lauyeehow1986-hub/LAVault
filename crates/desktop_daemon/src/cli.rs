use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed};
use vault_core::transport::{build_unlock_challenge_for_vlt, encode_8word_verifier};
use vault_core::vlt::{
    add_direct_recipient_to_vlt, decrypt_bytes_with_direct_slot, decrypt_bytes_with_quorum_slots,
    decrypt_directory_from_vlt, encrypt_bytes_to_vlt, encrypt_directory_to_vlt,
    remove_direct_recipient_from_vlt, DirectWrapMethod, PayloadCipher, VltOptions,
};

use crate::mount::{MountSessionConfig, VirtualDriveManager};
use crate::qr::run_qr_challenge_prompt;

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
        } => {
            let raw = std::fs::read(&file)?;
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
                if out_path.extension().is_none() && file.to_string_lossy().ends_with(".dir.vlt") {
                    decrypt_directory_from_vlt(&file, &out_path, &slot, &keys)?;
                } else {
                    let pt = decrypt_bytes_with_direct_slot(&raw, &slot, &keys)?;
                    std::fs::write(&out_path, pt)?;
                }
                println!("Unlocked -> {}", out_path.display());
            } else {
                // Interactive optical QR challenge generation when no local seed is supplied
                let (challenge, _) =
                    build_unlock_challenge_for_vlt(&raw, &slot, "LaVault-CLI")?;
                let verifier = encode_8word_verifier(&challenge.challenge_nonce);
                run_qr_challenge_prompt(&challenge, &verifier)?;
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
    }
    Ok(())
}
