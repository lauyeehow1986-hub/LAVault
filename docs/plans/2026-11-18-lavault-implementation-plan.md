# LaVault Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the complete LaVault monorepo (`crates/vault_core`, `crates/desktop_daemon`, `app_flutter`) with strict TDD, memory zeroization, MCP reference vector parity, tri-modal local transport, virtual volume encryption, and Flutter/Rust FFI integration.

**Architecture:** `crates/vault_core` houses all cryptographic primitives, OTP, SQLite+AEAD vault, `.vlt` CBOR header + STREAM encryption, GF(256) Shamir/SLIP-0039, VFS/XTS-AES-256 volume engine, BIP-39/`.rkf`/Guardian recovery, CBOR/bc-ur transport envelopes, and `flutter_rust_bridge` APIs. `crates/desktop_daemon` provides the CLI and background mDNS/TLS1.3/SPAKE2, BLE GATT, QR, and WinFsp/FUSE mount runner. `app_flutter` renders the 3-tab mobile/desktop interface with hardware keystore & biometric gating.

**Tech Stack:** Rust 1.96 (`zeroize`, `argon2`, `hkdf`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `aes-gcm`, `aes-kw`, `aes-siv`, `xts-mode`, `ciborium`, `rusqlite`, `bip39`, `rustls`, `mdns-sd`, `btleplug`, `spake2`, `clap`, `tokio`, `flutter_rust_bridge`), Python FastMCP (`mcp/mcp_vault_dev_server.py`), Flutter 3.47 / Dart 3.13 (`flutter_rust_bridge`, `local_auth`, `flutter_secure_storage`, `mobile_scanner`, `qr_flutter`).

---

### Task 1: Toolchain Installation & Monorepo Scaffold
- Install `flutter_rust_bridge_codegen` via `cargo install` and check `WinFsp` availability.
- Initialize git inside `LAVault` and scaffold `Cargo.toml` workspace + `crates/vault_core/Cargo.toml` + `crates/desktop_daemon/Cargo.toml`.

### Task 2: `vault_core` Identity, Memory Safety, KDF & OTP (`identity.rs`, `otp.rs`)
- **RED:** Write failing tests for `MasterIdentitySeed` Zeroize/ZeroizeOnDrop, Argon2id (`m=65536, t=3, p=4`), HKDF-SHA256 RFC 5869 Test Case 1 + domain separation (`x25519-kek`, `ed25519-sig`, `vault-db-key`, `xts-aes-512`), RFC 4226 HOTP vectors (counts 0..9), and RFC 6238 TOTP vectors (SHA1/SHA256/SHA512 at T=59).
- **GREEN:** Implement `crates/vault_core/src/identity.rs` and `crates/vault_core/src/otp.rs`.
- **VERIFY:** Run `cargo test -p vault_core` and cross-check against MCP `verify_crypto_primitives`.

### Task 3: `vault_core` Shamir GF(256) SLIP-0039 & Triple Recovery (`shamir.rs`, `recovery.rs`)
- **RED:** Write failing tests verifying exact GF(2^8) (`0x11B`, generator `0x03`) share parity against `mcp/mcp_vault_dev_server.py` (`verify_shamir_slip39_quorum`), K-of-N reconstruction, `K-1` failure, tamper commitment rejection, 24-word BIP-0039 roundtrip, `.rkf` Argon2id+XChaCha20-Poly1305 roundtrip, and signed Guardian QR capsules.
- **GREEN:** Implement `crates/vault_core/src/shamir.rs` and `crates/vault_core/src/recovery.rs`.
- **VERIFY:** `cargo test -p vault_core`.

### Task 4: `vault_core` Multi-User `.vlt` Header & STREAM Payload (`vlt.rs`)
- **RED:** Write failing tests for `"LAVAULT1"` + deterministic RFC 8949 CBOR header encoding/decoding, `direct_x25519` (RFC 3394 AES-256-KW & XChaCha20-Poly1305) 1-of-N unwrap, `shamir_quorum` K-of-N unwrap, Ed25519 signature verification, AAD tamper rejection, and 64 KB STREAM chunk encryption/decryption (file + directory tar stream).
- **GREEN:** Implement `crates/vault_core/src/vlt.rs`.
- **VERIFY:** `cargo test -p vault_core` and compare canonical CBOR & AAD behavior with MCP `pack_and_inspect_vlt_header`.

### Task 5: `vault_core` Password + Live TOTP Vault Engine (`vault_db.rs`)
- **RED:** Write failing tests for creating/unlocking an encrypted SQLite vault (`rusqlite` + XChaCha20-Poly1305 per-entry AEAD + KDBX 4.1 compatible export/import struct), CRUD entries, live rolling TOTP code + countdown computation, and wrong-key rejection.
- **GREEN:** Implement `crates/vault_core/src/vault_db.rs`.
- **VERIFY:** `cargo test -p vault_core`.

### Task 6: `vault_core` Virtual Encrypted Volume & XTS-AES-256 Engine (`volume.rs`)
- **RED:** Write failing tests for `XtsVolumeKey` asserting `Key_1 != Key_2` (rejecting identical subkeys per NIST SP 800-38E), sector-level XTS-AES-256 read/write roundtrip, 32 KB block + AES-SIV filename overlay VFS operations (create/read/write/rename/delete/list), OS RAM lock (`VirtualLock`/`mlock`), and immediate zeroize + lock on disconnect.
- **GREEN:** Implement `crates/vault_core/src/volume.rs`.
- **VERIFY:** `cargo test -p vault_core`.

### Task 7: `vault_core` Tri-Modal Transport Protocol & `bc-ur` (`transport.rs`, `api.rs`)
- **RED:** Write failing tests for canonical CBOR `UnlockChallenge` / `UnlockResponse`, `bc-ur` Bytewords + CRC32 (`ur:lavault-req` / `ur:lavault-res` matching `mcp_vault_dev_server.py` byte-for-byte), multipart fountain codes, 8-word one-time verifier fallback, SPAKE2 pairing handshake + pinned Ed25519 TLS 1.3 certs, and FRB API surface (`crates/vault_core/src/api.rs`).
- **GREEN:** Implement `crates/vault_core/src/transport.rs` and `crates/vault_core/src/api.rs`.
- **VERIFY:** `cargo test -p vault_core`.

### Task 8: `crates/desktop_daemon` CLI, Local Transports & Virtual Drive Mounter
- **RED:** Write failing integration tests for CLI commands (`lock`, `unlock`, `mount`, `recipients add/remove`, `pair`), end-to-end 1-of-N and 2-of-3 quorum file lock/unlock, local TLS 1.3 loopback challenge/response unlock, and virtual volume mount/unmount lifecycle.
- **GREEN:** Implement `crates/desktop_daemon/src/` (`main.rs`, `cli.rs`, `wifi.rs`, `ble.rs`, `qr.rs`, `mount.rs`).
- **VERIFY:** `cargo test --workspace` and run CLI smoke tests.

### Task 9: `app_flutter` FFI Generation & 3-Tab Cross-Platform UI
- Initialize/configure `app_flutter`, add `pubspec.yaml` dependencies (`flutter_rust_bridge`, `local_auth`, `flutter_secure_storage`, `qr_flutter`, `mobile_scanner`, `file_picker`), run `flutter_rust_bridge_codegen generate`.
- Implement hardware keystore/biometric gate, Tab 1 (Password + Live TOTP Vault with 30s circular timer), Tab 2 (File & Drive Unlocker: Wi-Fi/BLE approval queue + QR `ur:lavault-req`/`ur:lavault-res` + Shamir co-signing), Tab 3 (Peers & Guardians + Triple Recovery).
- Write Flutter unit & widget tests (`flutter test`) and verify Windows desktop build (`flutter build windows`).

### Task 10: Final End-to-End Verification & MCP Parity Check
- Run `python mcp/mcp_vault_dev_server.py --self-test`, `cargo test --workspace`, `cargo clippy --workspace`, and `flutter test` after final edits.
