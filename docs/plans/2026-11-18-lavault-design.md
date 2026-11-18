# LaVault Architecture & Design Document

**Date:** 2026-11-18
**Status:** Approved for Implementation

## 1. Overview & Security Model

LaVault is a zero-cloud, cross-platform Local Mobile Authenticator, Password + TOTP Vault, and Multi-User File & Virtual Volume Unlocker targeting Android, iOS, Windows, macOS, and Linux.

Core security invariants:
1. **Strict Separation of TOTP Display vs. Encryption Keys:** 6–8 digit RFC 6238 TOTP codes are display-only second-factor credentials and are never used as encryption keys.
2. **Memory Safety (`zeroize` + OS memory locking):** Every struct holding secret material (`MasterIdentitySeed`, `DataEncryptionKey`, `KeyEncryptionKey`, `ShamirShare`, `TotpSecret`, `VaultPassword`, `XtsVolumeKey`) derives `Zeroize` and `ZeroizeOnDrop`. Long-lived key material stays inside Rust (`vault_core`) and is never left on the Dart GC heap. Active volume keys are pinned in non-swappable RAM (`VirtualLock` on Windows, `mlock` on POSIX).
3. **Deterministic Binary & Protocol Parity:** All `.vlt` headers, Shamir GF(256) (`0x11B`) shares, HKDF domain separation, HOTP/TOTP calculations, and `bc-ur` optical QR payloads match the reference implementations in `mcp/mcp_vault_dev_server.py`.

---

## 2. Monorepo Structure

```text
LAVault/
├── Cargo.toml                         # Rust workspace (vault_core, desktop_daemon)
├── crates/
│   ├── vault_core/                    # Shared crypto, vault DB, .vlt format, FUSE/XTS, transport protocol, FRB API
│   └── desktop_daemon/                # CLI (`lavault`) + local mDNS/TLS1.3/SPAKE2, BLE, QR & virtual drive daemon
├── app_flutter/                       # Unified Flutter mobile & desktop UI + flutter_rust_bridge v2 bindings
├── mcp/mcp_vault_dev_server.py        # FastMCP verification server
├── .agents/skills/local-auth-vault/   # Antigravity skill definition
└── docs/plans/                        # Design & implementation plans
```

---

## 3. Cryptographic Architecture (`crates/vault_core`)

### 3.1 Identity Hierarchy
- **Seed Generation:** 256-bit `MasterIdentitySeed` generated via OS CSPRNG (`getrandom`).
- **Password/PIN Stretching:** Argon2id (RFC 9106: `m = 65536` KiB, `t = 3`, `p = 4`) combined with mobile hardware-keystore secret (`AndroidKeyStore` / iOS `SecureEnclave`) via HKDF-SHA256.
- **Domain-Separated Subkeys (HKDF-SHA256, RFC 5869):**
  - `"local-auth-vault/v1/x25519-kek"` → static X25519 key pair (key agreement / DEK unwrapping).
  - `"local-auth-vault/v1/ed25519-sig"` → Ed25519 key pair (signing `.vlt` headers, challenges, guardian shares).
  - `"local-auth-vault/v1/vault-db-key"` → 256-bit key for local Password + TOTP vault database.
  - `"local-auth-vault/v1/xts-aes-512"` → 512-bit XTS-AES-256 key (`Key_1 != Key_2` strictly asserted).

### 3.2 Phone Password + Live TOTP Vault
- **Storage:** Bundled SQLite (`rusqlite`) with per-entry XChaCha20-Poly1305 AEAD encryption + encrypted metadata envelope keyed by `vault-db-key`, plus KDBX 4.1-compatible export/import metadata structures.
- **OTP Engine:** RFC 4226 HOTP and RFC 6238 TOTP supporting SHA-1, SHA-256, SHA-512, 6–8 digits, configurable step (default 30s) and `t0 = 0`.

### 3.3 Multi-User `.vlt` Header (`LAVAULT1`)
- **Prefix:** 8-byte ASCII magic `"LAVAULT1"`, followed by 4-byte `u32` big-endian length + Deterministically Encoded CBOR (RFC 8949 via `ciborium`) + 64-byte Ed25519 signature + 32-byte owner Ed25519 verifying key.
- **1-of-N Direct Slots (`direct_x25519`):** Ephemeral-static X25519 → `HKDF-SHA256(ikm = shared_secret, salt = epk || pk_i, info = "local-auth-vault/v1/direct-slot")` → RFC 3394 AES-256 Key Wrap (`aes-kw`, 40-byte output with `0xA6A6A6A6A6A6A6A6` ICV) or XChaCha20-Poly1305 wrapping the 256-bit `DEK`.
- **K-of-N Threshold Quorum (`shamir_quorum`):** Random 256-bit `GroupKEK` wraps `DEK`. `GroupKEK` split into $N$ shares ($1 \le K \le N \le 255$) over $GF(2^8)$ with irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (`0x11B`) and generator `0x03` (SLIP-0039). Each share + index + 4-byte SHA-256 commitment is wrapped to member $j$'s X25519 public key.
- **AAD Binding:** `SHA-256(canonical_header_cbor)` is passed as Associated Data (`AAD`) to every payload AEAD chunk so header tampering invalidates decryption.

### 3.4 Dual Payload Modes
- **Mode A (Streaming `.vlt` File/Directory):** 64 KB (`65536` byte) STREAM chunks using 12-byte nonce `chunk_index_be_11bytes || is_final_byte_1byte` (`0x00` or `0x01`) with ChaCha20-Poly1305 or AES-256-GCM. Directories are archived as deterministic `tar` streams before encryption.
- **Mode B (Virtual Encrypted Volume):**
  - **Overlay Filesystem:** 32 KB AEAD blocks with per-block random nonces + deterministic AES-SIV encrypted filenames (`aes-siv`), exposed via WinFsp on Windows (`winfsp` crate / runtime detection) and `fuser` (libfuse/macFUSE) on Unix, with a portable in-process VFS engine for cross-platform unit/integration testing even when kernel FUSE/WinFsp drivers are absent.
  - **Sector Block Container:** XTS-AES-256 (`xts-mode` + `aes`) with strict `Key_1 != Key_2` enforcement and `VirtualLock`/`mlock` + auto-zeroize-and-unmount on phone disconnect or lock command.

### 3.5 Triple Recovery
1. **24-word BIP-0039 mnemonic** (`bip39` crate) encoding the 256-bit `MasterIdentitySeed`.
2. **Encrypted `.rkf` recovery keyfile** using Argon2id + XChaCha20-Poly1305.
3. **M-of-N Guardian Recovery Shares** using GF(256) / SLIP-0039 Shamir shares wrapped as Ed25519-signed capsules (`lavault-share://v1/...` and `ur:lavault-share/...`).

---

## 4. Tri-Modal Transport (`crates/vault_core` + `crates/desktop_daemon`)

Unified CBOR `UnlockChallenge` and `UnlockResponse` envelope across:
1. **Local Wi-Fi:** mDNS discovery `_localauth._tcp.local.` on TCP port `53319` (`mdns-sd`) + SPAKE2 (RFC 9382) initial 6-digit/3-word pairing + pinned mutual Ed25519 TLS 1.3 (`rustls`).
2. **Bluetooth Low Energy (BLE GATT):** Cross-platform GATT client (`btleplug`) connecting to service UUID `0000fffd-0000-1000-8000-00805f9b34fb` with application-layer X25519 + ChaCha20-Poly1305 session encryption.
3. **Air-Gapped Optical QR:** Blockchain Commons `bc-ur` Bytewords + CRC32 (`ur:lavault-req` / `ur:lavault-res`) with multipart fountain framing for large payloads + 8-word one-time verifier fallback.

---

## 5. Flutter Application (`app_flutter`)

- Bridged to `crates/vault_core` via `flutter_rust_bridge` v2.
- Biometric & hardware keystore integration via `local_auth` and `flutter_secure_storage`.
- Three primary tabs:
  1. **Vault (Password + Live TOTP):** Searchable credentials, masked/copyable passwords, live 30s rolling RFC 6238 OTP + circular countdown indicator.
  2. **Unlocker (Files & Drives):** Live approval queue for Wi-Fi (mDNS/TLS 1.3) and BLE GATT unlock requests, `ur:lavault-req`/`ur:lavault-res` QR scanner/generator, and K-of-N Shamir co-signing.
  3. **Peers & Guardians:** Manage 1-of-N authorized peers, K-of-N quorum groups, and Triple Recovery enrollment/verification.
