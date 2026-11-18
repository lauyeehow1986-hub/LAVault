# Antigravity IDE Copy-Paste Master Prompt: Local Authenticator, Password+TOTP Vault & Multi-User File Unlocker

## 1. Quick Setup in Your Project Workspace

1. **Place the Skill:** Copy `SKILL.md` into `.agents/skills/local-auth-vault/SKILL.md` in your workspace root ([Agent Skills Specification](https://agentskills.io/specification)).
2. **Place the MCP Server:** Copy `mcp_vault_dev_server.py` into `mcp/mcp_vault_dev_server.py` and register it in your Antigravity MCP settings (`.antigravity/mcp_config.json` or `.cursor/mcp.json`) per the [Model Context Protocol Specification](https://modelcontextprotocol.io/specification/2025-06-18):

```json
{
  "mcpServers": {
    "local-auth-vault-mcp": {
      "command": "python3",
      "args": ["mcp/mcp_vault_dev_server.py"]
    }
  }
}
```

3. **Run Self-Test Anytime:** Verify the MCP tools from your terminal with:

```bash
python3 mcp/mcp_vault_dev_server.py --self-test
```

---

## 2. Copy-Paste Master Prompt for Antigravity IDE

Copy the entire block below and paste it into Antigravity IDE to build the complete multi-platform workspace:

```text
Load and follow the instructions in `.agents/skills/local-auth-vault/SKILL.md` and use the connected `local-auth-vault-mcp` MCP server tools (`verify_crypto_primitives`, `pack_and_inspect_vlt_header`, `verify_shamir_slip39_quorum`, `check_mobile_and_fuse_bridge`) throughout development.

We are building **LaVault**, a cross-platform, zero-cloud Local Mobile Authenticator, Password + TOTP Vault, and Multi-User Computer File & Virtual Volume Unlocker across **Android, iOS, Windows, macOS, and Linux**.

### Target Architecture & Workspace Layout
Create a clean monorepo with the following structure:
1. `crates/vault_core/` (Rust shared cryptographic & protocol library):
   - Memory safety: Every struct holding secrets (`MasterIdentitySeed`, `DataEncryptionKey`, `KeyEncryptionKey`, `ShamirShare`, `TotpSecret`, `VaultPassword`) MUST derive `Zeroize` and `ZeroizeOnDrop` (`zeroize` crate).
   - Identity & Key Derivation:
     - Generate a 256-bit `MasterIdentitySeed` via OS CSPRNG (`getrandom`).
     - Stretch user master password/PIN using `argon2` (Argon2id, RFC 9106: m=65536 KiB, t=3, p=4).
     - Derive deterministic subkeys via `hkdf` (HKDF-SHA256, RFC 5869) with explicit domain-separation info strings:
       * `"local-auth-vault/v1/x25519-kek"` -> `x25519-dalek` static key pair for unwrapping file/volume DEKs
       * `"local-auth-vault/v1/ed25519-sig"` -> `ed25519-dalek` signing key pair for signing `.vlt` headers and unlock responses
       * `"local-auth-vault/v1/vault-db-key"` -> 256-bit key for the phone's local Password + TOTP vault
   - Phone Password + Live TOTP Vault Engine:
     - Store vault entries encrypted with `chacha20poly1305` (RFC 8439) or `aes-gcm` (NIST SP 800-38D) inside SQLite/SQLCipher or KDBX 4.1 compatible structures.
     - Implement RFC 4226 (HOTP) and RFC 6238 (TOTP: SHA1, SHA256, SHA512, 6-8 digits, 30s step) so unlocking an entry displays the stored password alongside the live rolling TOTP code and countdown timer.
   - Multi-User `.vlt` Header (1-of-N Direct & K-of-N Shamir Quorum):
     - Prefix every file/volume header with 8-byte ASCII magic `"LAVAULT1"` followed by Deterministically Encoded CBOR (RFC 8949, `ciborium`).
     - Support `direct_x25519` stanzas (1-of-N): Ephemeral-static X25519 + HKDF-SHA256 + RFC 3394 AES-256 Key Wrap (`aes-kw`) or XChaCha20-Poly1305 wrapping the 256-bit file/volume `DEK`.
     - Support `shamir_quorum` stanzas (K-of-N): Wrap `DEK` under a random 256-bit `GroupKEK`, split `GroupKEK` into N shares requiring K shares over GF(2^8) (irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0x11B per SLIP-0039), and wrap each share to member j's X25519 public key.
     - Sign the canonical CBOR header with the owner's Ed25519 key and bind the SHA-256 header hash as Associated Data (AAD) into the payload AEAD cipher.
   - Dual File Encryption Modes:
     - Mode A (On-Demand Streaming `.vlt` File/Folder Container): 64 KB STREAM AEAD chunks (`chunk_index_be_11bytes || is_final_byte_1byte` nonce) with ChaCha20-Poly1305 / AES-256-GCM.
     - Mode B (Mounted Virtual Encrypted Volume): Userspace FUSE/WinFsp overlay directory (32 KB AEAD blocks + encrypted filenames) and sector-level XTS-AES-256 (NIST SP 800-38E, strictly asserting `Key_1 != Key_2`), locking the Volume Master Key in RAM (`mlock` / `VirtualLock`) and zeroizing + unmounting immediately on phone disconnect or lock command.
   - Triple Backup & Recovery:
     - Option 1: 24-word BIP-0039 mnemonic phrase encoding the 256-bit `MasterIdentitySeed`.
     - Option 2: Encrypted `.rkf` recovery keyfile (Argon2id + XChaCha20-Poly1305).
     - Option 3: M-of-N Designated Recovery Guardians using SLIP-0039 / GF(256) Shamir shares exported as signed QR capsules.

2. `crates/desktop_daemon/` (Windows, macOS, Linux CLI + Background Unlocker & FUSE/WinFsp Mounter):
   - Provide CLI commands: `lavault lock <path>`, `lavault unlock <file.vlt>`, `lavault mount <vault_dir> <mount_point>`, `lavault recipients add/remove`, and `lavault pair`.
   - Implement all 3 local transport channels sharing the same CBOR `UnlockChallenge` / `UnlockResponse` envelope:
     * Channel 1 (Local Wi-Fi): mDNS (`_localauth._tcp.local.` on port 53319) + SPAKE2 (RFC 9382) initial pairing + pinned mutual Ed25519 TLS 1.3 (`rustls`).
     * Channel 2 (Bluetooth Low Energy): Cross-platform BLE GATT client (`btleplug`) connecting to the phone's GATT peripheral UUID `0000fffd-0000-1000-8000-00805f9b34fb`.
     * Channel 3 (Air-Gapped Optical QR): Encode challenge as `ur:lavault-req` and decode response from `ur:lavault-res` (or 8-word one-time verifier code when no webcam is present).

3. `app_flutter/` (Unified Flutter Mobile & Desktop UI bridged via `flutter_rust_bridge`):
   - Mobile Hardware Keystore & Biometrics: Use `local_auth` (`BiometricPrompt` / `LocalAuthentication`) and `flutter_secure_storage` (`AndroidKeyStore` / iOS `SecureEnclave` Keychain) to gate access to the hardware-wrapped `MasterIdentitySeed`.
   - Tab 1 (Password + Live TOTP Vault): Searchable vault cards showing username, masked/copyable password, and live 30-second RFC 6238 TOTP code with circular countdown indicator.
   - Tab 2 (File & Drive Unlocker): Live approval queue for incoming Wi-Fi (mDNS/TLS 1.3) and BLE GATT unlock requests, plus a built-in optical QR scanner/generator for air-gapped `ur:lavault-req` / `ur:lavault-res` unlocking and K-of-N Shamir quorum co-signing.
   - Tab 3 (Peers & Guardians): Manage authorized 1-of-N peers, configure K-of-N Shamir quorum groups, and export/verify the 3 recovery methods (24-word BIP-39 phrase, `.rkf` keyfile, and M-of-N Guardian QR shares).

### Execution & Verification Loop
- Step 1: Call the MCP tool `check_mobile_and_fuse_bridge` to inspect the host environment.
- Step 2: Build `crates/vault_core` first and run `cargo test` alongside the MCP tools `verify_crypto_primitives`, `pack_and_inspect_vlt_header`, and `verify_shamir_slip39_quorum` to verify bit-for-bit parity between Rust and the MCP reference vectors.
- Step 3: Build `crates/desktop_daemon` and verify end-to-end file lock/unlock (1-of-N and 2-of-3 quorum) and virtual volume mount/unmount.
- Step 4: Generate `flutter_rust_bridge` bindings and build the `app_flutter` mobile/desktop interface with full unit and integration tests.
```

---

## 3. Authoritative Standards & Reference Documentation Linked in This Kit

- **TOTP & HOTP:** [RFC 6238 TOTP](https://www.rfc-editor.org/info/rfc6238/), [RFC 4226 HOTP](https://www.rfc-editor.org/info/rfc4226/)
- **Key Derivation & Password Hashing:** [RFC 9106 Argon2id](https://www.rfc-editor.org/info/rfc9106/), [RFC 5869 HKDF](https://www.rfc-editor.org/info/rfc5869/), [RFC 7914 scrypt](https://www.rfc-editor.org/info/rfc7914/), [NIST SP 800-132 PBKDF2](https://csrc.nist.gov/pubs/sp/800/132/final)
- **Public-Key & Envelope Encryption:** [RFC 7748 X25519](https://www.rfc-editor.org/info/rfc7748/), [RFC 8032 Ed25519](https://www.rfc-editor.org/info/rfc8032/), [RFC 9180 HPKE](https://www.rfc-editor.org/info/rfc9180/), [RFC 3394 AES Key Wrap](https://www.rfc-editor.org/info/rfc3394/), [FiloSottile/age](https://github.com/filosottile/age)
- **AEAD & Storage Encryption:** [RFC 8439 ChaCha20-Poly1305](https://www.rfc-editor.org/info/rfc8439/), [NIST SP 800-38D AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final), [NIST SP 800-38E XTS-AES](https://csrc.nist.gov/pubs/sp/800/38/e/final), [RFC 5116 AEAD](https://www.rfc-editor.org/info/rfc5116/)
- **Threshold Recovery & Mnemonics:** [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), [SLIP-0039 Shamir Secret Sharing](https://github.com/satoshilabs/slips/blob/master/slip-0039.md), [Spark Shamir Glossary](https://www.spark.money/glossary/shamirs-secret-sharing)
- **Mobile Secure Hardware & Vaults:** [Android Keystore](https://developer.android.com/privacy-and-security/keystore), [Android BiometricPrompt](https://developer.android.com/identity/sign-in/biometric-auth), [Apple Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit), [KeePass KDBX 4](https://keepass.info/help/kb/kdbx_4.html), [SQLCipher](https://www.zetetic.net/sqlcipher/design/)
- **Local Transport & Virtual Filesystems:** [RFC 6762 mDNS](https://www.rfc-editor.org/info/rfc6762/), [RFC 8446 TLS 1.3](https://www.rfc-editor.org/info/rfc8446/), [RFC 9382 SPAKE2](https://www.rfc-editor.org/info/rfc9382/), [Bluetooth Core 5.4 LE Secure Connections](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html), [Blockchain Commons bc-ur](https://github.com/BlockchainCommons/bc-ur), [Linux libfuse](https://github.com/libfuse/libfuse), [Cryptomator WinFsp/FUSE Architecture](https://docs.cryptomator.org/security/architecture/), [gocryptfs](https://github.com/rfjakob/gocryptfs)
- **Agent Skills, MCP & Rust Security:** [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-06-18), [FastMCP](https://gofastmcp.com/docs/getting-started/welcome), [Agent Skills Specification](https://agentskills.io/specification), [Project Wycheproof](https://github.com/C2SP/wycheproof), [RustSec Advisory DB](https://github.com/rustsec/advisory-db), [Rust zeroize Crate](https://crates.io/crates/zeroize), [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge)
