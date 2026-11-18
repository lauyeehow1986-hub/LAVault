---
name: local-auth-vault
description: Build, audit, and test a cross-platform Local Mobile Authenticator, Password + TOTP Vault, and Multi-User File/Volume Unlocker (1-of-N X25519 envelope + K-of-N Shamir GF(256)/SLIP-39 quorum) across Android, iOS, Windows, macOS, and Linux using Rust, Flutter (flutter_rust_bridge), FUSE/WinFsp, and tri-modal local transport (mDNS/TLS 1.3, BLE GATT, and air-gapped bc-ur optical QR). Use whenever building, auditing, or extending local authenticators, password vaults, multi-recipient file encryption, FUSE virtual drives, or phone-to-PC unlock protocols in Antigravity IDE.
---
# Local Auth Vault

Build and verify a zero-cloud, hardware-backed mobile authenticator and password vault (Android + iOS) paired with a cross-platform desktop file and virtual-volume unlocker (Windows, macOS, Linux). This skill enforces cryptographic correctness, memory zeroization, deterministic binary headers, and tri-modal local transport across a shared Rust core (`libvault_core`) and Flutter UI (`flutter_rust_bridge`).

## When to Use

- Building or modifying the shared Rust cryptographic core (`libvault_core`) for [X25519 (RFC 7748)](https://www.rfc-editor.org/info/rfc7748/), [Ed25519 (RFC 8032)](https://www.rfc-editor.org/info/rfc8032/), [ChaCha20-Poly1305 (RFC 8439)](https://www.rfc-editor.org/info/rfc8439/), [AES-256-GCM (NIST SP 800-38D)](https://csrc.nist.gov/pubs/sp/800/38/d/final), or [AES Key Wrap (RFC 3394)](https://www.rfc-editor.org/info/rfc3394/)
- Implementing or auditing the mobile Password + live [TOTP (RFC 6238)](https://www.rfc-editor.org/info/rfc6238/) / [HOTP (RFC 4226)](https://www.rfc-editor.org/info/rfc4226/) vault backed by [SQLCipher](https://www.zetetic.net/sqlcipher/design/) or [KeePass KDBX 4.1](https://keepass.info/help/kb/kdbx_4.1.html)
- Designing or inspecting `.vlt` multi-recipient file headers combining 1-of-N direct recipient slots ([age v1](https://github.com/filosottile/age) / [HPKE RFC 9180](https://www.rfc-editor.org/info/rfc9180/)) and K-of-N threshold quorum slots ([Shamir Secret Sharing](https://www.spark.money/glossary/shamirs-secret-sharing) / [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md))
- Integrating mobile secure hardware via [Android Keystore](https://developer.android.com/privacy-and-security/keystore) + [BiometricPrompt](https://developer.android.com/identity/sign-in/biometric-auth) and [Apple Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) + [CryptoKit](https://developer.apple.com/documentation/cryptokit)
- Implementing desktop on-demand file encryption or mounted virtual drives via [Linux libfuse](https://github.com/libfuse/libfuse), macFUSE, or [WinFsp](https://cryptomator.org/blog/2023/02/01/1-7-0-what-you-need-to-know/)
- Implementing or debugging the three local phone-to-PC transport channels: Local Wi-Fi ([mDNS RFC 6762](https://www.rfc-editor.org/info/rfc6762/) + [TLS 1.3 RFC 8446](https://www.rfc-editor.org/info/rfc8446/) + [SPAKE2 RFC 9382](https://www.rfc-editor.org/info/rfc9382/)), Bluetooth Low Energy ([BLE GATT LE Secure Connections](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html) / [CTAP2 Hybrid Transport](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)), and air-gapped optical QR ([Blockchain Commons bc-ur](https://github.com/BlockchainCommons/bc-ur))

## Steps

### Step 1: Enforce Cryptographic Separation Between TOTP Display and Encryption Keys

Never use a 6-to-8-digit [RFC 6238 TOTP](https://www.rfc-editor.org/info/rfc6238/) code directly as a file or vault encryption key. A 6-digit TOTP has only $10^6$ possibilities and is trivially brute-forced offline.

- **Phone Vault Unlock:** Derive the Vault Master Key by combining a user password/PIN stretched via [Argon2id (RFC 9106)](https://www.rfc-editor.org/info/rfc9106/) (`m = 65536` KiB, `t = 3`, `p = 4`) with a hardware-bound secret unwrapped from the [Android Keystore](https://developer.android.com/privacy-and-security/keystore) or [Apple Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave) using [HKDF-SHA256 (RFC 5869)](https://www.rfc-editor.org/info/rfc5869/). Once the vault is unlocked in RAM, decrypt the entry's password and Base32 TOTP secret to render the password and rolling 30-second TOTP side-by-side.
- **Identity Key Hierarchy:** Generate a 256-bit `MasterIdentitySeed` on initial enrollment. Derive deterministic subkeys via [HKDF-SHA256 (RFC 5869)](https://www.rfc-editor.org/info/rfc5869/) with explicit domain-separation info strings:
  - `info = "local-auth-vault/v1/x25519-kek"` -> [X25519 (RFC 7748)](https://www.rfc-editor.org/info/rfc7748/) key agreement key pair for unwrapping file/volume DEKs
  - `info = "local-auth-vault/v1/ed25519-sig"` -> [Ed25519 (RFC 8032)](https://www.rfc-editor.org/info/rfc8032/) signing key pair for authenticating `.vlt` headers and unlock responses
  - `info = "local-auth-vault/v1/vault-db-key"` -> 256-bit key for local vault storage ([SQLCipher](https://www.zetetic.net/sqlcipher/about/) or [KDBX 4.1](https://keepass.info/help/kb/kdbx_4.1.html))

### Step 2: Implement the Unified `.vlt` Multi-Recipient Header (1-of-N and K-of-N)

Encode all file and volume headers using [Deterministically Encoded CBOR (RFC 8949)](https://www.rfc-editor.org/info/rfc8949/) preceded by the 8-byte ASCII magic header `LAVAULT1`.

- **Master Data Encryption Key (DEK):** Generate a fresh 256-bit random `DEK` from the OS CSPRNG ([NIST SP 800-57](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)) for every encrypted file or volume.
- **1-of-N Direct Recipient Stanza (`slot_type = "direct_x25519"`):**
  - Perform ephemeral-static [X25519 (RFC 7748)](https://www.rfc-editor.org/info/rfc7748/) Diffie-Hellman between an ephemeral key pair `(esk, epk)` and the recipient's static public key `pk_i`.
  - Derive a 256-bit `KEK_i` via `HKDF-SHA256(ikm = shared_secret, salt = epk || pk_i, info = "local-auth-vault/v1/direct-slot")`.
  - Wrap the 256-bit `DEK` under `KEK_i` using [RFC 3394 AES-256 Key Wrap](https://www.rfc-editor.org/info/rfc3394/) (producing a 40-byte wrapped key with the `0xA6A6A6A6A6A6A6A6` integrity check value) or [XChaCha20-Poly1305](https://docs.phase.dev/security/cryptography).
- **K-of-N Threshold Quorum Stanza (`slot_type = "shamir_quorum"`):**
  - Generate a random 256-bit `GroupKEK` and wrap `DEK` under `GroupKEK`.
  - Split `GroupKEK` into $N$ shares with threshold $K$ ($1 \le K \le N \le 255$) over $GF(2^8)$ using irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (`0x11B`), matching [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) field arithmetic.
  - Wrap each share `Share_j` (32 bytes + 1-byte index $x_j$) to quorum member $j$'s X25519 public key using the same ephemeral-static X25519 + HKDF + AEAD construction.
- **Header Integrity & Anti-Tamper Binding:**
  - Compute the SHA-256 hash of the canonical CBOR header and sign it with the owner's [Ed25519 (RFC 8032)](https://www.rfc-editor.org/info/rfc8032/) private key.
  - Pass the SHA-256 header digest as Associated Data (`AAD`) into the payload AEAD cipher ([RFC 5116](https://www.rfc-editor.org/info/rfc5116/)) so modifying any recipient slot invalidates payload decryption.

### Step 3: Implement Both Payload Encryption Modes (Streaming File & Virtual Volume)

Support both on-demand file encryption and live virtual drive mounting using the unwrapped 256-bit `DEK`:

- **Mode A - On-Demand Streaming File Container (`.vlt`):**
  - Split the input file (or tar/zstd directory stream) into `65536`-byte (64 KB) chunks.
  - Encrypt each chunk with [ChaCha20-Poly1305 (RFC 8439)](https://www.rfc-editor.org/info/rfc8439/) or [AES-256-GCM (NIST SP 800-38D)](https://csrc.nist.gov/pubs/sp/800/38/d/final) where the 12-byte nonce is `chunk_index (11 bytes big-endian) || is_final_chunk_flag (1 byte: 0x00 or 0x01)`, matching the STREAM construction used in [age](https://github.com/filosottile/age).
- **Mode B - Mounted Virtual Encrypted Drive ([libfuse](https://github.com/libfuse/libfuse) / macFUSE / [WinFsp](https://docs.cryptomator.org/security/architecture/)):**
  - Mount a userspace overlay directory (like [gocryptfs](https://github.com/rfjakob/gocryptfs) and [Cryptomator](https://docs.cryptomator.org/security/architecture/)) where each virtual file is divided into 32 KB AEAD blocks with per-block random nonces and deterministic encrypted filenames (AES-SIV or EME), OR mount a sector-level container using [XTS-AES-256 (NIST SP 800-38E)](https://csrc.nist.gov/pubs/sp/800/38/e/final) where `Key_1 != Key_2` is strictly verified before mounting.
  - Lock the unwrapped `DEK` in non-swappable RAM (`mlock` on POSIX, `VirtualLock` on Windows) and register an immediate zeroize-and-unmount hook triggered by phone proximity timeout or manual lock command.

### Step 4: Implement the Tri-Modal Local Transport & Triple Recovery

Use a single unified CBOR `UnlockChallenge` and `UnlockResponse` envelope across all three local transports:

- **Channel 1 - Local Wi-Fi ([mDNS RFC 6762](https://www.rfc-editor.org/info/rfc6762/) + [TLS 1.3 RFC 8446](https://www.rfc-editor.org/info/rfc8446/)):** Advertise `_localauth._tcp.local.` on port `53319`. Pair new devices using a 6-digit/3-word [SPAKE2 (RFC 9382)](https://www.rfc-editor.org/info/rfc9382/) handshake to pin mutual Ed25519 TLS 1.3 certificates (following [KDE Connect](https://github.com/kde/kdeconnect-kde) and [LocalSend](https://github.com/localsend/localsend)).
- **Channel 2 - Bluetooth Low Energy ([BLE GATT LE Secure Connections](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html)):** Expose a GATT service with a challenge write characteristic and notification response characteristic, enforcing application-layer X25519 session encryption on top of BLE link security.
- **Channel 3 - Air-Gapped Optical QR ([Blockchain Commons bc-ur](https://github.com/BlockchainCommons/bc-ur)):** Encode `UnlockChallenge` as `ur:lavault-req` and `UnlockResponse` as `ur:lavault-res` using Luby-transform fountain codes for payloads exceeding a single QR frame.
- **Triple Recovery Enrolment:** Provide (1) 24-word [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) paper recovery phrase, (2) Argon2id-encrypted `.rkf` recovery keyfile, and (3) M-of-N [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) guardian recovery shares.

### Step 5: Verify with the Bundled FastMCP Server

Before completing any cryptographic, binary-format, or transport task, run the bundled verification server (`scripts/mcp_vault_dev_server.py --self-test` or via MCP tool calls):

- Call `verify_crypto_primitives` to validate [RFC 6238 TOTP](https://www.rfc-editor.org/info/rfc6238/), [RFC 3394 AES Key Wrap](https://www.rfc-editor.org/info/rfc3394/), [RFC 5869 HKDF](https://www.rfc-editor.org/info/rfc5869/), and [Project Wycheproof](https://github.com/C2SP/wycheproof) edge cases.
- Call `pack_and_inspect_vlt_header` to verify deterministic CBOR encoding and 1-of-N + K-of-N slot unwrapping.
- Call `verify_shamir_slip39_quorum` to test GF(256) threshold splitting, Lagrange interpolation, and tamper detection.
- Call `check_mobile_and_fuse_bridge` to inspect connected Android (`adb`), iOS Simulator (`xcrun simctl`), and FUSE/WinFsp mount readiness.

## Gotchas

- **Memory Residual Leaks in Rust and Dart:** Standard `Drop` in Rust does not wipe heap or stack memory because LLVM dead-store elimination removes overwrites before deallocation. Always annotate sensitive structs with `#[derive(Zeroize, ZeroizeOnDrop)]` from the [`zeroize` crate](https://crates.io/crates/zeroize), and keep raw keys inside Rust rather than passing long-lived key buffers across [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge) into the Dart garbage-collected heap.
- **XTS-AES Identical Subkey Vulnerability:** Under [NIST SP 800-38E](https://content.govdelivery.com/accounts/USNIST/bulletins/3479da8), XTS-AES-256 uses a 512-bit key split into two 256-bit keys (`Key_1` for block encryption, `Key_2` for tweak encryption). If `Key_1 == Key_2`, XTS degrades catastrophically. Always assert `key[..32] != key[32..]` before mounting a block volume.
- **Android Keystore X25519 API Level Differences:** Hardware-backed `X25519` key agreement inside `AndroidKeyStore` requires API level 31+ (Android 12+). For older devices or uniform [BIP-0039](https://bitcoin.org/bip/39/) recovery compatibility, store a hardware-bound AES-256-GCM wrapping key in `AndroidKeyStore` / `SecureEnclave` (with `setUserAuthenticationRequired(true)`) that unwraps the deterministic `MasterIdentitySeed` into Rust locked memory only during an authenticated session.
- **Unauthenticated UDP Discovery Spoofing:** As documented in the [2025 KDE Connect Security Advisory](https://kde.org/info/security/advisory-20250418-2.txt), unauthenticated UDP mDNS packets can spoof device names on untrusted Wi-Fi networks. Never trust display names from raw UDP discovery packets; only display verified device identities from the pinned TLS 1.3 certificate or SPAKE2 transcript.
