# LaVault

Cross-platform, zero-cloud **Local Mobile Authenticator**, **Password + Live TOTP Vault**, and **Multi-User File & Virtual Volume Unlocker** built in Rust + Flutter (`flutter_rust_bridge`).

## Downloads (GitHub Releases)

Download pre-built binaries directly from [Releases](https://github.com/lauyeehow1986-hub/LAVault/releases):
- **Android Mobile App (`lavault-android.apk`):** Install directly on your Android phone (stores passwords + live TOTP codes behind biometrics/keystore and approves PC unlocks via Wi-Fi TLS 1.3, BLE GATT, or QR).
- **Windows Desktop (`lavault-windows-x64.zip`):** Contains `app_flutter.exe`, `vault_core.dll`, and the `lavault.exe` CLI.
- **Linux CLI (`lavault-cli-linux-x64.tar.gz`):** `lavault` CLI binary.

## Architecture

- `crates/vault_core/` — Shared Rust cryptographic core (`zeroize`, Argon2id, HKDF-SHA256, X25519, Ed25519, RFC 4226/6238 HOTP/TOTP, SQLite + XChaCha20-Poly1305 vault, `LAVAULT1` CBOR `.vlt` 1-of-N & K-of-N Shamir GF(256) `0x11B` containers, 64 KB STREAM encryption, 32 KB overlay VFS + XTS-AES-256, BIP-39 / `.rkf` / Guardian recovery, `bc-ur`, SPAKE2, `flutter_rust_bridge` API).
- `crates/desktop_daemon/` — Desktop CLI (`lock`, `unlock`, `mount`, `recipients add/remove`, `pair`), mDNS (`_localauth._tcp.local.:53319`) + pinned mutual Ed25519 TLS 1.3, `btleplug` BLE GATT, optical QR, and virtual volume manager.
- `app_flutter/` — Unified Flutter 3-tab app (`Vault + TOTP`, `Unlocker`, `Peers`) with `local_auth` & `flutter_secure_storage`.
- `mcp/mcp_vault_dev_server.py` — FastMCP verification server (`--self-test`).

## Quick Test Commands

```bash
python3 mcp/mcp_vault_dev_server.py --self-test
cargo test --workspace
cd app_flutter && flutter analyze && flutter test
```
