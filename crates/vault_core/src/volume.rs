use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::cipher::KeyInit as AesKeyInit;
use aes::Aes256;
use aes_siv::{
    aead::{Aead as SivAead, Payload as SivPayload},
    Aes256SivAead, Nonce as SivNonce,
};
use chacha20poly1305::{aead::Payload, XChaCha20Poly1305, XNonce};
use data_encoding::BASE64URL_NOPAD;
use xts_mode::{get_tweak_default, Xts128};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, VaultError};
use crate::identity::{hkdf_sha256, INFO_XTS_AES_512};

pub const OVERLAY_BLOCK_SIZE: usize = 32768;
const OVERLAY_FILE_MAGIC: &[u8; 8] = b"LAVBLK1\0";

fn lock_slice_in_ram(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(ptr as *const core::ffi::c_void, len) != 0
    }
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len) == 0
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (ptr, len);
        false
    }
}

fn unlock_slice_in_ram(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualUnlock(
            ptr as *const core::ffi::c_void,
            len,
        );
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// 512-bit XTS-AES-256 volume key (`Key_1 || Key_2`), strictly asserting `Key_1 != Key_2` per NIST SP 800-38E.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XtsVolumeKey {
    bytes: Box<[u8; 64]>,
    #[zeroize(skip)]
    ram_locked: bool,
}

impl XtsVolumeKey {
    pub fn from_bytes(raw: &[u8; 64]) -> Result<Self> {
        if raw[..32] == raw[32..] {
            return Err(VaultError::Crypto(
                "NIST SP 800-38E violation: XTS-AES-256 Key_1 and Key_2 must not be identical"
                    .into(),
            ));
        }
        let mut boxed = Box::new(*raw);
        let ram_locked = lock_slice_in_ram(boxed.as_ptr(), boxed.len());
        let _ = &mut boxed;
        Ok(Self {
            bytes: boxed,
            ram_locked,
        })
    }

    pub fn derive_from_seed(seed: &[u8], salt: &[u8]) -> Result<Self> {
        let mut derived = hkdf_sha256(seed, salt, INFO_XTS_AES_512, 64)?;
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&derived);
        derived.zeroize();
        let res = Self::from_bytes(&arr);
        arr.zeroize();
        res
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    pub fn is_ram_locked(&self) -> bool {
        self.ram_locked
    }

    pub fn wipe_and_unlock(&mut self) {
        self.bytes.zeroize();
        if self.ram_locked {
            unlock_slice_in_ram(self.bytes.as_ptr(), self.bytes.len());
            self.ram_locked = false;
        }
    }
}

/// Sector-level XTS-AES-256 encrypted virtual disk container.
pub struct XtsBlockContainer {
    file: File,
    key: Option<XtsVolumeKey>,
    sector_size: usize,
    sector_count: u64,
}

impl XtsBlockContainer {
    pub fn create_or_open(
        path: &Path,
        key: XtsVolumeKey,
        sector_count: u64,
        sector_size: usize,
    ) -> Result<Self> {
        if sector_size < 16 || sector_size % 16 != 0 {
            return Err(VaultError::InvalidInput(
                "XTS sector size must be a multiple of 16 bytes (>= 16)".into(),
            ));
        }
        let total_size = sector_count * sector_size as u64;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let meta = file.metadata()?;
        if meta.len() < total_size {
            file.set_len(total_size)?;
        }
        Ok(Self {
            file,
            key: Some(key),
            sector_size,
            sector_count,
        })
    }

    fn xts_cipher(&self) -> Result<Xts128<Aes256>> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| VaultError::AuthFailed("XTS volume is locked".into()))?;
        let raw = key.as_bytes();
        if raw[..32] == raw[32..] {
            return Err(VaultError::Crypto("XTS identical subkey violation".into()));
        }
        let c1 = Aes256::new_from_slice(&raw[..32])
            .map_err(|e| VaultError::Crypto(format!("AES key1 init: {e}")))?;
        let c2 = Aes256::new_from_slice(&raw[32..])
            .map_err(|e| VaultError::Crypto(format!("AES key2 init: {e}")))?;
        Ok(Xts128::<Aes256>::new(c1, c2))
    }

    pub fn write_sector(&mut self, sector_index: u64, data: &[u8]) -> Result<()> {
        if sector_index >= self.sector_count {
            return Err(VaultError::InvalidInput("sector index out of bounds".into()));
        }
        if data.len() != self.sector_size {
            return Err(VaultError::InvalidInput(format!(
                "expected {} byte sector, got {}",
                self.sector_size,
                data.len()
            )));
        }
        let xts = self.xts_cipher()?;
        let mut buf = data.to_vec();
        xts.encrypt_sector(&mut buf, get_tweak_default(sector_index as u128));
        self.file
            .seek(SeekFrom::Start(sector_index * self.sector_size as u64))?;
        self.file.write_all(&buf)?;
        self.file.flush()?;
        buf.zeroize();
        Ok(())
    }

    pub fn read_sector(&mut self, sector_index: u64) -> Result<Vec<u8>> {
        if sector_index >= self.sector_count {
            return Err(VaultError::InvalidInput("sector index out of bounds".into()));
        }
        let xts = self.xts_cipher()?;
        let mut buf = vec![0u8; self.sector_size];
        self.file
            .seek(SeekFrom::Start(sector_index * self.sector_size as u64))?;
        self.file.read_exact(&mut buf)?;
        xts.decrypt_sector(&mut buf, get_tweak_default(sector_index as u128));
        Ok(buf)
    }

    pub fn lock_and_zeroize(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.wipe_and_unlock();
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct OverlayRamKeys {
    siv_key: Box<[u8; 64]>,
    block_key: Box<[u8; 32]>,
    #[zeroize(skip)]
    ram_locked: bool,
}

impl OverlayRamKeys {
    fn from_master(master_key: &[u8; 32]) -> Result<Self> {
        let mut siv_vec = hkdf_sha256(
            master_key,
            b"lavault-overlay-v1",
            b"local-auth-vault/v1/overlay-filename-siv",
            64,
        )?;
        let mut blk_vec = hkdf_sha256(
            master_key,
            b"lavault-overlay-v1",
            b"local-auth-vault/v1/overlay-block-aead",
            32,
        )?;
        let mut siv_arr = [0u8; 64];
        siv_arr.copy_from_slice(&siv_vec);
        siv_vec.zeroize();

        let mut blk_arr = [0u8; 32];
        blk_arr.copy_from_slice(&blk_vec);
        blk_vec.zeroize();

        let siv_key = Box::new(siv_arr);
        let block_key = Box::new(blk_arr);
        siv_arr.zeroize();
        blk_arr.zeroize();

        let locked1 = lock_slice_in_ram(siv_key.as_ptr(), siv_key.len());
        let locked2 = lock_slice_in_ram(block_key.as_ptr(), block_key.len());

        Ok(Self {
            siv_key,
            block_key,
            ram_locked: locked1 && locked2,
        })
    }

    fn wipe(&mut self) {
        self.siv_key.zeroize();
        self.block_key.zeroize();
        if self.ram_locked {
            unlock_slice_in_ram(self.siv_key.as_ptr(), self.siv_key.len());
            unlock_slice_in_ram(self.block_key.as_ptr(), self.block_key.len());
            self.ram_locked = false;
        }
    }
}

/// Userspace encrypted overlay directory (32 KB AEAD blocks + AES-SIV deterministic encrypted filenames).
pub struct OverlayEncryptedVolume {
    backing_dir: PathBuf,
    keys: Option<OverlayRamKeys>,
}

impl OverlayEncryptedVolume {
    pub fn mount(backing_dir: &Path, master_key: &[u8; 32]) -> Result<Self> {
        fs::create_dir_all(backing_dir)?;
        let keys = OverlayRamKeys::from_master(master_key)?;
        Ok(Self {
            backing_dir: backing_dir.to_path_buf(),
            keys: Some(keys),
        })
    }

    pub fn is_mounted(&self) -> bool {
        self.keys.is_some()
    }

    pub fn backing_dir(&self) -> &Path {
        &self.backing_dir
    }

    pub fn unmount_and_zeroize(&mut self) {
        if let Some(mut k) = self.keys.take() {
            k.wipe();
        }
    }

    fn keys(&self) -> Result<&OverlayRamKeys> {
        self.keys
            .as_ref()
            .ok_or_else(|| VaultError::AuthFailed("virtual volume is locked/unmounted".into()))
    }

    fn encrypt_filename(&self, logical_name: &str) -> Result<(String, Vec<u8>)> {
        if logical_name.is_empty() || logical_name.contains("..") {
            return Err(VaultError::InvalidInput("invalid virtual filename".into()));
        }
        let keys = self.keys()?;
        let siv = Aes256SivAead::new_from_slice(keys.siv_key.as_slice())
            .map_err(|e| VaultError::Crypto(format!("AES-SIV init failed: {e}")))?;
        let nonce = SivNonce::from_slice(b"lavault-siv-128b");
        let ct = siv
            .encrypt(
                nonce,
                SivPayload {
                    msg: logical_name.as_bytes(),
                    aad: b"lavault-filename-v1",
                },
            )
            .map_err(|e| VaultError::Crypto(format!("AES-SIV filename encrypt failed: {e}")))?;
        let encoded = BASE64URL_NOPAD.encode(&ct);
        Ok((format!("{encoded}.lvb"), ct))
    }

    fn decrypt_filename(&self, disk_name: &str) -> Result<String> {
        let stem = disk_name
            .strip_suffix(".lvb")
            .ok_or_else(|| VaultError::InvalidInput("not a .lvb overlay file".into()))?;
        let ct = BASE64URL_NOPAD
            .decode(stem.as_bytes())
            .map_err(|_| VaultError::InvalidInput("invalid base64url filename".into()))?;
        let keys = self.keys()?;
        let siv = Aes256SivAead::new_from_slice(keys.siv_key.as_slice())
            .map_err(|e| VaultError::Crypto(format!("AES-SIV init failed: {e}")))?;
        let nonce = SivNonce::from_slice(b"lavault-siv-128b");
        let pt = siv
            .decrypt(
                nonce,
                SivPayload {
                    msg: &ct,
                    aad: b"lavault-filename-v1",
                },
            )
            .map_err(|_| VaultError::AuthFailed("AES-SIV filename decrypt failed".into()))?;
        String::from_utf8(pt)
            .map_err(|_| VaultError::Storage("decrypted filename is not UTF-8".into()))
    }

    pub fn write_file(&self, logical_name: &str, data: &[u8]) -> Result<()> {
        let keys = self.keys()?;
        let (disk_name, name_ct) = self.encrypt_filename(logical_name)?;
        let disk_path = self.backing_dir.join(disk_name);

        let cipher = XChaCha20Poly1305::new(keys.block_key.as_slice().into());
        let mut out = Vec::with_capacity(16 + data.len() + 1024);
        out.extend_from_slice(OVERLAY_FILE_MAGIC);
        out.extend_from_slice(&(data.len() as u64).to_be_bytes());

        let total_blocks = if data.is_empty() {
            1
        } else {
            data.len().div_ceil(OVERLAY_BLOCK_SIZE)
        };

        for block_idx in 0..total_blocks {
            let start = block_idx * OVERLAY_BLOCK_SIZE;
            let end = ((block_idx + 1) * OVERLAY_BLOCK_SIZE).min(data.len());
            let block = &data[start..end];

            let mut nonce = [0u8; 24];
            getrandom::getrandom(&mut nonce)
                .map_err(|e| VaultError::Crypto(format!("getrandom nonce failed: {e}")))?;

            let mut aad = Vec::with_capacity(name_ct.len() + 8);
            aad.extend_from_slice(&name_ct);
            aad.extend_from_slice(&(block_idx as u64).to_be_bytes());

            let ct = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: block,
                        aad: &aad,
                    },
                )
                .map_err(|e| VaultError::Crypto(format!("overlay block encrypt failed: {e}")))?;

            out.extend_from_slice(&nonce);
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&ct);
        }

        fs::write(disk_path, out)?;
        Ok(())
    }

    pub fn read_file(&self, logical_name: &str) -> Result<Vec<u8>> {
        let keys = self.keys()?;
        let (disk_name, name_ct) = self.encrypt_filename(logical_name)?;
        let disk_path = self.backing_dir.join(disk_name);
        let raw = fs::read(disk_path)?;
        if raw.len() < 16 || &raw[..8] != OVERLAY_FILE_MAGIC {
            return Err(VaultError::InvalidInput("corrupt overlay file header".into()));
        }

        let expected_len = u64::from_be_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| VaultError::InvalidInput("bad overlay len".into()))?,
        ) as usize;

        let cipher = XChaCha20Poly1305::new(keys.block_key.as_slice().into());
        let mut offset = 16usize;
        let mut block_idx = 0u64;
        let mut plaintext = Vec::with_capacity(expected_len);

        while offset < raw.len() {
            if offset + 28 > raw.len() {
                return Err(VaultError::InvalidInput("truncated overlay block".into()));
            }
            let nonce = &raw[offset..offset + 24];
            let ct_len = u32::from_be_bytes(
                raw[offset + 24..offset + 28]
                    .try_into()
                    .map_err(|_| VaultError::InvalidInput("bad block len".into()))?,
            ) as usize;
            offset += 28;
            if offset + ct_len > raw.len() {
                return Err(VaultError::InvalidInput("truncated overlay block ct".into()));
            }
            let ct = &raw[offset..offset + ct_len];
            offset += ct_len;

            let mut aad = Vec::with_capacity(name_ct.len() + 8);
            aad.extend_from_slice(&name_ct);
            aad.extend_from_slice(&block_idx.to_be_bytes());

            let pt = cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload { msg: ct, aad: &aad },
                )
                .map_err(|_| VaultError::AuthFailed("overlay block authentication failed".into()))?;
            plaintext.extend_from_slice(&pt);
            block_idx += 1;
        }

        if plaintext.len() != expected_len {
            return Err(VaultError::AuthFailed("overlay file length mismatch".into()));
        }
        Ok(plaintext)
    }

    pub fn list_files(&self) -> Result<Vec<String>> {
        let _ = self.keys()?;
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.backing_dir)? {
            let entry = entry?;
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.ends_with(".lvb") {
                names.push(self.decrypt_filename(&fname)?);
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn rename_file(&self, old_name: &str, new_name: &str) -> Result<()> {
        let data = self.read_file(old_name)?;
        self.write_file(new_name, &data)?;
        self.delete_file(old_name)?;
        Ok(())
    }

    pub fn delete_file(&self, logical_name: &str) -> Result<()> {
        let (disk_name, _) = self.encrypt_filename(logical_name)?;
        fs::remove_file(self.backing_dir.join(disk_name))?;
        Ok(())
    }
}
