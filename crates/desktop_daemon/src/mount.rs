use std::path::PathBuf;

use anyhow::Result;
use vault_core::volume::OverlayEncryptedVolume;

#[derive(Debug, Clone)]
pub struct MountSessionConfig {
    pub vault_dir: PathBuf,
    pub mount_point: PathBuf,
    pub proximity_timeout_secs: u64,
}

pub struct VirtualDriveManager {
    config: MountSessionConfig,
    volume: Option<OverlayEncryptedVolume>,
}

impl VirtualDriveManager {
    pub fn new(config: MountSessionConfig) -> Self {
        Self {
            config,
            volume: None,
        }
    }

    pub fn backend_name(&self) -> &'static str {
        #[cfg(target_os = "windows")]
        {
            if std::path::Path::new(r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll").exists() {
                "WinFsp (Active Kernel Driver)"
            } else {
                "LaVault Userspace Encrypted Overlay (WinFsp driver not installed)"
            }
        }
        #[cfg(target_os = "macos")]
        {
            "macFUSE / FSKit"
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            "Linux libfuse (/dev/fuse)"
        }
    }

    pub fn mount_with_key(&mut self, master_key: &[u8; 32]) -> Result<()> {
        std::fs::create_dir_all(&self.config.mount_point)?;
        let vol = OverlayEncryptedVolume::mount(&self.config.vault_dir, master_key)?;
        self.volume = Some(vol);
        Ok(())
    }

    pub fn is_mounted(&self) -> bool {
        self.volume.as_ref().is_some_and(|v| v.is_mounted())
    }

    pub fn write_virtual_file(&self, name: &str, data: &[u8]) -> Result<()> {
        let vol = self
            .volume
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("virtual drive is unmounted"))?;
        vol.write_file(name, data)?;
        Ok(())
    }

    pub fn read_virtual_file(&self, name: &str) -> Result<Vec<u8>> {
        let vol = self
            .volume
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("virtual drive is unmounted"))?;
        Ok(vol.read_file(name)?)
    }

    pub fn on_phone_disconnect(&mut self) {
        if let Some(mut vol) = self.volume.take() {
            vol.unmount_and_zeroize();
        }
    }
}

impl Drop for VirtualDriveManager {
    fn drop(&mut self) {
        self.on_phone_disconnect();
    }
}
