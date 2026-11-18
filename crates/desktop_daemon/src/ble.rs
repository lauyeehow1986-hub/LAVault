use anyhow::Result;
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use vault_core::transport::{
    BLE_GATT_CHALLENGE_CHAR_UUID, BLE_GATT_RESPONSE_CHAR_UUID, BLE_GATT_SERVICE_UUID,
};

#[derive(Debug, Clone)]
pub struct DiscoveredBleVault {
    pub name: String,
    pub address: String,
}

/// Scan nearby BLE peripherals advertising LaVault GATT service UUID `0000fffd-0000-1000-8000-00805f9b34fb`.
pub async fn scan_ble_authenticators() -> Result<Vec<DiscoveredBleVault>> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let mut found = Vec::new();
    for adapter in adapters {
        let _ = adapter.start_scan(ScanFilter::default()).await;
        let peripherals = adapter.peripherals().await?;
        for p in peripherals {
            if let Ok(Some(props)) = p.properties().await {
                let has_service = props
                    .services
                    .iter()
                    .any(|u| u.to_string().eq_ignore_ascii_case(BLE_GATT_SERVICE_UUID));
                if has_service {
                    found.push(DiscoveredBleVault {
                        name: props.local_name.unwrap_or_else(|| "LaVault Phone".into()),
                        address: props.address.to_string(),
                    });
                }
            }
        }
        let _ = adapter.stop_scan().await;
    }
    Ok(found)
}

pub fn ble_gatt_profile_summary() -> (&'static str, &'static str, &'static str) {
    (
        BLE_GATT_SERVICE_UUID,
        BLE_GATT_CHALLENGE_CHAR_UUID,
        BLE_GATT_RESPONSE_CHAR_UUID,
    )
}
