use hadron_core::{Result, ScanType, ScanJobId, ScanStatus, SystemStatus, ScanProgress, ScanResult, QuarantineEntry, RemovableDevice, DeviceType};
use hadron_core::config::AntivirusConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
pub struct MockApiClient {
    connected: Arc<RwLock<bool>>,
}
impl MockApiClient {
    pub fn new(_pipe_name: String) -> Self {
        Self {
            connected: Arc::new(RwLock::new(false)),
        }
    }
    pub async fn connect(&self) -> Result<()> {
        *self.connected.write().await = true;
        tracing::info!("Mock API client connected");
        Ok(())
    }
    pub async fn disconnect(&self) -> Result<()> {
        *self.connected.write().await = false;
        tracing::info!("Mock API client disconnected");
        Ok(())
    }
    pub async fn start_scan(&self, scan_type: ScanType, _targets: Vec<PathBuf>) -> Result<ScanJobId> {
        tracing::info!("Mock: Starting {:?} scan", scan_type);
        Ok(uuid::Uuid::new_v4())
    }
    pub async fn get_scan_status(&self, _job_id: ScanJobId) -> Result<ScanStatus> {
        Ok(ScanStatus::Running)
    }
    pub async fn get_system_status(&self) -> Result<SystemStatus> {
        Ok(SystemStatus {
            version: "1.0.0".to_string(),
            last_update: "2024.01.01".to_string(),
            real_time_protection: true,
            last_scan: Some(chrono::Utc::now()),
            threats_blocked_today: 0,
            total_threats_blocked: 0,
            license_status: "Active".to_string(),
            scan_engine_version: "1.0.0".to_string(),
            signature_database_version: "2024.01.01".to_string(),
            uptime_seconds: 3600,
            memory_usage_mb: 256,
            cpu_usage_percent: 15.5,
            quarantine_count: 0,
            system_health: "Good".to_string(),
        })
    }
    pub async fn get_scan_progress(&self, job_id: ScanJobId) -> Result<ScanProgress> {
        Ok(ScanProgress {
            scan_id: job_id,
            percentage_complete: 50.0,
            files_scanned: 1000,
            total_files: Some(2000),
            threats_found: 0,
            current_file: Some(PathBuf::from("C:\\Windows\\System32\\kernel32.dll")),
            estimated_time_remaining: Some(30000),
        })
    }
    pub async fn get_scan_result(&self, job_id: ScanJobId) -> Result<hadron_core::ScanResult> {
        use hadron_core::{ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
        let mut threats = Vec::new();
        if let Ok(threat1) = ThreatInfo::new(
            "Win32.TestVirus.A".to_string(),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from("C:\\Users\\Test\\Downloads\\suspicious.exe"),
            "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
            DetectionMethod::Signature,
        ) {
            threats.push(threat1);
        }
        if let Ok(threat2) = ThreatInfo::new(
            "Trojan.Generic.KD.12345".to_string(),
            ThreatType::Trojan,
            ThreatSeverity::Critical,
            PathBuf::from("C:\\Temp\\malware.dll"),
            "b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1".to_string(),
            DetectionMethod::Heuristic,
        ) {
            threats.push(threat2);
        }
        if let Ok(threat3) = ThreatInfo::new(
            "Adware.BrowserHelper".to_string(),
            ThreatType::Adware,
            ThreatSeverity::Medium,
            PathBuf::from("C:\\Program Files\\SuspiciousApp\\helper.exe"),
            "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2".to_string(),
            DetectionMethod::MachineLearning,
        ) {
            threats.push(threat3);
        }
        Ok(hadron_core::ScanResult {
            scan_id: job_id,
            scan_type: ScanType::QuickScan,
            status: ScanStatus::Completed,
            start_time: chrono::Utc::now() - chrono::Duration::minutes(5),
            end_time: Some(chrono::Utc::now()),
            scanned_files: 15420,
            threats_found: threats,
            errors: vec![],
            scan_path: Some(std::path::PathBuf::from("/")),
            total_size_scanned: 1024 * 1024 * 100, // 100MB
            scan_duration_ms: Some(300000),
        })
    }
    pub async fn get_quarantine_list(&self) -> Result<Vec<QuarantineEntry>> {
        Ok(vec![])
    }
    pub async fn restore_from_quarantine(&self, quarantine_id: String) -> Result<()> {
        tracing::info!("Mock: Restoring from quarantine: {}", quarantine_id);
        Ok(())
    }
    pub async fn delete_from_quarantine(&self, quarantine_id: String) -> Result<()> {
        tracing::info!("Mock: Deleting from quarantine: {}", quarantine_id);
        Ok(())
    }
    pub async fn check_updates(&self) -> Result<Vec<hadron_core::UpdateInfo>> {
        Ok(vec![])
    }
    pub async fn apply_updates(&self) -> Result<()> {
        tracing::info!("Mock: Applying updates");
        Ok(())
    }
    pub async fn get_configuration(&self) -> Result<AntivirusConfig> {
        Ok(AntivirusConfig::default())
    }
    pub async fn update_configuration_value(&self, key: String, value: String) -> Result<()> {
        tracing::info!("Mock: Updating configuration: {} = {}", key, value);
        Ok(())
    }
    pub async fn get_removable_devices(&self) -> Result<Vec<RemovableDevice>> {
        let mut devices = Vec::new();
        let device1 = RemovableDevice {
            id: "usb_001".to_string(),
            name: "Kingston DataTraveler".to_string(),
            device_type: DeviceType::UsbDrive,
            mount_path: PathBuf::from("/Volumes/KINGSTON"),
            size_bytes: 8_000_000_000,
            is_trusted: false,
            last_scan: None,
            threat_count: 0,
        };
        devices.push(device1);
        let device2 = RemovableDevice {
            id: "sd_001".to_string(),
            name: "SanDisk Ultra".to_string(),
            device_type: DeviceType::SdCard,
            mount_path: PathBuf::from("/Volumes/SANDISK"),
            size_bytes: 32_000_000_000,
            is_trusted: true,
            last_scan: Some(chrono::Utc::now() - chrono::Duration::hours(2)),
            threat_count: 0,
        };
        devices.push(device2);
        let device3 = RemovableDevice {
            id: "hdd_001".to_string(),
            name: "Seagate Backup Plus".to_string(),
            device_type: DeviceType::ExternalHdd,
            mount_path: PathBuf::from("/Volumes/BACKUP"),
            size_bytes: 1_000_000_000_000,
            is_trusted: false,
            last_scan: Some(chrono::Utc::now() - chrono::Duration::days(1)),
            threat_count: 2,
        };
        devices.push(device3);
        Ok(devices)
    }
    pub async fn scan_removable_device(&self, device_id: String) -> Result<ScanJobId> {
        tracing::info!("Mock: Scanning removable device: {}", device_id);
        let scan_id = uuid::Uuid::new_v4();
        if device_id.contains("usb") {
            tracing::info!("Mock: USB device scan will find threats");
        } else {
            tracing::info!("Mock: Device scan will be clean");
        }
        Ok(scan_id)
    }
    pub async fn get_removable_device_scan_result(&self, device_id: String) -> Result<hadron_core::ScanResult> {
        use hadron_core::{ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
        let scan_id = uuid::Uuid::new_v4();
        let mut threats = Vec::new();
        if device_id.contains("usb") {
            if let Ok(threat) = ThreatInfo::new(
                "USB.Autorun.Virus".to_string(),
                ThreatType::Virus,
                ThreatSeverity::High,
                PathBuf::from("/Volumes/KINGSTON/autorun.inf"),
                "d4e5f6789012345678901234567890123456789012345678901234567890a1b2c3".to_string(),
                DetectionMethod::Signature,
            ) {
                threats.push(threat);
            }
            if let Ok(threat) = ThreatInfo::new(
                "Suspicious.Executable".to_string(),
                ThreatType::Suspicious,
                ThreatSeverity::Medium,
                PathBuf::from("/Volumes/KINGSTON/setup.exe"),
                "e5f6789012345678901234567890123456789012345678901234567890a1b2c3d4".to_string(),
                DetectionMethod::Heuristic,
            ) {
                threats.push(threat);
            }
        }
        let files_scanned = if device_id.contains("hdd") { 5000 } else { 150 };
        Ok(hadron_core::ScanResult {
            scan_id,
            scan_type: ScanType::CustomScan,
            status: ScanStatus::Completed,
            start_time: chrono::Utc::now() - chrono::Duration::seconds(30),
            end_time: Some(chrono::Utc::now()),
            scanned_files: files_scanned,
            threats_found: threats.clone(),
            errors: vec![],
            scan_path: Some(std::path::PathBuf::from(&device_id)),
            total_size_scanned: files_scanned * 1024, // Approximate size
            scan_duration_ms: Some(30000),
        })
    }
    pub async fn clean_removable_device(&self, device_id: String) -> Result<()> {
        tracing::info!("Mock: Cleaning removable device: {}", device_id);
        Ok(())
    }
    pub async fn set_device_trust(&self, device_id: String, trusted: bool) -> Result<()> {
        tracing::info!("Mock: Setting device {} trust to: {}", device_id, trusted);
        Ok(())
    }
}