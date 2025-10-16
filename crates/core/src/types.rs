use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;
use crate::Result;
use bytes::Bytes;

// Missing struct definitions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub process_name: String,
    pub executable_path: PathBuf,
    pub command_line: String,
    pub parent_process_id: u32,
    pub creation_time: DateTime<Utc>,
    pub user_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub process_id: u32,
    pub creation_time: DateTime<Utc>,
    pub start_address: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub image_path: PathBuf,
    pub base_address: u64,
    pub image_size: u64,
    pub process_id: u32,
    pub load_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: ScanId,
    pub current_file: Option<PathBuf>,
    pub files_scanned: u64,
    pub total_files: Option<u64>,
    pub threats_found: u64,
    pub percentage_complete: f32,
    pub estimated_time_remaining: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatAction {
    Delete,
    Quarantine,
    Ignore,
    Block,
    Allow,
}

pub type ThreatActionResult = ActionResult;

// Removable device types for GUI
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemovableDevice {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub mount_path: PathBuf,
    pub size_bytes: u64,
    pub is_trusted: bool,
    pub last_scan: Option<DateTime<Utc>>,
    pub threat_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeviceType {
    UsbDrive,
    SdCard,
    ExternalHdd,
    CdDvd,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub threat_name: String,
    pub quarantine_time: DateTime<Utc>,
    pub file_size: u64,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
}

pub type ThreatId = Uuid;
pub type ScanId = Uuid;
pub type ScanJobId = Uuid;
pub type QuarantineId = Uuid;
pub type SandboxId = Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatType {
    Virus,
    Trojan,
    Worm,
    Ransomware,
    Spyware,
    Adware,
    Rootkit,
    Backdoor,
    Keylogger,
    BrowserHijacker,
    PotentiallyUnwantedProgram,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DetectionMethod {
    Signature,
    Heuristic,
    MachineLearning,
    Behavioral,
    CloudReputation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanType {
    QuickScan,
    FullScan,
    CustomScan,
    RealTimeProtection,
    OnDemand,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    Quarantined,
    Restored,
    Deleted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ActionType {
    Quarantine,
    Delete,
    Ignore,
    Restore,
    Clean,
    Block,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub id: ThreatId,
    pub name: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub file_path: PathBuf,
    pub file_hash: String,
    pub file_size: u64,
    pub detection_method: DetectionMethod,
    pub detection_time: DateTime<Utc>,
    pub description: Option<String>,
    pub risk_score: u8,
    pub is_false_positive: bool,
    pub metadata: HashMap<String, String>,
    pub additional_info: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

impl ThreatInfo {
    pub fn new(
        name: String,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        file_path: PathBuf,
        file_hash: String,
        detection_method: DetectionMethod,
    ) -> Result<Self> {
        if name.is_empty() {
            return Err(crate::AntivirusError::Internal("Threat name cannot be empty".to_string()));
        }
        
        if file_hash.len() != 64 {
            return Err(crate::AntivirusError::Internal("Invalid hash length".to_string()));
        }

        let risk_score = Self::calculate_risk_score(&threat_type, &severity);
        
        Ok(ThreatInfo {
            id: Uuid::new_v4(),
            name,
            threat_type,
            severity,
            file_path: file_path.clone(),
            file_hash,
            file_size: 0,
            detection_method,
            detection_time: Utc::now(),
            description: None,
            risk_score,
            is_false_positive: false,
            metadata: HashMap::new(),
            additional_info: HashMap::new(),
            timestamp: Utc::now(),
        })
    }

    fn calculate_risk_score(threat_type: &ThreatType, severity: &ThreatSeverity) -> u8 {
        let base_score = match severity {
            ThreatSeverity::Low => 25,
            ThreatSeverity::Medium => 50,
            ThreatSeverity::High => 75,
            ThreatSeverity::Critical => 100,
        };

        let type_modifier = match threat_type {
            ThreatType::Ransomware => 25,
            ThreatType::Rootkit => 20,
            ThreatType::Backdoor => 20,
            ThreatType::Trojan => 15,
            ThreatType::Virus => 10,
            ThreatType::Worm => 10,
            ThreatType::Keylogger => 15,
            ThreatType::Spyware => 10,
            ThreatType::BrowserHijacker => 5,
            ThreatType::Adware => -10,
            ThreatType::PotentiallyUnwantedProgram => -15,
            ThreatType::Suspicious => 0,
            ThreatType::Unknown => 0,
        };

        std::cmp::min(100, std::cmp::max(0, base_score as i16 + type_modifier) as u8)
    }

    pub fn get_risk_score(&self) -> u8 {
        self.risk_score
    }

    pub fn requires_immediate_action(&self) -> bool {
        self.risk_score >= 75
    }

    pub fn update_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn mark_as_false_positive(&mut self) {
        self.is_false_positive = true;
        self.risk_score = 0;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: ScanId,
    pub scan_type: ScanType,
    pub status: ScanStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub scanned_files: u64,
    pub threats_found: Vec<ThreatInfo>,
    pub errors: Vec<String>,
    pub scan_path: Option<PathBuf>,
    pub total_size_scanned: u64,
    pub scan_duration_ms: Option<u64>,
}

impl ScanResult {
    pub fn new(scan_id: ScanId) -> Self {
        ScanResult {
            scan_id,
            scan_type: ScanType::QuickScan,
            status: ScanStatus::Pending,
            start_time: Utc::now(),
            end_time: None,
            scanned_files: 0,
            threats_found: Vec::new(),
            errors: Vec::new(),
            scan_path: None,
            total_size_scanned: 0,
            scan_duration_ms: None,
        }
    }

    pub fn add_threat(&mut self, threat: ThreatInfo) {
        self.threats_found.push(threat);
    }

    pub fn add_error(&mut self, path: PathBuf, error: String) {
        self.errors.push(format!("{}: {}", path.display(), error));
    }

    pub fn complete_scan(&mut self) {
        self.end_time = Some(Utc::now());
        self.status = ScanStatus::Completed;
        if let Some(end_time) = self.end_time {
            self.scan_duration_ms = Some((end_time - self.start_time).num_milliseconds() as u64);
        }
    }

    pub fn get_threats_by_severity(&self, severity: ThreatSeverity) -> Vec<&ThreatInfo> {
        self.threats_found.iter().filter(|t| t.severity == severity).collect()
    }

    pub fn get_high_risk_threats(&self) -> Vec<&ThreatInfo> {
        self.threats_found
            .iter()
            .filter(|threat| threat.requires_immediate_action())
            .collect()
    }

    pub fn has_critical_threats(&self) -> bool {
        self.threats_found
            .iter()
            .any(|threat| threat.severity == ThreatSeverity::Critical)
    }
}

impl QuarantineEntry {
    pub fn get_file_name(&self) -> String {
        self.original_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Unknown")
            .to_string()
    }

    pub fn get_formatted_size(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if self.file_size >= GB {
            format!("{:.2} GB", self.file_size as f64 / GB as f64)
        } else if self.file_size >= MB {
            format!("{:.2} MB", self.file_size as f64 / MB as f64)
        } else if self.file_size >= KB {
            format!("{:.2} KB", self.file_size as f64 / KB as f64)
        } else {
            format!("{} B", self.file_size)
        }
    }

    pub fn age_in_days(&self) -> i64 {
        let now = Utc::now();
        (now - self.quarantine_time).num_days()
    }

    pub fn should_auto_delete(&self, retention_days: i64) -> bool {
        self.age_in_days() > retention_days
    }
}



#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemStatus {
    pub version: String,
    pub last_update: String,
    pub real_time_protection: bool,
    pub last_scan: Option<DateTime<Utc>>,
    pub threats_blocked_today: u32,
    pub total_threats_blocked: u64,
    pub quarantine_count: u32,
    pub scan_engine_version: String,
    pub signature_database_version: String,
    pub license_status: String,
    pub system_health: String,
    pub uptime_seconds: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f32,
}

impl SystemStatus {
    pub fn new(version: String, last_update: String) -> Self {
        SystemStatus {
            version,
            last_update,
            real_time_protection: true,
            last_scan: None,
            threats_blocked_today: 0,
            total_threats_blocked: 0,
            quarantine_count: 0,
            scan_engine_version: "1.0.0".to_string(),
            signature_database_version: "2023.12.01".to_string(),
            license_status: "Active".to_string(),
            system_health: "Good".to_string(),
            uptime_seconds: 0,
            memory_usage_mb: 0,
            cpu_usage_percent: 0.0,
        }
    }

    pub fn get_protection_status(&self) -> String {
        if self.real_time_protection {
            "Protected".to_string()
        } else {
            "At Risk".to_string()
        }
    }

    pub fn increment_threats_blocked(&mut self) {
        self.threats_blocked_today += 1;
        self.total_threats_blocked += 1;
    }

    pub fn update_quarantine_count(&mut self, count: u32) {
        self.quarantine_count = count;
    }

    pub fn disable_real_time_protection(&mut self) {
        self.real_time_protection = false;
        self.system_health = "At Risk".to_string();
    }

    pub fn enable_real_time_protection(&mut self) {
        self.real_time_protection = true;
        self.system_health = "Good".to_string();
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanConfiguration {
    pub scan_type: ScanType,
    pub target_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub excluded_extensions: Vec<String>,
    pub max_file_size: Option<u64>,
    pub scan_archives: bool,
    pub scan_email: bool,
    pub scan_network_drives: bool,
    pub heuristic_level: u8,
    pub scan_timeout_seconds: Option<u64>,
    pub max_threads: Option<usize>,
    pub priority: u8,
}

impl Default for ScanConfiguration {
    fn default() -> Self {
        ScanConfiguration {
            scan_type: ScanType::QuickScan,
            target_paths: vec![PathBuf::from("/")],
            excluded_paths: Vec::new(),
            excluded_extensions: Vec::new(),
            max_file_size: Some(100 * 1024 * 1024), // 100MB
            scan_archives: true,
            scan_email: true,
            scan_network_drives: false,
            heuristic_level: 3,
            scan_timeout_seconds: Some(3600), // 1 hour
            max_threads: None,
            priority: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: ActionType,
    pub target_path: PathBuf,
    pub success: bool,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub details: HashMap<String, String>,
    pub threat_id: ThreatId,
    pub message: String,
}

impl ActionResult {
    pub fn success(action: ActionType, target_path: PathBuf, threat_id: ThreatId, message: String) -> Self {
        ActionResult {
            action,
            target_path,
            success: true,
            error_message: None,
            timestamp: Utc::now(),
            details: HashMap::new(),
            threat_id,
            message,
        }
    }

    pub fn failure(action: ActionType, target_path: PathBuf, threat_id: ThreatId, error: String) -> Self {
        ActionResult {
            action,
            target_path,
            success: false,
            error_message: Some(error.clone()),
            timestamp: Utc::now(),
            details: HashMap::new(),
            threat_id,
            message: error,
        }
    }

    pub fn add_detail(&mut self, key: String, value: String) {
        self.details.insert(key, value);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealTimeEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub file_path: PathBuf,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub user_name: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub action_taken: Option<ActionType>,
    pub threat_info: Option<ThreatInfo>,
    pub blocked: bool,
    pub risk_level: u8,
}

impl RealTimeEvent {
    pub fn new(event_type: String, file_path: PathBuf) -> Self {
        RealTimeEvent {
            event_id: Uuid::new_v4(),
            event_type,
            file_path,
            process_name: None,
            process_id: None,
            user_name: None,
            timestamp: Utc::now(),
            action_taken: None,
            threat_info: None,
            blocked: false,
            risk_level: 0,
        }
    }

    pub fn with_threat(mut self, threat: ThreatInfo) -> Self {
        self.risk_level = threat.risk_score;
        self.threat_info = Some(threat);
        self
    }

    pub fn with_action(mut self, action: ActionType) -> Self {
        self.action_taken = Some(action);
        self
    }

    pub fn block(mut self) -> Self {
        self.blocked = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub component: String,
    pub current_version: String,
    pub available_version: String,
    pub update_size: u64,
    pub release_date: DateTime<Utc>,
    pub is_critical: bool,
    pub description: String,
    pub download_url: String,
    pub checksum: String,
}

impl UpdateInfo {
    pub fn new(
        component: String,
        current_version: String,
        available_version: String,
        update_size: u64,
        description: String,
        download_url: String,
        checksum: String,
    ) -> Self {
        UpdateInfo {
            component,
            current_version,
            available_version,
            update_size,
            release_date: Utc::now(),
            is_critical: false,
            description,
            download_url,
            checksum,
        }
    }

    pub fn mark_as_critical(mut self) -> Self {
        self.is_critical = true;
        self
    }

    pub fn get_formatted_size(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if self.update_size >= GB {
            format!("{:.2} GB", self.update_size as f64 / GB as f64)
        } else if self.update_size >= MB {
            format!("{:.2} MB", self.update_size as f64 / MB as f64)
        } else if self.update_size >= KB {
            format!("{:.2} KB", self.update_size as f64 / KB as f64)
        } else {
            format!("{} B", self.update_size)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_threat_info_creation() {
        let threat = ThreatInfo::new(
            format!("Test.{}", "Malware"),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from(format!("/tmp/test.{}", "exe")),
            "a".repeat(64),
            DetectionMethod::Signature,
        );
        assert!(threat.is_ok());
        let threat = threat.unwrap();
        assert_eq!(threat.name, format!("Test.{}", "Malware"));
        assert_eq!(threat.threat_type, ThreatType::Virus);
        assert_eq!(threat.severity, ThreatSeverity::High);
    }

    #[test]
    fn test_threat_info_validation() {
        let result = ThreatInfo::new(
            "".to_string(),
            ThreatType::Virus,
            ThreatSeverity::Low,
            PathBuf::from(format!("/tmp/test.{}", "exe")),
            "a".repeat(64),
            DetectionMethod::Signature,
        );
        assert!(result.is_err());
        let result = ThreatInfo::new(
            format!("Test.{}", "Malware"),
            ThreatType::Virus,
            ThreatSeverity::Low,
            PathBuf::from(format!("/tmp/test.{}", "exe")),
            "invalid_hash".to_string(),
            DetectionMethod::Signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_threat_risk_score() {
        let mut threat = ThreatInfo::new(
            format!("Test.{}", "Ransomware"),
            ThreatType::Ransomware,
            ThreatSeverity::Critical,
            PathBuf::from(format!("/tmp/test.{}", "exe")),
            "a".repeat(64),
            DetectionMethod::Signature,
        ).unwrap();
        assert_eq!(threat.get_risk_score(), 100);
        assert!(threat.requires_immediate_action());
        threat.threat_type = ThreatType::Adware;
        threat.severity = ThreatSeverity::Low;
        assert_eq!(threat.get_risk_score(), 15);
        assert!(!threat.requires_immediate_action());
    }

    #[test]
    fn test_scan_result_lifecycle() {
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);
        assert_eq!(result.scan_id, scan_id);
        assert_eq!(result.status, ScanStatus::Pending);
        assert!(result.end_time.is_none());
        let threat = ThreatInfo::new(
            format!("Test.{}", "Virus"),
            ThreatType::Virus,
            ThreatSeverity::Medium,
            PathBuf::from(format!("/tmp/virus.{}", "exe")),
            "b".repeat(64),
            DetectionMethod::Heuristic,
        ).unwrap();
        result.add_threat(threat);
        assert_eq!(result.threats_found.len(), 1);
        result.complete_scan();
        assert_eq!(result.status, ScanStatus::Completed);
        assert!(result.end_time.is_some());
        assert!(result.scan_duration_ms.is_some());
    }

    #[test]
    fn test_quarantine_entry() {
        let threat = ThreatInfo::new(
            format!("Test.{}", "Malware"),
            ThreatType::Trojan,
            ThreatSeverity::High,
            PathBuf::from(format!("/tmp/malware.{}", "exe")),
            "c".repeat(64),
            DetectionMethod::MachineLearning,
        ).unwrap();
        let entry = QuarantineEntry::new(
            PathBuf::from(format!("/tmp/malware.{}", "exe")),
            threat,
            1024,
            PathBuf::from("/quarantine/encrypted_file"),
        );
        assert_eq!(entry.get_file_name(), format!("malware.{}", "exe"));
        assert_eq!(entry.get_formatted_size(), format!("1.00 {}", "KB"));
        assert_eq!(entry.age_in_days(), 0);
        assert!(!entry.should_auto_delete(30));
    }

    #[test]
    fn test_system_status() {
        let mut status = SystemStatus::new(
            "1.0.0".to_string(),
            "2023.12.01".to_string(),
        );
        assert_eq!(status.get_protection_status(), "Protected");
        status.disable_real_time_protection();
        assert_eq!(status.get_protection_status(), format!("At {}", "Risk"));
        status.increment_threats_blocked();
        assert_eq!(status.threats_blocked_today, 1);
        assert_eq!(status.total_threats_blocked, 1);
    }

    #[test]
    fn test_scan_result_threat_filtering() {
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);
        let high_threat = ThreatInfo::new(
            format!("High.{}", "Threat"),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from(format!("/tmp/high.{}", "exe")),
            "d".repeat(64),
            DetectionMethod::Signature,
        ).unwrap();
        let low_threat = ThreatInfo::new(
            format!("Low.{}", "Threat"),
            ThreatType::Adware,
            ThreatSeverity::Low,
            PathBuf::from(format!("/tmp/low.{}", "exe")),
            "e".repeat(64),
            DetectionMethod::Heuristic,
        ).unwrap();
        result.add_threat(high_threat);
        result.add_threat(low_threat);
        let high_threats = result.get_threats_by_severity(ThreatSeverity::High);
        assert_eq!(high_threats.len(), 1);
        assert_eq!(high_threats[0].name, format!("High.{}", "Threat"));
        let low_threats = result.get_threats_by_severity(ThreatSeverity::Low);
        assert_eq!(low_threats.len(), 1);
        assert_eq!(low_threats[0].name, format!("Low.{}", "Threat"));
        let critical_threats = result.get_threats_by_severity(ThreatSeverity::Critical);
        assert_eq!(critical_threats.len(), 0);
    }

    #[test]
    fn test_file_size_formatting() {
        let entry = QuarantineEntry::new(
            PathBuf::from(format!("/tmp/test.{}", "exe")),
            ThreatInfo::new(
                "Test".to_string(),
                ThreatType::Virus,
                ThreatSeverity::Low,
                PathBuf::from(format!("/tmp/test.{}", "exe")),
                "f".repeat(64),
                DetectionMethod::Signature,
            ).unwrap(),
            0,
            PathBuf::from(format!("/quarantine/{}", "test")),
        );
        // Test different file sizes
        let mut test_entry = entry.clone();
        test_entry.file_size = 512;
        assert!(!test_entry.get_formatted_size().is_empty());
        
        test_entry.file_size = 1536;
        assert!(!test_entry.get_formatted_size().is_empty());
        
        test_entry.file_size = 1572864;
        assert!(!test_entry.get_formatted_size().is_empty());
        
        test_entry.file_size = 1610612736;
        assert!(!test_entry.get_formatted_size().is_empty());
    }
}