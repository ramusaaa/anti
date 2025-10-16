use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tracing::{debug, info, warn, error};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::{Result, AntivirusError, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};

#[derive(Debug)]
pub struct UsbProtection {
    config: UsbProtectionConfig,
    quarantine_path: PathBuf,
    known_threats: HashMap<String, UsbThreatSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbProtectionConfig {
    pub realtime_monitoring: bool,
    pub auto_scan_on_insert: bool,
    pub block_autorun: bool,
    pub block_suspicious_shortcuts: bool,
    pub auto_quarantine: bool,
    pub show_notifications: bool,
    pub max_scan_size_mb: u64,
    pub scan_hidden_files: bool,
}

impl Default for UsbProtectionConfig {
    fn default() -> Self {
        Self {
            realtime_monitoring: true,
            auto_scan_on_insert: true,
            block_autorun: true,
            block_suspicious_shortcuts: true,
            auto_quarantine: true,
            show_notifications: true,
            max_scan_size_mb: 100,
            scan_hidden_files: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbThreatSignature {
    pub name: String,
    pub description: String,
    pub file_patterns: Vec<String>,
    pub content_patterns: Vec<String>,
    pub severity: ThreatSeverity,
    pub action: UsbThreatAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsbThreatAction {
    Block,
    Quarantine,
    Delete,
    Warn,
}

#[derive(Debug, Clone)]
pub struct UsbThreatDetection {
    pub threat_type: UsbThreatType,
    pub file_path: PathBuf,
    pub threat_name: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub recommended_action: UsbThreatAction,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsbThreatType {
    AutorunWorm,
    ShortcutVirus,
    HiddenExecutable,
    SuspiciousScript,
    FakeFolder,
    DataStealer,
    Ransomware,
    Unknown,
}

impl UsbProtection {
    pub fn new(quarantine_path: PathBuf) -> Self {
        let mut protection = Self {
            config: UsbProtectionConfig::default(),
            quarantine_path,
            known_threats: HashMap::new(),
        };
        protection.load_threat_signatures();
        protection
    }

    pub fn with_config(config: UsbProtectionConfig, quarantine_path: PathBuf) -> Self {
        let mut protection = Self {
            config,
            quarantine_path,
            known_threats: HashMap::new(),
        };
        protection.load_threat_signatures();
        protection
    }

    fn load_threat_signatures(&mut self) {
        // Load basic threat signatures
        self.known_threats.insert("autorun_worm".to_string(), UsbThreatSignature {
            name: "Autorun Worm".to_string(),
            description: "Malicious autorun.inf file".to_string(),
            file_patterns: vec!["autorun.inf".to_string()],
            content_patterns: vec!["shellexecute=".to_string(), "open=".to_string()],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        self.known_threats.insert("shortcut_virus".to_string(), UsbThreatSignature {
            name: "Shortcut Virus".to_string(),
            description: "Malicious shortcut files".to_string(),
            file_patterns: vec!["*.lnk".to_string()],
            content_patterns: vec!["cmd /c".to_string(), "powershell".to_string()],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        info!("Loaded {} USB threat signatures", self.known_threats.len());
    }

    pub async fn scan_usb_device(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        info!("Starting USB threat scan for: {}", device_path.display());
        let mut detections = Vec::new();

        // Check for autorun threats
        detections.extend(self.check_autorun_threats(device_path).await?);
        
        // Scan files for threats
        detections.extend(self.scan_files_for_threats(device_path).await?);

        info!("USB scan completed. Found {} threats", detections.len());
        Ok(detections)
    }

    async fn check_autorun_threats(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        let mut detections = Vec::new();
        let autorun_path = device_path.join("autorun.inf");
        
        if autorun_path.exists() {
            info!("Found autorun.inf file: {}", autorun_path.display());
            match fs::read_to_string(&autorun_path).await {
                Ok(content) => {
                    let content_lower = content.to_lowercase();
                    let malicious_patterns = [
                        "shellexecute=",
                        "shell\\open\\command=",
                        ".exe",
                        ".scr",
                        ".com",
                    ];
                    
                    for pattern in &malicious_patterns {
                        if content_lower.contains(pattern) {
                            detections.push(UsbThreatDetection {
                                threat_type: UsbThreatType::AutorunWorm,
                                file_path: autorun_path.clone(),
                                threat_name: "Malicious Autorun File".to_string(),
                                severity: ThreatSeverity::High,
                                description: format!("Autorun.inf contains suspicious pattern: {}", pattern),
                                recommended_action: UsbThreatAction::Block,
                                detection_time: Utc::now(),
                            });
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Could not read autorun.inf: {}", e);
                }
            }
        }
        
        Ok(detections)
    }

    async fn scan_files_for_threats(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        let mut detections = Vec::new();
        let mut stack = vec![device_path.to_path_buf()];

        while let Some(current_path) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path).await {
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        if let Some(detection) = self.check_file_against_signatures(&path).await? {
                            detections.push(detection);
                        }
                    }
                }
            }
        }

        Ok(detections)
    }

    async fn check_file_against_signatures(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check for double extensions
        if self.has_double_extension(&file_name) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::SuspiciousScript,
                file_path: file_path.to_path_buf(),
                threat_name: "Double Extension Malware".to_string(),
                severity: ThreatSeverity::High,
                description: "File with suspicious double extension".to_string(),
                recommended_action: UsbThreatAction::Quarantine,
                detection_time: Utc::now(),
            }));
        }

        // Check for system file impersonation
        if self.is_system_file_impersonator(&file_name) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::HiddenExecutable,
                file_path: file_path.to_path_buf(),
                threat_name: "System File Impersonator".to_string(),
                severity: ThreatSeverity::Critical,
                description: "Executable disguised as legitimate system file".to_string(),
                recommended_action: UsbThreatAction::Quarantine,
                detection_time: Utc::now(),
            }));
        }

        Ok(None)
    }

    fn has_double_extension(&self, file_name: &str) -> bool {
        let common_fake_extensions = [
            ".jpg.exe", ".png.exe", ".pdf.exe", ".doc.exe", ".txt.exe",
        ];
        common_fake_extensions.iter().any(|ext| file_name.ends_with(ext))
    }

    fn is_system_file_impersonator(&self, file_name: &str) -> bool {
        let system_files = [
            "svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe",
        ];
        system_files.contains(&file_name)
    }

    pub async fn quarantine_threat(&self, threat: &UsbThreatDetection) -> Result<PathBuf> {
        info!("Quarantining USB threat: {}", threat.file_path.display());
        
        if !self.quarantine_path.exists() {
            fs::create_dir_all(&self.quarantine_path).await?;
        }
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let original_name = threat.file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let quarantine_filename = format!("{}_{}.quarantine", timestamp, original_name);
        let quarantine_file_path = self.quarantine_path.join(quarantine_filename);
        
        fs::rename(&threat.file_path, &quarantine_file_path).await?;
        
        info!("Threat quarantined to: {}", quarantine_file_path.display());
        Ok(quarantine_file_path)
    }

    pub fn matches_pattern(&self, filename: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.starts_with("*.") {
            let extension = &pattern[2..];
            return filename.ends_with(extension);
        }
        
        filename == pattern
    }

    pub async fn immunize_usb_device(&self, device_path: &Path) -> Result<()> {
        info!("Immunizing USB device: {}", device_path.display());
        
        let protection_marker = device_path.join(".hadron_protection");
        fs::write(&protection_marker, format!("HADRON USB Protection\nCreated: {}\nVersion: 1.0", Utc::now())).await?;
        
        let autorun_path = device_path.join("autorun.inf");
        let autorun_content = "[autorun]\n; HADRON USB Protection - Do not modify\nopen=\nshellexecute=\naction=\n";
        fs::write(&autorun_path, autorun_content).await?;
        
        info!("USB device immunization completed");
        Ok(())
    }

    pub async fn is_usb_immunized(&self, device_path: &Path) -> bool {
        let protection_marker = device_path.join(".hadron_protection");
        let autorun_protection = device_path.join("autorun.inf");
        protection_marker.exists() && autorun_protection.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_usb_protection_creation() {
        let temp_dir = TempDir::new().unwrap();
        let protection = UsbProtection::new(temp_dir.path().to_path_buf());
        assert!(!protection.known_threats.is_empty());
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let temp_dir = TempDir::new().unwrap();
        let protection = UsbProtection::new(temp_dir.path().to_path_buf());
        assert!(protection.matches_pattern("test.exe", "*.exe"));
        assert!(protection.matches_pattern("autorun.inf", "autorun.inf"));
        assert!(!protection.matches_pattern("test.txt", "*.exe"));
    }

    #[tokio::test]
    async fn test_autorun_detection() {
        let temp_dir = TempDir::new().unwrap();
        let protection = UsbProtection::new(temp_dir.path().to_path_buf());
        let autorun_path = temp_dir.path().join("autorun.inf");
        fs::write(&autorun_path, "[autorun]\nshellexecute=malware.exe\n").await.unwrap();
        let detections = protection.check_autorun_threats(temp_dir.path()).await.unwrap();
        assert!(!detections.is_empty());
        assert!(matches!(detections[0].threat_type, UsbThreatType::AutorunWorm));
    }
}