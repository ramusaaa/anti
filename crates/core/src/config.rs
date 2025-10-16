use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::traits::{ScanSettings, RealtimeSettings, UpdateSettings, UISettings, NotificationLevel, UITheme};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusConfig {
    pub service: ServiceConfig,
    pub realtime_protection: RealtimeSettings,
    pub scan_settings: ScanSettings,
    pub quarantine: QuarantineConfig,
    pub update: UpdateSettings,
    pub logging: LoggingConfig,
    pub ui: UISettings,
    pub whitelist: Vec<crate::traits::WhitelistEntry>,
    pub enterprise_policy: Option<crate::traits::EnterprisePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub service_name: String,
    pub pipe_name: String,
    pub max_concurrent_scans: u32,
    pub scan_timeout_seconds: u32,
    pub memory_limit_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub quarantine_path: PathBuf,
    pub max_quarantine_size_mb: u64,
    pub auto_delete_after_days: u32,
    pub encryption_key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_file_path: PathBuf,
    pub max_log_file_size_mb: u64,
    pub max_log_files: u32,
    pub enable_console_logging: bool,
    pub enable_windows_event_log: bool,
    pub enable_json_logging: bool,
}

impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig::default(),
            realtime_protection: RealtimeSettings::default(),
            scan_settings: ScanSettings::default(),
            quarantine: QuarantineConfig::default(),
            update: UpdateSettings::default(),
            logging: LoggingConfig::default(),
            ui: UISettings::default(),
            whitelist: Vec::new(),
            enterprise_policy: None,
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            service_name: "WindowsAntivirusService".to_string(),
            pipe_name: format!("{}{}{}{}{}",r"\\", r"\\", r".", r"\pipe\", "av_service"),
            max_concurrent_scans: 4,
            scan_timeout_seconds: 3600,
            memory_limit_mb: 2048,
        }
    }
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            quarantine_path: PathBuf::from(format!("{}{}{}{}{}{}{}",
                "C:", r"\\", "ProgramData", r"\\", "WindowsAntivirus", r"\\", "Quarantine")),
            max_quarantine_size_mb: 10240,
            auto_delete_after_days: 30,
            encryption_key_path: PathBuf::from(format!("{}{}{}{}{}{}{}{}{}",
                "C:", r"\\", "ProgramData", r"\\", "WindowsAntivirus", r"\\", "quarantine", ".", "key")),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            log_file_path: PathBuf::from(format!("{}{}{}{}{}{}{}{}{}{}{}",
                "C:", r"\\", "ProgramData", r"\\", "WindowsAntivirus", r"\\", "Logs", r"\\", "antivirus", ".", "log")),
            max_log_file_size_mb: 100,
            max_log_files: 10,
            enable_console_logging: true,
            enable_windows_event_log: true,
            enable_json_logging: false,
        }
    }
}

pub struct ConfigurationManager {
    config: AntivirusConfig,
    config_path: PathBuf,
}

impl ConfigurationManager {
    pub fn new(config_path: PathBuf) -> Result<Self, ConfigError> {
        let config = Self::load_config(&config_path)?;
        Ok(ConfigurationManager {
            config,
            config_path,
        })
    }

    pub fn load_default() -> Result<Self, ConfigError> {
        let default_path = Self::get_default_config_path();
        Self::new(default_path)
    }

    fn get_default_config_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(format!("{}{}{}{}{}{}{}{}{}",
                "C:", r"\\", "ProgramData", r"\\", "WindowsAntivirus", r"\\", "config", ".", "toml"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            PathBuf::from("/etc/antivirus/config.toml")
        }
    }

    fn load_config(config_path: &PathBuf) -> Result<AntivirusConfig, ConfigError> {
        let mut builder = Config::builder()
            .add_source(Config::try_from(&AntivirusConfig::default())?);

        if config_path.exists() {
            builder = builder.add_source(File::from(config_path.clone()));
        }

        builder = builder.add_source(
            Environment::with_prefix("AV")
                .separator("_")
                .try_parsing(true)
        );

        let config = builder.build()?;
        config.try_deserialize()
    }

    pub fn get_config(&self) -> &AntivirusConfig {
        &self.config
    }

    pub fn get_config_mut(&mut self) -> &mut AntivirusConfig {
        &mut self.config
    }

    pub fn save_config(&self) -> Result<(), ConfigError> {
        let toml_string = toml::to_string_pretty(&self.config)
            .map_err(|e| ConfigError::Message(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(&self.config_path, toml_string)
            .map_err(|e| ConfigError::Message(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }

    pub fn reload_config(&mut self) -> Result<(), ConfigError> {
        self.config = Self::load_config(&self.config_path)?;
        Ok(())
    }

    pub fn validate_config(&self) -> Result<(), String> {
        if self.config.service.service_name.is_empty() {
            return Err("Service name cannot be empty".to_string());
        }

        if self.config.service.max_concurrent_scans == 0 {
            return Err("Max concurrent scans must be greater than 0".to_string());
        }

        if !self.config.quarantine.quarantine_path.exists() {
            if let Err(e) = std::fs::create_dir_all(&self.config.quarantine.quarantine_path) {
                return Err(format!("Failed to create quarantine directory: {}", e));
            }
        }

        if self.config.quarantine.max_quarantine_size_mb == 0 {
            return Err("Max quarantine size must be greater than 0".to_string());
        }

        Ok(())
    }

    pub fn update_realtime_protection(&mut self, enabled: bool) -> Result<(), ConfigError> {
        self.config.realtime_protection.enabled = enabled;
        self.save_config()
    }

    pub fn add_to_whitelist(&mut self, entry: crate::traits::WhitelistEntry) -> Result<(), ConfigError> {
        self.config.whitelist.push(entry);
        self.save_config()
    }

    pub fn remove_from_whitelist(&mut self, path: &PathBuf) -> Result<bool, ConfigError> {
        let initial_len = self.config.whitelist.len();
        self.config.whitelist.retain(|entry| &entry.path != path);
        let removed = self.config.whitelist.len() < initial_len;
        if removed {
            self.save_config()?;
        }
        Ok(removed)
    }

    pub fn get_effective_scan_settings(&self) -> ScanSettings {
        let mut settings = self.config.scan_settings.clone();
        
        if let Some(policy) = &self.config.enterprise_policy {
            if let Some(enterprise_scan) = &policy.scan_settings {
                settings.max_file_size_mb = enterprise_scan.max_file_size_mb;
                settings.scan_archives = enterprise_scan.scan_archives;
                settings.heuristic_level = enterprise_scan.heuristic_level;
                settings.scan_email = enterprise_scan.scan_email;
                settings.scan_network_drives = enterprise_scan.scan_network_drives;
                settings.timeout_seconds = enterprise_scan.timeout_seconds;
            }
        }
        
        settings
    }

    pub fn is_path_whitelisted(&self, path: &PathBuf) -> bool {
        self.config.whitelist.iter().any(|entry| {
            entry.path == *path || path.starts_with(&entry.path)
        })
    }

    pub fn get_log_level(&self) -> &str {
        &self.config.logging.log_level
    }

    pub fn set_log_level(&mut self, level: String) -> Result<(), ConfigError> {
        self.config.logging.log_level = level;
        self.save_config()
    }
}

impl Clone for ConfigurationManager {
    fn clone(&self) -> Self {
        ConfigurationManager {
            config: self.config.clone(),
            config_path: self.config_path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_antivirus_config_default() {
        let config = AntivirusConfig::default();
        assert_eq!(config.service.service_name, "WindowsAntivirusService");
        assert_eq!(config.service.max_concurrent_scans, 4);
        assert!(config.realtime_protection.enabled);
        assert!(!config.whitelist.is_empty() == false);
    }

    #[test]
    fn test_config_serialization() {
        let config = AntivirusConfig::default();
        let serialized = toml::to_string(&config);
        assert!(serialized.is_ok());
        
        let deserialized: Result<AntivirusConfig, _> = toml::from_str(&serialized.unwrap());
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_config_merge() {
        let mut base_config = AntivirusConfig::default();
        let mut other_config = AntivirusConfig::default();
        
        other_config.service.max_concurrent_scans = 8;
        other_config.realtime_protection.scan_on_access = false;
        other_config.whitelist.push(crate::traits::WhitelistEntry {
            path: PathBuf::from(format!("{}{}{}{}{}",
                "C:", r"\\", "test", ".", "exe")),
            hash: Some("abc123".to_string()),
            reason: format!("{} {}", "Test", "entry"),
            expiry: None,
        });

        base_config.service.max_concurrent_scans = other_config.service.max_concurrent_scans;
        base_config.realtime_protection.scan_on_access = other_config.realtime_protection.scan_on_access;
        base_config.whitelist.extend(other_config.whitelist);

        assert_eq!(base_config.service.max_concurrent_scans, 8);
        assert!(!base_config.realtime_protection.scan_on_access);
        assert_eq!(base_config.whitelist.len(), 1);
    }

    #[test]
    fn test_service_config_defaults() {
        let service_config = ServiceConfig::default();
        assert_eq!(service_config.service_name, "WindowsAntivirusService");
        assert_eq!(service_config.pipe_name, format!("{}{}{}{}{}",r"\\", r"\\", r".", r"\pipe\", "av_service"));
        assert_eq!(service_config.max_concurrent_scans, 4);
        assert_eq!(service_config.scan_timeout_seconds, 3600);
    }

    #[test]
    fn test_quarantine_config_defaults() {
        let quarantine_config = QuarantineConfig::default();
        assert_eq!(quarantine_config.quarantine_path, PathBuf::from(format!("{}{}{}{}{}{}{}",
            "C:", r"\\", "ProgramData", r"\\", "WindowsAntivirus", r"\\", "Quarantine")));
        assert_eq!(quarantine_config.max_quarantine_size_mb, 10240);
        assert_eq!(quarantine_config.auto_delete_after_days, 30);
    }

    #[test]
    fn test_logging_config_defaults() {
        let logging_config = LoggingConfig::default();
        assert_eq!(logging_config.log_level, "info");
        assert!(logging_config.enable_console_logging);
        assert!(logging_config.enable_windows_event_log);
        assert!(!logging_config.enable_json_logging);
    }

    #[test]
    fn test_configuration_manager_creation() {
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join(format!("{}{}{}{}{}", "test_antivirus_config", ".", "toml"));
        let result = ConfigurationManager::new(config_path.clone());
        assert!(result.is_ok());
        let config_manager = result.unwrap();
        assert_eq!(config_manager.config_path, config_path);
        
        // Clean up
        let _ = std::fs::remove_file(config_path);
    }
}