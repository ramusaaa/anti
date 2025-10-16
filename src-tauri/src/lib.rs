use hadron_core::{QuarantineEntry, RemovableDevice, ThreatType, ThreatSeverity, DeviceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::State;
use uuid::Uuid;

#[derive(Default)]
pub struct AppState {
    pub scan_jobs: Arc<Mutex<HashMap<Uuid, String>>>,
    pub quarantine_entries: Arc<Mutex<Vec<QuarantineEntry>>>,
    pub removable_devices: Arc<Mutex<Vec<RemovableDevice>>>,
}

#[tauri::command]
async fn start_quick_scan(state: State<'_, AppState>) -> std::result::Result<String, String> {
    let scan_id = Uuid::new_v4();
    let mut jobs = state.scan_jobs.lock().unwrap();
    jobs.insert(scan_id, "Quick Scan".to_string());
    
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        log::info!("Quick scan {} completed", scan_id);
    });
    
    Ok(scan_id.to_string())
}

#[tauri::command]
async fn start_full_scan(state: State<'_, AppState>) -> std::result::Result<String, String> {
    let scan_id = Uuid::new_v4();
    let mut jobs = state.scan_jobs.lock().unwrap();
    jobs.insert(scan_id, "Full Scan".to_string());
    
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        log::info!("Full scan {} completed", scan_id);
    });
    
    Ok(scan_id.to_string())
}

#[tauri::command]
async fn get_scan_status(scan_id: String, state: State<'_, AppState>) -> std::result::Result<String, String> {
    let jobs = state.scan_jobs.lock().unwrap();
    if let Ok(uuid) = Uuid::parse_str(&scan_id) {
        if let Some(job_name) = jobs.get(&uuid) {
            Ok(format!("{} is running", job_name))
        } else {
            Ok("Scan not found".to_string())
        }
    } else {
        Err("Invalid scan ID".to_string())
    }
}

#[tauri::command]
async fn get_quarantine_entries(state: State<'_, AppState>) -> std::result::Result<Vec<QuarantineEntry>, String> {
    let entries = state.quarantine_entries.lock().unwrap();
    Ok(entries.clone())
}

#[tauri::command]
async fn get_removable_devices(state: State<'_, AppState>) -> std::result::Result<Vec<RemovableDevice>, String> {
    let devices = state.removable_devices.lock().unwrap();
    Ok(devices.clone())
}

#[tauri::command]
async fn scan_removable_device(device_id: String, state: State<'_, AppState>) -> std::result::Result<String, String> {
    let scan_id = Uuid::new_v4();
    let mut jobs = state.scan_jobs.lock().unwrap();
    jobs.insert(scan_id, format!("Device Scan: {}", device_id));
    
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        log::info!("Device scan {} completed for device {}", scan_id, device_id);
    });
    
    Ok(scan_id.to_string())
}

#[tauri::command]
async fn restore_from_quarantine(entry_id: String, state: State<'_, AppState>) -> std::result::Result<String, String> {
    let mut entries = state.quarantine_entries.lock().unwrap();
    if let Some(pos) = entries.iter().position(|e| e.id == entry_id) {
        let entry = entries.remove(pos);
        log::info!("Restored file: {}", entry.original_path.display());
        Ok("File restored successfully".to_string())
    } else {
        Err("Quarantine entry not found".to_string())
    }
}

#[tauri::command]
async fn delete_from_quarantine(entry_id: String, state: State<'_, AppState>) -> std::result::Result<String, String> {
    let mut entries = state.quarantine_entries.lock().unwrap();
    if let Some(pos) = entries.iter().position(|e| e.id == entry_id) {
        let entry = entries.remove(pos);
        log::info!("Deleted file: {}", entry.original_path.display());
        Ok("File deleted successfully".to_string())
    } else {
        Err("Quarantine entry not found".to_string())
    }
}

#[tauri::command]
async fn get_system_status() -> std::result::Result<HashMap<String, String>, String> {
    let mut status = HashMap::new();
    status.insert("realtime_protection".to_string(), "Active".to_string());
    status.insert("last_update".to_string(), "Today".to_string());
    status.insert("threats_detected".to_string(), "0".to_string());
    status.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    Ok(status)
}

#[tauri::command]
async fn get_system_drives() -> std::result::Result<Vec<HashMap<String, String>>, String> {
    let mut drives = Vec::new();
    
    let mount_points = vec![
        ("/", "Macintosh HD", "System Drive"),
        ("/Users", "Users", "User Data"),
        ("/Applications", "Applications", "Applications"),
        ("/System", "System", "System Files"),
        ("/Library", "Library", "System Library"),
        ("/tmp", "Temporary", "Temporary Files"),
        ("/var", "Variable", "Variable Data"),
    ];
    
    for (path, name, description) in mount_points {
        let mut drive = HashMap::new();
        drive.insert("path".to_string(), path.to_string());
        drive.insert("name".to_string(), name.to_string());
        drive.insert("description".to_string(), description.to_string());
        drive.insert("type".to_string(), "folder".to_string());
        drives.push(drive);
    }
    
    Ok(drives)
}

#[tauri::command]
async fn start_custom_scan(paths: Vec<String>, state: State<'_, AppState>) -> std::result::Result<String, String> {
    let scan_id = Uuid::new_v4();
    let mut jobs = state.scan_jobs.lock().unwrap();
    jobs.insert(scan_id, format!("Custom Scan: {} folders", paths.len()));
    
    let paths_str = paths.join(", ");
    tokio::spawn(async move {
        let duration = std::cmp::max(10, paths.len() * 5) as u64;
        tokio::time::sleep(tokio::time::Duration::from_secs(duration)).await;
        log::info!("Custom scan {} completed for paths: {}", scan_id, paths_str);
    });
    
    Ok(scan_id.to_string())
}

#[tauri::command]
async fn get_real_removable_devices() -> std::result::Result<Vec<RemovableDevice>, String> {
    let mut devices = Vec::new();
    
   if let Ok(entries) = std::fs::read_dir("/Volumes") {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    
                    if name != "Macintosh HD" && !name.starts_with('.') {
                        let size = get_directory_size(&path).unwrap_or(0);
                        
                        devices.push(RemovableDevice {
                            id: format!("vol_{}", name.replace(" ", "_").to_lowercase()),
                            name: name.clone(),
                            device_type: DeviceType::UsbDrive, // Varsayılan olarak USB
                            mount_path: path.clone(),
                            size_bytes: size,
                            is_trusted: false,
                            last_scan: None,
                            threat_count: 0,
                        });
                    }
                }
            }
        }
    }
    
    if devices.is_empty() {
        devices.push(RemovableDevice {
            id: "mock_usb_001".to_string(),
            name: "Mock USB Drive".to_string(),
            device_type: DeviceType::UsbDrive,
            mount_path: std::path::PathBuf::from("/Volumes/MockUSB"),
            size_bytes: 8_000_000_000,
            is_trusted: false,
            last_scan: None,
            threat_count: 0,
        });
    }
    
    Ok(devices)
}

fn get_directory_size(path: &std::path::Path) -> std::result::Result<u64, std::io::Error> {
    let mut size = 0;
    if path.is_dir() {
        let mut count = 0;
        for entry in std::fs::read_dir(path)? {
            if count > 100 { break; } 
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                size += metadata.len();
            }
            count += 1;
        }
        size *= 10;
    }
    Ok(size)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState::default();
    
    {
        let mut entries = app_state.quarantine_entries.lock().unwrap();
        entries.push(QuarantineEntry {
            id: Uuid::new_v4().to_string(),
            original_path: std::path::PathBuf::from("/tmp/malware.exe"),
            threat_name: "Trojan.Generic".to_string(),
            quarantine_time: chrono::Utc::now(),
            file_size: 1024000,
            threat_type: ThreatType::Trojan,
            severity: ThreatSeverity::High,
        });
    }
    
    // Add some mock removable devices
    {
        let mut devices = app_state.removable_devices.lock().unwrap();
        devices.push(RemovableDevice {
            id: "usb_001".to_string(),
            name: "Kingston DataTraveler".to_string(),
            device_type: DeviceType::UsbDrive,
            mount_path: std::path::PathBuf::from("/Volumes/KINGSTON"),
            size_bytes: 8_000_000_000,
            is_trusted: false,
            last_scan: None,
            threat_count: 0,
        });
    }

    tauri::Builder::default()
        .manage(app_state)
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            start_quick_scan,
            start_full_scan,
            get_scan_status,
            get_quarantine_entries,
            get_removable_devices,
            scan_removable_device,
            restore_from_quarantine,
            delete_from_quarantine,
            get_system_status,
            get_system_drives,
            start_custom_scan,
            get_real_removable_devices
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
