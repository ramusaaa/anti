use eframe::egui;
use hadron_core::{SystemStatus, ScanType, ScanJobId, ScanStatus, ScanProgress, QuarantineEntry, AntivirusConfig, ScanResult, ThreatInfo, RemovableDevice};
use crate::panels::{DashboardPanel, ScanPanel, QuarantinePanel, SettingsPanel, RemovableMediaPanel, ScanPanelAction, QuarantinePanelAction, SettingsPanelAction, RemovableMediaPanelAction};
use crate::notifications::{NotificationManager, NotificationType};
use crate::mock_api::MockApiClient;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
enum ScanEvent {
    Started(ScanJobId),
    Progress(ScanProgress),
    Completed(ScanResult),
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Idle,
    Scanning,
    Updating,
    Processing,
}

#[derive(Debug, Clone, PartialEq)]
enum FlashScanType {
    QuickScan,
    FullScan,
    CustomScan,
    MemoryScan,
    NetworkScan,
}

#[derive(Debug, Clone, Default)]
struct ScanStatistics {
    total_scans: u64,
    threats_found: u64,
    files_scanned: u64,
    last_scan_time: Option<std::time::SystemTime>,
    scan_duration: std::time::Duration,
}

#[derive(Debug, Clone, Default)]
struct SystemPerformance {
    cpu_usage: f32,
    memory_usage: f32,
    disk_usage: f32,
    scan_impact: f32,
}

#[derive(Debug, Clone, Default)]
struct NetworkActivity {
    connections_monitored: u32,
    threats_blocked: u32,
    bandwidth_usage: u64,
    suspicious_activity: Vec<String>,
}

pub struct AntivirusApp {
    api_client: Arc<RwLock<MockApiClient>>,
    dashboard_panel: DashboardPanel,
    scan_panel: ScanPanel,
    quarantine_panel: QuarantinePanel,
    settings_panel: SettingsPanel,
    removable_media_panel: RemovableMediaPanel,
    notification_manager: NotificationManager,
    selected_panel: Panel,
    status_message: String,
    current_scan_id: Option<ScanJobId>,
    app_state: AppState,
    scan_results: Vec<ScanResult>,
    threat_history: Vec<ThreatInfo>,
    scan_statistics: ScanStatistics,
    flash_scan_progress: f32,
    flash_scan_status: String,
    flash_scan_type: FlashScanType,
    system_performance: SystemPerformance,
    network_activity: NetworkActivity,
    runtime: Arc<tokio::runtime::Runtime>,
    last_status_update: std::time::Instant,
    last_scan_progress_update: std::time::Instant,
    last_removable_media_update: std::time::Instant,
    scan_event_receiver: Option<std::sync::mpsc::Receiver<ScanEvent>>,
    system_status_receiver: Option<std::sync::mpsc::Receiver<SystemStatus>>,
    removable_devices_receiver: Option<std::sync::mpsc::Receiver<Option<Vec<hadron_core::RemovableDevice>>>>,
    removable_scan_result_receiver: Option<std::sync::mpsc::Receiver<hadron_core::Result<hadron_core::ScanResult>>>,
    all_devices_scan_result_receiver: Option<std::sync::mpsc::Receiver<hadron_core::Result<(Vec<hadron_core::ThreatInfo>, u64)>>>,
}

#[derive(Debug, Clone, PartialEq)]
enum Panel {
    Dashboard,
    Scan,
    Quarantine,
    Settings,
    Notifications,
    RemovableMedia,
}

impl AntivirusApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let runtime = Arc::new(
            tokio::runtime::Runtime::new()
                .expect("Failed to create tokio runtime")
        );

        let api_client = Arc::new(RwLock::new(
            MockApiClient::new("\\\\.\\pipe\\av_service".to_string())
        ));

        let client_clone = api_client.clone();
        let runtime_clone = runtime.clone();

        std::thread::spawn(move || {
            runtime_clone.block_on(async {
                if let Err(e) = client_clone.write().await.connect().await {
                    tracing::warn!("Failed to connect to service: {}", e);
                }
            });
        });

        let mut app = Self {
            api_client,
            dashboard_panel: DashboardPanel::new(),
            scan_panel: ScanPanel::new(),
            quarantine_panel: QuarantinePanel::new(),
            settings_panel: SettingsPanel::new(),
            removable_media_panel: RemovableMediaPanel::new(),
            notification_manager: NotificationManager::new(),
            selected_panel: Panel::Dashboard,
            status_message: "Connecting to service...".to_string(),
            current_scan_id: None,
            app_state: AppState::Idle,
            scan_results: Vec::new(),
            threat_history: Vec::new(),
            scan_statistics: ScanStatistics::default(),
            flash_scan_progress: 0.0,
            flash_scan_status: "Ready".to_string(),
            flash_scan_type: FlashScanType::QuickScan,
            system_performance: SystemPerformance::default(),
            network_activity: NetworkActivity::default(),
            runtime,
            last_status_update: std::time::Instant::now(),
            last_scan_progress_update: std::time::Instant::now(),
            last_removable_media_update: std::time::Instant::now(),
            scan_event_receiver: None,
            system_status_receiver: None,
            removable_devices_receiver: None,
            removable_scan_result_receiver: None,
            all_devices_scan_result_receiver: None,
        };

        app.load_initial_removable_devices();
        app
    }

    fn show_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button(" File", |ui| {
                    if ui.button("🚪 Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button(" Scan", |ui| {
                    if ui.button(" Quick Scan").clicked() {
                        self.start_quick_scan();
                        ui.close_menu();
                    }
                    if ui.button(" Full Scan").clicked() {
                        self.start_full_scan();
                        ui.close_menu();
                    }
                    if ui.button(" Memory Scan").clicked() {
                        self.start_flash_scan(FlashScanType::MemoryScan);
                        ui.close_menu();
                    }
                    if ui.button(" Network Scan").clicked() {
                        self.start_flash_scan(FlashScanType::NetworkScan);
                        ui.close_menu();
                    }
                    if ui.button(" Flash Drive Scan").clicked() {
                        self.selected_panel = Panel::RemovableMedia;
                        ui.close_menu();
                    }
                });

                ui.menu_button(" Tools", |ui| {
                    if ui.button(" Refresh All Data").clicked() {
                        self.refresh_all_data();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(" Simulate Threat").clicked() {
                        self.simulate_threat_detection();
                        ui.close_menu();
                    }
                    if ui.button(" Simulate Scan Complete").clicked() {
                        self.simulate_scan_completion(2, 1500);
                        ui.close_menu();
                    }
                });

                ui.menu_button(" View", |ui| {
                    if ui.button(" Dashboard").clicked() {
                        self.selected_panel = Panel::Dashboard;
                        ui.close_menu();
                    }
                    if ui.button(" Advanced Scan").clicked() {
                        self.selected_panel = Panel::Scan;
                        ui.close_menu();
                    }
                    if ui.button(" Quarantine").clicked() {
                        self.selected_panel = Panel::Quarantine;
                        ui.close_menu();
                    }
                    if ui.button(" Removable Media").clicked() {
                        self.selected_panel = Panel::RemovableMedia;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(" Settings").clicked() {
                        self.selected_panel = Panel::Settings;
                        ui.close_menu();
                    }
                });

                ui.menu_button("❓ Help", |ui| {
                    if ui.button(" About").clicked() {
                        self.show_about_dialog(ctx);
                        ui.close_menu();
                    }
                    if ui.button("📚 Documentation").clicked() {
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let connection_color = if self.is_service_connected() {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    };
                    ui.colored_label(connection_color, "●");
                    ui.label("Service");
                });
            });
        });
    }

    fn show_side_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("side_panel")
            .min_width(200.0)
            .max_width(250.0)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(" HADRON");
                    ui.label("Antivirus");
                });

                ui.separator();
                ui.add_space(10.0);

                // Main navigation
                if ui.add_sized([ui.available_width(), 40.0],
                    egui::SelectableLabel::new(self.selected_panel == Panel::Dashboard, "🏠 Dashboard")
                ).clicked() {
                    self.selected_panel = Panel::Dashboard;
                }

                if ui.add_sized([ui.available_width(), 40.0],
                    egui::SelectableLabel::new(self.selected_panel == Panel::Scan, "🔍 Advanced Scan")
                ).clicked() {
                    self.selected_panel = Panel::Scan;
                }

                if ui.add_sized([ui.available_width(), 40.0],
                    egui::SelectableLabel::new(self.selected_panel == Panel::Quarantine, "🗂️ Quarantine")
                ).clicked() {
                    self.selected_panel = Panel::Quarantine;
                }

                if ui.add_sized([ui.available_width(), 40.0],
                    egui::SelectableLabel::new(self.selected_panel == Panel::RemovableMedia, "💾 Flash Bellek")
                ).clicked() {
                    self.selected_panel = Panel::RemovableMedia;
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                // Quick scan actions
                ui.label("⚡ Quick Scans");
                ui.add_space(5.0);

                if ui.add_enabled(
                    self.app_state != AppState::Scanning,
                    egui::Button::new(" Quick Scan").min_size(egui::vec2(ui.available_width(), 35.0))
                ).clicked() {
                    self.start_flash_scan(FlashScanType::QuickScan);
                }

                if ui.add_enabled(
                    self.app_state != AppState::Scanning,
                    egui::Button::new("🧠 Memory Scan").min_size(egui::vec2(ui.available_width(), 35.0))
                ).clicked() {
                    self.start_flash_scan(FlashScanType::MemoryScan);
                }

                if ui.add_enabled(
                    self.app_state != AppState::Scanning,
                    egui::Button::new("🌐 Network Scan").min_size(egui::vec2(ui.available_width(), 35.0))
                ).clicked() {
                    self.start_flash_scan(FlashScanType::NetworkScan);
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                // Settings and notifications
                if ui.add_sized([ui.available_width(), 40.0],
                    egui::SelectableLabel::new(self.selected_panel == Panel::Settings, "⚙️ Settings")
                ).clicked() {
                    self.selected_panel = Panel::Settings;
                }

                let unread_count = self.notification_manager.get_unread_count();
                let notification_label = if unread_count > 0 {
                    format!(" Notifications ({})", unread_count)
                } else {
                    " Notifications".to_string()
                };

                if ui.add_sized([ui.available_width(), 40.0],
                    egui::SelectableLabel::new(self.selected_panel == Panel::Notifications, notification_label)
                ).clicked() {
                    self.selected_panel = Panel::Notifications;
                }

                // Bottom status area
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(5.0);

                    let status_text = match self.app_state {
                        AppState::Scanning => format!(" Scanning... {:.0}%", self.flash_scan_progress * 100.0),
                        AppState::Updating => " Updating...".to_string(),
                        AppState::Processing => " Processing...".to_string(),
                        AppState::Idle => " System Protected".to_string(),
                    };

                    let status_color = match self.app_state {
                        AppState::Scanning => egui::Color32::YELLOW,
                        AppState::Updating => egui::Color32::BLUE,
                        AppState::Processing => egui::Color32::GRAY,
                        AppState::Idle => egui::Color32::GREEN,
                    };

                    ui.colored_label(status_color, status_text);

                    if self.scan_statistics.threats_found > 0 {
                        ui.colored_label(
                            egui::Color32::RED,
                            format!("⚠️ {} threats found", self.scan_statistics.threats_found)
                        );
                    }
                });
            });
    }

    fn show_main_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_panel {
                Panel::Dashboard => {
                    self.show_enhanced_dashboard(ui, ctx);
                }
                Panel::Scan => {
                    let action = self.scan_panel.show(ui);
                    self.handle_scan_action(action);
                }
                Panel::Quarantine => {
                    let action = self.quarantine_panel.show(ui);
                    self.handle_quarantine_action(action);
                }
                Panel::Settings => {
                    let action = self.settings_panel.show(ui);
                    self.handle_settings_action(action);
                }
                Panel::Notifications => {
                    self.notification_manager.show_notification_panel(ui);
                }
                Panel::RemovableMedia => {
                    if let Some(action) = self.removable_media_panel.show(ui) {
                        self.handle_removable_media_action(action);
                    }
                }
            }
        });
    }

    fn handle_scan_action(&mut self, action: ScanPanelAction) {
        match action {
            ScanPanelAction::StartQuickScan => {
                self.start_flash_scan(FlashScanType::QuickScan);
            }
            ScanPanelAction::StartFullScan => {
                self.start_flash_scan(FlashScanType::FullScan);
            }
            ScanPanelAction::StartCustomScan(targets) => {
                let paths: Vec<std::path::PathBuf> = targets
                    .split(';')
                    .map(|s| std::path::PathBuf::from(s.trim()))
                    .collect();
                self.start_scan_async(hadron_core::ScanType::Custom(paths.clone()), paths);
            }
            ScanPanelAction::StartMemoryScan => {
                self.start_flash_scan(FlashScanType::MemoryScan);
            }
            ScanPanelAction::StartNetworkScan => {
                self.start_flash_scan(FlashScanType::NetworkScan);
            }
            ScanPanelAction::StartFlashDriveScan => {
                self.status_message = "Flash drive scan started...".to_string();
                self.selected_panel = Panel::RemovableMedia;
            }
            ScanPanelAction::StartEmailScan => {
                self.status_message = "Email scan started...".to_string();
                self.start_email_scan_async();
            }
            ScanPanelAction::StartScheduledScan => {
                self.status_message = "Scheduled scan configured...".to_string();
            }
            ScanPanelAction::CancelScan => {
                if let Some(scan_id) = self.current_scan_id {
                    self.cancel_scan_async(scan_id);
                }
                self.app_state = AppState::Idle;
                self.flash_scan_status = "Scan cancelled".to_string();
            }
            ScanPanelAction::PauseScan => {
                self.status_message = "Scan paused...".to_string();
            }
            ScanPanelAction::None => {}
        }
    }

    fn handle_quarantine_action(&mut self, action: QuarantinePanelAction) {
        match action {
            QuarantinePanelAction::Restore(quarantine_id) => {
                self.restore_from_quarantine_async(quarantine_id);
            }
            QuarantinePanelAction::Delete(quarantine_id) => {
                self.delete_from_quarantine_async(quarantine_id);
            }
            QuarantinePanelAction::None => {}
        }
    }

    fn handle_settings_action(&mut self, action: SettingsPanelAction) {
        match action {
            SettingsPanelAction::SaveSettings => {
                self.save_settings_async();
            }
            SettingsPanelAction::None => {}
        }
    }

    fn handle_removable_media_action(&mut self, action: RemovableMediaPanelAction) {
        match action {
            RemovableMediaPanelAction::ScanAllDevices => {
                self.scan_all_removable_devices();
            }
            RemovableMediaPanelAction::ScanDevice(device_id) => {
                self.scan_removable_device(device_id);
            }
            RemovableMediaPanelAction::CleanDevice(device_id) => {
                self.clean_removable_device(device_id);
            }
            RemovableMediaPanelAction::TrustDevice(device_id, trusted) => {
                self.set_device_trust(device_id, trusted);
            }
            RemovableMediaPanelAction::RefreshDevices => {
                self.refresh_removable_devices();
            }
        }
    }

    fn start_scan_async(&mut self, scan_type: ScanType, targets: Vec<std::path::PathBuf>) {
        let client = self.api_client.clone();
        let runtime = self.runtime.clone();

        self.status_message = format!("Starting {:?} scan...", scan_type);
        let scan_type_clone = scan_type.clone();

        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            runtime.block_on(async {
                match client.read().await.start_scan(scan_type_clone, targets).await {
                    Ok(scan_id) => {
                        tracing::info!("Scan started with ID: {}", scan_id);
                        let _ = tx.send(ScanEvent::Started(scan_id));
                    }
                    Err(e) => {
                        tracing::error!("Failed to start scan: {}", e);
                        let _ = tx.send(ScanEvent::Error(e.to_string()));
                    }
                }
            });
        });

        self.scan_event_receiver = Some(rx);
        self.scan_panel.set_scanning(true);
    }

    fn cancel_scan_async(&mut self, scan_id: ScanJobId) {
        let client = self.api_client.clone();
        let runtime = self.runtime.clone();

        self.status_message = "Cancelling scan...".to_string();

        std::thread::spawn(move || {
            runtime.block_on(async {
                tracing::info!("Cancelling scan: {}", scan_id);
            });
        });

        self.scan_panel.set_scanning(false);
    }

    fn restore_from_quarantine_async(&mut self, quarantine_id: hadron_core::QuarantineId) {
        let client = self.api_client.clone();
        let runtime = self.runtime.clone();

        self.status_message = "Restoring file from quarantine...".to_string();

        std::thread::spawn(move || {
            runtime.block_on(async {
                match client.read().await.restore_from_quarantine(quarantine_id.to_string()).await {
                    Ok(()) => {
                        tracing::info!("File restored from quarantine");
                    }
                    Err(e) => {
                        tracing::error!("Failed to restore from quarantine: {}", e);
                    }
                }
            });
        });
    }

    fn delete_from_quarantine_async(&mut self, quarantine_id: hadron_core::QuarantineId) {
        let client = self.api_client.clone();
        let runtime = self.runtime.clone();

        self.status_message = "Deleting file from quarantine...".to_string();

        std::thread::spawn(move || {
            runtime.block_on(async {
                match client.read().await.delete_from_quarantine(quarantine_id.to_string()).await {
                    Ok(()) => {
                        tracing::info!("File deleted from quarantine");
                    }
                    Err(e) => {
                        tracing::error!("Failed to delete from quarantine: {}", e);
                    }
                }
            });
        });
    }

    fn start_flash_scan(&mut self, scan_type: FlashScanType) {
        self.app_state = AppState::Scanning;
        self.flash_scan_type = scan_type.clone();
        self.flash_scan_progress = 0.0;

        let scan_type_str = match scan_type {
            FlashScanType::QuickScan => {
                self.flash_scan_status = "Quick scan in progress...".to_string();
                ScanType::Quick
            }
            FlashScanType::FullScan => {
                self.flash_scan_status = "Full system scan in progress...".to_string();
                ScanType::Full
            }
            FlashScanType::CustomScan => {
                self.flash_scan_status = "Custom scan in progress...".to_string();
                ScanType::Custom(vec![std::path::PathBuf::from("/")])
            }
            FlashScanType::MemoryScan => {
                self.flash_scan_status = "Memory scan in progress...".to_string();
                ScanType::Memory
            }
            FlashScanType::NetworkScan => {
                self.flash_scan_status = "Network scan in progress...".to_string();
                ScanType::Quick
            }
        };

        let client = self.api_client.clone();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async {
                match client.read().await.start_scan(scan_type_str, vec![]).await {
                    Ok(job_id) => {
                        tracing::info!("Flash scan started with job ID: {:?}", job_id);
                    }
                    Err(e) => {
                        tracing::error!("Failed to start flash scan: {}", e);
                    }
                }
            });
        });
    }

    fn update_flash_scan_progress(&mut self) {
        if self.app_state == AppState::Scanning {
            self.flash_scan_progress += 0.01;

            if self.flash_scan_progress >= 1.0 {
                self.flash_scan_progress = 1.0;
                self.flash_scan_status = "Scan completed".to_string();
                self.app_state = AppState::Idle;
                self.add_mock_scan_result();
            }
        }
    }

    fn add_mock_scan_result(&mut self) {
        use hadron_core::{ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};

        let mock_threats = vec![
            ThreatInfo::new(
                "Suspicious.Test.File".to_string(),
                ThreatType::Suspicious,
                ThreatSeverity::Medium,
                std::path::PathBuf::from("/tmp/suspicious_file.txt"),
                "abc123def456".to_string(),
                DetectionMethod::Heuristic,
            ).unwrap_or_else(|_| {
                ThreatInfo {
                    id: uuid::Uuid::new_v4(),
                    name: "Suspicious.Test.File".to_string(),
                    threat_type: ThreatType::Suspicious,
                    severity: ThreatSeverity::Medium,
                    file_path: std::path::PathBuf::from("/tmp/suspicious_file.txt"),
                    file_hash: "abc123def456".to_string(),
                    detection_method: DetectionMethod::Heuristic,
                    timestamp: chrono::Utc::now(),
                    additional_info: std::collections::HashMap::new(),
                }
            })
        ];

        self.scan_statistics.total_scans += 1;
        self.scan_statistics.threats_found += mock_threats.len() as u64;
        self.scan_statistics.files_scanned += 1000;
        self.scan_statistics.last_scan_time = Some(std::time::SystemTime::now());
        self.scan_statistics.scan_duration = std::time::Duration::from_secs(30);

        self.threat_history.extend(mock_threats);
    }

    fn update_system_performance(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        self.system_performance.cpu_usage = 15.0 + (now as f32 * 0.1).sin() * 10.0;
        self.system_performance.memory_usage = 45.0 + (now as f32 * 0.05).cos() * 15.0;
        self.system_performance.disk_usage = 65.0;

        if self.app_state == AppState::Scanning {
            self.system_performance.scan_impact = 25.0 + (now as f32 * 0.2).sin() * 15.0;
        } else {
            self.system_performance.scan_impact = 2.0;
        }

        self.network_activity.connections_monitored = 150 + (now % 50) as u32;
        self.network_activity.threats_blocked = if now % 30 == 0 { 1 } else { 0 };
        self.network_activity.bandwidth_usage = 1024 * 1024 * (50 + (now % 100)) as u64;

        if now % 45 == 0 && self.network_activity.suspicious_activity.len() < 3 {
            self.network_activity.suspicious_activity.push(
                format!("Suspicious connection to 192.168.1.{}", 100 + (now % 50))
            );
        }

        if self.network_activity.suspicious_activity.len() > 5 {
            self.network_activity.suspicious_activity.remove(0);
        }
    }

    fn start_email_scan_async(&mut self) {
        let runtime = self.runtime.clone();
        self.app_state = AppState::Scanning;
        self.flash_scan_status = "Email scan in progress...".to_string();

        std::thread::spawn(move || {
            runtime.block_on(async {
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                tracing::info!("Email scan completed");
            });
        });
    }

    fn show_enhanced_dashboard(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.heading("🛡️ Hadron Antivirus Dashboard");
        ui.separator();
        ui.add_space(5.0);

        // Top status cards
        ui.horizontal(|ui| {
            // Protection Status Card
            ui.group(|ui| {
                ui.set_min_width(200.0);
                ui.vertical(|ui| {
                    ui.heading("Protection Status");
                    ui.separator();

                    let status_color = if self.app_state == AppState::Scanning {
                        egui::Color32::YELLOW
                    } else {
                        egui::Color32::GREEN
                    };

                    let status_text = match self.app_state {
                        AppState::Scanning => "🔍 SCANNING",
                        AppState::Updating => "⬇️ UPDATING",
                        AppState::Processing => "⚙️ PROCESSING",
                        AppState::Idle => "🛡️ PROTECTED",
                    };

                    ui.colored_label(status_color, status_text);
                    ui.label("Real-time protection: Active");
                    ui.label("Last update: Today");
                });
            });

            ui.add_space(10.0);

            // Quick Actions Card
            ui.group(|ui| {
                ui.set_min_width(250.0);
                ui.vertical(|ui| {
                    ui.heading("Quick Actions");
                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.add_enabled(
                            self.app_state != AppState::Scanning,
                            egui::Button::new("⚡ Quick Scan").min_size(egui::vec2(100.0, 30.0))
                        ).clicked() {
                            self.start_flash_scan(FlashScanType::QuickScan);
                        }

                        if ui.add_enabled(
                            self.app_state != AppState::Scanning,
                            egui::Button::new("🔍 Full Scan").min_size(egui::vec2(100.0, 30.0))
                        ).clicked() {
                            self.start_flash_scan(FlashScanType::FullScan);
                        }
                    });

                    ui.horizontal(|ui| {
                        if ui.add_enabled(
                            self.app_state != AppState::Scanning,
                            egui::Button::new("🧠 Memory Scan").min_size(egui::vec2(100.0, 30.0))
                        ).clicked() {
                            self.start_flash_scan(FlashScanType::MemoryScan);
                        }

                        if ui.add_enabled(
                            self.app_state != AppState::Scanning,
                            egui::Button::new("🌐 Network Scan").min_size(egui::vec2(100.0, 30.0))
                        ).clicked() {
                            self.start_flash_scan(FlashScanType::NetworkScan);
                        }
                    });
                });
            });

            ui.add_space(10.0);

            // System Performance Card
            ui.group(|ui| {
                ui.set_min_width(200.0);
                ui.vertical(|ui| {
                    ui.heading("System Performance");
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label("CPU:");
                        ui.add(egui::ProgressBar::new(self.system_performance.cpu_usage / 100.0)
                            .text(format!("{:.1}%", self.system_performance.cpu_usage)));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Memory:");
                        ui.add(egui::ProgressBar::new(self.system_performance.memory_usage / 100.0)
                            .text(format!("{:.1}%", self.system_performance.memory_usage)));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Scan Impact:");
                        ui.add(egui::ProgressBar::new(self.system_performance.scan_impact / 100.0)
                            .text(format!("{:.1}%", self.system_performance.scan_impact)));
                    });
                });
            });
        });

        ui.add_space(15.0);

        // Current Scan Progress (if scanning)
        if self.app_state == AppState::Scanning {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.heading("Current Scan Progress");
                    ui.separator();

                    ui.label(&self.flash_scan_status);
                    ui.add(egui::ProgressBar::new(self.flash_scan_progress)
                        .show_percentage()
                        .animate(true));

                    ui.horizontal(|ui| {
                        ui.label(format!("Scan Type: {:?}", self.flash_scan_type));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Cancel Scan").clicked() {
                                self.app_state = AppState::Idle;
                                self.flash_scan_status = "Scan cancelled".to_string();
                            }
                        });
                    });
                });
            });
            ui.add_space(15.0);
        }

        // Statistics and threat info row
        ui.horizontal(|ui| {
            // Scan Statistics
            ui.group(|ui| {
                ui.set_min_width(300.0);
                ui.vertical(|ui| {
                    ui.heading("📊 Scan Statistics");
                    ui.separator();

                    egui::Grid::new("stats_grid")
                        .num_columns(2)
                        .spacing([40.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Total Scans:");
                            ui.label(format!("{}", self.scan_statistics.total_scans));
                            ui.end_row();

                            ui.label("Threats Found:");
                            ui.colored_label(
                                if self.scan_statistics.threats_found > 0 { egui::Color32::RED } else { egui::Color32::GREEN },
                                format!("{}", self.scan_statistics.threats_found)
                            );
                            ui.end_row();

                            ui.label("Files Scanned:");
                            ui.label(format!("{}", self.scan_statistics.files_scanned));
                            ui.end_row();

                            if let Some(last_scan) = self.scan_statistics.last_scan_time {
                                ui.label("Last Scan:");
                                if let Ok(duration) = last_scan.duration_since(std::time::UNIX_EPOCH) {
                                    let datetime = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                                        .unwrap_or_else(|| chrono::Utc::now());
                                    ui.label(datetime.format("%H:%M:%S").to_string());
                                } else {
                                    ui.label("Unknown");
                                }
                                ui.end_row();
                            }
                        });
                });
            });

            ui.add_space(10.0);

            // Recent Threats
            ui.group(|ui| {
                ui.set_min_width(300.0);
                ui.vertical(|ui| {
                    ui.heading("🚨 Recent Threats");
                    ui.separator();

                    if self.threat_history.is_empty() {
                        ui.colored_label(egui::Color32::GREEN, "✅ No threats detected");
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(150.0)
                            .show(ui, |ui| {
                                for (i, threat) in self.threat_history.iter().rev().take(5).enumerate() {
                                    if i > 0 {
                                        ui.separator();
                                    }

                                    ui.horizontal(|ui| {
                                        let severity_color = match threat.severity {
                                            hadron_core::ThreatSeverity::Critical => egui::Color32::RED,
                                            hadron_core::ThreatSeverity::High => egui::Color32::from_rgb(255, 165, 0),
                                            hadron_core::ThreatSeverity::Medium => egui::Color32::YELLOW,
                                            hadron_core::ThreatSeverity::Low => egui::Color32::GREEN,
                                        };
                                        ui.colored_label(severity_color, "●");
                                        ui.vertical(|ui| {
                                            ui.label(&threat.name);
                                            ui.small(threat.file_path.to_string_lossy().to_string());
                                        });
                                    });
                                }
                            });
                    }
                });
            });

            ui.add_space(10.0);

            // Network Activity
            ui.group(|ui| {
                ui.set_min_width(250.0);
                ui.vertical(|ui| {
                    ui.heading("🌐 Network Activity");
                    ui.separator();

                    egui::Grid::new("network_grid")
                        .num_columns(2)
                        .spacing([40.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Connections:");
                            ui.label(format!("{}", self.network_activity.connections_monitored));
                            ui.end_row();

                            ui.label("Blocked:");
                            ui.colored_label(
                                if self.network_activity.threats_blocked > 0 { egui::Color32::RED } else { egui::Color32::GREEN },
                                format!("{}", self.network_activity.threats_blocked)
                            );
                            ui.end_row();

                            ui.label("Bandwidth:");
                            ui.label(format!("{} MB", self.network_activity.bandwidth_usage / 1024 / 1024));
                            ui.end_row();
                        });

                    if !self.network_activity.suspicious_activity.is_empty() {
                        ui.separator();
                        ui.label("Suspicious Activity:");
                        for activity in &self.network_activity.suspicious_activity {
                            ui.small(activity);
                        }
                    }
                });
            });
        });

        ui.add_space(15.0);

        // Navigation buttons
        ui.horizontal(|ui| {
            if ui.button("🔧 Open Settings").clicked() {
                self.selected_panel = Panel::Settings;
            }
            if ui.button("🗂️ View Quarantine").clicked() {
                self.selected_panel = Panel::Quarantine;
            }
            if ui.button("💾 Removable Media").clicked() {
                self.selected_panel = Panel::RemovableMedia;
            }
            if ui.button("🔍 Advanced Scan").clicked() {
                self.selected_panel = Panel::Scan;
            }
        });
    }
