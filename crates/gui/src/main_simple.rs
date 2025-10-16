use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Hadron Antivirus",
        options,
        Box::new(|_cc| Box::new(SimpleAntivirusApp::default())),
    )
}

struct SimpleAntivirusApp {
    scan_progress: f32,
    threats_found: u32,
    last_scan: String,
}

impl Default for SimpleAntivirusApp {
    fn default() -> Self {
        Self {
            scan_progress: 0.0,
            threats_found: 0,
            last_scan: "Never".to_string(),
        }
    }
}

impl eframe::App for SimpleAntivirusApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🛡️ Hadron Antivirus");
            ui.separator();

            // Status section
            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.colored_label(egui::Color32::GREEN, "✅ Protected");
            });

            ui.horizontal(|ui| {
                ui.label("Last scan:");
                ui.label(&self.last_scan);
            });

            ui.horizontal(|ui| {
                ui.label("Threats found:");
                if self.threats_found > 0 {
                    ui.colored_label(egui::Color32::RED, format!("{}", self.threats_found));
                } else {
                    ui.colored_label(egui::Color32::GREEN, "0");
                }
            });

            ui.separator();

            // Scan buttons
            ui.horizontal(|ui| {
                if ui.button("🔍 Quick Scan").clicked() {
                    self.start_scan();
                }
                if ui.button("🔍 Full Scan").clicked() {
                    self.start_scan();
                }
            });

            // Progress bar
            if self.scan_progress > 0.0 && self.scan_progress < 1.0 {
                ui.separator();
                ui.label("Scanning...");
                ui.add(egui::ProgressBar::new(self.scan_progress).show_percentage());
                
                // Simulate progress
                self.scan_progress += 0.01;
                ctx.request_repaint();
            } else if self.scan_progress >= 1.0 {
                self.scan_progress = 0.0;
                self.last_scan = "Just now".to_string();
            }

            ui.separator();

            // Footer
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.label("Hadron Antivirus v1.0.0 - Core Engine Running ✅");
            });
        });
    }
}

impl SimpleAntivirusApp {
    fn start_scan(&mut self) {
        self.scan_progress = 0.01; // Start scanning
    }
}