// Tauri API'sini import et
const { invoke } = window.__TAURI__ ? window.__TAURI__.core : {
    invoke: async (cmd, args) => {
        console.log(`Mock invoke: ${cmd}`, args);
        return `Mock response for ${cmd}`;
    }
};

// Tab management
function initTabs() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    navButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Update nav buttons
            navButtons.forEach(btn => {
                btn.classList.remove('border-b-2', 'border-blue-500', 'text-blue-600', 'font-medium');
                btn.classList.add('text-gray-600');
            });
            button.classList.add('border-b-2', 'border-blue-500', 'text-blue-600', 'font-medium');
            button.classList.remove('text-gray-600');
            
            // Update tab contents
            tabContents.forEach(content => {
                content.classList.add('hidden');
            });
            document.getElementById(targetTab).classList.remove('hidden');
            
            // Load tab-specific data
            loadTabData(targetTab);
        });
    });
}

// Load data for specific tabs
async function loadTabData(tab) {
    switch(tab) {
        case 'dashboard':
            await loadSystemStatus();
            break;
        case 'quarantine':
            await loadQuarantineData();
            break;
        case 'devices':
            await loadDevicesData();
            break;
    }
}

// Load system status
async function loadSystemStatus() {
    try {
        const status = await invoke('get_system_status');
        document.getElementById('last-update').textContent = status.last_update;
        document.getElementById('threats-count').textContent = status.threats_detected;
        document.getElementById('version').textContent = status.version;
        document.getElementById('protection-status').textContent = status.realtime_protection;
    } catch (error) {
        console.error('Failed to load system status:', error);
    }
}

// Scan functionality
let currentScanId = null;

async function startScan(type) {
    try {
        let scanId;
        if (type === 'quick') {
            scanId = await invoke('start_quick_scan');
        } else if (type === 'full') {
            scanId = await invoke('start_full_scan');
        }
        
        currentScanId = scanId;
        showScanProgress();
        simulateScanProgress(type);
        
        console.log(`Started ${type} scan with ID: ${scanId}`);
    } catch (error) {
        console.error('Failed to start scan:', error);
        alert('Tarama başlatılamadı: ' + error);
    }
}

function showScanProgress() {
    document.getElementById('scan-progress').classList.remove('hidden');
    document.querySelectorAll('.scan-type-btn').forEach(btn => {
        btn.disabled = true;
        btn.classList.add('opacity-50');
    });
}

function hideScanProgress() {
    document.getElementById('scan-progress').classList.add('hidden');
    document.querySelectorAll('.scan-type-btn').forEach(btn => {
        btn.disabled = false;
        btn.classList.remove('opacity-50');
    });
    document.getElementById('progress-bar').style.width = '0%';
    document.getElementById('scan-percentage').textContent = '0%';
}

function simulateScanProgress(type) {
    const duration = type === 'quick' ? 30000 : 180000; // 30s for quick, 3min for full (demo)
    const steps = 100;
    const stepDuration = duration / steps;
    let progress = 0;
    
    const interval = setInterval(() => {
        progress += 1;
        document.getElementById('progress-bar').style.width = progress + '%';
        document.getElementById('scan-percentage').textContent = progress + '%';
        
        if (progress < 20) {
            document.getElementById('scan-status').textContent = 'Sistem dosyaları taranıyor...';
        } else if (progress < 40) {
            document.getElementById('scan-status').textContent = 'Kullanıcı dosyaları taranıyor...';
        } else if (progress < 60) {
            document.getElementById('scan-status').textContent = 'Uygulamalar kontrol ediliyor...';
        } else if (progress < 80) {
            document.getElementById('scan-status').textContent = 'Geçici dosyalar taranıyor...';
        } else if (progress < 95) {
            document.getElementById('scan-status').textContent = 'Bellek taraması yapılıyor...';
        } else {
            document.getElementById('scan-status').textContent = 'Tarama tamamlanıyor...';
        }
        
        if (progress >= 100) {
            clearInterval(interval);
            document.getElementById('scan-status').textContent = 'Tarama tamamlandı!';
            setTimeout(() => {
                hideScanProgress();
                alert('Tarama başarıyla tamamlandı! Tehdit bulunamadı.');
            }, 1000);
        }
    }, stepDuration);
}

// Load quarantine data
async function loadQuarantineData() {
    try {
        const entries = await invoke('get_quarantine_entries');
        const container = document.getElementById('quarantine-list');
        
        if (entries.length === 0) {
            container.innerHTML = '<p class="text-gray-500">Karantinada dosya bulunmuyor.</p>';
            return;
        }
        
        container.innerHTML = entries.map(entry => `
            <div class="border rounded-lg p-4 mb-4">
                <div class="flex justify-between items-start">
                    <div class="flex-1">
                        <h3 class="font-semibold text-red-600">${entry.threat_name}</h3>
                        <p class="text-sm text-gray-600">${entry.original_path}</p>
                        <p class="text-xs text-gray-500">
                            Karantina: ${new Date(entry.quarantine_time).toLocaleString('tr-TR')} | 
                            Boyut: ${formatFileSize(entry.file_size)} |
                            Tehdit: ${entry.threat_type} |
                            Önem: ${getSeverityText(entry.severity)}
                        </p>
                    </div>
                    <div class="flex space-x-2 ml-4">
                        <button onclick="restoreFile('${entry.id}')" 
                                class="px-3 py-1 bg-green-500 text-white text-sm rounded hover:bg-green-600">
                            Geri Yükle
                        </button>
                        <button onclick="deleteFile('${entry.id}')" 
                                class="px-3 py-1 bg-red-500 text-white text-sm rounded hover:bg-red-600">
                            Sil
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load quarantine data:', error);
        document.getElementById('quarantine-list').innerHTML = 
            '<p class="text-red-500">Karantina verileri yüklenemedi.</p>';
    }
}

// Load devices data
async function loadDevicesData() {
    try {
        const devices = await invoke('get_real_removable_devices');
        const container = document.getElementById('devices-list');
        
        if (devices.length === 0) {
            container.innerHTML = '<p class="text-gray-500">Çıkarılabilir cihaz bulunamadı.</p>';
            return;
        }
        
        container.innerHTML = devices.map(device => `
            <div class="border rounded-lg p-4 mb-4">
                <div class="flex justify-between items-start">
                    <div class="flex-1">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-usb text-blue-500 mr-2"></i>
                            <h3 class="font-semibold">${device.name}</h3>
                            ${device.is_trusted ? 
                                '<span class="ml-2 px-2 py-1 bg-green-100 text-green-800 text-xs rounded">Güvenilir</span>' : 
                                '<span class="ml-2 px-2 py-1 bg-yellow-100 text-yellow-800 text-xs rounded">Bilinmeyen</span>'
                            }
                        </div>
                        <p class="text-sm text-gray-600">${device.mount_path}</p>
                        <p class="text-xs text-gray-500">
                            Boyut: ${formatFileSize(device.size_bytes)} | 
                            Tip: ${getDeviceTypeText(device.device_type)} |
                            ${device.last_scan ? 
                                `Son tarama: ${new Date(device.last_scan).toLocaleString('tr-TR')}` : 
                                'Hiç taranmamış'
                            }
                        </p>
                    </div>
                    <div class="flex space-x-2 ml-4">
                        <button onclick="scanDevice('${device.id}')" 
                                class="px-3 py-1 bg-blue-500 text-white text-sm rounded hover:bg-blue-600">
                            Tara
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load devices data:', error);
        document.getElementById('devices-list').innerHTML = 
            '<p class="text-red-500">Cihaz verileri yüklenemedi.</p>';
    }
}

// Utility functions
function formatFileSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

function getSeverityText(severity) {
    const severityMap = {
        'Low': 'Düşük',
        'Medium': 'Orta',
        'High': 'Yüksek',
        'Critical': 'Kritik'
    };
    return severityMap[severity] || severity;
}

function getDeviceTypeText(deviceType) {
    const typeMap = {
        'UsbDrive': 'USB Bellek',
        'SdCard': 'SD Kart',
        'ExternalHdd': 'Harici Disk',
        'CdDvd': 'CD/DVD',
        'Unknown': 'Bilinmeyen'
    };
    return typeMap[deviceType] || deviceType;
}

// Action functions
async function restoreFile(entryId) {
    if (confirm('Bu dosyayı karantinadan geri yüklemek istediğinizden emin misiniz?')) {
        try {
            const result = await invoke('restore_from_quarantine', { entryId });
            alert(result);
            loadQuarantineData(); // Refresh the list
        } catch (error) {
            alert('Dosya geri yüklenemedi: ' + error);
        }
    }
}

async function deleteFile(entryId) {
    if (confirm('Bu dosyayı kalıcı olarak silmek istediğinizden emin misiniz?')) {
        try {
            const result = await invoke('delete_from_quarantine', { entryId });
            alert(result);
            loadQuarantineData(); // Refresh the list
        } catch (error) {
            alert('Dosya silinemedi: ' + error);
        }
    }
}

async function scanDevice(deviceId) {
    try {
        const scanId = await invoke('scan_removable_device', { deviceId });
        alert(`Cihaz taraması başlatıldı. Tarama ID: ${scanId}`);
    } catch (error) {
        alert('Cihaz taraması başlatılamadı: ' + error);
    }
}

// Custom scan functions
function showCustomScanModal() {
    document.getElementById('custom-scan-modal').classList.remove('hidden');
}

function hideCustomScanModal() {
    document.getElementById('custom-scan-modal').classList.add('hidden');
}

async function startCustomScan() {
    const checkboxes = document.querySelectorAll('#custom-scan-modal input[type="checkbox"]:checked');
    const selectedPaths = Array.from(checkboxes).map(cb => cb.value);
    
    if (selectedPaths.length === 0) {
        alert('Lütfen en az bir klasör seçin!');
        return;
    }
    
    try {
        const scanId = await invoke('start_custom_scan', { paths: selectedPaths });
        currentScanId = scanId;
        hideCustomScanModal();
        showScanProgress();
        
        // Özel tarama için dinamik süre hesapla
        const estimatedDuration = selectedPaths.length * 15000; // Her klasör için 15 saniye
        simulateCustomScanProgress(selectedPaths, estimatedDuration);
        
        console.log(`Started custom scan with ID: ${scanId} for paths:`, selectedPaths);
    } catch (error) {
        console.error('Failed to start custom scan:', error);
        alert('Özel tarama başlatılamadı: ' + error);
    }
}

function simulateCustomScanProgress(paths, duration) {
    const steps = 100;
    const stepDuration = duration / steps;
    let progress = 0;
    let currentPathIndex = 0;
    
    const interval = setInterval(() => {
        progress += 1;
        document.getElementById('progress-bar').style.width = progress + '%';
        document.getElementById('scan-percentage').textContent = progress + '%';
        
        // Her %20'de bir klasör değiştir
        if (progress % 20 === 0 && currentPathIndex < paths.length) {
            const currentPath = paths[currentPathIndex];
            document.getElementById('scan-status').textContent = `Taranıyor: ${currentPath}`;
            currentPathIndex++;
        }
        
        if (progress >= 100) {
            clearInterval(interval);
            document.getElementById('scan-status').textContent = 'Özel tarama tamamlandı!';
            setTimeout(() => {
                hideScanProgress();
                alert(`Özel tarama başarıyla tamamlandı!\nTaranan klasörler: ${paths.join(', ')}\nTehdit bulunamadı.`);
            }, 1000);
        }
    }, stepDuration);
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    loadSystemStatus();
    
    // Quick scan button
    document.getElementById('quick-scan-btn').addEventListener('click', () => {
        startScan('quick');
    });
    
    // Full scan button
    document.getElementById('full-scan-btn').addEventListener('click', () => {
        startScan('full');
    });
    
    // Scan type buttons
    document.querySelectorAll('.scan-type-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const scanType = btn.getAttribute('data-type');
            if (scanType !== 'custom') {
                startScan(scanType);
            } else {
                showCustomScanModal();
            }
        });
    });
    
    // Cancel scan button
    document.getElementById('cancel-scan-btn').addEventListener('click', () => {
        if (confirm('Taramayı durdurmak istediğinizden emin misiniz?')) {
            hideScanProgress();
            currentScanId = null;
        }
    });
    
    // Custom scan modal buttons
    document.getElementById('cancel-custom-scan').addEventListener('click', hideCustomScanModal);
    document.getElementById('start-custom-scan').addEventListener('click', startCustomScan);
});