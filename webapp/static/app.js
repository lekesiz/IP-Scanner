// Professional IP Scanner V4.0 JavaScript
// Global variables
let currentDevices = [];
let scanInProgress = false;
let currentTheme = 'light';
let currentLanguage = 'tr';

// Translations
const translations = {
    tr: {
        title: 'IP Scanner V4.0 - Profesyonel Ağ Tarayıcı',
        scanning: 'Tarama yapılıyor...',
        no_devices: 'Henüz tarama yapılmadı',
        start_scan: 'Tarama Başlat',
        total_devices: 'Toplam Cihaz',
        online_devices: 'Çevrimiçi',
        open_ports: 'Açık Port',
        scan_time: 'Tarama Süresi',
        quick_scan: 'Hızlı Tarama',
        advanced_scan: 'Gelişmiş Tarama',
        network_map: 'Ağ Haritası',
        generate_report: 'Rapor Oluştur',
        scan_options: 'Tarama Seçenekleri',
        ip_range: 'IP Aralığı',
        scan_type: 'Tarama Türü',
        port_scan: 'Port Tarama',
        nmap_scan: 'Nmap',
        network_devices: 'Ağ Cihazları',
        refresh: 'Yenile',
        export: 'Dışa Aktar',
        device_details: 'Cihaz Detayları',
        status: 'Durum',
        vendor: 'Üretici',
        device_type: 'Cihaz Türü',
        confidence: 'Güven',
        last_seen: 'Son Görülme',
        actions: 'İşlemler',
        view_details: 'Detayları Gör',
        online: 'Çevrimiçi',
        offline: 'Çevrimdışı',
        unknown: 'Bilinmiyor',
        router: 'Router',
        computer: 'Bilgisayar',
        phone: 'Telefon',
        tablet: 'Tablet',
        printer: 'Yazıcı',
        camera: 'Kamera',
        other: 'Diğer',
        scan_completed: 'Tarama tamamlandı',
        scan_failed: 'Tarama başarısız',
        loading: 'Yükleniyor...',
        error: 'Hata',
        success: 'Başarılı',
        warning: 'Uyarı',
        info: 'Bilgi',
        // Traffic monitoring translations
        live_traffic: 'Canlı Ağ Trafiği',
        start_monitoring: 'İzlemeyi Başlat',
        stop_monitoring: 'Durdur',
        monitoring: 'İzleniyor',
        stopped: 'Durduruldu',
        auto_refresh: 'Her 2 saniyede bir güncellenir',
        bytes_sent: 'Gönderilen (B)',
        bytes_recv: 'Alınan (B)',
        packets_sent: 'Gönderilen Paket',
        packets_recv: 'Alınan Paket',
        active_connections: 'Aktif Bağlantılar',
        local_address: 'Yerel Adres',
        remote_address: 'Uzak Adres',
        no_connections: 'Bağlantı yok',
        traffic_error: 'Trafik verisi alınamadı',
        close: 'Kapat'
    },
    en: {
        title: 'IP Scanner V4.0 - Professional Network Scanner',
        scanning: 'Scanning...',
        no_devices: 'No scan performed yet',
        start_scan: 'Start Scan',
        total_devices: 'Total Devices',
        online_devices: 'Online',
        open_ports: 'Open Ports',
        scan_time: 'Scan Time',
        quick_scan: 'Quick Scan',
        advanced_scan: 'Advanced Scan',
        network_map: 'Network Map',
        generate_report: 'Generate Report',
        scan_options: 'Scan Options',
        ip_range: 'IP Range',
        scan_type: 'Scan Type',
        port_scan: 'Port Scan',
        nmap_scan: 'Nmap',
        network_devices: 'Network Devices',
        refresh: 'Refresh',
        export: 'Export',
        device_details: 'Device Details',
        status: 'Status',
        vendor: 'Vendor',
        device_type: 'Device Type',
        confidence: 'Confidence',
        last_seen: 'Last Seen',
        actions: 'Actions',
        view_details: 'View Details',
        online: 'Online',
        offline: 'Offline',
        unknown: 'Unknown',
        router: 'Router',
        computer: 'Computer',
        phone: 'Phone',
        tablet: 'Tablet',
        printer: 'Printer',
        camera: 'Camera',
        other: 'Other',
        scan_completed: 'Scan completed',
        scan_failed: 'Scan failed',
        loading: 'Loading...',
        error: 'Error',
        success: 'Success',
        warning: 'Warning',
        info: 'Info',
        // Traffic monitoring translations
        live_traffic: 'Live Network Traffic',
        start_monitoring: 'Start Monitoring',
        stop_monitoring: 'Stop',
        monitoring: 'Monitoring',
        stopped: 'Stopped',
        auto_refresh: 'Updates every 2 seconds',
        bytes_sent: 'Bytes Sent',
        bytes_recv: 'Bytes Received',
        packets_sent: 'Packets Sent',
        packets_recv: 'Packets Received',
        active_connections: 'Active Connections',
        local_address: 'Local Address',
        remote_address: 'Remote Address',
        no_connections: 'No connections',
        traffic_error: 'Failed to get traffic data',
        close: 'Close'
    }
};

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    checkAuth();
    setupEventListeners();
    loadUserPreferences();
    updateStats();
}

function checkAuth() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        window.location.href = '/login';
        return;
    }
    
    // Token'ı header'a ekleyerek sayfa yükle
    const headers = new Headers();
    headers.append('Authorization', `Bearer ${token}`);
    
    // Load user profile
    fetch('/api/auth/profile', {
        headers: headers
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Authentication failed');
        }
        return response.json();
    })
    .then(data => {
        if (data.status === 'ok') {
            document.getElementById('username').textContent = data.user.username;
        } else {
            throw new Error('Profile load failed');
        }
    })
    .catch(error => {
        console.error('Profile load error:', error);
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
    });
}

function setupEventListeners() {
    // Quick action buttons
    document.getElementById('quickScanBtn').addEventListener('click', () => startQuickScan());
    document.getElementById('advancedScanBtn').addEventListener('click', () => startAdvancedScan());
    document.getElementById('networkMapBtn').addEventListener('click', () => generateNetworkMap());
    document.getElementById('generateReportBtn').addEventListener('click', () => generateReports());
    
    // Control buttons
    document.getElementById('startScanBtn').addEventListener('click', () => startQuickScan());
    document.getElementById('refreshBtn').addEventListener('click', () => refreshDevices());
    document.getElementById('exportBtn').addEventListener('click', () => exportDevices());
    
    // Theme toggle
    document.getElementById('themeToggle').addEventListener('click', toggleTheme);
    
    // Language selector
    document.getElementById('languageSelect').addEventListener('change', (e) => changeLanguage(e.target.value));
    
    // User menu
    document.getElementById('logoutLink').addEventListener('click', logout);
    document.getElementById('profileLink').addEventListener('click', showProfile);
    document.getElementById('settingsLink').addEventListener('click', showSettings);
    
    // Navigation
    document.getElementById('dashboardLink').addEventListener('click', () => showSection('dashboard'));
    document.getElementById('scanLink').addEventListener('click', () => showSection('scan'));
    document.getElementById('devicesLink').addEventListener('click', () => showSection('devices'));
    document.getElementById('networkMapLink').addEventListener('click', () => showSection('network-map'));
    document.getElementById('reportsLink').addEventListener('click', () => showSection('reports'));
    document.getElementById('trafficLink').addEventListener('click', () => showSection('traffic'));
}

function loadUserPreferences() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    const savedLanguage = localStorage.getItem('language') || 'tr';
    
    setTheme(savedTheme);
    setLanguage(savedLanguage);
}

function setTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
    
    const themeIcon = document.querySelector('#themeToggle i');
    themeIcon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}

function toggleTheme() {
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

function setLanguage(lang) {
    currentLanguage = lang;
    document.getElementById('languageSelect').value = lang;
    localStorage.setItem('language', lang);
    applyTranslations();
}

function changeLanguage(lang) {
    setLanguage(lang);
}

function applyTranslations() {
    const t = translations[currentLanguage];
    
    // Update page title
    document.title = t.title;
    
    // Update all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (t[key]) {
            element.textContent = t[key];
        }
    });
}

function t(key) {
    return translations[currentLanguage][key] || key;
}

function startQuickScan() {
    if (scanInProgress) return;
    
    const ipRange = document.getElementById('ipRange').value;
    const portScan = document.getElementById('portScan').checked;
    
    showLoading();
    
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
            ip_range: ipRange,
            port_scan: portScan
        })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        if (data.success) {
            currentDevices = data.devices || [];
            displayDevices(currentDevices);
            updateStats();
            showNotification(t('scan_completed'), 'success');
        } else {
            showNotification(t('scan_failed'), 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Scan error:', error);
        showNotification(t('scan_failed'), 'error');
    });
}

function startAdvancedScan() {
    if (scanInProgress) return;
    
    const ipRange = document.getElementById('ipRange').value;
    const enableNmap = document.getElementById('nmapScan').checked;
    
    showLoading();
    
    fetch('/api/advanced-scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
            ip_range: ipRange,
            enable_nmap: enableNmap,
            enable_dhcp: true,
            enable_netbios: true,
            enable_mdns: true
        })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        if (data.success) {
            currentDevices = data.devices || [];
            displayDevices(currentDevices);
            updateStats();
            showNotification(t('scan_completed'), 'success');
        } else {
            showNotification(t('scan_failed'), 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Advanced scan error:', error);
        showNotification(t('scan_failed'), 'error');
    });
}

function showLoading() {
    scanInProgress = true;
    document.getElementById('loadingState').style.display = 'block';
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('devicesContainer').style.display = 'none';
}

function hideLoading() {
    scanInProgress = false;
    document.getElementById('loadingState').style.display = 'none';
}

function displayDevices(devices) {
    const container = document.getElementById('devicesContainer');
    
    if (devices.length === 0) {
        document.getElementById('emptyState').style.display = 'block';
        container.style.display = 'none';
        return;
    }
    
    document.getElementById('emptyState').style.display = 'none';
    container.style.display = 'block';
    
    container.innerHTML = devices.map(device => createDeviceCard(device)).join('');
}

function createDeviceCard(device) {
    const deviceIcon = getDeviceIcon(device.device_type);
    const statusClass = device.status === 'Aktif' ? 'online' : 'offline';
    const confidence = device.confidence || 0;
    
    return `
        <div class="col-md-6 col-lg-4 mb-3">
            <div class="card device-card ${statusClass}" onclick="showDeviceDetails('${device.ip}')">
                <div class="card-body">
                    <div class="d-flex align-items-center mb-3">
                        <i class="${deviceIcon} device-type-icon"></i>
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${device.ip}</h6>
                            <small class="text-muted">${device.mac}</small>
                        </div>
                        <span class="badge ${statusClass === 'online' ? 'bg-success' : 'bg-danger'}">${device.status}</span>
                    </div>
                    
                    <div class="row text-center">
                        <div class="col-6">
                            <small class="text-muted">${t('vendor')}</small>
                            <div class="fw-bold">${device.vendor || t('unknown')}</div>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">${t('device_type')}</small>
                            <div class="fw-bold">${device.device_type || t('unknown')}</div>
                        </div>
                    </div>
                    
                    ${confidence > 0 ? `
                        <div class="mt-2">
                            <small class="text-muted">${t('confidence')}</small>
                            <div class="progress" style="height: 6px;">
                                <div class="progress-bar bg-success" style="width: ${confidence}%"></div>
                            </div>
                            <small class="text-muted">${confidence}%</small>
                        </div>
                    ` : ''}
                    
                    ${device.open_ports && device.open_ports.length > 0 ? `
                        <div class="mt-2">
                            <small class="text-muted">${t('open_ports')}: ${device.open_ports.length}</small>
                            <div class="mt-1">
                                ${device.open_ports.slice(0, 3).map(port => 
                                    `<span class="badge bg-info me-1">${port}</span>`
                                ).join('')}
                                ${device.open_ports.length > 3 ? `<small class="text-muted">+${device.open_ports.length - 3}</small>` : ''}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

function getDeviceIcon(deviceType) {
    const icons = {
        'Router': 'fas fa-wifi',
        'Bilgisayar': 'fas fa-desktop',
        'Telefon': 'fas fa-mobile-alt',
        'Tablet': 'fas fa-tablet-alt',
        'Yazıcı': 'fas fa-print',
        'Kamera': 'fas fa-video',
        'Router/Modem': 'fas fa-wifi',
        'Windows Cihazı': 'fas fa-desktop',
        'Linux Cihazı': 'fas fa-desktop',
        'Apple Cihazı': 'fab fa-apple',
        'Android Cihazı': 'fab fa-android',
        'iOS Cihazı': 'fab fa-apple'
    };
    
    return icons[deviceType] || 'fas fa-cube';
}

function updateStats() {
    const totalDevices = currentDevices.length;
    const onlineDevices = currentDevices.filter(d => d.status === 'Aktif').length;
    const openPorts = currentDevices.reduce((sum, d) => sum + (d.open_ports ? d.open_ports.length : 0), 0);
    
    document.getElementById('totalDevices').textContent = totalDevices;
    document.getElementById('onlineDevices').textContent = onlineDevices;
    document.getElementById('openPorts').textContent = openPorts;
    document.getElementById('scanTime').textContent = '0s'; // TODO: Implement actual scan time
}

function showDeviceDetails(ip) {
    const device = currentDevices.find(d => d.ip === ip);
    if (!device) return;
    
    // Create and show modal with device details
    const modal = createDeviceDetailsModal(device);
    document.body.appendChild(modal);
    
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    modal.addEventListener('hidden.bs.modal', () => {
        modal.remove();
    });
}

function createDeviceDetailsModal(device) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="${getDeviceIcon(device.device_type)} me-2"></i>
                        ${device.ip} - ${t('device_details')}
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>${t('status')}</h6>
                            <p><span class="badge ${device.status === 'Aktif' ? 'bg-success' : 'bg-danger'}">${device.status}</span></p>
                            
                            <h6>${t('vendor')}</h6>
                            <p>${device.vendor || t('unknown')}</p>
                            
                            <h6>${t('device_type')}</h6>
                            <p>${device.device_type || t('unknown')}</p>
                            
                            <h6>MAC Adresi</h6>
                            <p><code>${device.mac}</code></p>
                        </div>
                        <div class="col-md-6">
                            <h6>${t('last_seen')}</h6>
                            <p>${new Date(device.last_seen).toLocaleString()}</p>
                            
                            ${device.confidence ? `
                                <h6>${t('confidence')}</h6>
                                <div class="progress mb-2">
                                    <div class="progress-bar bg-success" style="width: ${device.confidence}%"></div>
                                </div>
                                <small class="text-muted">${device.confidence}%</small>
                            ` : ''}
                            
                            ${device.open_ports && device.open_ports.length > 0 ? `
                                <h6>${t('open_ports')}</h6>
                                <div class="d-flex flex-wrap gap-1">
                                    ${device.open_ports.map(port => 
                                        `<span class="badge bg-info">${port}</span>`
                                    ).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    return modal;
}

function refreshDevices() {
    fetch('/api/devices', {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'ok') {
            currentDevices = data.devices || [];
            displayDevices(currentDevices);
            updateStats();
        }
    })
    .catch(error => {
        console.error('Refresh error:', error);
        showNotification('Yenileme hatası', 'error');
    });
}

function exportDevices() {
    if (currentDevices.length === 0) {
        showNotification('Dışa aktarılacak cihaz bulunamadı', 'warning');
        return;
    }
    
    const csv = convertToCSV(currentDevices);
    downloadCSV(csv, 'network_devices.csv');
    showNotification('Cihazlar dışa aktarıldı', 'success');
}

function convertToCSV(devices) {
    const headers = ['IP', 'MAC', 'Vendor', 'Device Type', 'Status', 'Open Ports', 'Last Seen'];
    const rows = devices.map(device => [
        device.ip,
        device.mac,
        device.vendor || '',
        device.device_type || '',
        device.status,
        device.open_ports ? device.open_ports.join(', ') : '',
        device.last_seen
    ]);
    
    return [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
}

function downloadCSV(csv, filename) {
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

function generateNetworkMap() {
    if (currentDevices.length === 0) {
        showNotification('Önce tarama yapın', 'warning');
        return;
    }
    
    fetch('/api/network-map', {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'ok') {
            window.open('/static/network.html', '_blank');
            showNotification('Ağ haritası oluşturuldu', 'success');
        } else {
            showNotification('Ağ haritası oluşturulamadı', 'error');
        }
    })
    .catch(error => {
        console.error('Network map error:', error);
        showNotification('Ağ haritası hatası', 'error');
    });
}

function generateReports() {
    if (currentDevices.length === 0) {
        showNotification('Önce tarama yapın', 'warning');
        return;
    }
    
    fetch('/api/generate-reports', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'ok') {
            showNotification('Raporlar oluşturuldu', 'success');
            // TODO: Show download links
        } else {
            showNotification('Rapor oluşturma hatası', 'error');
        }
    })
    .catch(error => {
        console.error('Report generation error:', error);
        showNotification('Rapor oluşturma hatası', 'error');
    });
}

function showSection(section) {
    console.log('Show section:', section);
    
    // Aktif menü öğesini güncelle
    updateActiveMenu(section);
    
    switch(section) {
        case 'dashboard':
            showDashboard();
            break;
        case 'scan':
            showScanSection();
            break;
        case 'devices':
            showDevicesSection();
            break;
        case 'network-map':
            showNetworkMapSection();
            break;
        case 'reports':
            showReportsSection();
            break;
        case 'traffic':
            showLiveTraffic();
            break;
        default:
            showDashboard();
    }
}

function updateActiveMenu(activeSection) {
    // Tüm menü öğelerinden active sınıfını kaldır
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Aktif menü öğesine active sınıfını ekle
    const activeLink = document.querySelector(`[data-section="${activeSection}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }
}

function showDashboard() {
    // Dashboard varsayılan görünüm - zaten görünür durumda
    showNotification('Ana sayfa görüntüleniyor', 'info');
}

function showScanSection() {
    // Tarama bölümünü göster
    showNotification('Tarama bölümü', 'info');
    // Tarama seçeneklerini vurgula
    document.querySelector('.card-header h5').scrollIntoView({ behavior: 'smooth' });
}

function showDevicesSection() {
    // Cihazlar bölümünü göster
    showNotification('Cihazlar bölümü', 'info');
    // Cihaz listesini vurgula
    document.getElementById('devicesContainer').scrollIntoView({ behavior: 'smooth' });
}

function showNetworkMapSection() {
    // Ağ haritası oluştur ve göster
    if (currentDevices.length === 0) {
        showNotification('Önce tarama yapın', 'warning');
        return;
    }
    
    generateNetworkMap();
}

function showReportsSection() {
    // Raporlar bölümünü göster
    if (currentDevices.length === 0) {
        showNotification('Önce tarama yapın', 'warning');
        return;
    }
    
    generateReports();
}

function showLiveTraffic() {
    // Modal'ı aç
    const modal = new bootstrap.Modal(document.getElementById('trafficModal'));
    modal.show();
    
    // Event listener'ları ekle
    setupTrafficControls();
}

function setupTrafficControls() {
    const startBtn = document.getElementById('startTrafficBtn');
    const stopBtn = document.getElementById('stopTrafficBtn');
    const statusBadge = document.getElementById('trafficStatus');
    
    let trafficInterval = null;
    
    startBtn.addEventListener('click', () => {
        // Önce kimlik doğrulamayı test et
        testAuthentication().then(() => {
            // İzlemeyi başlat
            startTrafficMonitoring();
            
            // UI'yi güncelle
            startBtn.style.display = 'none';
            stopBtn.style.display = 'inline-block';
            statusBadge.className = 'badge bg-success';
            statusBadge.innerHTML = '<i class="fas fa-circle"></i> <span data-i18n="monitoring">İzleniyor</span>';
            
            // İlk veriyi hemen al
            updateTrafficData();
            
            // Her 2 saniyede bir güncelle
            trafficInterval = setInterval(updateTrafficData, 2000);
        }).catch(error => {
            console.error('Authentication failed:', error);
            showTrafficError('Kimlik doğrulama başarısız. Lütfen tekrar giriş yapın.');
        });
    });
    
    stopBtn.addEventListener('click', () => {
        // İzlemeyi durdur
        if (trafficInterval) {
            clearInterval(trafficInterval);
            trafficInterval = null;
        }
        
        // UI'yi güncelle
        startBtn.style.display = 'inline-block';
        stopBtn.style.display = 'none';
        statusBadge.className = 'badge bg-secondary';
        statusBadge.innerHTML = '<i class="fas fa-circle"></i> <span data-i18n="stopped">Durduruldu</span>';
        
        // Verileri temizle
        clearTrafficData();
    });
    
    // Modal kapandığında interval'i durdur
    document.getElementById('trafficModal').addEventListener('hidden.bs.modal', () => {
        if (trafficInterval) {
            clearInterval(trafficInterval);
            trafficInterval = null;
        }
        
        // UI'yi sıfırla
        startBtn.style.display = 'inline-block';
        stopBtn.style.display = 'none';
        statusBadge.className = 'badge bg-secondary';
        statusBadge.innerHTML = '<i class="fas fa-circle"></i> <span data-i18n="stopped">Durduruldu</span>';
        
        clearTrafficData();
    });
}

function testAuthentication() {
    const token = localStorage.getItem('auth_token');
    
    if (!token) {
        return Promise.reject(new Error('No token found'));
    }
    
    return fetch('/api/debug/auth', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Auth test successful:', data);
        return data;
    });
}

function startTrafficMonitoring() {
    // Bu fonksiyon artık setupTrafficControls içinde çağrılıyor
    console.log('Traffic monitoring started');
}

function clearTrafficData() {
    // Verileri temizle
    document.getElementById('trafficBytesSent').textContent = '-';
    document.getElementById('trafficBytesRecv').textContent = '-';
    document.getElementById('trafficPacketsSent').textContent = '-';
    document.getElementById('trafficPacketsRecv').textContent = '-';
    document.getElementById('connectionCount').textContent = '0';
    
    const tbody = document.getElementById('trafficConnections');
    tbody.innerHTML = `
        <tr>
            <td colspan="4" class="text-center text-muted py-4">
                <i class="fas fa-info-circle me-2"></i>
                <span data-i18n="no_connections">Bağlantı yok</span>
            </td>
        </tr>
    `;
}

function updateTrafficData() {
    const token = localStorage.getItem('auth_token');
    
    if (!token) {
        console.error('No auth token found');
        showTrafficError('Kimlik doğrulama token\'ı bulunamadı');
        return;
    }
    
    console.log('Making traffic API call with token:', token.substring(0, 20) + '...');
    
    fetch('/api/network-traffic', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        console.log('Traffic API response status:', response.status);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Traffic API response:', data);
        if (data.status === 'ok') {
            // Trafik istatistiklerini güncelle
            document.getElementById('trafficBytesSent').textContent = formatBytes(data.traffic.bytes_sent);
            document.getElementById('trafficBytesRecv').textContent = formatBytes(data.traffic.bytes_recv);
            document.getElementById('trafficPacketsSent').textContent = data.traffic.packets_sent.toLocaleString();
            document.getElementById('trafficPacketsRecv').textContent = data.traffic.packets_recv.toLocaleString();
            
            // Bağlantı sayısını güncelle
            document.getElementById('connectionCount').textContent = data.connections ? data.connections.length : 0;
            
            // Aktif bağlantıları güncelle
            updateConnectionsTable(data.connections);
        } else {
            console.error('Traffic data error:', data.error);
            showTrafficError(data.error || 'Bilinmeyen hata');
        }
    })
    .catch(error => {
        console.error('Traffic data error:', error);
        showTrafficError(error.message || 'Ağ hatası');
    });
}

function showTrafficError(message = 'Trafik verisi alınamadı') {
    document.getElementById('trafficBytesSent').textContent = 'Hata';
    document.getElementById('trafficBytesRecv').textContent = 'Hata';
    document.getElementById('trafficPacketsSent').textContent = 'Hata';
    document.getElementById('trafficPacketsRecv').textContent = 'Hata';
    document.getElementById('connectionCount').textContent = '0';
    
    const tbody = document.getElementById('trafficConnections');
    tbody.innerHTML = `
        <tr>
            <td colspan="4" class="text-center text-danger py-4">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <span>${message}</span>
            </td>
        </tr>
    `;
}

function updateConnectionsTable(connections) {
    const tbody = document.getElementById('trafficConnections');
    
    if (!connections || connections.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center text-muted py-4">
                    <i class="fas fa-info-circle me-2"></i>
                    <span data-i18n="no_connections">Bağlantı yok</span>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = connections.slice(0, 20).map(conn => `
        <tr>
            <td><code class="text-primary">${conn.laddr || '-'}</code></td>
            <td><code class="text-success">${conn.raddr || '-'}</code></td>
            <td><span class="badge ${conn.status === 'ESTABLISHED' ? 'bg-success' : 'bg-warning'}">${conn.status}</span></td>
            <td><span class="badge bg-secondary">${conn.pid || '-'}</span></td>
        </tr>
    `).join('');
    
    // Eğer daha fazla bağlantı varsa bilgi ver
    if (connections.length > 20) {
        tbody.innerHTML += `
            <tr>
                <td colspan="4" class="text-center text-muted py-2">
                    <small>${connections.length - 20} bağlantı daha gösteriliyor...</small>
                </td>
            </tr>
        `;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function logout() {
    fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
    })
    .then(() => {
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
    })
    .catch(error => {
        console.error('Logout error:', error);
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
    });
}

function showProfile() {
    // Profil modal'ını aç
    const modal = new bootstrap.Modal(document.getElementById('profileModal'));
    modal.show();
    
    // Profil bilgilerini yükle
    loadProfileData();
}

function loadProfileData() {
    fetch('/api/auth/profile', {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'ok') {
            const user = data.user;
            document.getElementById('profileUsername').textContent = user.username;
            document.getElementById('profileEmail').textContent = user.email || 'Belirtilmemiş';
            document.getElementById('profileFullName').textContent = user.full_name || 'Belirtilmemiş';
            document.getElementById('profileRole').textContent = user.role || 'Kullanıcı';
            document.getElementById('profileCreatedAt').textContent = new Date(user.created_at).toLocaleDateString('tr-TR');
            document.getElementById('profileLastLogin').textContent = user.last_login ? new Date(user.last_login).toLocaleString('tr-TR') : 'Hiç giriş yapılmamış';
        }
    })
    .catch(error => {
        console.error('Profile load error:', error);
        showNotification('Profil bilgileri yüklenemedi', 'error');
    });
}

function showSettings() {
    // Ayarlar modal'ını aç
    const modal = new bootstrap.Modal(document.getElementById('settingsModal'));
    modal.show();
    
    // Mevcut ayarları yükle
    loadSettings();
}

function loadSettings() {
    // Tema ayarını yükle
    const currentTheme = localStorage.getItem('theme') || 'light';
    document.getElementById('themeSelect').value = currentTheme;
    
    // Dil ayarını yükle
    const currentLanguage = localStorage.getItem('language') || 'tr';
    document.getElementById('languageSelect').value = currentLanguage;
    
    // Diğer ayarları yükle
    const emailNotifications = localStorage.getItem('emailNotifications') !== 'false';
    const anomalyAlerts = localStorage.getItem('anomalyAlerts') !== 'false';
    const scanComplete = localStorage.getItem('scanComplete') !== 'false';
    
    document.getElementById('emailNotifications').checked = emailNotifications;
    document.getElementById('anomalyAlerts').checked = anomalyAlerts;
    document.getElementById('scanComplete').checked = scanComplete;
}

function saveSettings() {
    // Tema ayarını kaydet
    const theme = document.getElementById('themeSelect').value;
    setTheme(theme);
    
    // Dil ayarını kaydet
    const language = document.getElementById('languageSelect').value;
    setLanguage(language);
    
    // Diğer ayarları kaydet
    const emailNotifications = document.getElementById('emailNotifications').checked;
    const anomalyAlerts = document.getElementById('anomalyAlerts').checked;
    const scanComplete = document.getElementById('scanComplete').checked;
    
    localStorage.setItem('emailNotifications', emailNotifications);
    localStorage.setItem('anomalyAlerts', anomalyAlerts);
    localStorage.setItem('scanComplete', scanComplete);
    
    showNotification('Ayarlar kaydedildi', 'success');
    
    // Modal'ı kapat
    const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
    modal.hide();
}

function exportSettings() {
    const settings = {
        theme: localStorage.getItem('theme') || 'light',
        language: localStorage.getItem('language') || 'tr',
        emailNotifications: localStorage.getItem('emailNotifications') !== 'false',
        anomalyAlerts: localStorage.getItem('anomalyAlerts') !== 'false',
        scanComplete: localStorage.getItem('scanComplete') !== 'false'
    };
    
    const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ip_scanner_settings.json';
    a.click();
    window.URL.revokeObjectURL(url);
    
    showNotification('Ayarlar dışa aktarıldı', 'success');
}

function showNotification(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast-notification ${type}`;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : type === 'warning' ? '#ffc107' : '#17a2b8'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        max-width: 300px;
        animation: slideIn 0.3s ease;
    `;
    
    toast.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// PWA Support
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/static/service-worker.js');
    });
}

function editProfile() {
    // Profil düzenleme özelliği - şimdilik basit bir bildirim
    showNotification('Profil düzenleme özelliği yakında eklenecek', 'info');
    
    // Modal'ı kapat
    const modal = bootstrap.Modal.getInstance(document.getElementById('profileModal'));
    modal.hide();
} 