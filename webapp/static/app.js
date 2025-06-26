// IP Scanner V4.0 - Frontend JavaScript
// Modern UX ve error handling ile geliştirilmiş

class IPScannerApp {
    constructor() {
        this.currentUser = null;
        this.scanResults = [];
        this.isScanning = false;
        this.apiBaseUrl = '';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupLoadingStates();
        this.setupErrorHandling();
        this.setupNotifications();
    }

    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Register form
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }

        // Dashboard butonları
        const quickScanBtn = document.getElementById('quickScanBtn');
        if (quickScanBtn) {
            quickScanBtn.addEventListener('click', () => this.handleQuickScan());
        }

        const advancedScanBtn = document.getElementById('advancedScanBtn');
        if (advancedScanBtn) {
            advancedScanBtn.addEventListener('click', () => this.handleAdvancedScanClick());
        }

        const networkMapBtn = document.getElementById('networkMapBtn');
        if (networkMapBtn) {
            networkMapBtn.addEventListener('click', () => this.showNetworkMap());
        }

        const generateReportBtn = document.getElementById('generateReportBtn');
        if (generateReportBtn) {
            generateReportBtn.addEventListener('click', () => this.showReportModal());
        }

        const startScanBtn = document.getElementById('startScanBtn');
        if (startScanBtn) {
            startScanBtn.addEventListener('click', () => this.handleQuickScan());
        }

        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshDevices());
        }

        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.showExportOptions());
        }

        // User menu
        const logoutLink = document.getElementById('logoutLink');
        if (logoutLink) {
            logoutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
        }

        const profileLink = document.getElementById('profileLink');
        if (profileLink) {
            profileLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showProfileModal();
            });
        }

        const settingsLink = document.getElementById('settingsLink');
        if (settingsLink) {
            settingsLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showSettingsModal();
            });
        }

        // Navigation
        this.setupNavigation();

        // Modal events
        this.setupModalEvents();

        // Real-time updates
        this.setupRealTimeUpdates();
    }

    setupLoadingStates() {
        // Global loading overlay
        this.loadingOverlay = document.createElement('div');
        this.loadingOverlay.id = 'loadingOverlay';
        this.loadingOverlay.className = 'loading-overlay';
        this.loadingOverlay.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Yükleniyor...</span>
                </div>
                <div class="loading-text mt-2">İşlem yapılıyor...</div>
            </div>
        `;
        document.body.appendChild(this.loadingOverlay);

        // Button loading states
        this.setupButtonLoadingStates();
    }

    setupButtonLoadingStates() {
        // Login button
        const loginBtn = document.querySelector('#loginForm button[type="submit"]');
        if (loginBtn) {
            this.setupButtonLoading(loginBtn, 'Giriş yapılıyor...');
        }

        // Register button
        const registerBtn = document.querySelector('#registerForm button[type="submit"]');
        if (registerBtn) {
            this.setupButtonLoading(registerBtn, 'Kayıt yapılıyor...');
        }

        // Scan button
        const scanBtn = document.querySelector('#scanForm button[type="submit"]');
        if (scanBtn) {
            this.setupButtonLoading(scanBtn, 'Taranıyor...');
        }

        // Advanced scan button
        const advancedScanBtn = document.querySelector('#advancedScanForm button[type="submit"]');
        if (advancedScanBtn) {
            this.setupButtonLoading(advancedScanBtn, 'Gelişmiş tarama yapılıyor...');
        }
    }

    setupButtonLoading(button, loadingText) {
        const originalText = button.innerHTML;
        const originalDisabled = button.disabled;

        button.addEventListener('click', () => {
            if (!button.disabled) {
                button.disabled = true;
                button.innerHTML = `
                    <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                    ${loadingText}
                `;
            }
        });

        // Reset button after API call
        button.addEventListener('api-complete', () => {
            button.disabled = originalDisabled;
            button.innerHTML = originalText;
        });
    }

    setupErrorHandling() {
        // Global error handler
        window.addEventListener('error', (e) => {
            console.error('Global error:', e.error);
            this.showNotification('Bir hata oluştu', 'error');
        });

        // Unhandled promise rejection
        window.addEventListener('unhandledrejection', (e) => {
            console.error('Unhandled promise rejection:', e.reason);
            this.showNotification('Beklenmeyen bir hata oluştu', 'error');
        });

        // Network error handling
        this.setupNetworkErrorHandling();
    }

    setupNetworkErrorHandling() {
        // Offline detection
        window.addEventListener('offline', () => {
            this.showNotification('İnternet bağlantısı kesildi', 'warning');
        });

        window.addEventListener('online', () => {
            this.showNotification('İnternet bağlantısı geri geldi', 'success');
        });
    }

    setupNotifications() {
        // Notification container
        this.notificationContainer = document.createElement('div');
        this.notificationContainer.id = 'notificationContainer';
        this.notificationContainer.className = 'notification-container';
        document.body.appendChild(this.notificationContainer);
    }

    showNotification(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${this.getAlertType(type)} alert-dismissible fade show notification`;
        
        const icon = this.getNotificationIcon(type);
        
        notification.innerHTML = `
            <i class="${icon} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        this.notificationContainer.appendChild(notification);

        // Auto remove
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, duration);

        // Manual close
        notification.querySelector('.btn-close').addEventListener('click', () => {
            notification.remove();
        });
    }

    getAlertType(type) {
        const types = {
            'success': 'success',
            'error': 'danger',
            'warning': 'warning',
            'info': 'info'
        };
        return types[type] || 'info';
    }

    getNotificationIcon(type) {
        const icons = {
            'success': 'fas fa-check-circle',
            'error': 'fas fa-exclamation-circle',
            'warning': 'fas fa-exclamation-triangle',
            'info': 'fas fa-info-circle'
        };
        return icons[type] || 'fas fa-info-circle';
    }

    showLoading(message = 'Yükleniyor...') {
        this.loadingOverlay.querySelector('.loading-text').textContent = message;
        this.loadingOverlay.style.display = 'flex';
    }

    hideLoading() {
        this.loadingOverlay.style.display = 'none';
    }

    async makeApiCall(endpoint, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const finalOptions = { ...defaultOptions, ...options };

        // Add auth token if available
        const token = this.getAuthToken();
        if (token) {
            finalOptions.headers['Authorization'] = `Bearer ${token}`;
        }

        try {
            this.showLoading();
            
            const response = await fetch(`${this.apiBaseUrl}${endpoint}`, finalOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            return data;

        } catch (error) {
            console.error('API call failed:', error);
            this.handleApiError(error);
            throw error;
        } finally {
            this.hideLoading();
        }
    }

    handleApiError(error) {
        let message = 'Bir hata oluştu';
        let type = 'error';

        if (error.message.includes('401')) {
            message = 'Oturum süresi doldu. Lütfen tekrar giriş yapın.';
            this.handleLogout();
        } else if (error.message.includes('429')) {
            message = 'Çok fazla istek gönderildi. Lütfen bekleyin.';
            type = 'warning';
        } else if (error.message.includes('500')) {
            message = 'Sunucu hatası. Lütfen daha sonra tekrar deneyin.';
        } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
            message = 'İnternet bağlantısı hatası.';
            type = 'warning';
        }

        this.showNotification(message, type);
    }

    async handleLogin(event) {
        event.preventDefault();
        
        const form = event.target;
        const formData = new FormData(form);
        
        const loginData = {
            username: formData.get('username'),
            password: formData.get('password')
        };

        try {
            const response = await this.makeApiCall('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify(loginData)
            });

            if (response.success) {
                this.setAuthToken(response.token);
                this.currentUser = response.user;
                this.showNotification('Başarıyla giriş yapıldı', 'success');
                this.redirectToDashboard();
            } else {
                this.showNotification(response.message || 'Giriş başarısız', 'error');
            }

        } catch (error) {
            console.error('Login failed:', error);
        }
    }

    async handleRegister(event) {
        event.preventDefault();
        
        const form = event.target;
        const formData = new FormData(form);
        
        const registerData = {
            username: formData.get('username'),
            email: formData.get('email'),
            password: formData.get('password'),
            full_name: formData.get('full_name')
        };

        try {
            const response = await this.makeApiCall('/api/auth/register', {
                method: 'POST',
                body: JSON.stringify(registerData)
            });

            if (response.success) {
                this.showNotification('Kayıt başarılı! Giriş yapabilirsiniz.', 'success');
                this.switchToLogin();
            } else {
                this.showNotification(response.message || 'Kayıt başarısız', 'error');
            }

        } catch (error) {
            console.error('Registration failed:', error);
        }
    }

    async handleQuickScan() {
        if (this.isScanning) {
            this.showNotification('Zaten tarama yapılıyor', 'warning');
            return;
        }

        const ipRange = document.getElementById('ipRange')?.value || '192.168.1.0/24';
        const portScan = document.getElementById('portScan')?.checked || false;
        const nmapScan = document.getElementById('nmapScan')?.checked || false;

        this.isScanning = true;
        this.updateScanUI(true);

        try {
            const scanData = {
                ip_range: ipRange,
                enable_port_scan: portScan,
                enable_nmap: nmapScan
            };

            const response = await this.makeApiCall('/api/scan', {
                method: 'POST',
                body: JSON.stringify(scanData)
            });

            if (response.status === 'success') {
                this.scanResults = response.devices || [];
                this.showNotification(`Tarama tamamlandı: ${this.scanResults.length} cihaz bulundu`, 'success');
                this.displayScanResults();
                this.updateStats();
            } else {
                this.showNotification(response.message || 'Tarama başarısız', 'error');
            }

        } catch (error) {
            console.error('Quick scan failed:', error);
            this.showNotification('Tarama sırasında hata oluştu', 'error');
        } finally {
            this.isScanning = false;
            this.updateScanUI(false);
        }
    }

    async handleAdvancedScanClick() {
        if (this.isScanning) {
            this.showNotification('Zaten tarama yapılıyor', 'warning');
            return;
        }

        const ipRange = document.getElementById('ipRange')?.value || '192.168.1.0/24';

        this.isScanning = true;
        this.updateScanUI(true);

        try {
            const scanData = {
                ip_range: ipRange,
                enable_nmap: true,
                enable_dhcp: true,
                enable_netbios: true,
                enable_mdns: true
            };

            const response = await this.makeApiCall('/api/advanced-scan', {
                method: 'POST',
                body: JSON.stringify(scanData)
            });

            if (response.status === 'success') {
                this.scanResults = response.devices || [];
                this.showNotification(`Gelişmiş tarama tamamlandı: ${this.scanResults.length} cihaz bulundu`, 'success');
                this.displayScanResults();
                this.updateStats();
            } else {
                this.showNotification(response.message || 'Gelişmiş tarama başarısız', 'error');
            }

        } catch (error) {
            console.error('Advanced scan failed:', error);
            this.showNotification('Gelişmiş tarama sırasında hata oluştu', 'error');
        } finally {
            this.isScanning = false;
            this.updateScanUI(false);
        }
    }

    updateScanUI(isScanning) {
        const loadingState = document.getElementById('loadingState');
        const emptyState = document.getElementById('emptyState');
        const startScanBtn = document.getElementById('startScanBtn');
        const quickScanBtn = document.getElementById('quickScanBtn');
        const advancedScanBtn = document.getElementById('advancedScanBtn');
        
        if (isScanning) {
            if (loadingState) loadingState.style.display = 'block';
            if (emptyState) emptyState.style.display = 'none';
            if (startScanBtn) startScanBtn.disabled = true;
            if (quickScanBtn) quickScanBtn.disabled = true;
            if (advancedScanBtn) advancedScanBtn.disabled = true;
        } else {
            if (loadingState) loadingState.style.display = 'none';
            if (startScanBtn) startScanBtn.disabled = false;
            if (quickScanBtn) quickScanBtn.disabled = false;
            if (advancedScanBtn) advancedScanBtn.disabled = false;
        }
    }

    displayScanResults() {
        const container = document.getElementById('devicesContainer');
        const emptyState = document.getElementById('emptyState');
        
        if (!container) return;
        
        if (this.scanResults.length === 0) {
            container.innerHTML = '';
            if (emptyState) emptyState.style.display = 'block';
            return;
        }
        
        if (emptyState) emptyState.style.display = 'none';
        
        container.innerHTML = this.scanResults.map(device => this.createDeviceCard(device)).join('');
        
        // Cihaz kartlarına click event'leri ekle
        container.querySelectorAll('.device-card').forEach((card, index) => {
            card.addEventListener('click', () => {
                this.showDeviceModal(this.scanResults[index]);
            });
        });
    }

    createDeviceCard(device) {
        const statusClass = device.status === 'Aktif' ? 'online' : 'offline';
        const statusIcon = device.status === 'Aktif' ? 'fa-wifi' : 'fa-times-circle';
        const statusColor = device.status === 'Aktif' ? 'text-success' : 'text-danger';
        
        const deviceTypeIcon = this.getDeviceTypeIcon(device.device_type || 'unknown');
        
        return `
            <div class="col">
                <div class="card device-card ${statusClass} h-100" style="cursor: pointer;">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-2">
                            <i class="${deviceTypeIcon} device-type-icon"></i>
                            <div class="flex-grow-1">
                                <h6 class="card-title mb-1">${device.ip}</h6>
                                <small class="text-muted">${device.mac || 'MAC Yok'}</small>
                            </div>
                            <span class="${statusColor}">
                                <i class="fas ${statusIcon}"></i>
                            </span>
                        </div>
                        
                        <div class="mb-2">
                            <small class="text-muted">Cihaz Türü:</small><br>
                            <span class="badge bg-secondary">${device.device_type || 'Bilinmiyor'}</span>
                        </div>
                        
                        ${device.vendor ? `
                        <div class="mb-2">
                            <small class="text-muted">Üretici:</small><br>
                            <small>${device.vendor}</small>
                        </div>
                        ` : ''}
                        
                        ${device.open_ports && device.open_ports.length > 0 ? `
                        <div class="mb-2">
                            <small class="text-muted">Açık Portlar:</small><br>
                            <small>${device.open_ports.slice(0, 3).join(', ')}${device.open_ports.length > 3 ? '...' : ''}</small>
                        </div>
                        ` : ''}
                        
                        <div class="mt-auto">
                            <button class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation(); app.showDeviceDetails('${device.ip}')">
                                <i class="fas fa-info-circle me-1"></i>Detaylar
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getDeviceTypeIcon(deviceType) {
        const icons = {
            'router': 'fas fa-wifi',
            'switch': 'fas fa-network-wired',
            'server': 'fas fa-server',
            'desktop': 'fas fa-desktop',
            'laptop': 'fas fa-laptop',
            'mobile': 'fas fa-mobile-alt',
            'printer': 'fas fa-print',
            'camera': 'fas fa-video',
            'phone': 'fas fa-phone',
            'tablet': 'fas fa-tablet-alt',
            'tv': 'fas fa-tv',
            'game': 'fas fa-gamepad',
            'unknown': 'fas fa-question-circle'
        };
        return icons[deviceType.toLowerCase()] || icons['unknown'];
    }

    async showDeviceDetails(ip) {
        try {
            const response = await this.makeApiCall(`/api/device-details/${ip}`);
            if (response.device) {
                this.showDeviceModal(response.device);
            } else {
                this.showNotification('Cihaz detayları alınamadı', 'error');
            }
        } catch (error) {
            console.error('Device details failed:', error);
            this.showNotification('Cihaz detayları alınamadı', 'error');
        }
    }

    showDeviceModal(device) {
        const modal = new bootstrap.Modal(document.getElementById('deviceModal'));
        const modalBody = document.getElementById('deviceModalBody');
        
        if (modalBody) {
            modalBody.innerHTML = this.createDeviceDetailsHTML(device);
        }
        
        modal.show();
    }

    createDeviceDetailsHTML(device) {
        return `
            <div class="row">
                <div class="col-md-6">
                    <h6>Genel Bilgiler</h6>
                    <table class="table table-sm">
                        <tr><td>IP Adresi:</td><td><strong>${device.ip}</strong></td></tr>
                        <tr><td>MAC Adresi:</td><td><code>${device.mac || 'Bilinmiyor'}</code></td></tr>
                        <tr><td>Durum:</td><td><span class="badge ${device.status === 'Aktif' ? 'bg-success' : 'bg-danger'}">${device.status}</span></td></tr>
                        <tr><td>Cihaz Türü:</td><td>${device.device_type || 'Bilinmiyor'}</td></tr>
                        <tr><td>Üretici:</td><td>${device.vendor || 'Bilinmiyor'}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>Port Bilgileri</h6>
                    ${device.open_ports && device.open_ports.length > 0 ? `
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr><th>Port</th><th>Servis</th><th>Durum</th></tr>
                                </thead>
                                <tbody>
                                    ${device.open_ports.map(port => `
                                        <tr>
                                            <td>${port.port || port}</td>
                                            <td>${port.service || 'Bilinmiyor'}</td>
                                            <td><span class="badge bg-success">Açık</span></td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : '<p class="text-muted">Açık port bulunamadı</p>'}
                </div>
            </div>
            ${device.os_info ? `
            <div class="row mt-3">
                <div class="col-12">
                    <h6>İşletim Sistemi Bilgileri</h6>
                    <pre class="bg-light p-3 rounded">${JSON.stringify(device.os_info, null, 2)}</pre>
                </div>
            </div>
            ` : ''}
        `;
    }

    updateNetworkMap() {
        if (this.scanResults.length === 0) return;

        // Network visualization güncelle
        const networkContainer = document.getElementById('networkMap');
        if (networkContainer) {
            this.createNetworkVisualization();
        }
    }

    async createNetworkVisualization() {
        try {
            console.log('Ağ haritası oluşturuluyor...');
            const response = await this.makeApiCall('/api/network-map');
            console.log('Network map response:', response);
            
            if (response.status === 'ok' && response.network_map) {
                const container = document.getElementById('networkMapContainer');
                if (container) {
                    container.innerHTML = response.network_map;
                    this.showNotification('Ağ haritası oluşturuldu', 'success');
                } else {
                    console.error('Network map container bulunamadı');
                    this.showNotification('Ağ haritası container bulunamadı', 'error');
                }
            } else if (response.error) {
                console.error('Network map error:', response.error);
                this.showNotification(response.error, 'error');
            } else {
                console.error('Unexpected response format:', response);
                this.showNotification('Ağ haritası oluşturulamadı', 'error');
            }
        } catch (error) {
            console.error('Network visualization failed:', error);
            this.showNotification('Ağ haritası oluşturulamadı: ' + error.message, 'error');
        }
    }

    async exportResults(format) {
        try {
            const response = await this.makeApiCall(`/api/export/${format}`, {
                method: 'POST',
                body: JSON.stringify({ devices: this.scanResults })
            });

            if (response.download_url) {
                // Dosyayı indir
                const link = document.createElement('a');
                link.href = response.download_url;
                link.download = `network_scan_${format}_${new Date().toISOString().split('T')[0]}.${format}`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                this.showNotification(`${format.toUpperCase()} dosyası indirildi`, 'success');
            } else {
                this.showNotification('Dosya indirme başarısız', 'error');
            }
        } catch (error) {
            console.error('Export failed:', error);
            this.showNotification('Dışa aktarma başarısız', 'error');
        }
    }

    async generateReport() {
        try {
            const reportType = document.getElementById('reportTypeSelect')?.value || 'html';
            const email = document.getElementById('reportEmail')?.value;

            const reportData = {
                devices: this.scanResults,
                report_type: reportType
            };

            if (email) {
                reportData.email = email;
            }

            const response = await this.makeApiCall('/api/generate-reports', {
                method: 'POST',
                body: JSON.stringify(reportData)
            });

            if (response.success) {
                this.showNotification('Rapor oluşturuldu', 'success');
                
                if (response.download_url) {
                    // Raporu indir
                    const link = document.createElement('a');
                    link.href = response.download_url;
                    link.download = `network_report_${new Date().toISOString().split('T')[0]}.${reportType}`;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }
            } else {
                this.showNotification('Rapor oluşturma başarısız', 'error');
            }
        } catch (error) {
            console.error('Report generation failed:', error);
            this.showNotification('Rapor oluşturma başarısız', 'error');
        }
    }

    setupNavigation() {
        // Tab switching
        const tabLinks = document.querySelectorAll('[data-bs-toggle="tab"]');
        tabLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(link.getAttribute('href'));
                if (target) {
                    // Hide all tab contents
                    document.querySelectorAll('.tab-pane').forEach(pane => {
                        pane.classList.remove('show', 'active');
                    });
                    
                    // Show target tab
                    target.classList.add('show', 'active');
                    
                    // Update active tab
                    document.querySelectorAll('.nav-link').forEach(navLink => {
                        navLink.classList.remove('active');
                    });
                    link.classList.add('active');
                }
            });
        });
    }

    setupModalEvents() {
        // Modal close events
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('hidden.bs.modal', () => {
                // Reset form if exists
                const form = modal.querySelector('form');
                if (form) {
                    form.reset();
                }
            });
        });
    }

    setupRealTimeUpdates() {
        // Real-time device status updates
        setInterval(() => {
            if (this.scanResults.length > 0) {
                this.updateDeviceStatuses();
            }
        }, 30000); // 30 seconds
    }

    async updateDeviceStatuses() {
        try {
            const response = await this.makeApiCall('/api/device-status', {
                method: 'POST',
                body: JSON.stringify({ devices: this.scanResults })
            });

            if (response.success) {
                // Update device statuses in the table
                response.devices.forEach(updatedDevice => {
                    const row = document.querySelector(`tr[data-ip="${updatedDevice.ip}"]`);
                    if (row) {
                        const statusCell = row.querySelector('.status-cell');
                        if (statusCell) {
                            statusCell.innerHTML = `
                                <span class="${updatedDevice.status === 'Aktif' ? 'text-success' : 'text-danger'}">
                                    <i class="fas fa-circle"></i> ${updatedDevice.status}
                                </span>
                            `;
                        }
                    }
                });
            }
        } catch (error) {
            console.error('Status update failed:', error);
        }
    }

    checkAuthStatus() {
        const token = this.getAuthToken();
        if (token) {
            // Token varsa doğrula
            this.validateToken(token);
        } else {
            // Token yoksa login sayfasına yönlendir
            this.showLoginPage();
        }
    }

    async validateToken(token) {
        try {
            const response = await this.makeApiCall('/api/auth/profile', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (response.status === 'ok' || response.user) {
                this.currentUser = response.user || response;
                // Token geçerli, dashboard'da kal
                if (window.location.pathname !== '/') {
                    this.showDashboard();
                }
                return Promise.resolve();
            } else {
                this.handleLogout();
                return Promise.reject('Invalid token');
            }
        } catch (error) {
            console.error('Token validation failed:', error);
            this.handleLogout();
            return Promise.reject(error);
        }
    }

    getAuthToken() {
        return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    }

    setAuthToken(token) {
        localStorage.setItem('auth_token', token);
    }

    clearAuthToken() {
        localStorage.removeItem('auth_token');
        sessionStorage.removeItem('auth_token');
    }

    async handleLogout() {
        try {
            await this.makeApiCall('/api/auth/logout', { method: 'POST' });
        } catch (error) {
            console.error('Logout API failed:', error);
        } finally {
            this.clearAuthToken();
            this.currentUser = null;
            this.showLoginPage();
        }
    }

    showLoginPage() {
        window.location.href = '/login';
    }

    showDashboard() {
        // Dashboard zaten yüklüyse sadece gerekli güncellemeleri yap
        if (window.location.pathname === '/') {
            // Sayfa zaten dashboard'da, sadece içeriği güncelle
            this.loadDashboardData();
        } else {
            // Dashboard'a yönlendir
            window.location.href = '/';
        }
    }

    async loadDashboardData() {
        // Dashboard verilerini yükle
        try {
            // Kullanıcı bilgilerini al
            const response = await this.makeApiCall('/api/auth/profile');
            if (response.user) {
                this.currentUser = response.user;
                
                // Kullanıcı bilgilerini UI'da göster
                const usernameElement = document.getElementById('username');
                if (usernameElement) {
                    usernameElement.textContent = this.currentUser.username;
                }
            }
        } catch (error) {
            console.error('Dashboard data loading failed:', error);
        }
    }

    redirectToDashboard() {
        window.location.href = '/';
    }

    switchToLogin() {
        const loginTab = document.getElementById('login-tab');
        if (loginTab) {
            loginTab.click();
        }
    }

    showNetworkMap() {
        if (this.scanResults.length === 0) {
            this.showNotification('Önce tarama yapın', 'warning');
            return;
        }

        // Network map modal'ını aç
        const networkMapModal = document.getElementById('networkMapModal');
        if (networkMapModal) {
            const modal = new bootstrap.Modal(networkMapModal);
            modal.show();
            
            // Network visualization'ı oluştur
            this.createNetworkVisualization();
        } else {
            console.error('Network map modal bulunamadı');
            this.showNotification('Ağ haritası modal bulunamadı', 'error');
        }
    }

    showReportModal() {
        if (this.scanResults.length === 0) {
            this.showNotification('Önce tarama yapın', 'warning');
            return;
        }

        // Report modal'ını aç
        const reportModal = new bootstrap.Modal(document.getElementById('reportModal'));
        reportModal.show();
    }

    async refreshDevices() {
        if (this.scanResults.length === 0) {
            this.showNotification('Yenilenecek cihaz yok', 'info');
            return;
        }

        try {
            const response = await this.makeApiCall('/api/devices');
            if (response.devices) {
                this.scanResults = response.devices;
                this.displayScanResults();
                this.updateStats();
                this.showNotification('Cihazlar yenilendi', 'success');
            }
        } catch (error) {
            console.error('Refresh failed:', error);
            this.showNotification('Yenileme sırasında hata oluştu', 'error');
        }
    }

    showExportOptions() {
        if (this.scanResults.length === 0) {
            this.showNotification('Dışa aktarılacak veri yok', 'warning');
            return;
        }

        // Export modal'ını aç
        const exportModal = new bootstrap.Modal(document.getElementById('exportModal'));
        exportModal.show();
    }

    showProfileModal() {
        // Profile modal'ını aç
        const profileModal = new bootstrap.Modal(document.getElementById('profileModal'));
        profileModal.show();
    }

    showSettingsModal() {
        // Settings modal'ını aç
        const settingsModal = new bootstrap.Modal(document.getElementById('settingsModal'));
        settingsModal.show();
    }

    updateStats() {
        const totalDevices = this.scanResults.length;
        const onlineDevices = this.scanResults.filter(d => d.status === 'Aktif').length;
        const openPorts = this.scanResults.reduce((sum, d) => sum + (d.open_ports?.length || 0), 0);

        document.getElementById('totalDevices').textContent = totalDevices;
        document.getElementById('onlineDevices').textContent = onlineDevices;
        document.getElementById('openPorts').textContent = openPorts;
        document.getElementById('scanTime').textContent = '0s'; // Bu değer tarama sırasında güncellenebilir
    }

    async saveSettings() {
        try {
            const settings = {
                theme: document.getElementById('themeSelect')?.value || 'light',
                language: document.getElementById('languageSelect')?.value || 'tr',
                email_notifications: document.getElementById('emailNotifications')?.checked || false
            };

            const response = await this.makeApiCall('/api/auth/settings', {
                method: 'PUT',
                body: JSON.stringify(settings)
            });

            if (response.success) {
                this.showNotification('Ayarlar kaydedildi', 'success');
                
                // Tema ve dil değişikliklerini uygula
                if (settings.theme) {
                    document.documentElement.setAttribute('data-bs-theme', settings.theme);
                }
            } else {
                this.showNotification('Ayar kaydetme başarısız', 'error');
            }
        } catch (error) {
            console.error('Settings save failed:', error);
            this.showNotification('Ayar kaydetme başarısız', 'error');
        }
    }
}

// Global app instance
const app = new IPScannerApp();

// Export for global access
window.app = app; 