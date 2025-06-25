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
        this.checkAuthStatus();
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

        // Scan form
        const scanForm = document.getElementById('scanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => this.handleScan(e));
        }

        // Advanced scan form
        const advancedScanForm = document.getElementById('advancedScanForm');
        if (advancedScanForm) {
            advancedScanForm.addEventListener('submit', (e) => this.handleAdvancedScan(e));
        }

        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
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

    async handleScan(event) {
        event.preventDefault();
        
        if (this.isScanning) {
            this.showNotification('Zaten tarama yapılıyor', 'warning');
            return;
        }

        const form = event.target;
        const formData = new FormData(form);
        
        const scanData = {
            ip_range: formData.get('ip_range') || '192.168.1.0/24'
        };

        this.isScanning = true;
        this.updateScanUI(true);

        try {
            const response = await this.makeApiCall('/api/scan', {
                method: 'POST',
                body: JSON.stringify(scanData)
            });

            if (response.status === 'success') {
                this.scanResults = response.devices || [];
                this.showNotification(`Tarama tamamlandı: ${this.scanResults.length} cihaz bulundu`, 'success');
                this.displayScanResults();
                this.updateNetworkMap();
            } else {
                this.showNotification(response.message || 'Tarama başarısız', 'error');
            }

        } catch (error) {
            console.error('Scan failed:', error);
        } finally {
            this.isScanning = false;
            this.updateScanUI(false);
        }
    }

    async handleAdvancedScan(event) {
        event.preventDefault();
        
        if (this.isScanning) {
            this.showNotification('Zaten tarama yapılıyor', 'warning');
            return;
        }

        const form = event.target;
        const formData = new FormData(form);
        
        const scanData = {
            ip_range: formData.get('ip_range') || '192.168.1.0/24',
            enable_nmap: formData.get('enable_nmap') === 'on',
            enable_dhcp: formData.get('enable_dhcp') === 'on',
            enable_netbios: formData.get('enable_netbios') === 'on',
            enable_mdns: formData.get('enable_mdns') === 'on'
        };

        this.isScanning = true;
        this.updateScanUI(true);

        try {
            const response = await this.makeApiCall('/api/advanced-scan', {
                method: 'POST',
                body: JSON.stringify(scanData)
            });

            if (response.status === 'success') {
                this.scanResults = response.devices || [];
                this.showNotification(`Gelişmiş tarama tamamlandı: ${this.scanResults.length} cihaz bulundu`, 'success');
                this.displayScanResults();
                this.updateNetworkMap();
            } else {
                this.showNotification(response.message || 'Gelişmiş tarama başarısız', 'error');
            }

        } catch (error) {
            console.error('Advanced scan failed:', error);
        } finally {
            this.isScanning = false;
            this.updateScanUI(false);
        }
    }

    updateScanUI(isScanning) {
        const scanBtn = document.querySelector('#scanForm button[type="submit"]');
        const advancedScanBtn = document.querySelector('#advancedScanForm button[type="submit"]');
        
        if (scanBtn) {
            scanBtn.disabled = isScanning;
        }
        
        if (advancedScanBtn) {
            advancedScanBtn.disabled = isScanning;
        }

        // Progress bar
        const progressBar = document.getElementById('scanProgress');
        if (progressBar) {
            if (isScanning) {
                progressBar.style.display = 'block';
                progressBar.classList.add('progress-bar-animated');
            } else {
                progressBar.style.display = 'none';
                progressBar.classList.remove('progress-bar-animated');
            }
        }
    }

    displayScanResults() {
        const resultsContainer = document.getElementById('scanResults');
        if (!resultsContainer) return;

        if (this.scanResults.length === 0) {
            resultsContainer.innerHTML = '<div class="alert alert-info">Hiç cihaz bulunamadı.</div>';
            return;
        }

        const table = this.createResultsTable();
        resultsContainer.innerHTML = '';
        resultsContainer.appendChild(table);

        // Export buttons
        this.addExportButtons(resultsContainer);
    }

    createResultsTable() {
        const table = document.createElement('table');
        table.className = 'table table-striped table-hover';
        
        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>IP Adresi</th>
                <th>MAC Adresi</th>
                <th>Üretici</th>
                <th>Cihaz Türü</th>
                <th>Güven</th>
                <th>Durum</th>
                <th>İşlemler</th>
            </tr>
        `;
        
        const tbody = document.createElement('tbody');
        this.scanResults.forEach(device => {
            const row = this.createDeviceRow(device);
            tbody.appendChild(row);
        });

        table.appendChild(thead);
        table.appendChild(tbody);
        return table;
    }

    createDeviceRow(device) {
        const row = document.createElement('tr');
        
        const confidenceClass = this.getConfidenceClass(device.confidence);
        const statusClass = device.status === 'Aktif' ? 'text-success' : 'text-danger';
        
        row.innerHTML = `
            <td><strong>${device.ip}</strong></td>
            <td><code>${device.mac || 'Bilinmiyor'}</code></td>
            <td>${device.vendor || 'Bilinmiyor'}</td>
            <td>
                <span class="badge bg-primary">${device.device_type || 'Bilinmeyen'}</span>
            </td>
            <td>
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar ${confidenceClass}" style="width: ${device.confidence || 0}%">
                        ${device.confidence || 0}%
                    </div>
                </div>
            </td>
            <td>
                <span class="${statusClass}">
                    <i class="fas fa-circle"></i> ${device.status || 'Bilinmiyor'}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-info" onclick="app.showDeviceDetails('${device.ip}')">
                    <i class="fas fa-info-circle"></i> Detay
                </button>
            </td>
        `;
        
        return row;
    }

    getConfidenceClass(confidence) {
        if (confidence >= 80) return 'bg-success';
        if (confidence >= 50) return 'bg-warning';
        return 'bg-danger';
    }

    addExportButtons(container) {
        const exportDiv = document.createElement('div');
        exportDiv.className = 'mt-3';
        exportDiv.innerHTML = `
            <button class="btn btn-success me-2" onclick="app.exportResults('csv')">
                <i class="fas fa-download"></i> CSV İndir
            </button>
            <button class="btn btn-info me-2" onclick="app.exportResults('json')">
                <i class="fas fa-download"></i> JSON İndir
            </button>
            <button class="btn btn-warning me-2" onclick="app.generateReport()">
                <i class="fas fa-file-pdf"></i> Rapor Oluştur
            </button>
        `;
        container.appendChild(exportDiv);
    }

    async showDeviceDetails(ip) {
        try {
            const response = await this.makeApiCall(`/api/device-details/${ip}`);
            
            if (response.success) {
                this.showDeviceModal(response.device);
            } else {
                this.showNotification('Cihaz detayları alınamadı', 'error');
            }
        } catch (error) {
            console.error('Device details failed:', error);
        }
    }

    showDeviceModal(device) {
        const modal = document.getElementById('deviceModal');
        if (!modal) return;

        const modalBody = modal.querySelector('.modal-body');
        modalBody.innerHTML = this.createDeviceDetailsHTML(device);

        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    }

    createDeviceDetailsHTML(device) {
        return `
            <div class="row">
                <div class="col-md-6">
                    <h5>Temel Bilgiler</h5>
                    <table class="table table-sm">
                        <tr><td>IP Adresi:</td><td><strong>${device.ip}</strong></td></tr>
                        <tr><td>MAC Adresi:</td><td><code>${device.mac || 'Bilinmiyor'}</code></td></tr>
                        <tr><td>Üretici:</td><td>${device.vendor || 'Bilinmiyor'}</td></tr>
                        <tr><td>Cihaz Türü:</td><td>${device.device_type || 'Bilinmeyen'}</td></tr>
                        <tr><td>Hostname:</td><td>${device.hostname || 'Bilinmiyor'}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h5>Teknik Bilgiler</h5>
                    <table class="table table-sm">
                        <tr><td>Güven Seviyesi:</td><td>${device.confidence || 0}%</td></tr>
                        <tr><td>Durum:</td><td>${device.status || 'Bilinmiyor'}</td></tr>
                        <tr><td>Son Görülme:</td><td>${device.last_seen || 'Bilinmiyor'}</td></tr>
                        <tr><td>Protokoller:</td><td>${(device.protocols || []).join(', ') || 'Yok'}</td></tr>
                    </table>
                </div>
            </div>
            ${device.open_ports && device.open_ports.length > 0 ? `
            <div class="mt-3">
                <h5>Açık Portlar</h5>
                <div class="row">
                    ${device.open_ports.map(port => `
                        <div class="col-md-2 mb-2">
                            <span class="badge bg-success">${port}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
            ${device.services && device.services.length > 0 ? `
            <div class="mt-3">
                <h5>Servisler</h5>
                <div class="row">
                    ${device.services.map(service => `
                        <div class="col-md-4 mb-2">
                            <div class="card">
                                <div class="card-body p-2">
                                    <small><strong>${service.service || 'Bilinmiyor'}</strong></small><br>
                                    <small class="text-muted">Port: ${service.port || 'N/A'}</small>
                                </div>
                            </div>
                        </div>
                    `).join('')}
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
            const response = await this.makeApiCall('/api/network-visualization', {
                method: 'POST',
                body: JSON.stringify({ devices: this.scanResults })
            });

            if (response.success) {
                const networkContainer = document.getElementById('networkMap');
                if (networkContainer) {
                    networkContainer.innerHTML = `
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> Ağ haritası oluşturuldu
                        </div>
                        <a href="${response.html_file}" target="_blank" class="btn btn-primary">
                            <i class="fas fa-external-link-alt"></i> Ağ Haritasını Görüntüle
                        </a>
                    `;
                }
            }
        } catch (error) {
            console.error('Network visualization failed:', error);
        }
    }

    async exportResults(format) {
        try {
            const response = await this.makeApiCall(`/api/export/${format}`, {
                method: 'POST',
                body: JSON.stringify({ devices: this.scanResults })
            });

            if (response.success) {
                // Download file
                const link = document.createElement('a');
                link.href = response.file_url;
                link.download = `scan_results_${new Date().toISOString().slice(0, 10)}.${format}`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);

                this.showNotification(`${format.toUpperCase()} dosyası indirildi`, 'success');
            } else {
                this.showNotification('Dosya indirme başarısız', 'error');
            }
        } catch (error) {
            console.error('Export failed:', error);
        }
    }

    async generateReport() {
        try {
            const response = await this.makeApiCall('/api/generate-report', {
                method: 'POST',
                body: JSON.stringify({ devices: this.scanResults })
            });

            if (response.success) {
                this.showNotification('Rapor oluşturuldu', 'success');
                
                // Show report modal
                const reportModal = document.getElementById('reportModal');
                if (reportModal) {
                    const modalBody = reportModal.querySelector('.modal-body');
                    modalBody.innerHTML = `
                        <div class="text-center">
                            <i class="fas fa-file-pdf fa-3x text-danger mb-3"></i>
                            <h5>Rapor Hazır!</h5>
                            <p>Tarama raporunuz başarıyla oluşturuldu.</p>
                            <div class="d-grid gap-2">
                                <a href="${response.pdf_url}" target="_blank" class="btn btn-danger">
                                    <i class="fas fa-download"></i> PDF İndir
                                </a>
                                <a href="${response.html_url}" target="_blank" class="btn btn-primary">
                                    <i class="fas fa-eye"></i> HTML Görüntüle
                                </a>
                            </div>
                        </div>
                    `;
                    
                    const bsModal = new bootstrap.Modal(reportModal);
                    bsModal.show();
                }
            } else {
                this.showNotification('Rapor oluşturma başarısız', 'error');
            }
        } catch (error) {
            console.error('Report generation failed:', error);
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
            // Validate token
            this.validateToken(token);
        } else {
            this.showLoginPage();
        }
    }

    async validateToken(token) {
        try {
            const response = await this.makeApiCall('/api/auth/profile');
            if (response.status === 'ok') {
                this.currentUser = response.user;
                this.showDashboard();
            } else {
                this.handleLogout();
            }
        } catch (error) {
            this.handleLogout();
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
        window.location.href = '/';
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
}

// Global app instance
const app = new IPScannerApp();

// Export for global access
window.app = app; 