import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_cors import CORS
from flask_session import Session
import threading
import json
from scanner_v2 import IPScannerV2
from network_visualizer import create_network_visualization
from report_generator import generate_reports, ReportGenerator
from advanced_scanner import create_advanced_scanner
from user_management import user_manager
from datetime import datetime
import psutil
from device_detector import device_detector
import logging

# Logging konfigürasyonu
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ip_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Flask secret key ayarı - Session yönetimi için kritik
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'ip_scanner_secret_key_2024_change_in_production')

# Flask-Session konfigürasyonu
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(__file__), 'temp')
app.config['SESSION_FILE_THRESHOLD'] = 500
app.config['PERMANENT_SESSION_LIFETIME'] = 28800  # 8 saat

# Session klasörünü oluştur
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

Session(app)

# CORS policy - Güvenlik
CORS(app, origins=['http://localhost:5001', 'http://127.0.0.1:5001'], 
     supports_credentials=True, methods=['GET', 'POST', 'PUT', 'DELETE'])

# Rate limiting için basit cache
from collections import defaultdict
import time
rate_limit_cache = defaultdict(list)

def check_rate_limit(ip, limit=100, window=3600):
    """Basit rate limiting"""
    now = time.time()
    # Eski kayıtları temizle
    rate_limit_cache[ip] = [t for t in rate_limit_cache[ip] if now - t < window]
    
    if len(rate_limit_cache[ip]) >= limit:
        return False
    
    rate_limit_cache[ip].append(now)
    return True

scanner = None
scan_results = [
    {
        'ip': '192.168.1.1',
        'mac': '00:11:22:33:44:55',
        'vendor': 'TP-Link',
        'device_type': 'router',
        'status': 'Aktif',
        'confidence': 95,
        'hostname': 'router.local',
        'open_ports': [80, 443, 22],
        'protocols': ['HTTP', 'HTTPS', 'SSH']
    },
    {
        'ip': '192.168.1.100',
        'mac': 'AA:BB:CC:DD:EE:FF',
        'vendor': 'Apple Inc.',
        'device_type': 'computer',
        'status': 'Aktif',
        'confidence': 90,
        'hostname': 'macbook.local',
        'open_ports': [22, 80, 443, 548],
        'protocols': ['SSH', 'HTTP', 'HTTPS', 'AFP']
    },
    {
        'ip': '192.168.1.101',
        'mac': '11:22:33:44:55:66',
        'vendor': 'Samsung Electronics',
        'device_type': 'phone',
        'status': 'Aktif',
        'confidence': 85,
        'hostname': 'samsung-phone',
        'open_ports': [80, 443],
        'protocols': ['HTTP', 'HTTPS']
    }
]

@app.route('/')
def index():
    # Rate limiting
    if not check_rate_limit(request.remote_addr):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # Önce Authorization header'dan token kontrolü
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token[7:]
        user = user_manager.verify_token(token)
        if user:
            # Otomatik dil algılama
            lang = request.cookies.get('lang') or request.accept_languages.best_match(['tr', 'en']) or 'tr'
            return render_template('index.html', lang=lang)
    
    # Cookie'den token kontrolü
    token = request.cookies.get('auth_token')
    if token:
        user = user_manager.verify_token(token)
        if user:
            # Otomatik dil algılama
            lang = request.cookies.get('lang') or request.accept_languages.best_match(['tr', 'en']) or 'tr'
            return render_template('index.html', lang=lang)
    
    # Session kontrolü (geriye dönük uyumluluk için)
    if 'user_id' in session:
        token = session.get('token')
        if token and user_manager.verify_token(token):
            # Otomatik dil algılama
            lang = request.cookies.get('lang') or request.accept_languages.best_match(['tr', 'en']) or 'tr'
            return render_template('index.html', lang=lang)
    
    # Hiçbir kimlik doğrulama yöntemi başarılı değilse login'e yönlendir
    return redirect('/login')

@app.route('/login')
def login():
    # Rate limiting
    if not check_rate_limit(request.remote_addr, limit=10, window=300):
        return jsonify({'error': 'Too many login attempts'}), 429
    
    # Önce Authorization header'dan token kontrolü
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token[7:]
        if user_manager.verify_token(token):
            return redirect('/')
    
    # Cookie'den token kontrolü
    token = request.cookies.get('auth_token')
    if token and user_manager.verify_token(token):
        return redirect('/')
    
    # Session kontrolü (geriye dönük uyumluluk için)
    if 'user_id' in session:
        token = session.get('token')
        if token and user_manager.verify_token(token):
            return redirect('/')
    
    return render_template('login.html')

# Kullanıcı yönetimi endpoint'leri
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """Kullanıcı kaydı - Input validation ile"""
    # Rate limiting
    if not check_rate_limit(request.remote_addr, limit=5, window=3600):
        return jsonify({'error': 'Too many registration attempts'}), 429
    
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        
        if not all([username, email, password]):
            return jsonify({'error': 'Tüm alanlar gerekli'}), 400
        
        result = user_manager.register_user(username, email, password, full_name)
        
        if result['success']:
            logger.info(f"New user registered: {username}")
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Kullanıcı girişi - Güvenlik iyileştirmeleri ile"""
    # Rate limiting - Geçici olarak devre dışı
    # if not check_rate_limit(request.remote_addr, limit=10, window=300):
    #     return jsonify({'error': 'Too many login attempts'}), 429
    
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not all([username, password]):
            return jsonify({'error': 'Kullanıcı adı ve şifre gerekli'}), 400
        
        result = user_manager.login_user(username, password)
        
        if result['success']:
            logger.info(f"User login successful: {username}")
            
            # Session'a kullanıcı bilgilerini kaydet
            session['user_id'] = result['user']['id']
            session['username'] = result['user']['username']
            session['role'] = result['user']['role']
            session['token'] = result['token']
            
            response = jsonify(result)
            # Token'ı cookie olarak da set et - Güvenli
            response.set_cookie('auth_token', result['token'], 
                              max_age=8*60*60, httponly=True, 
                              samesite='Lax', secure=False)  # Production'da secure=True
            return response
        else:
            logger.warning(f"Failed login attempt: {username}")
            return jsonify(result), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@user_manager.require_auth
def api_logout():
    """Kullanıcı çıkışı"""
    try:
        token = request.headers.get('Authorization')
        if token.startswith('Bearer '):
            token = token[7:]
        
        result = user_manager.logout_user(token)
        
        # Session'ı temizle
        session.clear()
        
        response = jsonify(result)
        # Cookie'yi temizle
        response.delete_cookie('auth_token')
        logger.info(f"User logout: {request.current_user['username']}")
        return response
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/profile', methods=['GET'])
@user_manager.require_auth
def api_profile():
    """Kullanıcı profili"""
    try:
        user_id = request.current_user['user_id']
        profile = user_manager.get_user_profile(user_id)
        
        if profile:
            return jsonify({'status': 'ok', 'user': profile})
        else:
            return jsonify({'error': 'Profil bulunamadı'}), 404
            
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/settings', methods=['GET', 'PUT'])
@user_manager.require_auth
def api_settings():
    """Kullanıcı ayarları"""
    try:
        user_id = request.current_user['user_id']
        
        if request.method == 'GET':
            profile = user_manager.get_user_profile(user_id)
            if profile:
                return jsonify({'status': 'ok', 'settings': profile['settings']})
            else:
                return jsonify({'error': 'Ayarlar bulunamadı'}), 404
        
        elif request.method == 'PUT':
            data = request.json
            if not data:
                return jsonify({'error': 'Invalid JSON data'}), 400
            
            # Mevcut ayarları al
            profile = user_manager.get_user_profile(user_id)
            current_settings = profile['settings'] if profile else {}
            
            # Yeni ayarları mevcut ayarlarla birleştir
            updated_settings = {**current_settings, **data}
            
            result = user_manager.update_user_settings(user_id, updated_settings)
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
    except Exception as e:
        logger.error(f"Settings error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Tarama endpoint'leri (kimlik doğrulama ile)
@app.route('/api/scan', methods=['POST'])
@user_manager.require_auth
def api_scan():
    """Temel tarama - Güvenlik iyileştirmeleri ile"""
    global scan_results
    user_id = user_manager.get_user_id_from_token(request.headers.get('Authorization', '').replace('Bearer ', ''))
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        ip_range = data.get('ip_range', '192.168.1.0/24')
        
        # Input validation
        if not ip_range or '/' not in ip_range:
            return jsonify({'error': 'Geçerli IP aralığı giriniz'}), 400
        
        def do_scan():
            global scan_results
            try:
                # Yeni cihaz tespit sistemi ile tarama
                from device_detector import device_detector
                
                # Temel ARP taraması
                scanner = IPScannerV2()
                basic_results = scanner.scan_network(ip_range)
                
                # Gelişmiş analiz için device_detector kullan
                enhanced_results = []
                for device in basic_results:
                    # Zaten analiz edilmiş, sadece formatla
                    enhanced_device = {
                        'ip': device['ip'],
                        'mac': device['mac'],
                        'vendor': device['vendor'],
                        'device_type': device['device_type'],
                        'confidence': device.get('confidence', 0),
                        'open_ports': device.get('open_ports', []),
                        'status': 'Aktif',
                        'last_seen': datetime.now().isoformat(),
                        'hostname': device.get('hostname'),
                        'services': device.get('services', [])
                    }
                    enhanced_results.append(enhanced_device)
                
                scan_results = enhanced_results
                
            except Exception as e:
                logger.error(f"Scan error: {str(e)}")
                scan_results = []

        t = threading.Thread(target=do_scan)
        t.start()
        t.join()
        
        # Aktivite kaydet - thread dışında
        try:
            user_manager.log_activity(
                user_id,
                'scan',
                f'Tarama yapıldı: {ip_range} ({len(scan_results)} cihaz)'
            )
        except Exception as e:
            logger.error(f"Aktivite kaydetme hatası: {str(e)}")
        
        return jsonify({
            'status': 'success',
            'message': f'Tarama tamamlandı: {len(scan_results)} cihaz bulundu',
            'devices': scan_results,
            'scan_time': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"API scan error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/advanced-scan', methods=['POST'])
@user_manager.require_auth
def api_advanced_scan():
    global scan_results
    user_id = user_manager.get_user_id_from_token(request.headers.get('Authorization', '').replace('Bearer ', ''))
    
    data = request.get_json()
    ip_range = data.get('ip_range', '192.168.1.0/24')
    enable_nmap = data.get('enable_nmap', True)
    enable_dhcp = data.get('enable_dhcp', True)
    enable_netbios = data.get('enable_netbios', True)
    enable_mdns = data.get('enable_mdns', True)
    
    def do_advanced_scan():
        global scan_results
        try:
            # Temel tarama
            scanner = IPScannerV2()
            basic_results = scanner.scan_network(ip_range)
            
            # Gelişmiş tarama (nmap vb.)
            if enable_nmap:
                try:
                    advanced_scanner = AdvancedScanner()
                    advanced_results = advanced_scanner.comprehensive_scan(
                        ip_range, enable_nmap, enable_dhcp, enable_netbios, enable_mdns
                    )
                    
                    # Sonuçları birleştir
                    combined_results = []
                    basic_devices = {device['ip']: device for device in basic_results}
                    
                    for advanced_device in advanced_results:
                        ip = advanced_device['ip']
                        if ip in basic_devices:
                            # Temel bilgileri koru, gelişmiş bilgileri ekle
                            device = basic_devices[ip].copy()
                            device.update({
                                'os_info': advanced_device.get('os_info'),
                                'services': advanced_device.get('services', []),
                                'discovery_methods': advanced_device.get('discovery_methods', []),
                                'additional_info': advanced_device.get('additional_info', {})
                            })
                            
                            # Cihaz türünü yeniden tespit et
                            device_type, confidence = device_detector.detect_device_type(
                                device['mac'], 
                                device['vendor'],
                                device.get('open_ports', []),
                                device.get('services', [])
                            )
                            device['device_type'] = device_type
                            device['confidence'] = confidence
                            
                            combined_results.append(device)
                        else:
                            # Sadece gelişmiş taramada bulunan cihazlar
                            vendor = device_detector.get_vendor_from_api(advanced_device['mac'])
                            device_type, confidence = device_detector.detect_device_type(
                                advanced_device['mac'], vendor
                            )
                            
                            combined_results.append({
                                'ip': advanced_device['ip'],
                                'mac': advanced_device['mac'],
                                'vendor': vendor,
                                'device_type': device_type,
                                'confidence': confidence,
                                'open_ports': [service['port'] for service in advanced_device.get('services', [])],
                                'status': 'Aktif',
                                'last_seen': datetime.now().isoformat(),
                                'os_info': advanced_device.get('os_info'),
                                'services': advanced_device.get('services', []),
                                'discovery_methods': advanced_device.get('discovery_methods', []),
                                'additional_info': advanced_device.get('additional_info', {})
                            })
                    
                    scan_results = combined_results
                    
                except Exception as e:
                    print(f"Advanced scan error: {str(e)}")
                    scan_results = basic_results
            else:
                scan_results = basic_results
            
        except Exception as e:
            print(f"Advanced scan error: {str(e)}")
            scan_results = []

    t = threading.Thread(target=do_advanced_scan)
    t.start()
    t.join()
    
    # Aktivite kaydet - thread dışında
    try:
        user_manager.log_activity(
            user_id,
            'scan',
            f'Gelişmiş tarama yapıldı: {ip_range} ({len(scan_results)} cihaz)'
        )
    except Exception as e:
        print(f"Aktivite kaydetme hatası: {str(e)}")
    
    return jsonify({
        'success': True,
        'devices': scan_results,
        'total': len(scan_results)
    })

@app.route('/api/devices', methods=['GET'])
@user_manager.require_auth
def api_devices():
    return jsonify({'devices': scan_results})

@app.route('/api/device-details/<ip>', methods=['GET'])
@user_manager.require_auth
def api_device_details(ip):
    """Belirli bir cihazın detaylı bilgilerini döner"""
    device = next((d for d in scan_results if d['ip'] == ip), None)
    if device:
        return jsonify({'status': 'ok', 'device': device})
    else:
        return jsonify({'error': 'Cihaz bulunamadı'}), 404

@app.route('/api/network-map', methods=['GET'])
@user_manager.require_auth
def api_network_map():
    """Ağ haritası oluşturur ve HTML içeriğini döner"""
    try:
        print(f"Network-map endpoint çağrıldı. Scan results: {len(scan_results) if scan_results else 0}")
        
        if not scan_results:
            return jsonify({'error': 'Önce tarama yapın'}), 400
        
        # DEBUG: İlk birkaç cihazın verilerini göster
        print("DEBUG: İlk 3 scan result:")
        for i, device in enumerate(scan_results[:3]):
            print(f"  Scan Result {i+1}: {device}")
        
        # Ağ görselleştirmesi oluştur
        from network_visualizer import create_network_visualization
        result = create_network_visualization(scan_results)
        
        if result.get('success') and result.get('html_file'):
            # HTML dosyasını oku
            try:
                with open(result['html_file'], 'r', encoding='utf-8') as f:
                    html_content = f.read()
                
                return jsonify({
                    'status': 'ok',
                    'network_map': html_content,
                    'stats': result.get('stats', {}),
                    'html_path': result['html_file']
                })
            except Exception as e:
                print(f"HTML dosyası okuma hatası: {e}")
                return jsonify({'error': 'HTML dosyası okunamadı'}), 500
        else:
            return jsonify({'error': 'Ağ haritası oluşturulamadı'}), 500
            
    except Exception as e:
        import traceback
        print(f"Network-map endpoint hatası: {e}")
        print(traceback.format_exc())
        return jsonify({'error': f'Ağ haritası hatası: {str(e)}'}), 500

@app.route('/api/network-stats', methods=['GET'])
@user_manager.require_auth
def api_network_stats():
    """Ağ istatistiklerini döner"""
    if not scan_results:
        return jsonify({'error': 'Önce tarama yapın'}), 400
    
    try:
        from network_visualizer import NetworkVisualizer
        visualizer = NetworkVisualizer()
        stats = visualizer.generate_network_stats(scan_results)
        return jsonify({'status': 'ok', 'stats': stats})
    except Exception as e:
        return jsonify({'error': f'İstatistik hatası: {str(e)}'}), 500

@app.route('/api/generate-reports', methods=['POST'])
@user_manager.require_auth
def api_generate_reports():
    """PDF ve HTML raporları oluşturur"""
    if not scan_results:
        return jsonify({'error': 'Önce tarama yapın'}), 400
    
    try:
        # İstatistikleri al
        from network_visualizer import NetworkVisualizer
        visualizer = NetworkVisualizer()
        stats = visualizer.generate_network_stats(scan_results)
        
        # Raporları oluştur
        reports = generate_reports(scan_results, stats, "reports")
        
        # Aktivite kaydet
        user_manager.log_activity(
            request.current_user['user_id'],
            'report',
            f'Rapor oluşturuldu: {len(scan_results)} cihaz'
        )
        
        return jsonify({
            'status': 'ok',
            'reports': {
                'pdf': reports['pdf'],
                'html': reports['html'],
                'chart': reports['chart']
            }
        })
    except Exception as e:
        return jsonify({'error': f'Rapor oluşturma hatası: {str(e)}'}), 500

@app.route('/api/download-report/<report_type>', methods=['GET'])
@user_manager.require_auth
def api_download_report(report_type):
    """Rapor dosyalarını indirir"""
    if not scan_results:
        return jsonify({'error': 'Önce tarama yapın'}), 400
    
    try:
        if report_type == 'pdf':
            # PDF raporu oluştur ve gönder
            from network_visualizer import NetworkVisualizer
            visualizer = NetworkVisualizer()
            stats = visualizer.generate_network_stats(scan_results)
            
            generator = ReportGenerator()
            pdf_path = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            os.makedirs("reports", exist_ok=True)
            generator.generate_pdf_report(scan_results, stats, pdf_path)
            
            return send_file(pdf_path, as_attachment=True, download_name=f"network_scan_report.pdf")
        
        elif report_type == 'html':
            # HTML raporu oluştur ve gönder
            from network_visualizer import NetworkVisualizer
            visualizer = NetworkVisualizer()
            stats = visualizer.generate_network_stats(scan_results)
            
            generator = ReportGenerator()
            html_path = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            os.makedirs("reports", exist_ok=True)
            generator.generate_html_report(scan_results, stats, html_path)
            
            return send_file(html_path, as_attachment=True, download_name=f"network_scan_report.html")
        
        else:
            return jsonify({'error': 'Geçersiz rapor türü'}), 400
            
    except Exception as e:
        return jsonify({'error': f'Rapor indirme hatası: {str(e)}'}), 500

@app.route('/api/send-email', methods=['POST'])
@user_manager.require_auth
def api_send_email():
    """E-posta ile rapor gönderir"""
    if not scan_results:
        return jsonify({'error': 'Önce tarama yapın'}), 400
    
    try:
        data = request.json
        to_email = data.get('to_email')
        smtp_config = data.get('smtp_config')
        report_type = data.get('report_type', 'html')
        
        if not to_email or not smtp_config:
            return jsonify({'error': 'E-posta adresi ve SMTP konfigürasyonu gerekli'}), 400
        
        # İstatistikleri al
        from network_visualizer import NetworkVisualizer
        visualizer = NetworkVisualizer()
        stats = visualizer.generate_network_stats(scan_results)
        
        # Rapor oluştur
        generator = ReportGenerator()
        
        if report_type == 'pdf':
            report_path = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            os.makedirs("reports", exist_ok=True)
            generator.generate_pdf_report(scan_results, stats, report_path)
            subject = "IP Scanner V3.4 - Gelişmiş Ağ Tarama Raporu (PDF)"
            body = f"""
            <h2>IP Scanner V3.4 - Gelişmiş Ağ Tarama Raporu</h2>
            <p>Tarama Tarihi: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Toplam Cihaz: {stats.get('total_devices', 0)}</p>
            <p>Bu e-posta ile birlikte detaylı PDF raporu gönderilmiştir.</p>
            """
        else:
            report_path = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            os.makedirs("reports", exist_ok=True)
            generator.generate_html_report(scan_results, stats, report_path)
            subject = "IP Scanner V3.4 - Gelişmiş Ağ Tarama Raporu (HTML)"
            body = f"""
            <h2>IP Scanner V3.4 - Gelişmiş Ağ Tarama Raporu</h2>
            <p>Tarama Tarihi: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Toplam Cihaz: {stats.get('total_devices', 0)}</p>
            <p>Bu e-posta ile birlikte detaylı HTML raporu gönderilmiştir.</p>
            """
        
        # E-posta gönder
        success = generator.send_email_report(to_email, subject, body, report_path, smtp_config)
        
        if success:
            # Aktivite kaydet
            user_manager.log_activity(
                request.current_user['user_id'],
                'email',
                f'E-posta gönderildi: {to_email}'
            )
            return jsonify({'status': 'ok', 'message': 'E-posta başarıyla gönderildi'})
        else:
            return jsonify({'error': 'E-posta gönderilemedi'}), 500
            
    except Exception as e:
        return jsonify({'error': f'E-posta gönderme hatası: {str(e)}'}), 500

@app.route('/api/report', methods=['GET'])
@user_manager.require_auth
def api_report():
    # JSON raporunu geçici dosya olarak sun
    report_path = 'scan_report.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(scan_results, f, indent=2, ensure_ascii=False)
    return send_file(report_path, as_attachment=True)

# Admin endpoint'leri
@app.route('/api/admin/users', methods=['GET'])
@user_manager.require_auth
@user_manager.require_role('admin')
def api_admin_users():
    """Tüm kullanıcıları listele (sadece admin)"""
    try:
        import sqlite3
        conn = sqlite3.connect(user_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, full_name, role, created_at, last_login, is_active
            FROM users ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'full_name': user[3],
                'role': user[4],
                'created_at': user[5],
                'last_login': user[6],
                'is_active': bool(user[7])
            })
        
        return jsonify({'status': 'ok', 'users': user_list})
        
    except Exception as e:
        return jsonify({'error': f'Kullanıcı listesi hatası: {str(e)}'}), 500

@app.route('/api/admin/activities', methods=['GET'])
@user_manager.require_auth
@user_manager.require_role('admin')
def api_admin_activities():
    """Tüm aktiviteleri listele (sadece admin)"""
    try:
        import sqlite3
        conn = sqlite3.connect(user_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ua.id, u.username, ua.activity_type, ua.description, ua.ip_address, ua.timestamp
            FROM user_activities ua
            JOIN users u ON ua.user_id = u.id
            ORDER BY ua.timestamp DESC
            LIMIT 100
        ''')
        
        activities = cursor.fetchall()
        conn.close()
        
        activity_list = []
        for activity in activities:
            activity_list.append({
                'id': activity[0],
                'username': activity[1],
                'type': activity[2],
                'description': activity[3],
                'ip_address': activity[4],
                'timestamp': activity[5]
            })
        
        return jsonify({'status': 'ok', 'activities': activity_list})
        
    except Exception as e:
        return jsonify({'error': f'Aktivite listesi hatası: {str(e)}'}), 500

@app.route('/api/network-traffic', methods=['GET'])
@user_manager.require_auth
def api_network_traffic():
    """Gerçek zamanlı ağ trafiği ve bağlantı bilgisi döner"""
    try:
        # Debug: Log the current user
        print(f"Network traffic request from user: {request.current_user['username']}")
        
        # Ağ arayüzü istatistikleri
        net_io = psutil.net_io_counters()
        traffic = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
        
        # Aktif bağlantılar
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    connections.append({
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                        'status': conn.status,
                        'pid': conn.pid
                    })
        except Exception as conn_error:
            print(f"Connection error: {conn_error}")
            # Return empty connections if there's an error
            connections = []
        
        print(f"Traffic data: {traffic}, Connections: {len(connections)}")
        return jsonify({'status': 'ok', 'traffic': traffic, 'connections': connections})
        
    except Exception as e:
        print(f"Network traffic error: {e}")
        return jsonify({'status': 'error', 'error': str(e)})

# Debug endpoint to test authentication
@app.route('/api/debug/auth', methods=['GET'])
@user_manager.require_auth
def api_debug_auth():
    """Debug endpoint to test authentication"""
    return jsonify({
        'status': 'ok',
        'message': 'Authentication working',
        'user': request.current_user
    })

# Anomali tespiti için basit fonksiyon
def detect_anomalies(traffic_data, connections):
    """Basit anomali tespiti yapar"""
    anomalies = []
    
    # Trafik threshold kontrolü (örnek: 1GB/saniye)
    bytes_sent = traffic_data['bytes_sent']
    bytes_recv = traffic_data['bytes_recv']
    
    # Eğer trafik çok yüksekse
    if bytes_sent > 1000000000 or bytes_recv > 1000000000:  # 1GB
        anomalies.append({
            'type': 'high_traffic',
            'severity': 'warning',
            'message': 'Yüksek ağ trafiği tespit edildi',
            'details': f'Gönderilen: {bytes_sent}, Alınan: {bytes_recv}'
        })
    
    # Port tarama tespiti (çok fazla bağlantı)
    if len(connections) > 100:
        anomalies.append({
            'type': 'port_scan',
            'severity': 'danger',
            'message': 'Port tarama aktivitesi tespit edildi',
            'details': f'{len(connections)} aktif bağlantı'
        })
    
    # Bilinmeyen cihaz tespiti (yeni IP'ler)
    known_ips = set()  # Bu normalde veritabanından gelir
    for conn in connections:
        if conn['raddr'] and conn['raddr'] not in known_ips:
            anomalies.append({
                'type': 'unknown_device',
                'severity': 'info',
                'message': 'Bilinmeyen cihaz tespit edildi',
                'details': f'IP: {conn["raddr"]}'
            })
    
    return anomalies

@app.route('/api/anomaly-detection', methods=['GET'])
@user_manager.require_auth
def api_anomaly_detection():
    """Anomali tespiti yapar ve sonuçları döner"""
    try:
        # Trafik verilerini al
        net_io = psutil.net_io_counters()
        traffic = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
        
        # Aktif bağlantıları al
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                connections.append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'pid': conn.pid
                })
        
        # Anomali tespiti
        anomalies = detect_anomalies(traffic, connections)
        
        # Anomali varsa aktivite kaydet
        if anomalies:
            user_manager.log_activity(
                request.current_user['user_id'],
                'anomaly',
                f'Anomali tespit edildi: {len(anomalies)} adet'
            )
        
        return jsonify({
            'status': 'ok',
            'anomalies': anomalies,
            'traffic': traffic,
            'connections_count': len(connections)
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

if __name__ == '__main__':
    # Production ayarları
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5001))
    
    logger.info(f"Starting IP Scanner V4.0 on {host}:{port}")
    logger.info(f"Debug mode: {debug_mode}")
    
    # Production'da debug mode kapalı olmalı
    app.run(debug=debug_mode, host=host, port=port) 