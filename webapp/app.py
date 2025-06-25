import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import threading
import os
import json
from scanner_v2 import IPScannerV2
from network_visualizer import create_network_visualization
from report_generator import generate_reports, ReportGenerator
from advanced_scanner import create_advanced_scanner
from user_management import user_manager
from datetime import datetime
import psutil

app = Flask(__name__)
scanner = None
scan_results = []

@app.route('/')
def index():
    # Otomatik dil algılama
    lang = request.cookies.get('lang') or request.accept_languages.best_match(['tr', 'en']) or 'tr'
    return render_template('index.html', lang=lang)

@app.route('/login')
def login():
    return render_template('login.html')

# Kullanıcı yönetimi endpoint'leri
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """Kullanıcı kaydı"""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    
    if not all([username, email, password]):
        return jsonify({'error': 'Tüm alanlar gerekli'}), 400
    
    result = user_manager.register_user(username, email, password, full_name)
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Kullanıcı girişi"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({'error': 'Kullanıcı adı ve şifre gerekli'}), 400
    
    result = user_manager.login_user(username, password)
    
    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 401

@app.route('/api/auth/logout', methods=['POST'])
@user_manager.require_auth
def api_logout():
    """Kullanıcı çıkışı"""
    token = request.headers.get('Authorization')
    if token.startswith('Bearer '):
        token = token[7:]
    
    result = user_manager.logout_user(token)
    return jsonify(result)

@app.route('/api/auth/profile', methods=['GET'])
@user_manager.require_auth
def api_profile():
    """Kullanıcı profili"""
    user_id = request.current_user['user_id']
    profile = user_manager.get_user_profile(user_id)
    
    if profile:
        return jsonify({'status': 'ok', 'profile': profile})
    else:
        return jsonify({'error': 'Profil bulunamadı'}), 404

@app.route('/api/auth/settings', methods=['GET', 'PUT'])
@user_manager.require_auth
def api_settings():
    """Kullanıcı ayarları"""
    user_id = request.current_user['user_id']
    
    if request.method == 'GET':
        profile = user_manager.get_user_profile(user_id)
        if profile:
            return jsonify({'status': 'ok', 'settings': profile['settings']})
        else:
            return jsonify({'error': 'Ayarlar bulunamadı'}), 404
    
    elif request.method == 'PUT':
        data = request.json
        
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

# Tarama endpoint'leri (kimlik doğrulama ile)
@app.route('/api/scan', methods=['POST'])
@user_manager.require_auth
def api_scan():
    global scan_results
    ip_range = request.json.get('ip_range', '192.168.1.0/24')
    port_scan = request.json.get('port_scan', True)

    def do_scan():
        global scan_results
        scanner = IPScannerV2()
        scanner.port_scan_var.set(port_scan)
        results = scanner.scan_network(ip_range)
        scan_results = results
        
        # Aktivite kaydet
        user_manager.log_activity(
            request.current_user['user_id'],
            'scan',
            f'Temel tarama yapıldı: {ip_range}'
        )

    t = threading.Thread(target=do_scan)
    t.start()
    t.join()
    return jsonify({'status': 'ok', 'devices': scan_results})

@app.route('/api/advanced-scan', methods=['POST'])
@user_manager.require_auth
def api_advanced_scan():
    """Gelişmiş tarama endpoint'i"""
    global scan_results
    
    data = request.json
    ip_range = data.get('ip_range', '192.168.1.0/24')
    enable_nmap = data.get('enable_nmap', True)
    enable_dhcp = data.get('enable_dhcp', True)
    enable_netbios = data.get('enable_netbios', True)
    enable_mdns = data.get('enable_mdns', True)

    def do_advanced_scan():
        global scan_results
        try:
            advanced_scanner = create_advanced_scanner()
            results = advanced_scanner.comprehensive_scan(
                ip_range=ip_range,
                enable_nmap=enable_nmap,
                enable_dhcp=enable_dhcp,
                enable_netbios=enable_netbios,
                enable_mdns=enable_mdns
            )
            
            # Sonuçları standart formata dönüştür
            formatted_results = []
            for device in results:
                # Vendor bilgisini al (basit tarama ile)
                basic_scanner = IPScannerV2()
                vendor = basic_scanner.get_vendor(device['mac'])
                
                # Gelişmiş cihaz türü tespiti
                device_type_info = advanced_scanner.detect_device_type_advanced(
                    device['ip'], 
                    device['mac'], 
                    vendor,
                    device.get('os_info'),
                    device.get('services')
                )
                
                formatted_device = {
                    'ip': device['ip'],
                    'mac': device['mac'],
                    'vendor': vendor,
                    'device_type': device_type_info['device_type'],
                    'confidence': device_type_info['confidence'],
                    'open_ports': [service['port'] for service in device.get('services', [])],
                    'status': 'Aktif',
                    'last_seen': datetime.now().isoformat(),
                    'os_info': device.get('os_info'),
                    'services': device.get('services'),
                    'discovery_methods': device.get('discovery_methods', []),
                    'additional_info': device.get('additional_info', {})
                }
                
                formatted_results.append(formatted_device)
            
            scan_results = formatted_results
            
            # Aktivite kaydet
            user_manager.log_activity(
                request.current_user['user_id'],
                'scan',
                f'Gelişmiş tarama yapıldı: {ip_range} ({len(formatted_results)} cihaz)'
            )
            
        except Exception as e:
            print(f"Advanced scan error: {str(e)}")
            scan_results = []

    t = threading.Thread(target=do_advanced_scan)
    t.start()
    t.join()
    
    return jsonify({'status': 'ok', 'devices': scan_results})

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
    """Ağ haritası oluşturur ve HTML dosyasını döner"""
    if not scan_results:
        return jsonify({'error': 'Önce tarama yapın'}), 400
    
    try:
        # Ağ görselleştirmesi oluştur
        result = create_network_visualization(scan_results)
        
        if result['html_path']:
            return jsonify({
                'status': 'ok',
                'html_path': '/static/network.html',
                'stats': result['stats']
            })
        else:
            return jsonify({'error': 'Ağ haritası oluşturulamadı'}), 500
            
    except Exception as e:
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
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                connections.append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'pid': conn.pid
                })
        return jsonify({'status': 'ok', 'traffic': traffic, 'connections': connections})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

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
    app.run(debug=True, port=5000) 