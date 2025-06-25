from flask import Flask, render_template, request, jsonify, send_file
import threading
import os
import json
from scanner_v2 import IPScannerV2
from network_visualizer import create_network_visualization
from report_generator import generate_reports, ReportGenerator
from datetime import datetime

app = Flask(__name__)
scanner = None
scan_results = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
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

    t = threading.Thread(target=do_scan)
    t.start()
    t.join()
    return jsonify({'status': 'ok', 'devices': scan_results})

@app.route('/api/devices', methods=['GET'])
def api_devices():
    return jsonify({'devices': scan_results})

@app.route('/api/network-map', methods=['GET'])
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
            subject = "IP Scanner V3.2 - Ağ Tarama Raporu (PDF)"
            body = f"""
            <h2>IP Scanner V3.2 - Ağ Tarama Raporu</h2>
            <p>Tarama Tarihi: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Toplam Cihaz: {stats.get('total_devices', 0)}</p>
            <p>Bu e-posta ile birlikte detaylı PDF raporu gönderilmiştir.</p>
            """
        else:
            report_path = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            os.makedirs("reports", exist_ok=True)
            generator.generate_html_report(scan_results, stats, report_path)
            subject = "IP Scanner V3.2 - Ağ Tarama Raporu (HTML)"
            body = f"""
            <h2>IP Scanner V3.2 - Ağ Tarama Raporu</h2>
            <p>Tarama Tarihi: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Toplam Cihaz: {stats.get('total_devices', 0)}</p>
            <p>Bu e-posta ile birlikte detaylı HTML raporu gönderilmiştir.</p>
            """
        
        # E-posta gönder
        success = generator.send_email_report(to_email, subject, body, report_path, smtp_config)
        
        if success:
            return jsonify({'status': 'ok', 'message': 'E-posta başarıyla gönderildi'})
        else:
            return jsonify({'error': 'E-posta gönderilemedi'}), 500
            
    except Exception as e:
        return jsonify({'error': f'E-posta gönderme hatası: {str(e)}'}), 500

@app.route('/api/report', methods=['GET'])
def api_report():
    # JSON raporunu geçici dosya olarak sun
    report_path = 'scan_report.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(scan_results, f, indent=2, ensure_ascii=False)
    return send_file(report_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000) 