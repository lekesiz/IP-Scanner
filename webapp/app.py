from flask import Flask, render_template, request, jsonify, send_file
import threading
import os
import json
from scanner_v2 import IPScannerV2
from network_visualizer import create_network_visualization

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

@app.route('/api/report', methods=['GET'])
def api_report():
    # JSON raporunu geçici dosya olarak sun
    report_path = 'scan_report.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(scan_results, f, indent=2, ensure_ascii=False)
    return send_file(report_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000) 