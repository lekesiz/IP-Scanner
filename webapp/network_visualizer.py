import json
import os
from datetime import datetime
import traceback

class NetworkVisualizer:
    def __init__(self):
        self.html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Ağ Haritası - IP Scanner V4.0</title>
    <meta charset=\"utf-8\">
    <script src=\"https://unpkg.com/vis-network/standalone/umd/vis-network.min.js\"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ padding: 20px; border-bottom: 1px solid #eee; }}
        .header h1 {{ margin: 0; color: #333; }}
        .stats {{ padding: 20px; background: #f8f9fa; border-bottom: 1px solid #eee; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 6px; border: 1px solid #ddd; }}
        .stat-card h3 {{ margin: 0 0 10px 0; color: #555; font-size: 14px; }}
        .stat-card p {{ margin: 0; font-size: 24px; font-weight: bold; color: #333; }}
        #network-container {{ height: 600px; border: 1px solid #ddd; }}
        .legend {{ padding: 20px; display: flex; flex-wrap: wrap; gap: 15px; }}
        .legend-item {{ display: flex; align-items: center; gap: 8px; }}
        .legend-color {{ width: 20px; height: 20px; border-radius: 50%; }}
    </style>
</head>
<body>
    <div class=\"container\">
        <div class=\"header\">
            <h1>🌐 Ağ Haritası - IP Scanner V4.0</h1>
            <p>Tarama Tarihi: {scan_time}</p>
        </div>
        
        <div class=\"stats\">
            <h2>📊 Ağ İstatistikleri</h2>
            <div class=\"stats-grid\">
                <div class=\"stat-card\">
                    <h3>Toplam Cihaz</h3>
                    <p>{total_devices}</p>
                </div>
                <div class=\"stat-card\">
                    <h3>Cihaz Türleri</h3>
                    <p>{device_types_count}</p>
                </div>
                <div class=\"stat-card\">
                    <h3>Üreticiler</h3>
                    <p>{vendors_count}</p>
                </div>
                <div class=\"stat-card\">
                    <h3>Açık Portlar</h3>
                    <p>{open_ports_count}</p>
                </div>
            </div>
        </div>
        
        <div class=\"legend\">
            <h3>🎨 Cihaz Türleri:</h3>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #ff6b6b;\"></div><span>Router</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #4ecdc4;\"></div><span>Bilgisayar</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #45b7d1;\"></div><span>Apple Cihazı</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #96ceb4;\"></div><span>Android Cihazı</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #feca57;\"></div><span>Huawei Cihazı</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #ff9ff3;\"></div><span>Xiaomi Cihazı</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #54a0ff;\"></div><span>Windows Cihazı</span></div>
            <div class=\"legend-item\"><div class=\"legend-color\" style=\"background: #c8d6e5;\"></div><span>Bilinmeyen</span></div>
        </div>
        
        <div id=\"network-container\"></div>
    </div>
    
    <script>
        var nodes = new vis.DataSet({nodes_data});
        var edges = new vis.DataSet({edges_data});
        
        var container = document.getElementById('network-container');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            nodes: {{
                shape: 'dot',
                size: 20,
                font: {{
                    size: 12,
                    face: 'Arial'
                }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                width: 2,
                shadow: true,
                smooth: {{
                    type: 'continuous'
                }}
            }},
            physics: {{
                stabilization: false,
                barnesHut: {{
                    gravitationalConstant: -80000,
                    springConstant: 0.001,
                    springLength: 200
                }}
            }},
            interaction: {{
                navigationButtons: true,
                keyboard: true
            }}
        }};
        
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""
    
    def generate_network_html(self, devices, output_path="webapp/static/network.html"):
        """Ağ haritasını HTML olarak oluşturur"""
        try:
            if not devices:
                print("Cihaz listesi boş")
                return None
            
            print(f"Ağ haritası oluşturuluyor: {len(devices)} cihaz")
            
            # DEBUG: İlk birkaç cihazın verilerini göster
            print("DEBUG: İlk 3 cihazın verileri:")
            for i, device in enumerate(devices[:3]):
                print(f"  Cihaz {i+1}: {device}")
            
            # Vis.js için node ve edge verilerini hazırla
            nodes_data = []
            edges_data = []
            
            # Cihaz türlerine göre renk kodları
            device_colors = {
                'Router': '#ff6b6b',
                'Bilgisayar': '#4ecdc4', 
                'Apple Cihazı': '#45b7d1',
                'Android Cihazı': '#96ceb4',
                'Huawei Cihazı': '#feca57',
                'Xiaomi Cihazı': '#ff9ff3',
                'Windows Cihazı': '#54a0ff',
                'Bilinmeyen Cihaz': '#c8d6e5',
                'Bilinmeyen': '#c8d6e5'  # Eksik olan bu
            }
            
            # Node'ları ekle
            for i, device in enumerate(devices):
                # DEBUG: Her cihazı işlerken log
                print(f"İşleniyor cihaz {i+1}/{len(devices)}: {device.get('ip', 'IP yok')}")
                
                # Eksik alanları kontrol et ve varsayılan değerler ata
                device_type = device.get('device_type', 'Bilinmeyen')
                vendor = device.get('vendor', 'Bilinmiyor')
                ip = device.get('ip', f'Unknown_{i}')
                mac = device.get('mac', 'Bilinmiyor')
                open_ports = device.get('open_ports', [])
                
                color = device_colors.get(device_type, '#c8d6e5')
                
                label = f"{ip}\n{device_type}"
                if vendor != 'Bilinmiyor':
                    label += f"\n{vendor}"
                
                nodes_data.append({
                    'id': ip,
                    'label': label,
                    'title': f"IP: {ip}<br>MAC: {mac}<br>Üretici: {vendor}<br>Tür: {device_type}<br>Açık Portlar: {', '.join(map(str, open_ports)) if open_ports else 'Yok'}",
                    'color': color,
                    'size': 20
                })
            
            # Bağlantıları oluştur - Hub-and-spoke modeli
            print("Bağlantılar oluşturuluyor...")
            
            # İlk cihazı hub olarak kullan (genellikle router)
            hub_ip = devices[0].get('ip', 'Unknown_0')
            hub_device_type = devices[0].get('device_type', 'Bilinmeyen')
            
            # Diğer tüm cihazları hub'a bağla
            for i, device in enumerate(devices[1:], 1):
                device_ip = device.get('ip', f'Unknown_{i}')
                device_type = device.get('device_type', 'Bilinmeyen')
                
                # Router bağlantıları daha kalın
                if hub_device_type == 'Router' or device_type == 'Router':
                    edge_width = 3
                    edge_color = '#ff6b6b'
                else:
                    edge_width = 2
                    edge_color = '#4ecdc4'
                
                edges_data.append({
                    'from': hub_ip,
                    'to': device_ip,
                    'width': edge_width,
                    'color': edge_color,
                    'title': f"Hub bağlantısı: {hub_ip} ↔ {device_ip}"
                })
            
            print(f"DEBUG: Toplam {len(nodes_data)} node ve {len(edges_data)} edge oluşturuldu")
            print(f"Hub cihazı: {hub_ip} ({hub_device_type})")
            
            # İstatistikleri hesapla
            stats = self.generate_network_stats(devices)
            
            # HTML dosyasını oluştur
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            print(f"HTML dosyası oluşturuluyor: {output_path}")
            
            html_content = self.html_template.format(
                scan_time=stats.get('scan_time', ''),
                total_devices=stats.get('total_devices', 0),
                device_types_count=len(stats.get('device_types', {})),
                vendors_count=len(stats.get('vendors', {})),
                open_ports_count=len(stats.get('open_ports', {})),
                nodes_data=json.dumps(nodes_data),
                edges_data=json.dumps(edges_data)
            )
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"Ağ haritası başarıyla oluşturuldu: {output_path}")
            return output_path
        except Exception as e:
            print(f"generate_network_html hatası: {e}")
            print(traceback.format_exc())
            raise
    
    def generate_network_stats(self, devices):
        """Ağ istatistiklerini hesaplar"""
        try:
            if not devices:
                return {}
            
            stats = {
                'total_devices': len(devices),
                'device_types': {},
                'vendors': {},
                'open_ports': {},
                'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            for device in devices:
                # Cihaz türü sayısı
                device_type = device['device_type']
                stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
                
                # Üretici sayısı
                vendor = device['vendor']
                if vendor != 'Bilinmiyor':
                    stats['vendors'][vendor] = stats['vendors'].get(vendor, 0) + 1
                
                # Açık port sayısı
                for port in device.get('open_ports', []):
                    stats['open_ports'][str(port)] = stats['open_ports'].get(str(port), 0) + 1
            
            return stats
        except Exception as e:
            print(f"generate_network_stats hatası: {e}")
            print(traceback.format_exc())
            raise

def create_network_visualization(devices):
    """Ana fonksiyon: Ağ görselleştirmesi oluşturur"""
    try:
        print(f"Ağ görselleştirmesi başlatılıyor: {len(devices)} cihaz")
        visualizer = NetworkVisualizer()
        
        # HTML dosyasını oluştur
        html_path = visualizer.generate_network_html(devices)
        
        # İstatistikleri hesapla
        stats = visualizer.generate_network_stats(devices)
        
        return {
            'html_path': html_path,
            'stats': stats
        }
    except Exception as e:
        print(f"create_network_visualization hatası: {e}")
        print(traceback.format_exc())
        raise 