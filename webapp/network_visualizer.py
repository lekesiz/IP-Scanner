import networkx as nx
import json
import os
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import traceback
from constants import DEVICE_TYPES, REPORTS_DIR

# Logging konfigürasyonu
logger = logging.getLogger(__name__)

class NetworkVisualizer:
    def __init__(self):
        self.graph = nx.Graph()
        self.device_colors = {
            'router': '#FF6B6B',      # Kırmızı
            'computer': '#4ECDC4',    # Turkuaz
            'phone': '#45B7D1',       # Mavi
            'tablet': '#96CEB4',      # Yeşil
            'printer': '#FFEAA7',     # Sarı
            'camera': '#DDA0DD',      # Mor
            'server': '#FF8C42',      # Turuncu
            'switch': '#6C5CE7',      # Mor
            'unknown': '#B2B2B2'      # Gri
        }
    
    def generate_network_html(self, devices: List[Dict], output_path: str = None) -> str:
        """Ağ görselleştirmesi HTML dosyası oluşturur"""
        try:
            if not devices:
                logger.warning("Cihaz listesi boş")
                return ""
            
            logger.info(f"Ağ haritası oluşturuluyor: {len(devices)} cihaz")
            
            # İlk birkaç cihazın verilerini logla
            for i, device in enumerate(devices[:3]):
                logger.debug(f"Cihaz {i+1}: {device}")
            
            # NetworkX graph oluştur
            self.graph.clear()
            
            # Node'ları ekle
            nodes_data = []
            for i, device in enumerate(devices):
                logger.debug(f"İşleniyor cihaz {i+1}/{len(devices)}: {device.get('ip', 'IP yok')}")
                
                ip = device.get('ip', '')
                mac = device.get('mac', '')
                device_type = device.get('device_type', 'unknown').lower()
                vendor = device.get('vendor', 'Bilinmiyor')
                confidence = device.get('confidence', 0)
                hostname = device.get('hostname', '')
                
                # Node rengi belirle
                color = self.device_colors.get(device_type, self.device_colors['unknown'])
                
                # Node etiketi
                label = hostname if hostname else ip
                
                # Node verisi
                node_data = {
                    'id': ip,
                    'label': label,
                    'title': f"IP: {ip}<br>MAC: {mac}<br>Vendor: {vendor}<br>Type: {device_type}<br>Confidence: {confidence}%",
                    'color': color,
                    'size': 25,
                    'font': {'size': 12},
                    'shape': 'dot'
                }
                
                nodes_data.append(node_data)
                self.graph.add_node(ip, **device)
            
            # Edge'leri oluştur (router bağlantıları)
            edges_data = []
            hub_ip = None
            hub_device_type = 'unknown'
            
            # Router'ı bul
            for device in devices:
                device_type = device.get('device_type', '').lower()
                if 'router' in device_type or 'modem' in device_type:
                    hub_ip = device.get('ip')
                    hub_device_type = device_type
                    break
            
            # Router yoksa ilk cihazı hub yap
            if not hub_ip and devices:
                hub_ip = devices[0].get('ip')
                hub_device_type = devices[0].get('device_type', 'unknown').lower()
            
            logger.info("Bağlantılar oluşturuluyor...")
            
            # Her cihazı router'a bağla
            if hub_ip:
                for device in devices:
                    device_ip = device.get('ip')
                    if device_ip and device_ip != hub_ip:
                        edge_data = {
                            'from': hub_ip,
                            'to': device_ip,
                            'arrows': 'to',
                            'color': {'color': '#2E86AB', 'opacity': 0.6},
                            'width': 2,
                            'title': f"Router -> {device.get('hostname', device_ip)}"
                        }
                        edges_data.append(edge_data)
                        self.graph.add_edge(hub_ip, device_ip)
            
            logger.info(f"Toplam {len(nodes_data)} node ve {len(edges_data)} edge oluşturuldu")
            logger.info(f"Hub cihazı: {hub_ip} ({hub_device_type})")
            
            # HTML template oluştur
            html_content = self._create_html_template(nodes_data, edges_data)
            
            # Dosyaya kaydet
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(REPORTS_DIR, f"network_map_{timestamp}.html")
            
            # Reports dizinini oluştur
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            logger.info(f"HTML dosyası oluşturuluyor: {output_path}")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Ağ haritası başarıyla oluşturuldu: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"generate_network_html hatası: {e}")
            logger.error(traceback.format_exc())
            return ""
    
    def _create_html_template(self, nodes_data: List[Dict], edges_data: List[Dict]) -> str:
        """HTML template oluşturur"""
        html_template = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Scanner V4.0 - Ağ Haritası</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        #mynetworkid {{
            width: 100%;
            height: 600px;
            border: 1px solid lightgray;
        }}
        .legend {{
            position: absolute;
            top: 10px;
            left: 10px;
            background: white;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            font-size: 12px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }}
    </style>
</head>
<body>
    <div class="legend">
        <h4>Ağ Cihazları</h4>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['router']}"></div>
            <span>Router/Modem</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['computer']}"></div>
            <span>Bilgisayar</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['phone']}"></div>
            <span>Telefon</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['tablet']}"></div>
            <span>Tablet</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['printer']}"></div>
            <span>Yazıcı</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['camera']}"></div>
            <span>Kamera</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['server']}"></div>
            <span>Sunucu</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['switch']}"></div>
            <span>Switch</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.device_colors['unknown']}"></div>
            <span>Bilinmeyen</span>
        </div>
    </div>
    
    <div id="mynetworkid"></div>
    
    <script type="text/javascript">
        // Network verisi
        var nodes = new vis.DataSet({json.dumps(nodes_data)});
        var edges = new vis.DataSet({json.dumps(edges_data)});
        
        // Network konfigürasyonu
        var data = {{
            nodes: nodes,
            edges: edges
        }};
        
        var options = {{
            nodes: {{
                shape: 'dot',
                size: 25,
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
                keyboard: true,
                hover: true
            }}
        }};
        
        // Network oluştur
        var container = document.getElementById('mynetworkid');
        var network = new vis.Network(container, data, options);
        
        // Event listeners
        network.on('click', function(params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var node = nodes.get(nodeId);
                console.log('Clicked node:', node);
            }}
        }});
        
        // Network stabilizasyonu tamamlandığında
        network.on('stabilizationProgress', function(params) {{
            console.log('Stabilization progress:', params.iterations + '/' + params.total);
        }});
        
        network.on('stabilizationIterationsDone', function() {{
            console.log('Network stabilized');
        }});
    </script>
</body>
</html>
        """
        return html_template
    
    def generate_network_stats(self, devices: List[Dict]) -> Dict:
        """Ağ istatistikleri oluşturur"""
        try:
            stats = {
                'total_devices': len(devices),
                'device_types': {},
                'vendors': {},
                'confidence_levels': {
                    'high': 0,    # 80-100%
                    'medium': 0,  # 50-79%
                    'low': 0      # 0-49%
                },
                'ports': {},
                'protocols': {}
            }
            
            for device in devices:
                # Cihaz türü istatistikleri
                device_type = device.get('device_type', 'unknown').lower()
                stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
                
                # Vendor istatistikleri
                vendor = device.get('vendor', 'Bilinmiyor')
                stats['vendors'][vendor] = stats['vendors'].get(vendor, 0) + 1
                
                # Güven seviyesi istatistikleri
                confidence = device.get('confidence', 0)
                if confidence >= 80:
                    stats['confidence_levels']['high'] += 1
                elif confidence >= 50:
                    stats['confidence_levels']['medium'] += 1
                else:
                    stats['confidence_levels']['low'] += 1
                
                # Port istatistikleri
                open_ports = device.get('open_ports', [])
                for port in open_ports:
                    stats['ports'][port] = stats['ports'].get(port, 0) + 1
                
                # Protokol istatistikleri
                protocols = device.get('protocols', [])
                for protocol in protocols:
                    stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
            
            return stats
            
        except Exception as e:
            logger.error(f"generate_network_stats hatası: {e}")
            logger.error(traceback.format_exc())
            return {}
    
    def create_network_visualization(self, devices: List[Dict], output_dir: str = None) -> Dict:
        """Ana ağ görselleştirme fonksiyonu"""
        try:
            logger.info(f"Ağ görselleştirmesi başlatılıyor: {len(devices)} cihaz")
            
            # Çıktı dizinini belirle
            if output_dir is None:
                output_dir = REPORTS_DIR
            
            # Dizini oluştur
            os.makedirs(output_dir, exist_ok=True)
            
            # HTML dosyası oluştur
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_path = os.path.join(output_dir, f"network_map_{timestamp}.html")
            
            html_file = self.generate_network_html(devices, html_path)
            
            # İstatistikler oluştur
            stats = self.generate_network_stats(devices)
            
            # Sonuçları döndür
            result = {
                'success': True,
                'html_file': html_file,
                'stats': stats,
                'timestamp': timestamp,
                'device_count': len(devices)
            }
            
            logger.info(f"Ağ görselleştirmesi tamamlandı: {html_file}")
            return result
            
        except Exception as e:
            logger.error(f"create_network_visualization hatası: {e}")
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'html_file': '',
                'stats': {},
                'timestamp': datetime.now().strftime("%Y%m%d_%H%M%S"),
                'device_count': 0
            }

# Global instance
network_visualizer = NetworkVisualizer()

def create_network_visualization(devices: List[Dict], output_dir: str = None) -> Dict:
    """Ağ görselleştirmesi oluşturur"""
    return network_visualizer.create_network_visualization(devices, output_dir) 