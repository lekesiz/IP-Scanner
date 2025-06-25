import networkx as nx
from pyvis.network import Network
import json
import os
from datetime import datetime

class NetworkVisualizer:
    def __init__(self):
        self.net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="#000000")
        self.net.set_options("""
        var options = {
          "nodes": {
            "color": {
              "background": "#97C2FC",
              "border": "#2B7CE9"
            },
            "font": {
              "size": 12
            },
            "shape": "dot"
          },
          "edges": {
            "color": {
              "color": "#848484",
              "highlight": "#848484",
              "hover": "#848484"
            },
            "smooth": {
              "type": "continuous"
            }
          },
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -50,
              "centralGravity": 0.01,
              "springLength": 100,
              "springConstant": 0.08
            },
            "maxVelocity": 50,
            "minVelocity": 0.1,
            "solver": "forceAtlas2Based",
            "timestep": 0.35
          }
        }
        """)
    
    def create_network_graph(self, devices):
        """Cihazlardan ağ grafiği oluşturur"""
        G = nx.Graph()
        
        # Cihaz türlerine göre renk kodları
        device_colors = {
            'Router': '#ff6b6b',
            'Bilgisayar': '#4ecdc4', 
            'Apple Cihazı': '#45b7d1',
            'Android Cihazı': '#96ceb4',
            'Huawei Cihazı': '#feca57',
            'Xiaomi Cihazı': '#ff9ff3',
            'Windows Cihazı': '#54a0ff',
            'Bilinmeyen Cihaz': '#c8d6e5'
        }
        
        # Cihazları grafiğe ekle
        for device in devices:
            node_id = device['ip']
            device_type = device['device_type']
            color = device_colors.get(device_type, '#c8d6e5')
            
            # Node etiketi
            label = f"{device['ip']}\n{device['device_type']}"
            if device['vendor'] != 'Bilinmiyor':
                label += f"\n{device['vendor']}"
            
            # Node'u grafiğe ekle
            G.add_node(node_id, 
                      label=label,
                      title=f"IP: {device['ip']}<br>MAC: {device['mac']}<br>Üretici: {device['vendor']}<br>Tür: {device['device_type']}<br>Açık Portlar: {', '.join(map(str, device['open_ports'])) if device['open_ports'] else 'Yok'}",
                      color=color,
                      size=20)
            
            # Router varsa diğer cihazlarla bağlantı kur
            if device_type == 'Router':
                for other_device in devices:
                    if other_device['ip'] != device['ip']:
                        G.add_edge(device['ip'], other_device['ip'], 
                                  title=f"Router bağlantısı: {device['ip']} ↔ {other_device['ip']}")
        
        return G
    
    def generate_network_html(self, devices, output_path="webapp/static/network.html"):
        """Ağ haritasını HTML olarak oluşturur"""
        if not devices:
            return None
        
        # Ağ grafiği oluştur
        G = self.create_network_graph(devices)
        
        # Pyvis network'e dönüştür
        for node in G.nodes():
            node_data = G.nodes[node]
            self.net.add_node(node, 
                             label=node_data['label'],
                             title=node_data['title'],
                             color=node_data['color'],
                             size=node_data['size'])
        
        for edge in G.edges():
            edge_data = G.edges[edge]
            self.net.add_edge(edge[0], edge[1], title=edge_data.get('title', ''))
        
        # HTML dosyasını oluştur
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        self.net.show(output_path)
        
        return output_path
    
    def generate_network_stats(self, devices):
        """Ağ istatistiklerini hesaplar"""
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

def create_network_visualization(devices):
    """Ana fonksiyon: Ağ görselleştirmesi oluşturur"""
    visualizer = NetworkVisualizer()
    
    # HTML dosyasını oluştur
    html_path = visualizer.generate_network_html(devices)
    
    # İstatistikleri hesapla
    stats = visualizer.generate_network_stats(devices)
    
    return {
        'html_path': html_path,
        'stats': stats
    } 