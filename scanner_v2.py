from threading import Thread, Event
import time
import json
import csv
from datetime import datetime
from scapy.all import ARP, Ether, srp, sr, IP, TCP, ICMP
import requests
import socket
import re
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os

# Yeni cihaz tespit modülünü import et
sys.path.append(os.path.join(os.path.dirname(__file__), 'webapp'))
from device_detector import device_detector

class IPScannerV2:
    def __init__(self):
        # Cache ve durum değişkenleri
        self.scanning = False
        self.monitoring = False
        self.monitor_event = Event()
        self.devices = []
        self.known_devices = set()
        
        # Yaygın portlar
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        # Web uygulaması için port_scan_var
        self.port_scan_var = type('obj', (object,), {
            'get': lambda self: True,
            'set': lambda self, x: None
        })()
        
    def get_vendor(self, mac):
        """MAC adresinden üretici bilgisi alır - Yeni detector kullanır"""
        return device_detector.get_vendor_from_api(mac)
    
    def detect_device_type(self, mac, vendor):
        """MAC adresi ve üretici bilgisinden cihaz türünü tespit eder - Yeni detector kullanır"""
        device_type, confidence = device_detector.detect_device_type(mac, vendor)
        return device_type
    
    def port_scan(self, ip, ports=None):
        """Belirtilen IP adresinde port taraması yapar"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # ThreadPoolExecutor ile paralel port taraması
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports

    def scan_network(self, ip_range):
        """Ağı tarar ve cihazları bulur"""
        try:
            print(f"Ağ taranıyor: {ip_range}")
            
            # Önce Scapy ile dene
            try:
                # ARP taraması
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
                result = srp(arp_request, timeout=3, verbose=0)[0]
                
                devices = []
                for sent, received in result:
                    # Yeni cihaz tespit sistemi ile analiz et
                    device_info = device_detector.analyze_device(received.psrc, received.hwsrc)
                    
                    device = {
                        'ip': device_info.ip,
                        'mac': device_info.mac,
                        'vendor': device_info.vendor,
                        'device_type': device_info.device_type,
                        'confidence': device_info.confidence,
                        'open_ports': device_info.open_ports,
                        'status': 'Aktif',
                        'last_seen': datetime.now().isoformat(),
                        'hostname': device_info.hostname,
                        'services': device_info.services
                    }
                    
                    devices.append(device)
                
                self.devices = devices
                return devices
                
            except PermissionError:
                print("Scapy yetkisi yok, alternatif yöntem kullanılıyor...")
                return self.scan_network_alternative(ip_range)
                
        except Exception as e:
            print(f"Tarama hatası: {str(e)}")
            return self.scan_network_alternative(ip_range)

    def scan_network_alternative(self, ip_range):
        """Alternatif tarama yöntemi (ping/arp tabanlı)"""
        try:
            print("Alternatif tarama yöntemi kullanılıyor...")
            
            # IP aralığını parse et
            if '/' in ip_range:
                base_ip = ip_range.split('/')[0]
                prefix = int(ip_range.split('/')[1])
                
                if prefix == 24:
                    # 192.168.1.0/24 -> 192.168.1.1-254
                    base_parts = base_ip.split('.')
                    base_network = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                    
                    devices = []
                    
                    def scan_host(host_num):
                        ip = f"{base_network}.{host_num}"
                        
                        try:
                            if platform.system() == "Windows":
                                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                                      capture_output=True, text=True, timeout=3)
                            else:
                                result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                                      capture_output=True, text=True, timeout=3)
                            
                            if result.returncode == 0:
                                print(f"Ping başarılı: {ip}")
                                # MAC adresini al
                                mac = self.get_mac_address(ip)
                                if mac:
                                    print(f"MAC bulundu: {ip} -> {mac}")
                                    
                                    # Yeni cihaz tespit sistemi ile analiz et
                                    device_info = device_detector.analyze_device(ip, mac)
                                    
                                    device = {
                                        'ip': device_info.ip,
                                        'mac': device_info.mac,
                                        'vendor': device_info.vendor,
                                        'device_type': device_info.device_type,
                                        'confidence': device_info.confidence,
                                        'open_ports': device_info.open_ports,
                                        'status': 'Aktif',
                                        'last_seen': datetime.now().isoformat(),
                                        'hostname': device_info.hostname,
                                        'services': device_info.services
                                    }
                                    
                                    return device
                        except Exception as e:
                            print(f"Ping hatası {ip}: {str(e)}")
                            pass
                        return None
                    
                    # Paralel tarama
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        future_to_host = {executor.submit(scan_host, i): i for i in range(1, 255)}
                        for future in as_completed(future_to_host):
                            result = future.result()
                            if result:
                                devices.append(result)
                    
                    self.devices = devices
                    return devices
                    
            else:
                print("Geçersiz IP aralığı formatı")
                return []
                
        except Exception as e:
            print(f"Alternatif tarama hatası: {str(e)}")
            return []

    def get_mac_address(self, ip):
        """IP adresinden MAC adresi alır"""
        try:
            if platform.system() == "Windows":
                # Windows için arp -a komutu
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    # MAC adresini regex ile bul
                    mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                    match = re.search(mac_pattern, result.stdout)
                    if match:
                        return match.group(0)
            else:
                # Linux/Mac için arp komutu
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    # MAC adresini regex ile bul
                    mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                    match = re.search(mac_pattern, result.stdout)
                    if match:
                        return match.group(0)
        except Exception as e:
            print(f"MAC adresi alma hatası {ip}: {str(e)}")
        
        return None

    def get_mac_address_alternative(self, ip):
        """Alternatif MAC adresi alma yöntemi"""
        try:
            # getmac komutu (Windows)
            if platform.system() == "Windows":
                result = subprocess.run(['getmac', '/fo', 'csv', '/nh'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split(',')
                            if len(parts) >= 2:
                                mac = parts[1].strip().strip('"')
                                if re.match(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', mac):
                                    return mac
        except:
            pass
        
        return self.get_mac_address(ip)

    def save_results(self, filename=None):
        """Tarama sonuçlarını kaydeder"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.devices, f, ensure_ascii=False, indent=2)
            print(f"Sonuçlar kaydedildi: {filename}")
        except Exception as e:
            print(f"Kaydetme hatası: {str(e)}")

    def export_csv(self, filename=None):
        """Sonuçları CSV formatında dışa aktarır"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'MAC', 'Vendor', 'Device Type', 'Confidence', 'Open Ports', 'Status', 'Last Seen'])
                
                for device in self.devices:
                    writer.writerow([
                        device['ip'],
                        device['mac'],
                        device['vendor'],
                        device['device_type'],
                        device.get('confidence', 0),
                        ', '.join(map(str, device.get('open_ports', []))),
                        device['status'],
                        device['last_seen']
                    ])
            print(f"CSV dosyası oluşturuldu: {filename}")
        except Exception as e:
            print(f"CSV export hatası: {str(e)}")

# Test fonksiyonu
if __name__ == "__main__":
    scanner = IPScannerV2()
    results = scanner.scan_network("192.168.1.0/24")
    print(f"Bulunan cihaz sayısı: {len(results)}")
    
    for device in results:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, Type: {device['device_type']}, Confidence: {device.get('confidence', 0)}%") 