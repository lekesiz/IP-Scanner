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

class IPScannerV2:
    def __init__(self):
        # Cache ve durum değişkenleri
        self.mac_vendor_cache = {}
        self.scanning = False
        self.monitoring = False
        self.monitor_event = Event()
        self.devices = []
        self.known_devices = set()
        
        # Yaygın portlar
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        # MAC prefix'leri için cihaz türü tespiti
        self.device_patterns = {
            'router': ['00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D', '00:1E:40', '00:1F:3A'],
            'apple': ['00:1C:B3', '00:1E:C2', '00:23:12', '00:23:76', '00:25:00', '00:26:08'],
            'samsung': ['00:16:32', '00:19:C5', '00:1B:98', '00:1C:62', '00:1D:25', '00:1E:7D'],
            'huawei': ['00:1E:10', '00:25:9E', '00:26:18', '00:26:4A', '00:27:19', '00:28:6F'],
            'xiaomi': ['00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D', '00:1E:40', '00:1F:3A']
        }
        
        # Web uygulaması için port_scan_var
        self.port_scan_var = type('obj', (object,), {
            'get': lambda self: True,
            'set': lambda self, x: None
        })()
        
    def get_vendor(self, mac):
        """MAC adresinden üretici bilgisi alır"""
        mac_prefix = mac.upper().replace(":", "")[:6]
        if mac_prefix in self.mac_vendor_cache:
            return self.mac_vendor_cache[mac_prefix]
        
        try:
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                vendor = response.text
                self.mac_vendor_cache[mac_prefix] = vendor
                return vendor
        except:
            pass
        return "Bilinmiyor"
    
    def detect_device_type(self, mac, vendor):
        """MAC adresi ve üretici bilgisinden cihaz türünü tespit eder"""
        mac_upper = mac.upper()
        
        # MAC prefix kontrolü
        for device_type, prefixes in self.device_patterns.items():
            for prefix in prefixes:
                if mac_upper.startswith(prefix):
                    if device_type == 'router':
                        return "Router"
                    elif device_type == 'apple':
                        return "Apple Cihazı"
                    elif device_type == 'samsung':
                        return "Samsung Cihazı"
                    elif device_type == 'huawei':
                        return "Huawei Cihazı"
                    elif device_type == 'xiaomi':
                        return "Xiaomi Cihazı"
        
        # Vendor kontrolü
        vendor_lower = vendor.lower()
        if any(keyword in vendor_lower for keyword in ['router', 'gateway', 'modem']):
            return "Router"
        elif any(keyword in vendor_lower for keyword in ['apple', 'mac']):
            return "Apple Cihazı"
        elif any(keyword in vendor_lower for keyword in ['samsung', 'lg']):
            return "Android Cihazı"
        elif any(keyword in vendor_lower for keyword in ['huawei', 'xiaomi', 'oppo', 'vivo']):
            return "Android Cihazı"
        elif any(keyword in vendor_lower for keyword in ['microsoft', 'dell', 'hp', 'lenovo', 'asus']):
            return "Bilgisayar"
        else:
            return "Bilinmeyen Cihaz"
    
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
                    device = {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'vendor': self.get_vendor(received.hwsrc),
                        'device_type': self.detect_device_type(received.hwsrc, self.get_vendor(received.hwsrc)),
                        'open_ports': [],
                        'status': 'Aktif',
                        'last_seen': datetime.now().isoformat()
                    }
                    
                    # Port taraması
                    if self.port_scan_var.get():
                        device['open_ports'] = self.port_scan(device['ip'])
                    
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
        """Alternatif tarama yöntemi - ping ve arp kullanır"""
        try:
            print("Alternatif tarama yöntemi kullanılıyor...")
            
            # IP aralığını parse et
            if '/' in ip_range:
                base_ip = ip_range.split('/')[0]
                prefix = int(ip_range.split('/')[1])
                
                if prefix == 24:  # /24 ağı
                    base_parts = base_ip.split('.')
                    base_network = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                    
                    devices = []
                    
                    # Ping ile cihazları bul
                    def ping_host(host_num):
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
                                    device = {
                                        'ip': ip,
                                        'mac': mac,
                                        'vendor': self.get_vendor(mac),
                                        'device_type': self.detect_device_type(mac, self.get_vendor(mac)),
                                        'open_ports': [],
                                        'status': 'Aktif',
                                        'last_seen': datetime.now().isoformat()
                                    }
                                    
                                    # Port taraması
                                    if self.port_scan_var.get():
                                        device['open_ports'] = self.port_scan(device['ip'])
                                    
                                    return device
                        except Exception as e:
                            print(f"Ping hatası {ip}: {str(e)}")
                            pass
                        return None
                    
                    # Paralel ping taraması
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = [executor.submit(ping_host, i) for i in range(1, 255)]
                        for future in as_completed(futures):
                            result = future.result()
                            if result:
                                devices.append(result)
                    
                    self.devices = devices
                    return devices
                    
            return []
            
        except Exception as e:
            print(f"Alternatif tarama hatası: {str(e)}")
            return []
    
    def get_mac_address(self, ip):
        """IP adresinden MAC adresi alır"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            
            if result.returncode == 0:
                # MAC adresini regex ile bul
                mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                match = re.search(mac_pattern, result.stdout)
                if match:
                    return match.group(0)
        except:
            pass
        return None

# Web uygulaması için uyumlu hale getirildi
# Tkinter bağımlılıkları kaldırıldı 