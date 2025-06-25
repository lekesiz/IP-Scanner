#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json
import requests
import socket
import subprocess
import platform
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class DeviceInfo:
    ip: str
    mac: str
    vendor: str
    device_type: str
    confidence: int
    os_info: Optional[Dict] = None
    services: List[Dict] = None
    hostname: Optional[str] = None
    open_ports: List[int] = None

class ProfessionalDeviceDetector:
    def __init__(self):
        self.mac_vendor_cache = {}
        self.device_signatures = self._load_device_signatures()
        self.port_services = self._load_port_services()
        
    def _load_device_signatures(self) -> Dict:
        """Cihaz imzalarını yükler"""
        return {
            # Router/Modem imzaları
            'router': {
                'mac_prefixes': [
                    '00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D', '00:1E:40', '00:1F:3A',
                    'BC:CF:4F', '00:14:22', '00:16:3E', '00:18:F8', '00:1A:92', '00:1C:7E',
                    '00:1E:58', '00:20:78', '00:22:6B', '00:24:01', '00:26:18', '00:28:6F'
                ],
                'vendor_keywords': ['router', 'gateway', 'modem', 'zyxel', 'tp-link', 'asus', 'netgear'],
                'port_signatures': [80, 443, 22, 23, 8080, 8443],
                'service_keywords': ['http', 'https', 'telnet', 'ssh', 'dhcp', 'dns']
            },
            
            # Apple cihazları
            'apple': {
                'mac_prefixes': [
                    '00:1C:B3', '00:1E:C2', '00:23:12', '00:23:76', '00:25:00', '00:26:08',
                    '00:26:B0', '00:26:BB', '00:27:84', '00:28:6F', '00:2A:10', '00:2A:6A',
                    '00:2B:03', '00:2C:BE', '00:2D:76', '00:2E:20', '00:30:65', '00:32:5A'
                ],
                'vendor_keywords': ['apple', 'mac', 'iphone', 'ipad'],
                'port_signatures': [22, 80, 443, 548, 631, 3283, 5900],
                'service_keywords': ['ssh', 'http', 'https', 'afp', 'ipp', 'vnc']
            },
            
            # Samsung cihazları
            'samsung': {
                'mac_prefixes': [
                    '00:16:32', '00:19:C5', '00:1B:98', '00:1C:62', '00:1D:25', '00:1E:7D',
                    '00:20:DB', '00:23:39', '00:25:38', '00:26:18', '00:27:19', '00:28:6F',
                    '00:2A:10', '00:2B:03', '00:2C:BE', '00:2D:76', '00:2E:20', '00:30:65'
                ],
                'vendor_keywords': ['samsung', 'lg', 'android'],
                'port_signatures': [22, 80, 443, 8080],
                'service_keywords': ['ssh', 'http', 'https']
            },
            
            # Huawei cihazları
            'huawei': {
                'mac_prefixes': [
                    '00:1E:10', '00:25:9E', '00:26:18', '00:26:4A', '00:27:19', '00:28:6F',
                    '00:2A:10', '00:2B:03', '00:2C:BE', '00:2D:76', '00:2E:20', '00:30:65'
                ],
                'vendor_keywords': ['huawei', 'honor'],
                'port_signatures': [22, 80, 443, 8080],
                'service_keywords': ['ssh', 'http', 'https']
            },
            
            # Windows bilgisayarlar
            'windows': {
                'mac_prefixes': [
                    '00:0C:29', '00:05:69', '00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D',
                    '00:1E:40', '00:1F:3A', '00:50:56', '00:0D:3A', '00:16:3E', '00:18:F8'
                ],
                'vendor_keywords': ['microsoft', 'dell', 'hp', 'lenovo', 'asus', 'acer'],
                'port_signatures': [22, 80, 443, 135, 139, 445, 3389],
                'service_keywords': ['ssh', 'http', 'https', 'netbios', 'rdp']
            },
            
            # Linux bilgisayarlar
            'linux': {
                'mac_prefixes': [
                    '00:0C:29', '00:05:69', '00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D',
                    '00:1E:40', '00:1F:3A', '00:50:56', '00:0D:3A', '00:16:3E', '00:18:F8'
                ],
                'vendor_keywords': ['linux', 'ubuntu', 'debian', 'centos', 'redhat'],
                'port_signatures': [22, 80, 443, 21, 23, 25, 53],
                'service_keywords': ['ssh', 'http', 'https', 'ftp', 'telnet', 'smtp', 'dns']
            },
            
            # Yazıcılar
            'printer': {
                'mac_prefixes': [
                    '00:00:74', '00:00:0C', '00:00:0E', '00:00:0F', '00:00:10', '00:00:11',
                    '00:00:12', '00:00:13', '00:00:14', '00:00:15', '00:00:16', '00:00:17'
                ],
                'vendor_keywords': ['hp', 'canon', 'epson', 'brother', 'samsung', 'lexmark'],
                'port_signatures': [80, 443, 631, 9100, 515, 631],
                'service_keywords': ['http', 'https', 'ipp', 'lpr', 'cups']
            },
            
            # IP Kameralar
            'camera': {
                'mac_prefixes': [
                    '00:0C:29', '00:05:69', '00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D'
                ],
                'vendor_keywords': ['hikvision', 'dahua', 'axis', 'foscam', 'd-link'],
                'port_signatures': [80, 443, 554, 8000, 8080, 9000],
                'service_keywords': ['http', 'https', 'rtsp', 'rtp']
            }
        }
    
    def _load_port_services(self) -> Dict:
        """Port-servis eşleştirmelerini yükler"""
        return {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 548: 'AFP',
            631: 'IPP', 993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            9100: 'Printer', 3389: 'RDP', 5900: 'VNC', 554: 'RTSP', 8000: 'HTTP-Alt',
            9000: 'HTTP-Alt', 515: 'LPR', 3283: 'Net Assistant'
        }
    
    def get_vendor_from_api(self, mac: str) -> str:
        """MAC adresinden üretici bilgisini API'den alır"""
        mac_prefix = mac.upper().replace(":", "")[:6]
        
        if mac_prefix in self.mac_vendor_cache:
            return self.mac_vendor_cache[mac_prefix]
        
        try:
            # Önce yerel cache'i kontrol et
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=3)
            
            if response.status_code == 200:
                vendor = response.text.strip()
                self.mac_vendor_cache[mac_prefix] = vendor
                return vendor
                
        except Exception as e:
            print(f"Vendor API error for {mac}: {str(e)}")
        
        return "Bilinmiyor"
    
    def detect_device_type(self, mac: str, vendor: str, open_ports: List[int] = None, 
                          services: List[Dict] = None) -> Tuple[str, int]:
        """Gelişmiş cihaz türü tespiti"""
        mac_upper = mac.upper()
        vendor_lower = vendor.lower()
        confidence = 0
        detected_type = "Bilinmeyen Cihaz"
        
        # Her cihaz türü için skor hesapla
        device_scores = {}
        
        for device_type, signatures in self.device_signatures.items():
            score = 0
            
            # MAC prefix kontrolü
            for prefix in signatures['mac_prefixes']:
                if mac_upper.startswith(prefix):
                    score += 30
                    break
            
            # Vendor keyword kontrolü
            for keyword in signatures['vendor_keywords']:
                if keyword in vendor_lower:
                    score += 25
                    break
            
            # Port signature kontrolü
            if open_ports:
                for port in signatures['port_signatures']:
                    if port in open_ports:
                        score += 15
                        break
            
            # Service keyword kontrolü
            if services:
                service_names = [s.get('service', '').lower() for s in services]
                for keyword in signatures['service_keywords']:
                    if any(keyword in name for name in service_names):
                        score += 20
                        break
            
            device_scores[device_type] = score
        
        # En yüksek skorlu cihaz türünü seç
        if device_scores:
            best_type = max(device_scores, key=device_scores.get)
            best_score = device_scores[best_type]
            
            if best_score >= 30:
                detected_type = self._get_device_type_name(best_type)
                confidence = min(best_score, 95)
        
        return detected_type, confidence
    
    def _get_device_type_name(self, device_type: str) -> str:
        """Cihaz türü adını döndürür"""
        type_names = {
            'router': 'Router/Modem',
            'apple': 'Apple Cihazı',
            'samsung': 'Samsung Cihazı',
            'huawei': 'Huawei Cihazı',
            'windows': 'Windows Bilgisayar',
            'linux': 'Linux Bilgisayar',
            'printer': 'Yazıcı',
            'camera': 'IP Kamera'
        }
        return type_names.get(device_type, 'Bilinmeyen Cihaz')
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """IP adresinden hostname alır"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname if hostname != ip else None
        except:
            return None
    
    def scan_ports_fast(self, ip: str, ports: List[int] = None) -> List[int]:
        """Hızlı port taraması"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 548, 631, 993, 995, 8080, 8443]
        
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
        
        # Paralel port taraması
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def get_port_services(self, open_ports: List[int]) -> List[Dict]:
        """Açık portlardan servis bilgilerini alır"""
        services = []
        for port in open_ports:
            service_name = self.port_services.get(port, f'Port {port}')
            services.append({
                'port': port,
                'service': service_name,
                'protocol': 'tcp'
            })
        return services
    
    def analyze_device(self, ip: str, mac: str) -> DeviceInfo:
        """Tek bir cihazı analiz eder"""
        # Vendor bilgisini al
        vendor = self.get_vendor_from_api(mac)
        
        # Hostname al
        hostname = self.get_hostname(ip)
        
        # Port taraması yap
        open_ports = self.scan_ports_fast(ip)
        services = self.get_port_services(open_ports)
        
        # Cihaz türünü tespit et
        device_type, confidence = self.detect_device_type(mac, vendor, open_ports, services)
        
        return DeviceInfo(
            ip=ip,
            mac=mac,
            vendor=vendor,
            device_type=device_type,
            confidence=confidence,
            services=services,
            hostname=hostname,
            open_ports=open_ports
        )
    
    def analyze_devices_batch(self, devices: List[Dict]) -> List[DeviceInfo]:
        """Toplu cihaz analizi"""
        results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_device = {
                executor.submit(self.analyze_device, device['ip'], device['mac']): device 
                for device in devices
            }
            
            for future in as_completed(future_to_device):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"Device analysis error: {str(e)}")
        
        return results

# Global instance
device_detector = ProfessionalDeviceDetector() 