import nmap
import socket
import struct
import time
import threading
from scapy.all import *
from scapy.layers.http import HTTPRequest
import subprocess
import platform
import json
import os
import logging
from typing import Dict, List, Optional, Tuple
from constants import COMMON_PORTS, DEFAULT_SCAN_TIMEOUT, DEFAULT_PORT_TIMEOUT

# Logging konfigürasyonu
logger = logging.getLogger(__name__)

class AdvancedScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        # Nmap programının path'ini manuel olarak belirt
        try:
            self.nm.scan('127.0.0.1', arguments='-sn')  # Test scan
        except Exception as e:
            logger.warning(f"Nmap initialization failed: {e}")
        
        self.device_info = {}
        self.os_signatures = {
            'Windows': ['Windows', 'Microsoft', 'MS'],
            'Linux': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'RedHat'],
            'macOS': ['macOS', 'Mac', 'Apple'],
            'iOS': ['iOS', 'iPhone', 'iPad'],
            'Android': ['Android', 'Samsung', 'Huawei', 'Xiaomi']
        }
        
    def nmap_os_detection(self, ip: str) -> Optional[Dict]:
        """Nmap ile OS tespiti yapar"""
        try:
            # Önce basit port taraması yap
            result = self.nm.scan(ip, arguments='-sS -T4 --max-retries 1')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                
                # OS bilgisi (root yetkisi olmadan)
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_info = host_info['osmatch'][0]
                    return {
                        'os_name': os_info.get('name', 'Unknown'),
                        'os_accuracy': os_info.get('accuracy', '0'),
                        'os_line': os_info.get('osline', 'Unknown')
                    }
                
                # OS guess
                if 'osguess' in host_info and host_info['osguess']:
                    os_guess = host_info['osguess'][0]
                    return {
                        'os_name': os_guess.get('name', 'Unknown'),
                        'os_accuracy': os_guess.get('accuracy', '0'),
                        'os_line': os_guess.get('osline', 'Unknown')
                    }
                    
        except Exception as e:
            logger.error(f"Nmap OS detection error for {ip}: {str(e)}")
            # Root yetkisi yoksa basit tespit yap
            return self.simple_os_detection(ip)
        
        return None
    
    def simple_os_detection(self, ip: str) -> Optional[Dict]:
        """Basit OS tespiti - root yetkisi gerektirmez"""
        try:
            # Basit port taraması
            result = self.nm.scan(ip, arguments='-sT -T4 --max-retries 1')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                
                # Port'lara göre OS tahmini
                open_ports = []
                if 'tcp' in host_info:
                    open_ports = [port for port, info in host_info['tcp'].items() if info['state'] == 'open']
                
                # Port'lara göre OS tahmini
                if 22 in open_ports and 80 in open_ports:
                    return {
                        'os_name': 'Linux/Unix',
                        'os_accuracy': '60',
                        'os_line': 'Linux/Unix Server'
                    }
                elif 3389 in open_ports:
                    return {
                        'os_name': 'Windows',
                        'os_accuracy': '70',
                        'os_line': 'Windows Server'
                    }
                elif 22 in open_ports:
                    return {
                        'os_name': 'Linux/Unix',
                        'os_accuracy': '65',
                        'os_line': 'Linux/Unix System'
                    }
                elif 80 in open_ports or 443 in open_ports:
                    return {
                        'os_name': 'Unknown',
                        'os_accuracy': '50',
                        'os_line': 'Web Server'
                    }
                    
        except Exception as e:
            logger.error(f"Simple OS detection error for {ip}: {str(e)}")
        
        return None
    
    def nmap_service_detection(self, ip: str) -> List[Dict]:
        """Nmap ile servis tespiti yapar"""
        try:
            # Nmap service detection scan - daha basit parametreler
            result = self.nm.scan(ip, arguments='-sV --version-intensity 3 --max-retries 1')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                services = []
                
                if 'tcp' in host_info:
                    for port, port_info in host_info['tcp'].items():
                        if port_info['state'] == 'open':
                            services.append({
                                'port': port,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            })
                
                return services
                
        except Exception as e:
            logger.error(f"Nmap service detection error for {ip}: {str(e)}")
        
        return []
    
    def dhcp_discovery(self, ip_range: str) -> List[Dict]:
        """DHCP protokolü ile cihaz tespiti"""
        dhcp_devices = []
        
        try:
            # DHCP Discover paketi
            dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                          IP(src="0.0.0.0", dst="255.255.255.255") / \
                          UDP(sport=68, dport=67) / \
                          BOOTP(chaddr=RandMAC(), giaddr="0.0.0.0") / \
                          DHCP(options=[("message-type", "discover"), "end"])
            
            # DHCP paketlerini yakala
            responses = srp(dhcp_discover, timeout=5, verbose=0)[0]
            
            for _, response in responses:
                if DHCP in response:
                    dhcp_options = dict(response[DHCP].options)
                    
                    if 'yiaddr' in dhcp_options:
                        device_ip = dhcp_options['yiaddr']
                        device_mac = response[Ether].src
                        
                        dhcp_devices.append({
                            'ip': device_ip,
                            'mac': device_mac,
                            'protocol': 'DHCP',
                            'hostname': dhcp_options.get('hostname', 'Unknown')
                        })
                        
        except Exception as e:
            logger.error(f"DHCP discovery error: {str(e)}")
        
        return dhcp_devices
    
    def netbios_discovery(self, ip: str) -> Optional[Dict]:
        """NetBIOS protokolü ile cihaz tespiti"""
        try:
            # NetBIOS Name Query
            netbios_query = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                           IP(dst=ip) / \
                           UDP(dport=137) / \
                           NBTDatagram() / \
                           NBTDatagramQuery()
            
            responses = srp(netbios_query, timeout=3, verbose=0)[0]
            
            for _, response in responses:
                if NBTDatagram in response:
                    netbios_data = response[NBTDatagram]
                    
                    return {
                        'ip': ip,
                        'protocol': 'NetBIOS',
                        'hostname': str(netbios_data),
                        'mac': response[Ether].src
                    }
                    
        except Exception as e:
            logger.error(f"NetBIOS discovery error for {ip}: {str(e)}")
        
        return None
    
    def mdns_discovery(self, ip: str) -> Optional[Dict]:
        """mDNS (Bonjour) protokolü ile cihaz tespiti"""
        try:
            # mDNS Query for device info
            mdns_query = Ether(dst="01:00:5e:00:00:fb") / \
                        IP(dst="224.0.0.251") / \
                        UDP(dport=5353) / \
                        DNS(rd=1, qd=DNSQR(qname="local"))
            
            responses = srp(mdns_query, timeout=3, verbose=0)[0]
            
            for _, response in responses:
                if DNS in response:
                    dns_data = response[DNS]
                    
                    return {
                        'ip': ip,
                        'protocol': 'mDNS',
                        'hostname': str(dns_data.qd.qname) if dns_data.qd else 'Unknown',
                        'mac': response[Ether].src
                    }
                    
        except Exception as e:
            logger.error(f"mDNS discovery error for {ip}: {str(e)}")
        
        return None
    
    def http_fingerprinting(self, ip: str, port: int = 80) -> Optional[Dict]:
        """HTTP fingerprinting ile servis tespiti"""
        try:
            # HTTP HEAD request
            http_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                          IP(dst=ip) / \
                          TCP(dport=port) / \
                          HTTPRequest(
                              Method=b'HEAD',
                              Path=b'/',
                              Http_Version=b'HTTP/1.1',
                              Host=ip.encode(),
                              User_Agent=b'IP-Scanner/4.0'
                          )
            
            responses = srp(http_request, timeout=3, verbose=0)[0]
            
            for _, response in responses:
                if HTTP in response:
                    http_data = response[HTTP]
                    
                    return {
                        'ip': ip,
                        'port': port,
                        'protocol': 'HTTP',
                        'server': http_data.get_field('Server', 'Unknown'),
                        'content_type': http_data.get_field('Content-Type', 'Unknown')
                    }
                    
        except Exception as e:
            logger.error(f"HTTP fingerprinting error for {ip}: {str(e)}")
        
        return None
    
    def detect_device_type_advanced(self, ip: str, mac: str, vendor: str, 
                                   os_info: Optional[Dict] = None, 
                                   services: Optional[List[Dict]] = None) -> Tuple[str, int]:
        """Gelişmiş cihaz türü tespiti"""
        confidence = 0
        device_type = "Bilinmeyen Cihaz"
        
        # MAC prefix kontrolü
        mac_upper = mac.upper()
        for prefix in MAC_VENDOR_PREFIXES.get('router', []):
            if mac_upper.startswith(prefix):
                confidence += 30
                device_type = "Router/Modem"
                break
        
        # Vendor keyword kontrolü
        vendor_lower = vendor.lower()
        if any(keyword in vendor_lower for keyword in ['router', 'gateway', 'modem']):
            confidence += 25
            device_type = "Router/Modem"
        
        # OS bilgisi kontrolü
        if os_info:
            os_name = os_info.get('os_name', '').lower()
            if 'windows' in os_name:
                confidence += 20
                device_type = "Windows Bilgisayar"
            elif 'linux' in os_name or 'ubuntu' in os_name:
                confidence += 20
                device_type = "Linux Bilgisayar"
            elif 'macos' in os_name or 'apple' in os_name:
                confidence += 20
                device_type = "Apple Cihaz"
        
        # Servis kontrolü
        if services:
            service_names = [s.get('service', '').lower() for s in services]
            if 'http' in service_names and 'ssh' in service_names:
                confidence += 15
                device_type = "Sunucu"
            elif 'printer' in service_names or 'ipp' in service_names:
                confidence += 20
                device_type = "Yazıcı"
        
        return device_type, min(confidence, 100)
    
    def comprehensive_scan(self, ip_range: str, enable_nmap: bool = True, 
                          enable_dhcp: bool = True, enable_netbios: bool = True, 
                          enable_mdns: bool = True) -> List[Dict]:
        """Kapsamlı tarama - Tüm yöntemleri kullanır"""
        all_devices = []
        
        try:
            # IP aralığını parse et
            network = ipaddress.IPv4Network(ip_range, strict=False)
            
            # Her IP için tarama yap
            for ip in network.hosts():
                ip_str = str(ip)
                device_info = {
                    'ip': ip_str,
                    'mac': '',
                    'vendor': 'Bilinmiyor',
                    'device_type': 'Bilinmeyen',
                    'confidence': 0,
                    'os_info': None,
                    'services': [],
                    'protocols': []
                }
                
                # Nmap taraması
                if enable_nmap:
                    try:
                        device_info['os_info'] = self.nmap_os_detection(ip_str)
                        device_info['services'] = self.nmap_service_detection(ip_str)
                        device_info['protocols'].append('Nmap')
                    except Exception as e:
                        logger.error(f"Nmap scan error for {ip_str}: {str(e)}")
                
                # NetBIOS taraması
                if enable_netbios:
                    try:
                        netbios_info = self.netbios_discovery(ip_str)
                        if netbios_info:
                            device_info['mac'] = netbios_info['mac']
                            device_info['hostname'] = netbios_info['hostname']
                            device_info['protocols'].append('NetBIOS')
                    except Exception as e:
                        logger.error(f"NetBIOS scan error for {ip_str}: {str(e)}")
                
                # mDNS taraması
                if enable_mdns:
                    try:
                        mdns_info = self.mdns_discovery(ip_str)
                        if mdns_info:
                            if not device_info['mac']:
                                device_info['mac'] = mdns_info['mac']
                            if not device_info.get('hostname'):
                                device_info['hostname'] = mdns_info['hostname']
                            device_info['protocols'].append('mDNS')
                    except Exception as e:
                        logger.error(f"mDNS scan error for {ip_str}: {str(e)}")
                
                # HTTP fingerprinting
                try:
                    http_info = self.http_fingerprinting(ip_str, 80)
                    if http_info:
                        device_info['services'].append(http_info)
                        device_info['protocols'].append('HTTP')
                except Exception as e:
                    logger.error(f"HTTP fingerprinting error for {ip_str}: {str(e)}")
                
                # Cihaz türü tespiti
                if device_info['mac']:
                    device_type, confidence = self.detect_device_type_advanced(
                        ip_str, device_info['mac'], device_info['vendor'],
                        device_info['os_info'], device_info['services']
                    )
                    device_info['device_type'] = device_type
                    device_info['confidence'] = confidence
                
                all_devices.append(device_info)
                
        except Exception as e:
            logger.error(f"Comprehensive scan error: {str(e)}")
        
        return all_devices
    
    def comprehensive_scan_alternative(self, ip_range: str, enable_nmap: bool = True, 
                                     enable_dhcp: bool = True, enable_netbios: bool = True, 
                                     enable_mdns: bool = True) -> List[Dict]:
        """Alternatif kapsamlı tarama - Scapy yetkisi yoksa"""
        all_devices = []
        
        try:
            # IP aralığını parse et
            network = ipaddress.IPv4Network(ip_range, strict=False)
            total_hosts = len(list(network.hosts()))
            
            logger.info(f"Alternative comprehensive scan starting: {ip_range} ({total_hosts} hosts)")
            
            # Thread pool ile paralel tarama
            with ThreadPoolExecutor(max_workers=10) as executor:
                def scan_host(host_num):
                    try:
                        ip = str(network[host_num + 1])  # +1 because network[0] is network address
                        
                        device_info = {
                            'ip': ip,
                            'mac': '',
                            'vendor': 'Bilinmiyor',
                            'device_type': 'Bilinmeyen',
                            'confidence': 0,
                            'os_info': None,
                            'services': [],
                            'protocols': []
                        }
                        
                        # Ping ile cihaz kontrolü
                        if self.ping_host(ip):
                            device_info['status'] = 'Aktif'
                            
                            # MAC adresi alma
                            mac = self.get_mac_address_alternative(ip)
                            if mac:
                                device_info['mac'] = mac
                                device_info['vendor'] = self.get_vendor_from_mac(mac)
                            
                            # Port tarama
                            open_ports = self.scan_ports_fast(ip)
                            device_info['open_ports'] = open_ports
                            
                            # HTTP fingerprinting
                            if 80 in open_ports:
                                http_info = self.http_fingerprinting_alternative(ip, 80)
                                if http_info:
                                    device_info['services'].append(http_info)
                            
                            # Cihaz türü tespiti
                            if device_info['mac']:
                                device_type, confidence = self.detect_device_type_advanced(
                                    ip, device_info['mac'], device_info['vendor'],
                                    device_info['os_info'], device_info['services']
                                )
                                device_info['device_type'] = device_type
                                device_info['confidence'] = confidence
                            
                            return device_info
                        
                        return None
                        
                    except Exception as e:
                        logger.error(f"Host scan error for {ip}: {str(e)}")
                        return None
                
                # Paralel tarama
                futures = [executor.submit(scan_host, i) for i in range(total_hosts)]
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            all_devices.append(result)
                    except Exception as e:
                        logger.error(f"Future result error: {str(e)}")
            
            logger.info(f"Alternative comprehensive scan completed: {len(all_devices)} devices found")
            
        except Exception as e:
            logger.error(f"Alternative comprehensive scan error: {str(e)}")
        
        return all_devices
    
    def ping_host(self, ip: str) -> bool:
        """Basit ping kontrolü"""
        try:
            if platform.system().lower() == "windows":
                command = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                command = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def get_mac_address_alternative(self, ip: str) -> Optional[str]:
        """Alternatif MAC adresi alma yöntemi"""
        try:
            # ARP tablosundan MAC adresi alma
            if platform.system().lower() == "windows":
                command = ['arp', '-a', ip]
            else:
                command = ['arp', '-n', ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # MAC adresi regex ile çıkar
                import re
                mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                match = re.search(mac_pattern, result.stdout)
                if match:
                    return match.group(0)
            
            return None
            
        except Exception:
            return None
    
    def get_vendor_from_mac(self, mac: str) -> str:
        """MAC adresinden vendor bilgisi alma"""
        try:
            # Basit vendor lookup
            mac_prefix = mac.upper().replace(":", "")[:6]
            
            # Yerel vendor database kontrolü
            vendor_map = {
                '000C29': 'VMware',
                '001A11': 'Google',
                '001B63': 'Apple',
                '001CC0': 'Cisco',
                'BCF4F': 'Dell',
                '001422': 'Dell',
                '00163E': 'Hewlett-Packard',
                '0018F8': 'Cisco',
                '001A92': 'Apple',
                '001C7E': 'Cisco'
            }
            
            return vendor_map.get(mac_prefix, 'Bilinmiyor')
            
        except Exception:
            return 'Bilinmiyor'
    
    def scan_ports_fast(self, ip: str, ports: Optional[List[int]] = None) -> List[int]:
        """Hızlı port tarama"""
        if ports is None:
            ports = COMMON_PORTS
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(DEFAULT_PORT_TIMEOUT)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None
        
        # Paralel port tarama
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception:
                    continue
        
        return open_ports
    
    def http_fingerprinting_alternative(self, ip: str, port: int = 80) -> Optional[Dict]:
        """Alternatif HTTP fingerprinting"""
        try:
            import requests
            
            url = f"http://{ip}:{port}"
            response = requests.head(url, timeout=3, allow_redirects=False)
            
            return {
                'ip': ip,
                'port': port,
                'protocol': 'HTTP',
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'status_code': response.status_code
            }
            
        except Exception as e:
            logger.error(f"Alternative HTTP fingerprinting error for {ip}: {str(e)}")
            return None

def create_advanced_scanner() -> AdvancedScanner:
    """Advanced scanner instance oluştur"""
    return AdvancedScanner() 