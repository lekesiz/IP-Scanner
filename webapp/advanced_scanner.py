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

class AdvancedScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.device_info = {}
        self.os_signatures = {
            'Windows': ['Windows', 'Microsoft', 'MS'],
            'Linux': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'RedHat'],
            'macOS': ['macOS', 'Mac', 'Apple'],
            'iOS': ['iOS', 'iPhone', 'iPad'],
            'Android': ['Android', 'Samsung', 'Huawei', 'Xiaomi']
        }
        
    def nmap_os_detection(self, ip):
        """Nmap ile OS tespiti yapar"""
        try:
            # Nmap OS detection scan
            result = self.nm.scan(ip, arguments='-O --osscan-guess')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                
                # OS bilgisi
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
            print(f"Nmap OS detection error for {ip}: {str(e)}")
        
        return None
    
    def nmap_service_detection(self, ip):
        """Nmap ile servis tespiti yapar"""
        try:
            # Nmap service detection scan
            result = self.nm.scan(ip, arguments='-sV --version-intensity 5')
            
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
            print(f"Nmap service detection error for {ip}: {str(e)}")
        
        return []
    
    def dhcp_discovery(self, ip_range):
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
            print(f"DHCP discovery error: {str(e)}")
        
        return dhcp_devices
    
    def netbios_discovery(self, ip):
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
            print(f"NetBIOS discovery error for {ip}: {str(e)}")
        
        return None
    
    def mdns_discovery(self, ip):
        """mDNS (Bonjour) protokolü ile cihaz tespiti"""
        try:
            # mDNS Query for device info
            mdns_query = Ether(dst="01:00:5e:00:00:fb") / \
                        IP(dst="224.0.0.251") / \
                        UDP(dport=5353) / \
                        DNS(rd=1, qd=DNSQR(qname="local", qtype="PTR"))
            
            responses = srp(mdns_query, timeout=3, verbose=0)[0]
            
            mdns_devices = []
            for _, response in responses:
                if DNS in response:
                    dns_data = response[DNS]
                    
                    if dns_data.an:
                        for answer in dns_data.an:
                            mdns_devices.append({
                                'ip': ip,
                                'protocol': 'mDNS',
                                'hostname': str(answer.rdata),
                                'mac': response[Ether].src
                            })
            
            return mdns_devices
            
        except Exception as e:
            print(f"mDNS discovery error for {ip}: {str(e)}")
        
        return []
    
    def http_fingerprinting(self, ip, port=80):
        """HTTP başlıkları ile cihaz tespiti"""
        try:
            # HTTP GET request
            http_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                          IP(dst=ip) / \
                          TCP(dport=port) / \
                          HTTPRequest(
                              Host=ip,
                              User_Agent="Mozilla/5.0 (compatible; IPScanner/3.3)"
                          )
            
            responses = srp(http_request, timeout=3, verbose=0)[0]
            
            for _, response in responses:
                if HTTPResponse in response:
                    http_data = response[HTTPResponse]
                    
                    server_header = http_data.getfieldval('Server', 'Unknown')
                    
                    return {
                        'ip': ip,
                        'protocol': 'HTTP',
                        'server': server_header,
                        'port': port,
                        'mac': response[Ether].src
                    }
                    
        except Exception as e:
            print(f"HTTP fingerprinting error for {ip}: {str(e)}")
        
        return None
    
    def detect_device_type_advanced(self, ip, mac, vendor, os_info=None, services=None):
        """Gelişmiş cihaz türü tespiti"""
        device_type = "Bilinmeyen Cihaz"
        confidence = 0
        
        # OS bilgisine göre tespit
        if os_info and os_info.get('os_name'):
            os_name = os_info['os_name'].lower()
            
            if any(keyword in os_name for keyword in ['windows', 'microsoft']):
                device_type = "Windows Cihazı"
                confidence = 80
            elif any(keyword in os_name for keyword in ['linux', 'ubuntu', 'debian']):
                device_type = "Linux Cihazı"
                confidence = 80
            elif any(keyword in os_name for keyword in ['macos', 'mac', 'apple']):
                device_type = "Apple Cihazı"
                confidence = 85
            elif any(keyword in os_name for keyword in ['ios', 'iphone', 'ipad']):
                device_type = "iOS Cihazı"
                confidence = 90
            elif any(keyword in os_name for keyword in ['android']):
                device_type = "Android Cihazı"
                confidence = 85
        
        # Servis bilgisine göre tespit
        if services:
            service_names = [service['service'].lower() for service in services]
            
            # Router/Modem tespiti
            if any(service in service_names for service in ['http', 'https', 'telnet', 'ssh']):
                if any(keyword in vendor.lower() for keyword in ['router', 'modem', 'gateway']):
                    device_type = "Router/Modem"
                    confidence = 95
                elif any(service in service_names for service in ['dhcp', 'dns']):
                    device_type = "Router/Modem"
                    confidence = 90
            
            # Web sunucu tespiti
            if 'http' in service_names or 'https' in service_names:
                if 'apache' in str(services).lower() or 'nginx' in str(services).lower():
                    device_type = "Web Sunucu"
                    confidence = 85
            
            # FTP sunucu tespiti
            if 'ftp' in service_names:
                device_type = "FTP Sunucu"
                confidence = 80
        
        # MAC adresine göre tespit
        mac_upper = mac.upper()
        if mac_upper.startswith(('00:1A:11', '00:1B:63', '00:1C:C0')):
            device_type = "Router"
            confidence = 85
        elif mac_upper.startswith(('00:1C:B3', '00:1E:C2', '00:23:12')):
            device_type = "Apple Cihazı"
            confidence = 90
        elif mac_upper.startswith(('00:16:32', '00:19:C5', '00:1B:98')):
            device_type = "Samsung Cihazı"
            confidence = 85
        
        return {
            'device_type': device_type,
            'confidence': confidence,
            'os_info': os_info,
            'services': services
        }
    
    def comprehensive_scan(self, ip_range, enable_nmap=True, enable_dhcp=True, enable_netbios=True, enable_mdns=True):
        """Kapsamlı ağ taraması"""
        results = []
        
        # Temel ARP taraması
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        arp_results = srp(packet, timeout=3, verbose=0)[0]
        
        for _, received in arp_results:
            ip = received.psrc
            mac = received.hwsrc
            
            device_info = {
                'ip': ip,
                'mac': mac,
                'discovery_methods': ['ARP'],
                'os_info': None,
                'services': [],
                'additional_info': {}
            }
            
            # Nmap taraması (isteğe bağlı)
            if enable_nmap:
                try:
                    # OS detection
                    os_info = self.nmap_os_detection(ip)
                    if os_info:
                        device_info['os_info'] = os_info
                        device_info['discovery_methods'].append('Nmap OS')
                    
                    # Service detection
                    services = self.nmap_service_detection(ip)
                    if services:
                        device_info['services'] = services
                        device_info['discovery_methods'].append('Nmap Services')
                        
                except Exception as e:
                    print(f"Nmap scan error for {ip}: {str(e)}")
            
            # NetBIOS taraması
            if enable_netbios:
                try:
                    netbios_info = self.netbios_discovery(ip)
                    if netbios_info:
                        device_info['additional_info']['netbios'] = netbios_info
                        device_info['discovery_methods'].append('NetBIOS')
                except Exception as e:
                    print(f"NetBIOS scan error for {ip}: {str(e)}")
            
            # mDNS taraması
            if enable_mdns:
                try:
                    mdns_info = self.mdns_discovery(ip)
                    if mdns_info:
                        device_info['additional_info']['mdns'] = mdns_info
                        device_info['discovery_methods'].append('mDNS')
                except Exception as e:
                    print(f"mDNS scan error for {ip}: {str(e)}")
            
            # HTTP fingerprinting
            try:
                http_info = self.http_fingerprinting(ip)
                if http_info:
                    device_info['additional_info']['http'] = http_info
                    device_info['discovery_methods'].append('HTTP')
            except Exception as e:
                print(f"HTTP fingerprinting error for {ip}: {str(e)}")
            
            results.append(device_info)
        
        # DHCP taraması (isteğe bağlı)
        if enable_dhcp:
            try:
                dhcp_devices = self.dhcp_discovery(ip_range)
                for dhcp_device in dhcp_devices:
                    # DHCP cihazını mevcut sonuçlarla birleştir
                    existing_device = next((d for d in results if d['ip'] == dhcp_device['ip']), None)
                    if existing_device:
                        existing_device['additional_info']['dhcp'] = dhcp_device
                        if 'DHCP' not in existing_device['discovery_methods']:
                            existing_device['discovery_methods'].append('DHCP')
                    else:
                        # Yeni DHCP cihazı ekle
                        dhcp_device['discovery_methods'] = ['DHCP']
                        dhcp_device['os_info'] = None
                        dhcp_device['services'] = []
                        dhcp_device['additional_info'] = {}
                        results.append(dhcp_device)
            except Exception as e:
                print(f"DHCP scan error: {str(e)}")
        
        return results

def create_advanced_scanner():
    """Gelişmiş tarayıcı örneği oluşturur"""
    return AdvancedScanner() 