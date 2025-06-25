import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Thread, Event
import time
import json
import csv
from datetime import datetime
from scapy.all import ARP, Ether, srp, sr, IP, TCP, ICMP
import requests
import socket
import re

class IPScannerV2:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IP Scanner V2 - Gelişmiş Ağ Tarama")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
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
        
        self.setup_ui()
        
    def setup_ui(self):
        # Ana frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Grid konfigürasyonu
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Başlık
        title_label = ttk.Label(main_frame, text="IP Scanner V2 - Gelişmiş Ağ Tarama", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Kontrol paneli
        control_frame = ttk.LabelFrame(main_frame, text="Kontrol Paneli", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        control_frame.columnconfigure(1, weight=1)
        
        # IP Aralığı
        ttk.Label(control_frame, text="IP Aralığı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.ip_range_var = tk.StringVar(value="192.168.1.0/24")
        ip_entry = ttk.Entry(control_frame, textvariable=self.ip_range_var, width=20)
        ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Port tarama seçeneği
        self.port_scan_var = tk.BooleanVar(value=True)
        port_check = ttk.Checkbutton(control_frame, text="Port Tarama", variable=self.port_scan_var)
        port_check.grid(row=0, column=2, padx=(0, 10))
        
        # Gerçek zamanlı izleme
        self.monitor_var = tk.BooleanVar(value=False)
        monitor_check = ttk.Checkbutton(control_frame, text="Gerçek Zamanlı İzleme", 
                                       variable=self.monitor_var, command=self.toggle_monitoring)
        monitor_check.grid(row=0, column=3, padx=(0, 10))
        
        # Butonlar
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=(10, 0))
        
        self.scan_btn = ttk.Button(button_frame, text="Taramayı Başlat", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.save_btn = ttk.Button(button_frame, text="Sonuçları Kaydet", command=self.save_results)
        self.save_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.clear_btn = ttk.Button(button_frame, text="Temizle", command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Filtre paneli
        filter_frame = ttk.LabelFrame(main_frame, text="Filtreler", padding="10")
        filter_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Cihaz türü filtresi
        ttk.Label(filter_frame, text="Cihaz Türü:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.device_filter_var = tk.StringVar(value="Tümü")
        device_filter_combo = ttk.Combobox(filter_frame, textvariable=self.device_filter_var, 
                                          values=["Tümü", "Router", "Bilgisayar", "Mobil", "IoT"], 
                                          state="readonly", width=15)
        device_filter_combo.grid(row=0, column=1, padx=(0, 10))
        device_filter_combo.bind('<<ComboboxSelected>>', self.apply_filters)
        
        # IP filtresi
        ttk.Label(filter_frame, text="IP Filtresi:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.ip_filter_var = tk.StringVar()
        ip_filter_entry = ttk.Entry(filter_frame, textvariable=self.ip_filter_var, width=15)
        ip_filter_entry.grid(row=0, column=3, padx=(0, 10))
        ip_filter_entry.bind('<KeyRelease>', self.apply_filters)
        
        # MAC filtresi
        ttk.Label(filter_frame, text="MAC Filtresi:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.mac_filter_var = tk.StringVar()
        mac_filter_entry = ttk.Entry(filter_frame, textvariable=self.mac_filter_var, width=15)
        mac_filter_entry.grid(row=0, column=5, padx=(0, 10))
        mac_filter_entry.bind('<KeyRelease>', self.apply_filters)
        
        # Sonuçlar tablosu
        result_frame = ttk.LabelFrame(main_frame, text="Tarama Sonuçları", padding="10")
        result_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        # Treeview
        columns = ("IP", "MAC", "Üretici", "Cihaz Türü", "Açık Portlar", "Durum")
        self.tree = ttk.Treeview(result_frame, columns=columns, show='headings', height=15)
        
        # Sütun başlıkları
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
            if col == "IP":
                self.tree.column(col, width=120)
            elif col == "MAC":
                self.tree.column(col, width=140)
            elif col == "Üretici":
                self.tree.column(col, width=150)
            elif col == "Cihaz Türü":
                self.tree.column(col, width=100)
            elif col == "Açık Portlar":
                self.tree.column(col, width=150)
            else:
                self.tree.column(col, width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Durum çubuğu
        self.status_var = tk.StringVar(value="Hazır")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_label.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Sağ tık menüsü
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Port Taraması Yap", command=self.port_scan_selected)
        self.context_menu.add_command(label="Ping Test", command=self.ping_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Cihaz Detayları", command=self.show_device_details)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        
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
        
        # Üretici adından tespit
        vendor_lower = vendor.lower()
        if any(keyword in vendor_lower for keyword in ['router', 'modem', 'gateway']):
            return "Router"
        elif any(keyword in vendor_lower for keyword in ['apple', 'mac']):
            return "Apple Cihazı"
        elif any(keyword in vendor_lower for keyword in ['samsung', 'android']):
            return "Android Cihazı"
        elif any(keyword in vendor_lower for keyword in ['huawei', 'honor']):
            return "Huawei Cihazı"
        elif any(keyword in vendor_lower for keyword in ['xiaomi', 'redmi']):
            return "Xiaomi Cihazı"
        elif any(keyword in vendor_lower for keyword in ['intel', 'amd', 'nvidia']):
            return "Bilgisayar"
        elif any(keyword in vendor_lower for keyword in ['microsoft', 'windows']):
            return "Windows Cihazı"
        
        return "Bilinmeyen Cihaz"
    
    def port_scan(self, ip, ports=None):
        """Belirtilen IP adresinde port taraması yapar"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        try:
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
        except:
            pass
        
        return open_ports
    
    def scan_network(self, ip_range):
        """Ağı tarar ve cihazları bulur"""
        try:
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, timeout=3, verbose=0)[0]
            devices = []
            
            for _, received in result:
                ip = received.psrc
                mac = received.hwsrc
                vendor = self.get_vendor(mac)
                device_type = self.detect_device_type(mac, vendor)
                
                # Port tarama
                open_ports = []
                if self.port_scan_var.get():
                    open_ports = self.port_scan(ip)
                
                device = {
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'device_type': device_type,
                    'open_ports': open_ports,
                    'status': 'Aktif',
                    'last_seen': datetime.now().isoformat()
                }
                
                devices.append(device)
            
            return devices
        except Exception as e:
            self.status_var.set(f"Tarama hatası: {str(e)}")
            return []
    
    def start_scan(self):
        """Taramayı başlatır"""
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_btn.config(state='disabled')
        self.status_var.set("Taranıyor...")
        
        def scan_thread():
            try:
                ip_range = self.ip_range_var.get()
                devices = self.scan_network(ip_range)
                
                # UI güncelleme
                self.root.after(0, self.update_results, devices)
                
            except Exception as e:
                self.root.after(0, lambda: self.status_var.set(f"Hata: {str(e)}"))
            finally:
                self.root.after(0, self.scan_finished)
        
        Thread(target=scan_thread, daemon=True).start()
    
    def update_results(self, devices):
        """Sonuçları tabloya ekler"""
        self.devices = devices
        
        # Mevcut cihazları güncelle
        for device in devices:
            device_key = f"{device['ip']}_{device['mac']}"
            self.known_devices.add(device_key)
        
        self.apply_filters()
        self.status_var.set(f"{len(devices)} cihaz bulundu")
    
    def scan_finished(self):
        """Tarama tamamlandığında çağrılır"""
        self.scanning = False
        self.scan_btn.config(state='normal')
    
    def apply_filters(self, event=None):
        """Filtreleri uygular"""
        self.tree.delete(*self.tree.get_children())
        
        device_filter = self.device_filter_var.get()
        ip_filter = self.ip_filter_var.get().lower()
        mac_filter = self.mac_filter_var.get().lower()
        
        for device in self.devices:
            # Cihaz türü filtresi
            if device_filter != "Tümü" and device_filter not in device['device_type']:
                continue
            
            # IP filtresi
            if ip_filter and ip_filter not in device['ip'].lower():
                continue
            
            # MAC filtresi
            if mac_filter and mac_filter not in device['mac'].lower():
                continue
            
            # Tabloya ekle
            open_ports_str = ", ".join(map(str, device['open_ports'])) if device['open_ports'] else "Yok"
            self.tree.insert('', 'end', values=(
                device['ip'],
                device['mac'],
                device['vendor'],
                device['device_type'],
                open_ports_str,
                device['status']
            ))
    
    def sort_treeview(self, col):
        """Tabloyu sütuna göre sıralar"""
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
        items.sort()
        
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
    
    def save_results(self):
        """Sonuçları dosyaya kaydeder"""
        if not self.devices:
            messagebox.showwarning("Uyarı", "Kaydedilecek sonuç bulunamadı!")
            return
        
        file_types = [
            ("CSV dosyası", "*.csv"),
            ("JSON dosyası", "*.json"),
            ("Tüm dosyalar", "*.*")
        ]
        
        filename = filedialog.asksaveasfilename(
            title="Sonuçları Kaydet",
            filetypes=file_types,
            defaultextension=".csv"
        )
        
        if not filename:
            return
        
        try:
            if filename.endswith('.csv'):
                self.save_as_csv(filename)
            elif filename.endswith('.json'):
                self.save_as_json(filename)
            else:
                self.save_as_csv(filename + '.csv')
            
            messagebox.showinfo("Başarılı", f"Sonuçlar {filename} dosyasına kaydedildi!")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu: {str(e)}")
    
    def save_as_csv(self, filename):
        """Sonuçları CSV formatında kaydeder"""
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['IP', 'MAC', 'Üretici', 'Cihaz Türü', 'Açık Portlar', 'Durum', 'Son Görülme'])
            
            for device in self.devices:
                open_ports_str = ", ".join(map(str, device['open_ports'])) if device['open_ports'] else "Yok"
                writer.writerow([
                    device['ip'],
                    device['mac'],
                    device['vendor'],
                    device['device_type'],
                    open_ports_str,
                    device['status'],
                    device['last_seen']
                ])
    
    def save_as_json(self, filename):
        """Sonuçları JSON formatında kaydeder"""
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(self.devices, file, indent=2, ensure_ascii=False)
    
    def clear_results(self):
        """Sonuçları temizler"""
        self.tree.delete(*self.tree.get_children())
        self.devices = []
        self.known_devices.clear()
        self.status_var.set("Hazır")
    
    def toggle_monitoring(self):
        """Gerçek zamanlı izlemeyi açıp kapatır"""
        if self.monitor_var.get():
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Gerçek zamanlı izlemeyi başlatır"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_event.clear()
        self.status_var.set("Gerçek zamanlı izleme aktif...")
        
        def monitor_thread():
            while self.monitoring and not self.monitor_event.is_set():
                try:
                    ip_range = self.ip_range_var.get()
                    current_devices = self.scan_network(ip_range)
                    
                    # Yeni cihazları tespit et
                    new_devices = []
                    for device in current_devices:
                        device_key = f"{device['ip']}_{device['mac']}"
                        if device_key not in self.known_devices:
                            new_devices.append(device)
                            self.known_devices.add(device_key)
                    
                    # UI güncelleme
                    if new_devices:
                        self.root.after(0, lambda: self.add_new_devices(new_devices))
                    
                    time.sleep(30)  # 30 saniyede bir kontrol
                    
                except Exception as e:
                    self.root.after(0, lambda: self.status_var.set(f"İzleme hatası: {str(e)}"))
                    time.sleep(10)
        
        Thread(target=monitor_thread, daemon=True).start()
    
    def stop_monitoring(self):
        """Gerçek zamanlı izlemeyi durdurur"""
        self.monitoring = False
        self.monitor_event.set()
        self.status_var.set("İzleme durduruldu")
    
    def add_new_devices(self, new_devices):
        """Yeni cihazları listeye ekler"""
        self.devices.extend(new_devices)
        self.apply_filters()
        
        if new_devices:
            messagebox.showinfo("Yeni Cihaz", f"{len(new_devices)} yeni cihaz tespit edildi!")
    
    def show_context_menu(self, event):
        """Sağ tık menüsünü gösterir"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def port_scan_selected(self):
        """Seçili cihaz için detaylı port taraması yapar"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir cihaz seçin!")
            return
        
        item = selection[0]
        ip = self.tree.item(item, 'values')[0]
        
        # Detaylı port taraması
        all_ports = list(range(1, 1025))  # İlk 1024 port
        open_ports = self.port_scan(ip, all_ports)
        
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))
            messagebox.showinfo("Port Tarama Sonucu", f"{ip} için açık portlar:\n{ports_str}")
        else:
            messagebox.showinfo("Port Tarama Sonucu", f"{ip} için açık port bulunamadı.")
    
    def ping_selected(self):
        """Seçili cihazı ping'ler"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir cihaz seçin!")
            return
        
        item = selection[0]
        ip = self.tree.item(item, 'values')[0]
        
        try:
            response = sr(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
            if response[0]:
                messagebox.showinfo("Ping Sonucu", f"{ip} erişilebilir!")
            else:
                messagebox.showwarning("Ping Sonucu", f"{ip} erişilemiyor!")
        except:
            messagebox.showerror("Hata", "Ping testi başarısız!")
    
    def show_device_details(self):
        """Seçili cihazın detaylarını gösterir"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir cihaz seçin!")
            return
        
        item = selection[0]
        values = self.tree.item(item, 'values')
        
        details = f"""
Cihaz Detayları:
IP Adresi: {values[0]}
MAC Adresi: {values[1]}
Üretici: {values[2]}
Cihaz Türü: {values[3]}
Açık Portlar: {values[4]}
Durum: {values[5]}
        """
        
        messagebox.showinfo("Cihaz Detayları", details)
    
    def run(self):
        """Uygulamayı çalıştırır"""
        self.root.mainloop()

if __name__ == "__main__":
    app = IPScannerV2()
    app.run() 