import tkinter as tk
from tkinter import ttk
from threading import Thread
from scapy.all import ARP, Ether, srp
import requests

# Lookup constructeur MAC (cache pour éviter appels répétés)
mac_vendor_cache = {}

def get_vendor(mac):
    mac_prefix = mac.upper().replace(":", "")[:6]
    if mac_prefix in mac_vendor_cache:
        return mac_vendor_cache[mac_prefix]
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            vendor = response.text
            mac_vendor_cache[mac_prefix] = vendor
            return vendor
    except:
        return "Inconnu"
    return "Inconnu"

def scan(ip_range="192.168.1.0/24"):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []

    for _, received in result:
        mac = received.hwsrc
        vendor = get_vendor(mac)
        devices.append({'ip': received.psrc, 'mac': mac, 'vendor': vendor})
    return devices

def start_scan():
    btn.config(state='disabled')
    tree.delete(*tree.get_children())
    devices = scan()
    for dev in devices:
        tree.insert('', 'end', values=(dev['ip'], dev['vendor'], dev['mac']))
    btn.config(state='normal')

# Interface
root = tk.Tk()
root.title("IP Scanner Réseau")
root.geometry("600x400")

btn = ttk.Button(root, text="Scanner le Réseau", command=lambda: Thread(target=start_scan).start())
btn.pack(pady=10)

columns = ("IP", "Constructeur", "Adresse MAC")
tree = ttk.Treeview(root, columns=columns, show='headings')
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200 if col != "IP" else 150)
tree.pack(expand=True, fill='both', padx=10, pady=10)

root.mainloop()
