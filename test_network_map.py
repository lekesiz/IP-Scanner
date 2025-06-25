#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append('.')

# Test cihaz verisi
test_devices = [
    {
        'ip': '192.168.1.1',
        'mac': 'bc:cf:4f:3d:92:6f',
        'vendor': 'Huawei',
        'device_type': 'Router',
        'open_ports': [80, 443, 22],
        'hostname': 'router.local'
    },
    {
        'ip': '192.168.1.2',
        'mac': '00:11:22:33:44:55',
        'vendor': 'Apple',
        'device_type': 'Apple Cihazı',
        'open_ports': [22, 80],
        'hostname': 'macbook.local'
    },
    {
        'ip': '192.168.1.3',
        'mac': 'aa:bb:cc:dd:ee:ff',
        'vendor': 'Samsung',
        'device_type': 'Android Cihazı',
        'open_ports': [80],
        'hostname': 'android.local'
    }
]

try:
    from webapp.network_visualizer import create_network_visualization
    
    print("Ağ haritası test ediliyor...")
    print(f"Test cihazları: {len(test_devices)}")
    
    result = create_network_visualization(test_devices)
    
    print(f"Sonuç: {result}")
    print("Test başarılı!")
    
except Exception as e:
    print(f"Test hatası: {e}")
    import traceback
    traceback.print_exc() 