#!/usr/bin/env python3
"""
Rate Limiting Cache Temizleme Scripti
"""

import os
import sys
import signal
import subprocess
import time

def clear_rate_limit():
    print("Rate limiting cache temizleniyor...")
    
    # 1. PID dosyasını kontrol et
    pid_file = "ip_scanner.pid"
    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            pid = f.read().strip()
        
        print(f"Uygulama PID: {pid}")
        
        # 2. Uygulamayı yeniden başlat
        print("Uygulama yeniden başlatılıyor...")
        
        # Önce durdur
        try:
            os.kill(int(pid), signal.SIGTERM)
            time.sleep(2)
            print("Uygulama durduruldu")
        except:
            print("Uygulama zaten durmuş")
        
        # Sonra başlat
        try:
            subprocess.run(["./start.sh"], check=True)
            print("Uygulama yeniden başlatıldı")
            print("Rate limiting cache temizlendi!")
            print("Şimdi admin/admin123 ile giriş yapabilirsiniz.")
        except subprocess.CalledProcessError as e:
            print(f"Hata: {e}")
            return False
    else:
        print("PID dosyası bulunamadı, uygulama çalışmıyor olabilir")
        return False
    
    return True

if __name__ == "__main__":
    clear_rate_limit() 