#!/usr/bin/env python3
"""
Mikail kullanıcısını admin yapma scripti
"""

import os
import sys
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'webapp'))
from user_management import user_manager

def make_admin():
    username = "mikail"
    
    print(f"'{username}' kullanıcısı admin yapılıyor...")
    
    conn = sqlite3.connect(user_manager.db_path)
    cursor = conn.cursor()
    
    # Kullanıcıyı kontrol et
    cursor.execute('SELECT id, username, role FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user:
        print(f"Hata: '{username}' kullanıcısı bulunamadı!")
        return False
    
    user_id, username, current_role = user
    print(f"Kullanıcı bulundu: ID={user_id}, Rol={current_role}")
    
    # Admin yap
    cursor.execute('UPDATE users SET role = ? WHERE username = ?', ('admin', username))
    conn.commit()
    
    # Kontrol et
    cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
    new_role = cursor.fetchone()[0]
    
    conn.close()
    
    if new_role == 'admin':
        print(f"✅ '{username}' kullanıcısı başarıyla admin yapıldı!")
        return True
    else:
        print(f"❌ Hata: Rol güncellenemedi!")
        return False

if __name__ == "__main__":
    make_admin() 