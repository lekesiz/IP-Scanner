#!/usr/bin/env python3
"""
Login işlemini test etme scripti
"""

import os
import sys
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'webapp'))
from user_management import user_manager

def test_login():
    print("Login işlemi test ediliyor...")
    
    username = "admin"
    password = "admin123"
    
    print(f"Kullanıcı Adı: {username}")
    print(f"Şifre: {password}")
    
    # Login işlemini test et
    result = user_manager.login_user(username, password)
    
    print(f"\nLogin Sonucu:")
    print(f"Başarılı: {result.get('success', False)}")
    print(f"Mesaj: {result.get('message', 'Mesaj yok')}")
    
    if result.get('success'):
        print(f"Token: {result.get('token', 'Token yok')[:50]}...")
        user_info = result.get('user', {})
        print(f"Kullanıcı Bilgileri:")
        print(f"  ID: {user_info.get('id')}")
        print(f"  Kullanıcı Adı: {user_info.get('username')}")
        print(f"  E-posta: {user_info.get('email')}")
        print(f"  Rol: {user_info.get('role')}")
    else:
        print("Login başarısız!")
        
        # Şifre doğrulama testi
        print("\nŞifre doğrulama testi:")
        conn = sqlite3.connect(user_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result_db = cursor.fetchone()
        
        if result_db:
            stored_hash = result_db[0]
            test_hash = user_manager.hash_password(password)
            print(f"Veritabanındaki Hash: {stored_hash}")
            print(f"Test Hash: {test_hash}")
            print(f"Eşleşiyor: {stored_hash == test_hash}")
        else:
            print("Kullanıcı veritabanında bulunamadı!")
        
        conn.close()

if __name__ == "__main__":
    test_login() 