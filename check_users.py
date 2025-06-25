#!/usr/bin/env python3
"""
Veritabanındaki kullanıcıları kontrol etme scripti
"""

import os
import sys
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'webapp'))
from user_management import user_manager

def check_users():
    print("Veritabanındaki kullanıcılar kontrol ediliyor...")
    
    conn = sqlite3.connect(user_manager.db_path)
    cursor = conn.cursor()
    
    # Tüm kullanıcıları listele
    cursor.execute('''
        SELECT id, username, email, password_hash, full_name, role, created_at, is_active
        FROM users ORDER BY id
    ''')
    
    users = cursor.fetchall()
    
    if not users:
        print("Veritabanında hiç kullanıcı bulunamadı!")
        return
    
    print(f"\nToplam {len(users)} kullanıcı bulundu:")
    print("-" * 80)
    
    for user in users:
        user_id, username, email, password_hash, full_name, role, created_at, is_active = user
        print(f"ID: {user_id}")
        print(f"Kullanıcı Adı: {username}")
        print(f"E-posta: {email}")
        print(f"Şifre Hash: {password_hash[:20]}...")
        print(f"Ad Soyad: {full_name}")
        print(f"Rol: {role}")
        print(f"Oluşturulma: {created_at}")
        print(f"Aktif: {bool(is_active)}")
        print("-" * 80)
    
    # Admin kullanıcısını özel olarak kontrol et
    admin_user = None
    for user in users:
        if user[1] == 'admin':
            admin_user = user
            break
    
    if admin_user:
        print("\n[ADMIN KULLANICI BULUNDU]")
        print(f"Kullanıcı Adı: {admin_user[1]}")
        print(f"Şifre Hash: {admin_user[3]}")
        print(f"Rol: {admin_user[5]}")
        
        # Şifre testi yap
        test_password = "admin123"
        test_hash = user_manager.hash_password(test_password)
        print(f"Test Şifre Hash: {test_hash}")
        print(f"Hash Eşleşiyor: {test_hash == admin_user[3]}")
        
    else:
        print("\n[ADMIN KULLANICI BULUNAMADI]")
    
    conn.close()

if __name__ == "__main__":
    check_users() 