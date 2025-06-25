import os
import sys
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'webapp'))
from user_management import user_manager

username = 'admin'
new_password = 'admin123'
role = 'admin'

conn = sqlite3.connect(user_manager.db_path)
cursor = conn.cursor()

# Şifreyi hashle
password_hash = user_manager.hash_password(new_password)

cursor.execute('UPDATE users SET password_hash=?, role=? WHERE username=?', (password_hash, role, username))
conn.commit()
conn.close()

print('[SUCCESS] Admin şifresi admin123 olarak sıfırlandı ve rolü admin olarak ayarlandı.') 