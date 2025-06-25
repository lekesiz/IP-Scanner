import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'webapp'))
from user_management import user_manager

username = 'admin'
email = 'admin@localhost'
password = 'admin123'
full_name = 'Administrator'
role = 'admin'

# Eğer admin varsa şifresini güncelle, yoksa oluştur
user = user_manager.get_user_by_username(username)
if user:
    print(f"[INFO] Admin kullanıcısı zaten var. Şifre güncelleniyor...")
    user_manager.update_password(username, password)
    user_manager.set_user_role(username, role)
    print(f"[SUCCESS] Admin şifresi ve rolü güncellendi.")
else:
    result = user_manager.register_user(username, email, password, full_name, role=role)
    if result.get('success'):
        print(f"[SUCCESS] Admin kullanıcısı oluşturuldu.")
    else:
        print(f"[ERROR] {result.get('error', 'Bilinmeyen hata')}") 