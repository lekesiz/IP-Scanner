import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta
import jwt
from functools import wraps
from flask import request, jsonify, current_app

class UserManagement:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self.secret_key = "ip_scanner_secret_key_2024"
        self.init_database()
    
    def init_database(self):
        """Veritabanını başlat ve tabloları oluştur"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Kullanıcılar tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                settings TEXT DEFAULT '{}'
            )
        ''')
        
        # Kullanıcı aktiviteleri tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                activity_type TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Kullanıcı oturumları tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Varsayılan admin kullanıcısı oluştur
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@ipscanner.com', self.hash_password('admin123'), 'Sistem Yöneticisi', 'admin'))
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Şifreyi hash'le"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password, password_hash):
        """Şifreyi doğrula"""
        return self.hash_password(password) == password_hash
    
    def register_user(self, username, email, password, full_name=None, role='user'):
        """Yeni kullanıcı kaydı"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Kullanıcı adı ve e-posta kontrolü
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                return {'success': False, 'message': 'Kullanıcı adı veya e-posta zaten kullanımda'}
            
            # Yeni kullanıcı oluştur
            password_hash = self.hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, full_name, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, password_hash, full_name, role))
            
            user_id = cursor.lastrowid
            
            # Aktivite kaydı
            cursor.execute('''
                INSERT INTO user_activities (user_id, activity_type, description, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'register', 'Kullanıcı kaydı oluşturuldu', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': 'Kullanıcı başarıyla oluşturuldu'}
            
        except Exception as e:
            return {'success': False, 'message': f'Kayıt hatası: {str(e)}'}
    
    def login_user(self, username, password):
        """Kullanıcı girişi"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Kullanıcıyı bul
            cursor.execute('''
                SELECT id, username, email, password_hash, full_name, role, settings
                FROM users WHERE username = ? AND is_active = 1
            ''', (username,))
            
            user = cursor.fetchone()
            if not user:
                return {'success': False, 'message': 'Geçersiz kullanıcı adı veya şifre'}
            
            user_id, username, email, password_hash, full_name, role, settings = user
            
            # Şifre kontrolü
            if not self.verify_password(password, password_hash):
                return {'success': False, 'message': 'Geçersiz kullanıcı adı veya şifre'}
            
            # JWT token oluştur
            token = jwt.encode({
                'user_id': user_id,
                'username': username,
                'role': role,
                'exp': datetime.utcnow() + timedelta(hours=8)
            }, self.secret_key, algorithm='HS256')
            
            # Oturum kaydı
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token, datetime.utcnow() + timedelta(hours=8)))
            
            # Son giriş zamanını güncelle
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            
            # Aktivite kaydı
            cursor.execute('''
                INSERT INTO user_activities (user_id, activity_type, description, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'login', 'Kullanıcı girişi yapıldı', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'message': 'Giriş başarılı',
                'token': token,
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email,
                    'full_name': full_name,
                    'role': role,
                    'settings': json.loads(settings) if settings else {}
                }
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Giriş hatası: {str(e)}'}
    
    def verify_token(self, token):
        """JWT token'ı doğrula"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Oturum kontrolü
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT us.id, u.id, u.username, u.email, u.full_name, u.role, u.settings
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.session_token = ? AND us.is_active = 1 AND us.expires_at > CURRENT_TIMESTAMP
            ''', (token,))
            
            session = cursor.fetchone()
            conn.close()
            
            if not session:
                return None
            
            return {
                'user_id': session[1],
                'username': session[2],
                'email': session[3],
                'full_name': session[4],
                'role': session[5],
                'settings': json.loads(session[6]) if session[6] else {}
            }
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception as e:
            print(f"Token verification error: {str(e)}")
            return None
    
    def get_user_id_from_token(self, token):
        """Token'dan user_id'yi al"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload.get('user_id')
        except:
            return None
    
    def logout_user(self, token):
        """Kullanıcı çıkışı"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Oturumu deaktif et
            cursor.execute('''
                UPDATE user_sessions SET is_active = 0 WHERE session_token = ?
            ''', (token,))
            
            # Kullanıcı ID'sini al
            cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (token,))
            result = cursor.fetchone()
            
            if result:
                user_id = result[0]
                # Aktivite kaydı
                cursor.execute('''
                    INSERT INTO user_activities (user_id, activity_type, description, ip_address)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, 'logout', 'Kullanıcı çıkışı yapıldı', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': 'Çıkış başarılı'}
            
        except Exception as e:
            return {'success': False, 'message': f'Çıkış hatası: {str(e)}'}
    
    def get_user_profile(self, user_id):
        """Kullanıcı profilini getir"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, full_name, role, created_at, last_login, settings
                FROM users WHERE id = ? AND is_active = 1
            ''', (user_id,))
            
            user = cursor.fetchone()
            if not user:
                return None
            
            # Kullanım istatistikleri
            cursor.execute('''
                SELECT 
                    COUNT(CASE WHEN activity_type = 'scan' THEN 1 END) as scan_count,
                    COUNT(CASE WHEN activity_type = 'report' THEN 1 END) as report_count,
                    COUNT(CASE WHEN activity_type = 'login' THEN 1 END) as login_count
                FROM user_activities WHERE user_id = ?
            ''', (user_id,))
            
            stats = cursor.fetchone()
            
            # Son aktiviteler
            cursor.execute('''
                SELECT activity_type, description, timestamp
                FROM user_activities 
                WHERE user_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 5
            ''', (user_id,))
            
            activities = cursor.fetchall()
            
            conn.close()
            
            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'full_name': user[3],
                'role': user[4],
                'created_at': user[5],
                'last_login': user[6],
                'settings': json.loads(user[7]) if user[7] else {},
                'stats': {
                    'scan_count': stats[0] or 0,
                    'report_count': stats[1] or 0,
                    'login_count': stats[2] or 0
                },
                'recent_activities': [
                    {
                        'type': activity[0],
                        'description': activity[1],
                        'timestamp': activity[2]
                    } for activity in activities
                ]
            }
            
        except Exception as e:
            return None
    
    def update_user_settings(self, user_id, settings):
        """Kullanıcı ayarlarını güncelle"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET settings = ? WHERE id = ?
            ''', (json.dumps(settings), user_id))
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': 'Ayarlar güncellendi'}
            
        except Exception as e:
            return {'success': False, 'message': f'Ayar güncelleme hatası: {str(e)}'}
    
    def log_activity(self, user_id, activity_type, description):
        """Kullanıcı aktivitesini kaydet"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO user_activities (user_id, activity_type, description, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, activity_type, description, request.remote_addr))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Aktivite kaydetme hatası: {str(e)}")
    
    def require_auth(self, f):
        """Kimlik doğrulama decorator'ı"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization')
            
            if not token:
                return jsonify({'error': 'Token gerekli'}), 401
            
            if token.startswith('Bearer '):
                token = token[7:]
            
            user = self.verify_token(token)
            if not user:
                return jsonify({'error': 'Geçersiz token'}), 401
            
            request.current_user = user
            return f(*args, **kwargs)
        
        return decorated_function
    
    def require_role(self, required_role):
        """Rol kontrolü decorator'ı"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not hasattr(request, 'current_user'):
                    return jsonify({'error': 'Kimlik doğrulama gerekli'}), 401
                
                if request.current_user['role'] != required_role and request.current_user['role'] != 'admin':
                    return jsonify({'error': 'Yetkisiz erişim'}), 403
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator

# Global user management instance
user_manager = UserManagement() 