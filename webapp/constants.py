"""
IP Scanner V4.0 - Constants
Tüm sabit değerler ve konfigürasyon ayarları
"""

import os
from typing import List, Dict

# Güvenlik Sabitleri
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'ip_scanner_secret_key_2024_change_in_production')
PASSWORD_SALT = os.getenv('PASSWORD_SALT', 'default_salt_change_in_production')
JWT_EXPIRY_HOURS = 8
PASSWORD_MIN_LENGTH = 6
USERNAME_MIN_LENGTH = 3

# Rate Limiting
RATE_LIMIT_DEFAULT = 100
RATE_LIMIT_WINDOW = 3600  # 1 saat
RATE_LIMIT_LOGIN = 10
RATE_LIMIT_LOGIN_WINDOW = 300  # 5 dakika
RATE_LIMIT_REGISTER = 5
RATE_LIMIT_REGISTER_WINDOW = 3600  # 1 saat

# Tarama Sabitleri
DEFAULT_IP_RANGE = '192.168.1.0/24'
DEFAULT_SCAN_TIMEOUT = 30
DEFAULT_PORT_TIMEOUT = 3
MAX_CONCURRENT_SCANS = 5

# Port Sabitleri
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 548, 631, 993, 995, 8080, 8443, 9100, 3389, 5900, 554, 8000, 9000, 515, 3283]

# Cihaz Türleri
DEVICE_TYPES = {
    'router': 'Router/Modem',
    'computer': 'Bilgisayar',
    'phone': 'Telefon',
    'tablet': 'Tablet',
    'printer': 'Yazıcı',
    'camera': 'Kamera',
    'server': 'Sunucu',
    'switch': 'Switch',
    'unknown': 'Bilinmeyen'
}

# MAC Vendor Prefixes
MAC_VENDOR_PREFIXES = {
    'router': [
        '00:1A:11', '00:1B:63', '00:1C:C0', '00:1D:7D', '00:1E:40', '00:1F:3A',
        'BC:CF:4F', '00:14:22', '00:16:3E', '00:18:F8', '00:1A:92', '00:1C:7E',
        '00:1E:58', '00:20:78', '00:22:6B', '00:24:01', '00:26:18', '00:28:6F'
    ],
    'apple': [
        '00:1C:B3', '00:1E:C2', '00:23:12', '00:23:76', '00:25:00', '00:26:08',
        '00:26:B0', '00:26:BB', '00:27:84', '00:28:6F', '00:2A:10', '00:2A:6A',
        '00:2B:03', '00:2C:BE', '00:2D:76', '00:2E:20', '00:30:65', '00:32:5A'
    ],
    'samsung': [
        '00:16:32', '00:19:C5', '00:1B:98', '00:1C:62', '00:1D:25', '00:1E:7D',
        '00:20:DB', '00:23:39', '00:25:38', '00:26:18', '00:27:19', '00:28:6F',
        '00:2A:10', '00:2B:03', '00:2C:BE', '00:2D:76', '00:2E:20', '00:30:65'
    ]
}

# Servis Sabitleri
SERVICE_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 548: 'AFP',
    631: 'IPP', 993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9100: 'Printer', 3389: 'RDP', 5900: 'VNC', 554: 'RTSP', 8000: 'HTTP-Alt',
    9000: 'HTTP-Alt', 515: 'LPR', 3283: 'Net Assistant'
}

# HTTP Status Codes
HTTP_STATUS = {
    'OK': 200,
    'CREATED': 201,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'NOT_FOUND': 404,
    'RATE_LIMIT': 429,
    'INTERNAL_ERROR': 500
}

# Logging Levels
LOG_LEVELS = {
    'DEBUG': 'DEBUG',
    'INFO': 'INFO',
    'WARNING': 'WARNING',
    'ERROR': 'ERROR',
    'CRITICAL': 'CRITICAL'
}

# File Paths
REPORTS_DIR = 'reports'
LOGS_DIR = 'logs'
TEMP_DIR = 'temp'

# Database
DB_NAME = 'users.db'
DB_TIMEOUT = 30

# Web Server
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 5001
DEFAULT_DEBUG = False

# CORS Origins
ALLOWED_ORIGINS = [
    'http://localhost:5001',
    'http://127.0.0.1:5001',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
]

# API Endpoints
API_PREFIX = '/api'
AUTH_PREFIX = '/api/auth'
SCAN_PREFIX = '/api/scan'

# Error Messages
ERROR_MESSAGES = {
    'INVALID_JSON': 'Invalid JSON data',
    'MISSING_FIELDS': 'Required fields are missing',
    'INVALID_IP': 'Invalid IP range format',
    'RATE_LIMIT': 'Rate limit exceeded',
    'AUTH_FAILED': 'Authentication failed',
    'PERMISSION_DENIED': 'Permission denied',
    'INTERNAL_ERROR': 'Internal server error',
    'NOT_FOUND': 'Resource not found'
}

# Success Messages
SUCCESS_MESSAGES = {
    'SCAN_COMPLETED': 'Scan completed successfully',
    'USER_CREATED': 'User created successfully',
    'LOGIN_SUCCESS': 'Login successful',
    'LOGOUT_SUCCESS': 'Logout successful',
    'SETTINGS_UPDATED': 'Settings updated successfully'
} 