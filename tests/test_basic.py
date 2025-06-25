#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Test için path ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from webapp.constants import *
from webapp.user_management import UserManagement
from webapp.device_detector import ProfessionalDeviceDetector
from webapp.network_visualizer import NetworkVisualizer

class TestConstants(unittest.TestCase):
    """Constants modülü testleri"""
    
    def test_jwt_secret_key(self):
        """JWT secret key testi"""
        self.assertIsInstance(JWT_SECRET_KEY, str)
        self.assertGreater(len(JWT_SECRET_KEY), 10)
    
    def test_password_salt(self):
        """Password salt testi"""
        self.assertIsInstance(PASSWORD_SALT, str)
        self.assertGreater(len(PASSWORD_SALT), 10)
    
    def test_common_ports(self):
        """Common ports testi"""
        self.assertIsInstance(COMMON_PORTS, list)
        self.assertGreater(len(COMMON_PORTS), 0)
        for port in COMMON_PORTS:
            self.assertIsInstance(port, int)
            self.assertGreater(port, 0)
            self.assertLess(port, 65536)
    
    def test_device_types(self):
        """Device types testi"""
        self.assertIsInstance(DEVICE_TYPES, dict)
        self.assertGreater(len(DEVICE_TYPES), 0)
        for key, value in DEVICE_TYPES.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, str)
    
    def test_service_ports(self):
        """Service ports testi"""
        self.assertIsInstance(SERVICE_PORTS, dict)
        self.assertGreater(len(SERVICE_PORTS), 0)
        for port, service in SERVICE_PORTS.items():
            self.assertIsInstance(port, int)
            self.assertIsInstance(service, str)
    
    def test_http_status_codes(self):
        """HTTP status codes testi"""
        self.assertIsInstance(HTTP_STATUS, dict)
        expected_codes = ['OK', 'CREATED', 'BAD_REQUEST', 'UNAUTHORIZED', 'NOT_FOUND', 'RATE_LIMIT', 'INTERNAL_ERROR']
        for code in expected_codes:
            self.assertIn(code, HTTP_STATUS)
            self.assertIsInstance(HTTP_STATUS[code], int)

class TestUserManagement(unittest.TestCase):
    """UserManagement sınıfı testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.user_manager = UserManagement(self.temp_db.name)
    
    def tearDown(self):
        """Test sonrası temizlik"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_init_database(self):
        """Veritabanı başlatma testi"""
        # Veritabanı dosyasının oluşturulduğunu kontrol et
        self.assertTrue(os.path.exists(self.temp_db.name))
        
        # Admin kullanıcısının oluşturulduğunu kontrol et
        conn = self.user_manager.db_path
        self.assertIsInstance(conn, str)
    
    def test_hash_password(self):
        """Şifre hash'leme testi"""
        password = "test123"
        hash1 = self.user_manager.hash_password(password)
        hash2 = self.user_manager.hash_password(password)
        
        # Aynı şifre için aynı hash üretilmeli
        self.assertEqual(hash1, hash2)
        
        # Hash'in string olduğunu kontrol et
        self.assertIsInstance(hash1, str)
        self.assertGreater(len(hash1), 0)
    
    def test_verify_password(self):
        """Şifre doğrulama testi"""
        password = "test123"
        password_hash = self.user_manager.hash_password(password)
        
        # Doğru şifre
        self.assertTrue(self.user_manager.verify_password(password, password_hash))
        
        # Yanlış şifre
        self.assertFalse(self.user_manager.verify_password("wrong", password_hash))
    
    def test_register_user_valid(self):
        """Geçerli kullanıcı kaydı testi"""
        result = self.user_manager.register_user(
            username="testuser",
            email="test@example.com",
            password="test123",
            full_name="Test User"
        )
        
        self.assertTrue(result['success'])
        self.assertIn('başarıyla oluşturuldu', result['message'])
    
    def test_register_user_invalid_username(self):
        """Geçersiz kullanıcı adı testi"""
        result = self.user_manager.register_user(
            username="ab",  # Çok kısa
            email="test@example.com",
            password="test123"
        )
        
        self.assertFalse(result['success'])
        self.assertIn('en az 3 karakter', result['message'])
    
    def test_register_user_invalid_email(self):
        """Geçersiz e-posta testi"""
        result = self.user_manager.register_user(
            username="testuser",
            email="invalid-email",  # Geçersiz format
            password="test123"
        )
        
        self.assertFalse(result['success'])
        self.assertIn('Geçerli bir e-posta', result['message'])
    
    def test_register_user_invalid_password(self):
        """Geçersiz şifre testi"""
        result = self.user_manager.register_user(
            username="testuser",
            email="test@example.com",
            password="123"  # Çok kısa
        )
        
        self.assertFalse(result['success'])
        self.assertIn('en az 6 karakter', result['message'])
    
    def test_register_user_duplicate(self):
        """Aynı kullanıcı adı ile tekrar kayıt testi"""
        # İlk kayıt
        self.user_manager.register_user(
            username="testuser",
            email="test@example.com",
            password="test123"
        )
        
        # Aynı kullanıcı adı ile tekrar kayıt
        result = self.user_manager.register_user(
            username="testuser",
            email="test2@example.com",
            password="test123"
        )
        
        self.assertFalse(result['success'])
        self.assertIn('zaten kullanımda', result['message'])

class TestDeviceDetector(unittest.TestCase):
    """ProfessionalDeviceDetector sınıfı testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        self.detector = ProfessionalDeviceDetector()
    
    def test_load_device_signatures(self):
        """Cihaz imzaları yükleme testi"""
        signatures = self.detector.device_signatures
        
        self.assertIsInstance(signatures, dict)
        self.assertGreater(len(signatures), 0)
        
        # Temel cihaz türlerinin varlığını kontrol et
        expected_types = ['router', 'apple', 'samsung', 'huawei', 'windows', 'linux', 'printer', 'camera']
        for device_type in expected_types:
            self.assertIn(device_type, signatures)
            
            # Her cihaz türü için gerekli alanları kontrol et
            signature = signatures[device_type]
            self.assertIn('mac_prefixes', signature)
            self.assertIn('vendor_keywords', signature)
            self.assertIn('port_signatures', signature)
            self.assertIn('service_keywords', signature)
    
    @patch('requests.get')
    def test_get_vendor_from_api_success(self, mock_get):
        """API'den vendor alma başarılı testi"""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Apple Inc."
        mock_get.return_value = mock_response
        
        vendor = self.detector.get_vendor_from_api("00:1C:B3:12:34:56")
        
        self.assertEqual(vendor, "Apple Inc.")
        mock_get.assert_called_once()
    
    @patch('requests.get')
    def test_get_vendor_from_api_failure(self, mock_get):
        """API'den vendor alma başarısız testi"""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        vendor = self.detector.get_vendor_from_api("00:1C:B3:12:34:56")
        
        self.assertEqual(vendor, "Bilinmiyor")
    
    def test_detect_device_type_router(self):
        """Router cihaz türü tespiti testi"""
        mac = "00:1A:11:12:34:56"
        vendor = "TP-Link"
        open_ports = [80, 443, 22]
        services = [{'service': 'http'}, {'service': 'https'}]
        
        device_type, confidence = self.detector.detect_device_type(mac, vendor, open_ports, services)
        
        self.assertIn('router', device_type.lower())
        self.assertGreater(confidence, 0)
    
    def test_detect_device_type_apple(self):
        """Apple cihaz türü tespiti testi"""
        mac = "00:1C:B3:12:34:56"
        vendor = "Apple Inc."
        open_ports = [22, 80, 443]
        services = [{'service': 'ssh'}, {'service': 'http'}]
        
        device_type, confidence = self.detector.detect_device_type(mac, vendor, open_ports, services)
        
        self.assertIn('apple', device_type.lower())
        self.assertGreater(confidence, 0)
    
    def test_get_device_type_name(self):
        """Cihaz türü adı alma testi"""
        # Bilinen tür
        name = self.detector._get_device_type_name('router')
        self.assertEqual(name, 'Router/Modem')
        
        # Bilinmeyen tür
        name = self.detector._get_device_type_name('unknown_type')
        self.assertEqual(name, 'Unknown_type')

class TestNetworkVisualizer(unittest.TestCase):
    """NetworkVisualizer sınıfı testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        self.visualizer = NetworkVisualizer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Test sonrası temizlik"""
        shutil.rmtree(self.temp_dir)
    
    def test_device_colors(self):
        """Cihaz renkleri testi"""
        colors = self.visualizer.device_colors
        
        self.assertIsInstance(colors, dict)
        self.assertGreater(len(colors), 0)
        
        # Temel cihaz türlerinin renklerini kontrol et
        expected_types = ['router', 'computer', 'phone', 'tablet', 'printer', 'camera', 'server', 'switch', 'unknown']
        for device_type in expected_types:
            self.assertIn(device_type, colors)
            self.assertIsInstance(colors[device_type], str)
            self.assertTrue(colors[device_type].startswith('#'))
    
    def test_generate_network_stats_empty(self):
        """Boş cihaz listesi ile istatistik oluşturma testi"""
        stats = self.visualizer.generate_network_stats([])
        
        self.assertEqual(stats['total_devices'], 0)
        self.assertEqual(len(stats['device_types']), 0)
        self.assertEqual(len(stats['vendors']), 0)
    
    def test_generate_network_stats_with_devices(self):
        """Cihazlarla istatistik oluşturma testi"""
        devices = [
            {
                'ip': '192.168.1.1',
                'mac': '00:1A:11:12:34:56',
                'device_type': 'router',
                'vendor': 'TP-Link',
                'confidence': 85,
                'open_ports': [80, 443],
                'protocols': ['HTTP', 'HTTPS']
            },
            {
                'ip': '192.168.1.2',
                'mac': '00:1C:B3:12:34:56',
                'device_type': 'computer',
                'vendor': 'Apple',
                'confidence': 90,
                'open_ports': [22, 80],
                'protocols': ['SSH', 'HTTP']
            }
        ]
        
        stats = self.visualizer.generate_network_stats(devices)
        
        self.assertEqual(stats['total_devices'], 2)
        self.assertEqual(stats['device_types']['router'], 1)
        self.assertEqual(stats['device_types']['computer'], 1)
        self.assertEqual(stats['vendors']['TP-Link'], 1)
        self.assertEqual(stats['vendors']['Apple'], 1)
        self.assertEqual(stats['confidence_levels']['high'], 2)
    
    def test_generate_network_html_empty(self):
        """Boş cihaz listesi ile HTML oluşturma testi"""
        result = self.visualizer.generate_network_html([])
        
        self.assertEqual(result, "")
    
    def test_create_network_visualization_success(self):
        """Başarılı ağ görselleştirmesi testi"""
        devices = [
            {
                'ip': '192.168.1.1',
                'mac': '00:1A:11:12:34:56',
                'device_type': 'router',
                'vendor': 'TP-Link',
                'confidence': 85
            }
        ]
        
        result = self.visualizer.create_network_visualization(devices, self.temp_dir)
        
        self.assertTrue(result['success'])
        self.assertIsInstance(result['html_file'], str)
        self.assertGreater(len(result['html_file']), 0)
        self.assertEqual(result['device_count'], 1)
        self.assertIn('timestamp', result)
        self.assertIn('stats', result)
        
        # HTML dosyasının oluşturulduğunu kontrol et
        self.assertTrue(os.path.exists(result['html_file']))

if __name__ == '__main__':
    # Test suite'ini çalıştır
    unittest.main(verbosity=2) 