#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
import os
import tempfile
import shutil
import json
import time
from unittest.mock import patch, MagicMock

# Test için path ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from webapp.app import app
from webapp.user_management import UserManagement
from webapp.device_detector import ProfessionalDeviceDetector
from webapp.network_visualizer import NetworkVisualizer
from webapp.advanced_scanner import AdvancedScanner

class TestFlaskApp(unittest.TestCase):
    """Flask uygulaması integration testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        
        # Test veritabanı
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        
        # Test kullanıcısı oluştur
        self.user_manager = UserManagement(self.temp_db.name)
        self.test_user = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'test123',
            'full_name': 'Test User'
        }
    
    def tearDown(self):
        """Test sonrası temizlik"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_index_route_redirect(self):
        """Ana sayfa yönlendirme testi"""
        response = self.client.get('/')
        
        # Giriş yapmamış kullanıcı login sayfasına yönlendirilmeli
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)
    
    def test_login_page(self):
        """Login sayfası testi"""
        response = self.client.get('/login')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login', response.data.lower())
    
    def test_register_api_success(self):
        """Başarılı kayıt API testi"""
        response = self.client.post('/api/auth/register',
                                  json=self.test_user,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
    
    def test_register_api_invalid_data(self):
        """Geçersiz veri ile kayıt API testi"""
        invalid_user = {
            'username': 'ab',  # Çok kısa
            'email': 'invalid-email',
            'password': '123'  # Çok kısa
        }
        
        response = self.client.post('/api/auth/register',
                                  json=invalid_user,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
    
    def test_login_api_success(self):
        """Başarılı giriş API testi"""
        # Önce kullanıcı kaydı yap
        self.client.post('/api/auth/register',
                        json=self.test_user,
                        content_type='application/json')
        
        # Giriş yap
        login_data = {
            'username': self.test_user['username'],
            'password': self.test_user['password']
        }
        
        response = self.client.post('/api/auth/login',
                                  json=login_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('token', data)
    
    def test_login_api_invalid_credentials(self):
        """Geçersiz kimlik bilgileri ile giriş API testi"""
        login_data = {
            'username': 'nonexistent',
            'password': 'wrongpassword'
        }
        
        response = self.client.post('/api/auth/login',
                                  json=login_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
    
    def test_scan_api_unauthorized(self):
        """Yetkisiz tarama API testi"""
        scan_data = {
            'ip_range': '192.168.1.0/24'
        }
        
        response = self.client.post('/api/scan',
                                  json=scan_data,
                                  content_type='application/json')
        
        # Yetkisiz erişim 401 döndürmeli
        self.assertEqual(response.status_code, 401)
    
    @patch('webapp.app.IPScannerV2')
    def test_scan_api_authorized(self, mock_scanner):
        """Yetkili tarama API testi"""
        # Mock scanner setup
        mock_instance = MagicMock()
        mock_instance.scan_network.return_value = [
            {
                'ip': '192.168.1.1',
                'mac': '00:1A:11:12:34:56',
                'vendor': 'TP-Link',
                'device_type': 'Router/Modem',
                'confidence': 85
            }
        ]
        mock_scanner.return_value = mock_instance
        
        # Önce kullanıcı kaydı ve girişi yap
        self.client.post('/api/auth/register',
                        json=self.test_user,
                        content_type='application/json')
        
        login_response = self.client.post('/api/auth/login',
                                        json={
                                            'username': self.test_user['username'],
                                            'password': self.test_user['password']
                                        },
                                        content_type='application/json')
        
        login_data = json.loads(login_response.data)
        token = login_data['token']
        
        # Tarama yap
        scan_data = {
            'ip_range': '192.168.1.0/24'
        }
        
        response = self.client.post('/api/scan',
                                  json=scan_data,
                                  content_type='application/json',
                                  headers={'Authorization': f'Bearer {token}'})
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('devices', data)

class TestDeviceDetectionIntegration(unittest.TestCase):
    """Cihaz tespiti integration testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        self.detector = ProfessionalDeviceDetector()
        self.scanner = AdvancedScanner()
    
    @patch('requests.get')
    def test_device_detection_workflow(self, mock_get):
        """Cihaz tespiti iş akışı testi"""
        # Mock vendor API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Apple Inc."
        mock_get.return_value = mock_response
        
        # Test cihazı
        test_device = {
            'ip': '192.168.1.2',
            'mac': '00:1C:B3:12:34:56'
        }
        
        # Cihaz analizi
        device_info = self.detector.analyze_device(test_device['ip'], test_device['mac'])
        
        # Sonuçları kontrol et
        self.assertEqual(device_info.ip, test_device['ip'])
        self.assertEqual(device_info.mac, test_device['mac'])
        self.assertEqual(device_info.vendor, "Apple Inc.")
        self.assertIsInstance(device_info.device_type, str)
        self.assertIsInstance(device_info.confidence, int)
        self.assertGreaterEqual(device_info.confidence, 0)
        self.assertLessEqual(device_info.confidence, 100)
    
    def test_batch_device_analysis(self):
        """Toplu cihaz analizi testi"""
        test_devices = [
            {'ip': '192.168.1.1', 'mac': '00:1A:11:12:34:56'},
            {'ip': '192.168.1.2', 'mac': '00:1C:B3:12:34:56'},
            {'ip': '192.168.1.3', 'mac': '00:16:32:12:34:56'}
        ]
        
        results = self.detector.analyze_devices_batch(test_devices)
        
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIsInstance(result.ip, str)
            self.assertIsInstance(result.mac, str)
            self.assertIsInstance(result.vendor, str)
            self.assertIsInstance(result.device_type, str)
            self.assertIsInstance(result.confidence, int)

class TestNetworkVisualizationIntegration(unittest.TestCase):
    """Ağ görselleştirmesi integration testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        self.visualizer = NetworkVisualizer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Test sonrası temizlik"""
        shutil.rmtree(self.temp_dir)
    
    def test_full_visualization_workflow(self):
        """Tam görselleştirme iş akışı testi"""
        # Test cihazları
        test_devices = [
            {
                'ip': '192.168.1.1',
                'mac': '00:1A:11:12:34:56',
                'device_type': 'router',
                'vendor': 'TP-Link',
                'confidence': 85,
                'open_ports': [80, 443, 22],
                'protocols': ['HTTP', 'HTTPS', 'SSH']
            },
            {
                'ip': '192.168.1.2',
                'mac': '00:1C:B3:12:34:56',
                'device_type': 'computer',
                'vendor': 'Apple',
                'confidence': 90,
                'open_ports': [22, 80, 443],
                'protocols': ['SSH', 'HTTP', 'HTTPS']
            },
            {
                'ip': '192.168.1.3',
                'mac': '00:16:32:12:34:56',
                'device_type': 'phone',
                'vendor': 'Samsung',
                'confidence': 75,
                'open_ports': [80, 443],
                'protocols': ['HTTP', 'HTTPS']
            }
        ]
        
        # Görselleştirme oluştur
        result = self.visualizer.create_network_visualization(test_devices, self.temp_dir)
        
        # Sonuçları kontrol et
        self.assertTrue(result['success'])
        self.assertIsInstance(result['html_file'], str)
        self.assertTrue(os.path.exists(result['html_file']))
        self.assertEqual(result['device_count'], 3)
        self.assertIn('timestamp', result)
        self.assertIn('stats', result)
        
        # İstatistikleri kontrol et
        stats = result['stats']
        self.assertEqual(stats['total_devices'], 3)
        self.assertEqual(stats['device_types']['router'], 1)
        self.assertEqual(stats['device_types']['computer'], 1)
        self.assertEqual(stats['device_types']['phone'], 1)
        self.assertEqual(stats['confidence_levels']['high'], 2)
        self.assertEqual(stats['confidence_levels']['medium'], 1)
    
    def test_html_file_content(self):
        """HTML dosya içeriği testi"""
        test_devices = [
            {
                'ip': '192.168.1.1',
                'mac': '00:1A:11:12:34:56',
                'device_type': 'router',
                'vendor': 'TP-Link',
                'confidence': 85
            }
        ]
        
        result = self.visualizer.create_network_visualization(test_devices, self.temp_dir)
        
        # HTML dosyasını oku ve içeriğini kontrol et
        with open(result['html_file'], 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Temel HTML yapısını kontrol et
        self.assertIn('<!DOCTYPE html>', html_content)
        self.assertIn('<html', html_content)
        self.assertIn('</html>', html_content)
        self.assertIn('vis-network', html_content)
        self.assertIn('192.168.1.1', html_content)

class TestAdvancedScannerIntegration(unittest.TestCase):
    """Gelişmiş tarayıcı integration testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        self.scanner = AdvancedScanner()
    
    @patch('subprocess.run')
    def test_ping_host_success(self, mock_run):
        """Başarılı ping testi"""
        # Mock successful ping
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        result = self.scanner.ping_host('192.168.1.1')
        
        self.assertTrue(result)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_ping_host_failure(self, mock_run):
        """Başarısız ping testi"""
        # Mock failed ping
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        
        result = self.scanner.ping_host('192.168.1.999')
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_get_mac_address_alternative(self, mock_run):
        """MAC adresi alma testi"""
        # Mock ARP response
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "192.168.1.1 00:1A:11:12:34:56"
        mock_run.return_value = mock_result
        
        mac = self.scanner.get_mac_address_alternative('192.168.1.1')
        
        self.assertEqual(mac, '00:1A:11:12:34:56')
    
    def test_get_vendor_from_mac(self):
        """MAC adresinden vendor alma testi"""
        # Bilinen vendor
        vendor = self.scanner.get_vendor_from_mac('00:1C:B3:12:34:56')
        self.assertEqual(vendor, 'Apple')
        
        # Bilinmeyen vendor
        vendor = self.scanner.get_vendor_from_mac('FF:FF:FF:12:34:56')
        self.assertEqual(vendor, 'Bilinmiyor')
    
    @patch('socket.socket')
    def test_scan_ports_fast(self, mock_socket):
        """Hızlı port tarama testi"""
        # Mock socket behavior
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = [0, 1, 0]  # Port 21 açık, 22 kapalı, 23 açık
        mock_socket.return_value = mock_sock
        
        open_ports = self.scanner.scan_ports_fast('192.168.1.1', [21, 22, 23])
        
        self.assertIn(21, open_ports)
        self.assertIn(23, open_ports)
        self.assertNotIn(22, open_ports)

class TestErrorHandling(unittest.TestCase):
    """Hata yönetimi integration testleri"""
    
    def setUp(self):
        """Test öncesi hazırlık"""
        app.config['TESTING'] = True
        self.client = app.test_client()
    
    def test_invalid_json_request(self):
        """Geçersiz JSON isteği testi"""
        response = self.client.post('/api/auth/register',
                                  data='invalid json',
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_missing_required_fields(self):
        """Eksik zorunlu alanlar testi"""
        incomplete_user = {
            'username': 'testuser'
            # email ve password eksik
        }
        
        response = self.client.post('/api/auth/register',
                                  json=incomplete_user,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_rate_limiting(self):
        """Rate limiting testi"""
        # Çok fazla istek gönder
        for _ in range(15):  # Limit 10
            response = self.client.post('/api/auth/login',
                                      json={'username': 'test', 'password': 'test'},
                                      content_type='application/json')
        
        # Son istek rate limit hatası döndürmeli
        self.assertEqual(response.status_code, 429)
        data = json.loads(response.data)
        self.assertIn('error', data)

if __name__ == '__main__':
    # Test suite'ini çalıştır
    unittest.main(verbosity=2) 