#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP Scanner V4.0 - Test Runner
Tüm testleri çalıştırır ve sonuçları raporlar
"""

import unittest
import sys
import os
import time
import json
from datetime import datetime

# Test dizinini path'e ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def run_all_tests():
    """Tüm testleri çalıştırır"""
    print("🧪 IP Scanner V4.0 - Test Suite Başlatılıyor...")
    print("=" * 60)
    
    # Test başlangıç zamanı
    start_time = time.time()
    
    # Test dizinini bul
    test_dir = os.path.join(os.path.dirname(__file__), 'tests')
    
    # Test loader oluştur
    loader = unittest.TestLoader()
    
    # Test suite'leri oluştur
    test_suites = []
    
    # Temel testler
    try:
        basic_suite = loader.discover(test_dir, pattern='test_basic.py')
        test_suites.append(('Temel Testler', basic_suite))
        print("✅ Temel testler yüklendi")
    except Exception as e:
        print(f"❌ Temel testler yüklenemedi: {e}")
    
    # Integration testler
    try:
        integration_suite = loader.discover(test_dir, pattern='test_integration.py')
        test_suites.append(('Integration Testler', integration_suite))
        print("✅ Integration testler yüklendi")
    except Exception as e:
        print(f"❌ Integration testler yüklenemedi: {e}")
    
    # Test runner oluştur
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    
    # Sonuçları topla
    all_results = {
        'timestamp': datetime.now().isoformat(),
        'total_tests': 0,
        'passed': 0,
        'failed': 0,
        'errors': 0,
        'skipped': 0,
        'duration': 0,
        'suites': []
    }
    
    # Her test suite'ini çalıştır
    for suite_name, suite in test_suites:
        print(f"\n🚀 {suite_name} çalıştırılıyor...")
        print("-" * 40)
        
        try:
            result = runner.run(suite)
            
            suite_result = {
                'name': suite_name,
                'tests_run': result.testsRun,
                'failures': len(result.failures),
                'errors': len(result.errors),
                'skipped': len(result.skipped) if hasattr(result, 'skipped') else 0
            }
            
            all_results['suites'].append(suite_result)
            all_results['total_tests'] += result.testsRun
            all_results['passed'] += result.testsRun - len(result.failures) - len(result.errors)
            all_results['failed'] += len(result.failures)
            all_results['errors'] += len(result.errors)
            
            print(f"✅ {suite_name} tamamlandı: {result.testsRun} test, {len(result.failures)} başarısız, {len(result.errors)} hata")
            
        except Exception as e:
            print(f"❌ {suite_name} çalıştırılamadı: {e}")
            all_results['errors'] += 1
    
    # Toplam süreyi hesapla
    all_results['duration'] = time.time() - start_time
    
    # Sonuçları yazdır
    print("\n" + "=" * 60)
    print("📊 TEST SONUÇLARI")
    print("=" * 60)
    print(f"⏱️  Toplam Süre: {all_results['duration']:.2f} saniye")
    print(f"🧪 Toplam Test: {all_results['total_tests']}")
    print(f"✅ Başarılı: {all_results['passed']}")
    print(f"❌ Başarısız: {all_results['failed']}")
    print(f"⚠️  Hata: {all_results['errors']}")
    print(f"⏭️  Atlanan: {all_results['skipped']}")
    
    # Başarı oranı
    if all_results['total_tests'] > 0:
        success_rate = (all_results['passed'] / all_results['total_tests']) * 100
        print(f"📈 Başarı Oranı: {success_rate:.1f}%")
        
        if success_rate >= 90:
            print("🎉 Mükemmel! Testler başarıyla geçti!")
        elif success_rate >= 80:
            print("👍 İyi! Testler büyük ölçüde başarılı.")
        elif success_rate >= 70:
            print("⚠️  Orta! Bazı testler başarısız.")
        else:
            print("🚨 Düşük! Birçok test başarısız.")
    else:
        print("⚠️  Hiç test çalıştırılamadı!")
    
    # Detaylı sonuçları JSON dosyasına kaydet
    results_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Detaylı sonuçlar kaydedildi: {results_file}")
    except Exception as e:
        print(f"❌ Sonuçlar kaydedilemedi: {e}")
    
    # Çıkış kodu
    if all_results['failed'] > 0 or all_results['errors'] > 0:
        print("\n❌ Bazı testler başarısız oldu!")
        return 1
    else:
        print("\n✅ Tüm testler başarıyla geçti!")
        return 0

def run_specific_test(test_name):
    """Belirli bir testi çalıştırır"""
    print(f"🧪 {test_name} testi çalıştırılıyor...")
    
    # Test loader oluştur
    loader = unittest.TestLoader()
    
    try:
        # Test'i yükle
        test_suite = loader.loadTestsFromName(test_name)
        
        # Test runner oluştur
        runner = unittest.TextTestRunner(verbosity=2)
        
        # Test'i çalıştır
        result = runner.run(test_suite)
        
        # Sonuçları yazdır
        print(f"\n📊 Sonuç: {result.testsRun} test, {len(result.failures)} başarısız, {len(result.errors)} hata")
        
        return len(result.failures) + len(result.errors) == 0
        
    except Exception as e:
        print(f"❌ Test çalıştırılamadı: {e}")
        return False

def main():
    """Ana fonksiyon"""
    if len(sys.argv) > 1:
        # Belirli bir test çalıştır
        test_name = sys.argv[1]
        success = run_specific_test(test_name)
        return 0 if success else 1
    else:
        # Tüm testleri çalıştır
        return run_all_tests()

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code) 