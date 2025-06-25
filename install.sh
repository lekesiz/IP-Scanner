#!/bin/bash

# IP Scanner V2 Kurulum Scripti
echo "=========================================="
echo "IP Scanner V2 - Kurulum Başlatılıyor..."
echo "=========================================="

# Python versiyonunu kontrol et
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if [[ $(echo "$python_version >= 3.7" | bc -l) -eq 0 ]]; then
    echo "❌ Hata: Python 3.7 veya üzeri gerekli. Mevcut versiyon: $python_version"
    exit 1
fi
echo "✅ Python versiyonu uygun: $python_version"

# Sanal ortam oluştur
echo "📦 Sanal ortam oluşturuluyor..."
python3 -m venv scanner-venv

# Sanal ortamı aktifleştir
echo "🔧 Sanal ortam aktifleştiriliyor..."
source scanner-venv/bin/activate

# Bağımlılıkları yükle
echo "📥 Bağımlılıklar yükleniyor..."
pip install --upgrade pip
pip install -r requirements.txt

# Kurulum tamamlandı
echo "=========================================="
echo "✅ Kurulum tamamlandı!"
echo "=========================================="
echo ""
echo "Kullanım:"
echo "1. Sanal ortamı aktifleştir: source scanner-venv/bin/activate"
echo "2. V1 çalıştır: python scanner.py"
echo "3. V2 çalıştır: python scanner_v2.py"
echo ""
echo "macOS .app dosyası oluşturmak için:"
echo "python setup_v2.py py2app"
echo "==========================================" 