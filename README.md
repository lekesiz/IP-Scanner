# IP Scanner V3.3 - Gelişmiş Ağ Tarayıcı

Profesyonel ağ tarama ve cihaz tespit aracı. Desktop ve web arayüzleri ile kapsamlı ağ analizi yapabilir.

## 🚀 Özellikler

### V3.3 - Gelişmiş Cihaz Tespiti
- **Nmap Entegrasyonu**: OS fingerprinting ve servis tespiti
- **DHCP Keşfi**: DHCP protokolü ile cihaz tespiti
- **NetBIOS Keşfi**: Windows ağlarında cihaz tespiti
- **mDNS Keşfi**: Apple cihazları ve Bonjour protokolü
- **HTTP Fingerprinting**: Web servisleri tespiti
- **Gelişmiş Cihaz Sınıflandırma**: OS, servis ve MAC tabanlı tespit
- **Güven Seviyesi**: Cihaz tespit doğruluğu yüzdesi

### V3.2 - Raporlama ve E-posta
- **PDF Raporları**: Detaylı PDF raporları
- **HTML Raporları**: Web tabanlı raporlar
- **E-posta Gönderimi**: SMTP ile otomatik rapor gönderimi
- **İnteraktif Grafikler**: Matplotlib ile görsel raporlar
- **Rapor Paneli**: Web arayüzünde rapor yönetimi

### V3.1 - Web Arayüzü ve Görselleştirme
- **Flask Web Arayüzü**: Modern web tabanlı kullanıcı arayüzü
- **REST API**: Tam API desteği
- **Ağ Görselleştirmesi**: NetworkX ve Pyvis ile interaktif ağ haritası
- **Gerçek Zamanlı İstatistikler**: Ağ durumu ve cihaz istatistikleri
- **Responsive Tasarım**: Mobil uyumlu arayüz

### V2 - Gelişmiş Özellikler
- **Port Tarama**: Açık port tespiti
- **Cihaz Türü Tespiti**: Otomatik cihaz sınıflandırma
- **Sonuç Kaydetme**: JSON formatında sonuç saklama
- **Gelişmiş Filtreleme**: IP, MAC, vendor bazlı filtreleme
- **Gerçek Zamanlı İzleme**: Sürekli ağ izleme
- **Modern GUI**: Tkinter tabanlı gelişmiş arayüz

### V1 - Temel Özellikler
- **ARP Tarama**: Hızlı ağ tarama
- **MAC Vendor Lookup**: Cihaz üretici bilgisi
- **Basit GUI**: Tkinter arayüzü
- **Sonuç Görüntüleme**: Tablo formatında sonuçlar

## 📋 Gereksinimler

```bash
# Temel gereksinimler
scapy>=2.5.0
requests>=2.28.0

# Web arayüzü
flask>=3.0.0
jinja2>=3.0.0

# Görselleştirme
networkx>=3.0
pyvis>=0.3.1

# Raporlama
reportlab>=4.0.0
matplotlib>=3.5.0

# Gelişmiş tarama (V3.3)
python-nmap>=0.7.1
pyshark>=0.6
scapy-http>=1.8.2
```

## 🛠️ Kurulum

### 1. Repository'yi Klonlayın
```bash
git clone https://github.com/kullaniciadi/IP_Scan.git
cd IP_Scan
```

### 2. Sanal Ortam Oluşturun
```bash
python -m venv scanner-venv
source scanner-venv/bin/activate  # Linux/Mac
# veya
scanner-venv\Scripts\activate     # Windows
```

### 3. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 4. Nmap Kurulumu (V3.3 için)
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Windows
# https://nmap.org/download.html adresinden indirin
```

## 🚀 Kullanım

### Web Arayüzü (Önerilen)
```bash
cd webapp
python app.py
```
Tarayıcınızda `http://localhost:5000` adresine gidin.

### Desktop Uygulaması
```bash
# V2 - Gelişmiş GUI
python scanner_v2.py

# V1 - Temel GUI
python scanner.py
```

## 📊 Özellik Karşılaştırması

| Özellik | V1 | V2 | V3.1 | V3.2 | V3.3 |
|---------|----|----|----|----|----|
| ARP Tarama | ✅ | ✅ | ✅ | ✅ | ✅ |
| Port Tarama | ❌ | ✅ | ✅ | ✅ | ✅ |
| Web Arayüzü | ❌ | ❌ | ✅ | ✅ | ✅ |
| Ağ Görselleştirme | ❌ | ❌ | ✅ | ✅ | ✅ |
| PDF Raporları | ❌ | ❌ | ❌ | ✅ | ✅ |
| E-posta Gönderimi | ❌ | ❌ | ❌ | ✅ | ✅ |
| Nmap Entegrasyonu | ❌ | ❌ | ❌ | ❌ | ✅ |
| DHCP/NetBIOS/mDNS | ❌ | ❌ | ❌ | ❌ | ✅ |
| Gelişmiş Cihaz Tespiti | ❌ | ❌ | ❌ | ❌ | ✅ |

## 🔧 API Kullanımı

### Temel Tarama
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"ip_range": "192.168.1.0/24", "port_scan": true}'
```

### Gelişmiş Tarama
```bash
curl -X POST http://localhost:5000/api/advanced-scan \
  -H "Content-Type: application/json" \
  -d '{
    "ip_range": "192.168.1.0/24",
    "enable_nmap": true,
    "enable_dhcp": true,
    "enable_netbios": true,
    "enable_mdns": true
  }'
```

### Cihaz Detayları
```bash
curl http://localhost:5000/api/device-details/192.168.1.1
```

### Rapor Oluşturma
```bash
curl -X POST http://localhost:5000/api/generate-reports
```

## 📁 Proje Yapısı

```
IP_Scan/
├── scanner.py              # V1 - Temel tarayıcı
├── scanner_v2.py           # V2 - Gelişmiş tarayıcı
├── setup.py               # V1 kurulum
├── setup_v2.py            # V2 kurulum
├── requirements.txt       # Python bağımlılıkları
├── webapp/               # Web arayüzü (V3.x)
│   ├── app.py            # Flask uygulaması
│   ├── advanced_scanner.py # Gelişmiş tarama (V3.3)
│   ├── network_visualizer.py # Ağ görselleştirme
│   ├── report_generator.py   # Rapor oluşturma
│   ├── templates/
│   │   └── index.html    # Web arayüzü
│   └── static/           # Statik dosyalar
├── reports/              # Oluşturulan raporlar
└── README.md
```

## 🎯 Kullanım Senaryoları

### 1. Ağ Yöneticileri
- Ağ envanteri oluşturma
- Güvenlik taraması
- Cihaz tespiti ve sınıflandırma

### 2. Sistem Yöneticileri
- Sunucu keşfi
- Servis tespiti
- Ağ topolojisi analizi

### 3. Güvenlik Uzmanları
- Penetrasyon testi
- Açık port analizi
- OS fingerprinting

### 4. IT Destek
- Cihaz sorun giderme
- Ağ bağlantı kontrolü
- Rapor oluşturma

## 🔒 Güvenlik

- Sadece kendi ağınızda kullanın
- Gerekli izinleri alın
- Güvenlik politikalarına uyun
- Test ortamında deneyin

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Push yapın (`git push origin feature/AmazingFeature`)
5. Pull Request açın

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 🆘 Destek

- **GitHub Issues**: Hata bildirimi ve özellik istekleri
- **Dokümantasyon**: Bu README dosyası
- **Örnekler**: `examples/` klasörü

## 🔄 Güncellemeler

### V3.3 (Güncel)
- Nmap entegrasyonu eklendi
- DHCP, NetBIOS, mDNS protokolleri
- Gelişmiş cihaz tespiti
- Güven seviyesi hesaplama

### V3.2
- PDF ve HTML raporları
- E-posta gönderimi
- İnteraktif grafikler

### V3.1
- Web arayüzü
- Ağ görselleştirmesi
- REST API

### V2
- Port tarama
- Cihaz türü tespiti
- Gelişmiş GUI

### V1
- Temel ARP tarama
- Basit GUI

---

**IP Scanner V3.3** - Profesyonel ağ tarama çözümü 🚀 