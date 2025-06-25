# IP Scanner - Ağ Tarama Uygulaması

Modern ve kullanıcı dostu bir ağ tarama uygulaması. ARP protokolü kullanarak yerel ağdaki cihazları tespit eder ve MAC adreslerinden üretici bilgilerini çeker.

## 🚀 Özellikler

- **Hızlı Ağ Tarama**: ARP protokolü ile saniyeler içinde ağ taraması
- **MAC Vendor Lookup**: MAC adreslerinden otomatik üretici bilgisi
- **Modern GUI**: Tkinter tabanlı kullanıcı dostu arayüz
- **Port Tarama**: Belirli portların açık olup olmadığını kontrol etme
- **Cihaz Türü Tespiti**: Router, PC, mobil cihaz vb. sınıflandırma
- **Kaydetme Özelliği**: Tarama sonuçlarını CSV/JSON formatında kaydetme
- **Gelişmiş Filtreleme**: IP aralığı, MAC prefix vb. filtreleme
- **Gerçek Zamanlı İzleme**: Sürekli ağ izleme modu
- **Çoklu İş Parçacığı**: UI donma önleme
- **Cache Sistemi**: Performans optimizasyonu

## 📋 Gereksinimler

- Python 3.7+
- macOS, Windows, Linux

## 🛠️ Kurulum

### 1. Repository'yi klonlayın
```bash
git clone https://github.com/lekesiz/IP-Scanner.git
cd IP-Scanner
```

### 2. Sanal ortam oluşturun
```bash
python -m venv scanner-venv
source scanner-venv/bin/activate  # macOS/Linux
# veya
scanner-venv\Scripts\activate  # Windows
```

### 3. Bağımlılıkları yükleyin
```bash
pip install -r requirements.txt
```

## 🎯 Kullanım

### Temel Kullanım
```bash
python scanner.py
```

### Gelişmiş Özellikler
- **IP Aralığı Belirtme**: Varsayılan `192.168.1.0/24`
- **Port Tarama**: Belirli portları kontrol etme
- **Sonuçları Kaydetme**: CSV/JSON formatında dışa aktarma
- **Filtreleme**: Cihaz türü, IP aralığı vb. filtreleme

## 📁 Proje Yapısı

```
IP-Scanner/
├── scanner.py          # Ana uygulama
├── scanner_v2.py       # Gelişmiş V2 sürümü
├── setup.py           # Paketleme konfigürasyonu
├── requirements.txt   # Python bağımlılıkları
├── README.md         # Bu dosya
└── .gitignore        # Git ignore dosyası
```

## 🔧 Gelişmiş Özellikler

### Port Tarama
- TCP SYN tarama
- Yaygın portlar (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995)
- Özel port aralığı belirtme

### Cihaz Türü Tespiti
- Router/Modem tespiti
- Bilgisayar tespiti
- Mobil cihaz tespiti
- IoT cihaz tespiti

### Veri Kaydetme
- CSV formatında dışa aktarma
- JSON formatında dışa aktarma
- Otomatik dosya adlandırma

### Gerçek Zamanlı İzleme
- Sürekli ağ izleme
- Yeni cihaz tespiti
- Cihaz çıkış tespiti

## 🚨 Güvenlik

Bu uygulama sadece kendi ağınızda kullanılmalıdır. Başkalarının ağlarını izinsiz taramak yasal değildir.

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Branch'e push yapın (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## 📞 İletişim

- GitHub: [@lekesiz](https://github.com/lekesiz)

## 🙏 Teşekkürler

- [Scapy](https://scapy.net/) - Ağ paket manipülasyonu
- [MAC Vendors API](https://api.macvendors.com/) - MAC vendor bilgileri
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - GUI framework 