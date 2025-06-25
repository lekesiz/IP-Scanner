# IP Scanner V4.0 - Script Kullanım Kılavuzu

Bu kılavuz, IP Scanner V4.0 projesini yönetmek için kullanılan scriptlerin detaylı kullanımını açıklar.

## 📋 Scriptler

### 1. `start.sh` - Uygulama Başlatma Scripti
Güvenli ve kontrollü bir şekilde IP Scanner uygulamasını başlatır.

#### Özellikler:
- ✅ Önceki çalışan örnekleri tespit eder ve durdurur
- ✅ Python versiyonu kontrolü (3.7+ gerekli)
- ✅ Virtual environment oluşturma ve aktifleştirme
- ✅ Gereklilikleri otomatik yükleme
- ✅ Dosya ve dizin kontrolü
- ✅ Veritabanı kontrolü ve oluşturma
- ✅ Çevre değişkenlerini ayarlama
- ✅ Güvenli başlatma ve PID takibi

#### Kullanım:
```bash
./start.sh
```

#### Çıktı Örneği:
```
[2024-01-15 10:30:00] IP Scanner V4.0 başlatılıyor...
[2024-01-15 10:30:00] Çalışma dizini: /Users/mikail/Desktop/Projeler/IP_Scan
[2024-01-15 10:30:01] Önceki çalışan örnekler kontrol ediliyor...
[2024-01-15 10:30:02] Python versiyonu kontrol ediliyor...
[SUCCESS] Python versiyonu uygun: 3.11.0
[2024-01-15 10:30:03] Virtual environment kontrol ediliyor...
[2024-01-15 10:30:04] Gereklilikler kontrol ediliyor ve yükleniyor...
[SUCCESS] Gereklilikler yüklendi
[2024-01-15 10:30:05] Yetkiler kontrol ediliyor...
[SUCCESS] Uygulama başarıyla başlatıldı (PID: 12345)
[SUCCESS] Port 5001 aktif ve dinleniyor

================================
  IP Scanner V4.0 BAŞLATILDI
================================
URL: http://localhost:5001
PID: 12345
Log: logs/app.log
Durdurmak için: ./stop.sh
================================
```

---

### 2. `stop.sh` - Uygulama Durdurma Scripti
Güvenli ve kapsamlı bir şekilde IP Scanner uygulamasını durdurur ve temizlik yapar.

#### Özellikler:
- ✅ Ana uygulama sürecini nazikçe durdurma
- ✅ Port kontrolü ve temizlik
- ✅ İlgili Python süreçlerini temizleme
- ✅ PID dosyası temizliği
- ✅ Geçici dosyaları temizleme
- ✅ Veritabanı kilitlerini temizleme
- ✅ Socket dosyalarını temizleme
- ✅ Memory ve cache temizliği
- ✅ Final kontrol ve raporlama

#### Kullanım:
```bash
# Normal durdurma
./stop.sh

# Log dosyalarını da temizleyerek durdurma
./stop.sh --clean-logs
```

#### Çıktı Örneği:
```
[2024-01-15 10:35:00] IP Scanner V4.0 durduruluyor...
[2024-01-15 10:35:01] Ana uygulama süreci durduruluyor (PID: 12345)...
[SUCCESS] Uygulama nazikçe durduruldu
[2024-01-15 10:35:02] Port 5001 zaten boş
[2024-01-15 10:35:03] İlgili süreçler kontrol ediliyor...
[2024-01-15 10:35:04] Geçici dosyalar temizleniyor...
[SUCCESS] PID dosyası silindi
[2024-01-15 10:35:05] Final kontrol yapılıyor...
[SUCCESS] Port 5001 boş
[SUCCESS] PID dosyası temizlendi
[SUCCESS] Tüm Python süreçleri durduruldu

================================
  IP Scanner V4.0 DURDURULDU
================================
Temizlik tamamlandı
Başlatmak için: ./start.sh
================================
```

---

### 3. `status.sh` - Durum Kontrol Scripti
Uygulamanın mevcut durumunu detaylı bir şekilde raporlar.

#### Özellikler:
- ✅ PID dosyası ve süreç kontrolü
- ✅ Port kullanım durumu
- ✅ Python süreçleri listesi
- ✅ Dosya ve dizin kontrolü
- ✅ Veritabanı durumu
- ✅ Log dosyaları kontrolü
- ✅ Sistem kaynakları (Memory, CPU, Disk)
- ✅ Ağ bağlantıları
- ✅ Virtual environment kontrolü
- ✅ Özet rapor ve öneriler

#### Kullanım:
```bash
./status.sh
```

#### Çıktı Örneği:
```
================================
  IP Scanner V4.0 DURUM RAPORU
================================

[SUCCESS] PID dosyası mevcut: 12345
[INFO] Süreç durumu: ÇALIŞIYOR
[Süreç detayları:]
  12345 1 mikail 0.5 2.1 1234567 89012 10:30 Jan15 00:05:00 python app.py

[SUCCESS] Port 5001 kullanımda
[INFO] Port 5001'u kullanan süreçler: 12345

[SUCCESS] Python süreçleri bulundu:
  mikail 12345 1 0.5 2.1 1234567 89012 10:30 pts/0 S+ 0:05 python app.py

[SUCCESS] ✓ webapp/app.py
[SUCCESS] ✓ webapp/constants.py
[SUCCESS] ✓ requirements.txt

[SUCCESS] ✓ webapp/
[SUCCESS] ✓ webapp/reports/
[SUCCESS] ✓ webapp/logs/

[SUCCESS] Veritabanı mevcut: 32K
[SUCCESS] Veritabanı kilitli değil

[SUCCESS] ✓ logs/app.log (1.2K, 45 satır)

[INFO] Memory kullanımı: 89.01 MB
[INFO] CPU kullanımı: 0.5%
[INFO] Proje disk kullanımı: 15M

[INFO] Port 5001 bağlantı sayısı: 3

[SUCCESS] Virtual environment mevcut
[INFO] Virtual env Python: Python 3.11.0

================================
  ÖZET RAPOR
================================
Uygulama Durumu: ÇALIŞIYOR

[ÖNERİLER:]
  • Uygulama sorunsuz çalışıyor

================================
```

---

## 🔧 Gelişmiş Kullanım

### Otomatik Yeniden Başlatma
```bash
# Uygulamayı durdur ve yeniden başlat
./stop.sh && ./start.sh
```

### Log Dosyalarını Temizleme
```bash
# Uygulamayı durdur ve log dosyalarını temizle
./stop.sh --clean-logs
```

### Durum Kontrolü ve Başlatma
```bash
# Durumu kontrol et, çalışmıyorsa başlat
./status.sh && if [ $? -ne 0 ]; then ./start.sh; fi
```

### Sürekli İzleme
```bash
# Her 30 saniyede bir durum kontrolü
watch -n 30 ./status.sh
```

---

## 🚨 Hata Durumları ve Çözümler

### 1. "Permission denied" Hatası
```bash
# Scriptlere çalıştırma izni ver
chmod +x start.sh stop.sh status.sh
```

### 2. "Python3 bulunamadı" Hatası
```bash
# Python3 yükle (macOS)
brew install python3

# Python3 yükle (Ubuntu/Debian)
sudo apt update && sudo apt install python3 python3-venv
```

### 3. "Port 5001 kullanımda" Hatası
```bash
# Portu kullanan süreçleri bul ve durdur
lsof -ti:5001 | xargs kill -9
```

### 4. "Virtual environment bulunamadı" Hatası
```bash
# Manuel olarak virtual environment oluştur
python3 -m venv scanner-venv
source scanner-venv/bin/activate
pip install -r requirements.txt
```

### 5. "Veritabanı hatası" Durumu
```bash
# Veritabanını yeniden oluştur
rm -f webapp/users.db
./start.sh
```

---

## 📊 Performans İzleme

### Memory Kullanımı İzleme
```bash
# Gerçek zamanlı memory kullanımı
watch -n 1 'ps aux | grep python | grep app.py | awk "{print \$6/1024 \" MB\"}"'
```

### CPU Kullanımı İzleme
```bash
# Gerçek zamanlı CPU kullanımı
top -pid $(cat ip_scanner.pid)
```

### Log Dosyası İzleme
```bash
# Log dosyasını gerçek zamanlı izle
tail -f logs/app.log
```

---

## 🔒 Güvenlik Notları

1. **Çevre Değişkenleri**: Production ortamında `JWT_SECRET_KEY` ve `PASSWORD_SALT` değerlerini değiştirin
2. **Port Güvenliği**: Firewall ayarlarını kontrol edin
3. **Log Dosyaları**: Hassas bilgileri içerebilecek log dosyalarını düzenli olarak temizleyin
4. **PID Dosyası**: PID dosyasının güvenliğini sağlayın

---

## 📝 Log Dosyaları

### Ana Log Dosyaları:
- `logs/app.log` - Ana uygulama logları
- `webapp/logs/app.log` - Webapp logları
- `ip_scanner.log` - Genel log dosyası

### Log Seviyeleri:
- `DEBUG` - Detaylı debug bilgileri
- `INFO` - Genel bilgi mesajları
- `WARNING` - Uyarı mesajları
- `ERROR` - Hata mesajları
- `CRITICAL` - Kritik hata mesajları

---

## 🆘 Destek

Herhangi bir sorun yaşarsanız:

1. `./status.sh` ile durumu kontrol edin
2. Log dosyalarını inceleyin: `tail -f logs/app.log`
3. Gerekli dosyaların varlığını kontrol edin
4. Sistem kaynaklarını kontrol edin

---

## 📋 Hızlı Referans

| Komut | Açıklama |
|-------|----------|
| `./start.sh` | Uygulamayı başlat |
| `./stop.sh` | Uygulamayı durdur |
| `./stop.sh --clean-logs` | Uygulamayı durdur ve logları temizle |
| `./status.sh` | Durum raporu al |
| `chmod +x *.sh` | Tüm scriptlere izin ver |
| `tail -f logs/app.log` | Log dosyasını izle | 