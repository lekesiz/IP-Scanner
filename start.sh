#!/bin/bash

# IP Scanner V4.0 - Start Script
# Güvenli başlatma ve kontrol scripti

set -e  # Hata durumunda dur

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log fonksiyonu
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Script dizinini al
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log "IP Scanner V4.0 başlatılıyor..."
log "Çalışma dizini: $SCRIPT_DIR"

# 1. ÖNCEKİ ÖRNEKLERİ KONTROL ET VE DURDUR
log "Önceki çalışan örnekler kontrol ediliyor..."

# PID dosyası kontrolü
PID_FILE="$SCRIPT_DIR/ip_scanner.pid"
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        warning "Önceki örnek bulundu (PID: $OLD_PID), durduruluyor..."
        kill -TERM "$OLD_PID" 2>/dev/null || true
        sleep 2
        if ps -p "$OLD_PID" > /dev/null 2>&1; then
            warning "Zorla durduruluyor..."
            kill -KILL "$OLD_PID" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
        success "Önceki örnek durduruldu"
    else
        log "PID dosyası bulundu ama süreç çalışmıyor, temizleniyor..."
        rm -f "$PID_FILE"
    fi
fi

# Port kontrolü
PORT=5001
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    warning "Port $PORT kullanımda, kontrol ediliyor..."
    PORT_PID=$(lsof -Pi :$PORT -sTCP:LISTEN -t)
    if [ -n "$PORT_PID" ]; then
        warning "Port $PORT'u kullanan süreç bulundu (PID: $PORT_PID), durduruluyor..."
        kill -TERM "$PORT_PID" 2>/dev/null || true
        sleep 2
        if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
            warning "Zorla durduruluyor..."
            kill -KILL "$PORT_PID" 2>/dev/null || true
        fi
        success "Port $PORT temizlendi"
    fi
fi

# 2. PYTHON VERSIYONU KONTROL ET
log "Python versiyonu kontrol ediliyor..."
if ! command -v python3 &> /dev/null; then
    error "Python3 bulunamadı! Lütfen Python 3.7+ yükleyin."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    error "Python 3.7+ gerekli! Mevcut versiyon: $PYTHON_VERSION"
    exit 1
fi

success "Python versiyonu uygun: $PYTHON_VERSION"

# 3. VIRTUAL ENVIRONMENT KONTROL ET
log "Virtual environment kontrol ediliyor..."
if [ ! -d "scanner-venv" ]; then
    log "Virtual environment bulunamadı, oluşturuluyor..."
    python3 -m venv scanner-venv
    success "Virtual environment oluşturuldu"
fi

# Virtual environment'ı aktifleştir
source scanner-venv/bin/activate

# 4. GEREKLİLİKLERİ YÜKLE
log "Gereklilikler kontrol ediliyor ve yükleniyor..."
if [ ! -f "requirements.txt" ]; then
    error "requirements.txt dosyası bulunamadı!"
    exit 1
fi

# pip'i güncelle
python -m pip install --upgrade pip

# Gereklilikleri yükle
pip install -r requirements.txt

success "Gereklilikler yüklendi"

# 5. YETKİLERİ KONTROL ET
log "Yetkiler kontrol ediliyor..."

# Webapp dizini kontrolü
if [ ! -d "webapp" ]; then
    error "webapp dizini bulunamadı!"
    exit 1
fi

# Gerekli dosyaları kontrol et
REQUIRED_FILES=(
    "webapp/app.py"
    "webapp/constants.py"
    "webapp/user_management.py"
    "webapp/device_detector.py"
    "webapp/network_visualizer.py"
    "webapp/advanced_scanner.py"
    "webapp/report_generator.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        error "Gerekli dosya bulunamadı: $file"
        exit 1
    fi
done

# Dizinler oluştur
mkdir -p webapp/reports
mkdir -p webapp/logs
mkdir -p webapp/temp

# Dosya izinlerini kontrol et
log "Dosya izinleri kontrol ediliyor..."
chmod +x webapp/app.py 2>/dev/null || true

# 6. VERITABANI KONTROL ET
log "Veritabanı kontrol ediliyor..."
if [ ! -f "webapp/users.db" ]; then
    log "Veritabanı bulunamadı, oluşturuluyor..."
    python3 -c "
import sys
sys.path.insert(0, 'webapp')
from user_management import user_manager
print('Veritabanı oluşturuldu')
"
    success "Veritabanı oluşturuldu"
else
    success "Veritabanı mevcut"
fi

# 7. ÇEVRE DEĞİŞKENLERİNİ AYARLA
log "Çevre değişkenleri ayarlanıyor..."
export JWT_SECRET_KEY="${JWT_SECRET_KEY:-ip_scanner_secret_key_2024_change_in_production}"
export PASSWORD_SALT="${PASSWORD_SALT:-default_salt_change_in_production}"
export FLASK_ENV="development"
export FLASK_DEBUG="False"

# 8. UYGULAMAYI BAŞLAT
log "Uygulama başlatılıyor..."

# Arka planda çalıştır
cd webapp
nohup python app.py > ../logs/app.log 2>&1 &
APP_PID=$!

# PID'yi kaydet
echo $APP_PID > ../ip_scanner.pid

# Başlatma kontrolü
sleep 3
if ps -p $APP_PID > /dev/null; then
    success "Uygulama başarıyla başlatıldı (PID: $APP_PID)"
    log "Uygulama URL: http://localhost:5001"
    log "Log dosyası: logs/app.log"
    log "PID dosyası: ip_scanner.pid"
    
    # Port kontrolü
    if lsof -Pi :5001 -sTCP:LISTEN -t >/dev/null 2>&1; then
        success "Port 5001 aktif ve dinleniyor"
    else
        warning "Port 5001 henüz aktif değil, biraz bekleyin..."
    fi
    
    echo ""
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  IP Scanner V4.0 BAŞLATILDI${NC}"
    echo -e "${GREEN}================================${NC}"
    echo -e "URL: ${BLUE}http://localhost:5001${NC}"
    echo -e "PID: ${BLUE}$APP_PID${NC}"
    echo -e "Log: ${BLUE}logs/app.log${NC}"
    echo -e "Durdurmak için: ${YELLOW}./stop.sh${NC}"
    echo -e "${GREEN}================================${NC}"
    
else
    error "Uygulama başlatılamadı!"
    log "Log dosyasını kontrol edin: logs/app.log"
    exit 1
fi 