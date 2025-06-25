#!/bin/bash

# IP Scanner V4.0 - Stop Script
# Güvenli durdurma ve temizlik scripti

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

log "IP Scanner V4.0 durduruluyor..."
log "Çalışma dizini: $SCRIPT_DIR"

# PID dosyası kontrolü
PID_FILE="$SCRIPT_DIR/ip_scanner.pid"
APP_PID=""

if [ -f "$PID_FILE" ]; then
    APP_PID=$(cat "$PID_FILE")
    log "PID dosyası bulundu: $APP_PID"
else
    warning "PID dosyası bulunamadı, port kontrolü yapılıyor..."
fi

# 1. ANA UYGULAMA SÜRECİNİ DURDUR
if [ -n "$APP_PID" ] && ps -p "$APP_PID" > /dev/null 2>&1; then
    log "Ana uygulama süreci durduruluyor (PID: $APP_PID)..."
    
    # Önce SIGTERM ile nazikçe durdur
    kill -TERM "$APP_PID" 2>/dev/null || true
    
    # 10 saniye bekle
    for i in {1..10}; do
        if ! ps -p "$APP_PID" > /dev/null 2>&1; then
            success "Uygulama nazikçe durduruldu"
            break
        fi
        log "Bekleniyor... ($i/10)"
        sleep 1
    done
    
    # Hala çalışıyorsa zorla durdur
    if ps -p "$APP_PID" > /dev/null 2>&1; then
        warning "Uygulama hala çalışıyor, zorla durduruluyor..."
        kill -KILL "$APP_PID" 2>/dev/null || true
        sleep 2
        
        if ps -p "$APP_PID" > /dev/null 2>&1; then
            error "Uygulama durdurulamadı!"
        else
            success "Uygulama zorla durduruldu"
        fi
    fi
else
    log "Ana uygulama süreci bulunamadı"
fi

# 2. PORT KONTROLÜ VE TEMİZLİK
PORT=5001
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    warning "Port $PORT hala kullanımda, kontrol ediliyor..."
    PORT_PIDS=$(lsof -Pi :$PORT -sTCP:LISTEN -t)
    
    for pid in $PORT_PIDS; do
        log "Port $PORT'u kullanan süreç durduruluyor (PID: $pid)..."
        kill -TERM "$pid" 2>/dev/null || true
        sleep 2
        
        if ps -p "$pid" > /dev/null 2>&1; then
            warning "Zorla durduruluyor..."
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    
    # Port kontrolü
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        error "Port $PORT hala kullanımda!"
    else
        success "Port $PORT temizlendi"
    fi
else
    success "Port $PORT zaten boş"
fi

# 3. İLGİLİ SÜREÇLERİ TEMİZLE
log "İlgili süreçler kontrol ediliyor..."

# Python süreçlerini kontrol et
PYTHON_PROCESSES=$(ps aux | grep -E "python.*app\.py|python.*scanner" | grep -v grep | awk '{print $2}' || true)

if [ -n "$PYTHON_PROCESSES" ]; then
    warning "İlgili Python süreçleri bulundu, durduruluyor..."
    for pid in $PYTHON_PROCESSES; do
        log "Python süreci durduruluyor (PID: $pid)..."
        kill -TERM "$pid" 2>/dev/null || true
        sleep 1
        if ps -p "$pid" > /dev/null 2>&1; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    success "İlgili Python süreçleri temizlendi"
fi

# 4. PID DOSYASINI TEMİZLE
if [ -f "$PID_FILE" ]; then
    rm -f "$PID_FILE"
    success "PID dosyası silindi"
fi

# 5. GEÇİCİ DOSYALARI TEMİZLE
log "Geçici dosyalar temizleniyor..."

# Python cache dosyaları
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true

# Geçici dosyalar
rm -rf webapp/temp/* 2>/dev/null || true
rm -f webapp/*.tmp 2>/dev/null || true
rm -f *.tmp 2>/dev/null || true

# Log dosyalarını temizle (opsiyonel)
if [ "$1" = "--clean-logs" ]; then
    log "Log dosyaları temizleniyor..."
    rm -f logs/*.log 2>/dev/null || true
    rm -f webapp/logs/*.log 2>/dev/null || true
    success "Log dosyaları temizlendi"
fi

# 6. VERİTABANI KİLİTLERİNİ TEMİZLE
log "Veritabanı kilidi kontrol ediliyor..."
if [ -f "webapp/users.db-journal" ]; then
    log "Veritabanı journal dosyası temizleniyor..."
    rm -f webapp/users.db-journal
    success "Veritabanı journal dosyası temizlendi"
fi

# 7. SOCKET DOSYALARINI TEMİZLE
log "Socket dosyaları kontrol ediliyor..."
find /tmp -name "*ip_scanner*" -delete 2>/dev/null || true
find /tmp -name "*flask*" -delete 2>/dev/null || true

# 8. MEMORY VE CACHE TEMİZLİĞİ
log "Memory ve cache temizliği yapılıyor..."

# macOS için
if [[ "$OSTYPE" == "darwin"* ]]; then
    # DNS cache temizle
    sudo dscacheutil -flushcache 2>/dev/null || true
    sudo killall -HUP mDNSResponder 2>/dev/null || true
fi

# 9. FİNAL KONTROL
log "Final kontrol yapılıyor..."

# Port kontrolü
if lsof -Pi :5001 -sTCP:LISTEN -t >/dev/null 2>&1; then
    error "Port 5001 hala kullanımda!"
else
    success "Port 5001 boş"
fi

# PID kontrolü
if [ -f "$PID_FILE" ]; then
    error "PID dosyası hala mevcut!"
else
    success "PID dosyası temizlendi"
fi

# Python süreç kontrolü
REMAINING_PROCESSES=$(ps aux | grep -E "python.*app\.py|python.*scanner" | grep -v grep | wc -l)
if [ "$REMAINING_PROCESSES" -gt 0 ]; then
    warning "Hala $REMAINING_PROCESSES Python süreci çalışıyor"
else
    success "Tüm Python süreçleri durduruldu"
fi

# 10. DURUM RAPORU
echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  IP Scanner V4.0 DURDURULDU${NC}"
echo -e "${GREEN}================================${NC}"
echo -e "Temizlik tamamlandı"
echo -e "Başlatmak için: ${YELLOW}./start.sh${NC}"
echo -e "${GREEN}================================${NC}"

# 11. SİSTEM KAYNAKLARINI KONTROL ET
log "Sistem kaynakları kontrol ediliyor..."

# Memory kullanımı
MEMORY_USAGE=$(ps aux | grep -E "python.*app\.py|python.*scanner" | grep -v grep | awk '{sum+=$6} END {print sum/1024 " MB"}' || echo "0 MB")
log "Memory kullanımı: $MEMORY_USAGE"

# Disk kullanımı
DISK_USAGE=$(du -sh . 2>/dev/null | cut -f1 || echo "Unknown")
log "Proje disk kullanımı: $DISK_USAGE"

success "IP Scanner V4.0 başarıyla durduruldu ve temizlendi!" 