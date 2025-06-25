#!/bin/bash

# IP Scanner V4.0 - Status Script
# Uygulama durumu kontrol scripti

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Script dizinini al
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  IP Scanner V4.0 DURUM RAPORU${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# 1. PID DOSYASI KONTROLÜ
PID_FILE="$SCRIPT_DIR/ip_scanner.pid"
if [ -f "$PID_FILE" ]; then
    APP_PID=$(cat "$PID_FILE")
    if ps -p "$APP_PID" > /dev/null 2>&1; then
        success "PID dosyası mevcut: $APP_PID"
        info "Süreç durumu: ÇALIŞIYOR"
        
        # Süreç detayları
        PROCESS_INFO=$(ps -p "$APP_PID" -o pid,ppid,user,%cpu,%mem,vsz,rss,start,etime,command --no-headers 2>/dev/null || echo "Bilgi alınamadı")
        if [ "$PROCESS_INFO" != "Bilgi alınamadı" ]; then
            echo -e "${CYAN}Süreç detayları:${NC}"
            echo "$PROCESS_INFO" | while IFS= read -r line; do
                echo "  $line"
            done
        fi
    else
        warning "PID dosyası mevcut ama süreç çalışmıyor: $APP_PID"
        info "Önerilen aksiyon: ./stop.sh ile temizlik yapın"
    fi
else
    info "PID dosyası bulunamadı"
fi

echo ""

# 2. PORT KONTROLÜ
PORT=5001
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    PORT_PIDS=$(lsof -Pi :$PORT -sTCP:LISTEN -t)
    success "Port $PORT kullanımda"
    info "Port $PORT'u kullanan süreçler: $PORT_PIDS"
    
    # Port detayları
    PORT_INFO=$(lsof -Pi :$PORT -sTCP:LISTEN 2>/dev/null || echo "Port bilgisi alınamadı")
    if [ "$PORT_INFO" != "Port bilgisi alınamadı" ]; then
        echo -e "${CYAN}Port detayları:${NC}"
        echo "$PORT_INFO" | while IFS= read -r line; do
            echo "  $line"
        done
    fi
else
    info "Port $PORT boş"
fi

echo ""

# 3. PYTHON SÜREÇLERİ
log "Python süreçleri kontrol ediliyor..."
PYTHON_PROCESSES=$(ps aux | grep -E "python.*app\.py|python.*scanner" | grep -v grep || echo "Python süreci bulunamadı")

if [ "$PYTHON_PROCESSES" != "Python süreci bulunamadı" ]; then
    success "Python süreçleri bulundu:"
    echo "$PYTHON_PROCESSES" | while IFS= read -r line; do
        echo "  $line"
    done
else
    info "Python süreci bulunamadı"
fi

echo ""

# 4. DOSYA VE DİZİN KONTROLÜ
log "Dosya ve dizin kontrolü yapılıyor..."

# Gerekli dosyalar
REQUIRED_FILES=(
    "webapp/app.py"
    "webapp/constants.py"
    "webapp/user_management.py"
    "webapp/device_detector.py"
    "webapp/network_visualizer.py"
    "webapp/advanced_scanner.py"
    "webapp/report_generator.py"
    "requirements.txt"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        success "✓ $file"
    else
        error "✗ $file"
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo ""
    warning "Eksik dosyalar: ${MISSING_FILES[*]}"
fi

echo ""

# 5. DİZİN KONTROLÜ
REQUIRED_DIRS=(
    "webapp"
    "webapp/reports"
    "webapp/logs"
    "webapp/temp"
    "tests"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        success "✓ $dir/"
    else
        warning "✗ $dir/ (oluşturulacak)"
    fi
done

echo ""

# 6. VERİTABANI KONTROLÜ
log "Veritabanı kontrol ediliyor..."
if [ -f "webapp/users.db" ]; then
    DB_SIZE=$(du -h webapp/users.db | cut -f1)
    success "Veritabanı mevcut: $DB_SIZE"
    
    # Veritabanı kilidi kontrolü
    if [ -f "webapp/users.db-journal" ]; then
        warning "Veritabanı journal dosyası mevcut (kilit)"
    else
        success "Veritabanı kilitli değil"
    fi
else
    info "Veritabanı bulunamadı"
fi

echo ""

# 7. LOG DOSYALARI
log "Log dosyaları kontrol ediliyor..."
LOG_FILES=(
    "logs/app.log"
    "webapp/logs/app.log"
    "ip_scanner.log"
)

for log_file in "${LOG_FILES[@]}"; do
    if [ -f "$log_file" ]; then
        LOG_SIZE=$(du -h "$log_file" | cut -f1)
        LOG_LINES=$(wc -l < "$log_file" 2>/dev/null || echo "0")
        success "✓ $log_file ($LOG_SIZE, $LOG_LINES satır)"
    else
        info "✗ $log_file"
    fi
done

echo ""

# 8. SİSTEM KAYNAKLARI
log "Sistem kaynakları kontrol ediliyor..."

# Memory kullanımı
MEMORY_USAGE=$(ps aux | grep -E "python.*app\.py|python.*scanner" | grep -v grep | awk '{sum+=$6} END {print sum/1024 " MB"}' || echo "0 MB")
info "Memory kullanımı: $MEMORY_USAGE"

# CPU kullanımı
CPU_USAGE=$(ps aux | grep -E "python.*app\.py|python.*scanner" | grep -v grep | awk '{sum+=$3} END {print sum "%"}' || echo "0%")
info "CPU kullanımı: $CPU_USAGE"

# Disk kullanımı
DISK_USAGE=$(du -sh . 2>/dev/null | cut -f1 || echo "Unknown")
info "Proje disk kullanımı: $DISK_USAGE"

echo ""

# 9. AĞ BAĞLANTILARI
log "Ağ bağlantıları kontrol ediliyor..."
if command -v netstat &> /dev/null; then
    NETWORK_CONNECTIONS=$(netstat -an | grep :5001 | wc -l)
    info "Port 5001 bağlantı sayısı: $NETWORK_CONNECTIONS"
elif command -v ss &> /dev/null; then
    NETWORK_CONNECTIONS=$(ss -an | grep :5001 | wc -l)
    info "Port 5001 bağlantı sayısı: $NETWORK_CONNECTIONS"
else
    info "Ağ bağlantı bilgisi alınamadı"
fi

echo ""

# 10. VIRTUAL ENVIRONMENT
log "Virtual environment kontrol ediliyor..."
if [ -d "scanner-venv" ]; then
    success "Virtual environment mevcut"
    
    # Python versiyonu
    if [ -f "scanner-venv/bin/python" ]; then
        VENV_PYTHON_VERSION=$("scanner-venv/bin/python" --version 2>&1 || echo "Versiyon alınamadı")
        info "Virtual env Python: $VENV_PYTHON_VERSION"
    fi
else
    warning "Virtual environment bulunamadı"
fi

echo ""

# 11. ÖZET RAPOR
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  ÖZET RAPOR${NC}"
echo -e "${GREEN}================================${NC}"

# Uygulama durumu
if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then
    echo -e "Uygulama Durumu: ${GREEN}ÇALIŞIYOR${NC}"
elif lsof -Pi :5001 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "Uygulama Durumu: ${YELLOW}PORT KULLANIMDA${NC}"
else
    echo -e "Uygulama Durumu: ${RED}DURMUŞ${NC}"
fi

# Öneriler
echo ""
echo -e "${CYAN}ÖNERİLER:${NC}"
if [ -f "$PID_FILE" ] && ! ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then
    echo "  • ./stop.sh ile temizlik yapın"
fi

if [ ! -d "scanner-venv" ]; then
    echo "  • ./start.sh ile virtual environment oluşturun"
fi

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo "  • Eksik dosyaları kontrol edin"
fi

echo ""
echo -e "${GREEN}================================${NC}" 