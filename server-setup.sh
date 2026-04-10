#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[·]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     NOISE TUNNEL — УСТАНОВКА СЕРВЕРА     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

[ "$EUID" -ne 0 ] && err "Запусти от root: sudo bash server-setup.sh"

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
info "Сетевой интерфейс: $IFACE"

# ─── Обновление ───────────────────────────────────────────────
log "Обновляю пакеты..."
sudo apt update -qq && apt upgrade -y -qq

# ─── Базовые утилиты ──────────────────────────────────────────
log "Устанавливаю базовые утилиты..."
apt install -y -qq \
    curl wget git vim htop \
    build-essential pkg-config \
    libssl-dev ca-certificates \
    certbot net-tools iptables-persistent

# ─── Rust ─────────────────────────────────────────────────────
if command -v cargo &> /dev/null; then
    warn "Rust уже установлен: $(rustc --version)"
else
    log "Устанавливаю Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    source "$HOME/.cargo/env"
    log "Rust установлен: $(rustc --version)"
fi

# ─── IP forwarding ────────────────────────────────────────────
log "Включаю IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p -q
fi

# ─── iptables ─────────────────────────────────────────────────
log "Настраиваю iptables..."
iptables -F
iptables -t nat -F
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# NAT
iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT

# Разрешаем нужные порты
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 2443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Сохраняем
netfilter-persistent save
log "iptables настроен и сохранён"

# ─── TLS сертификат ───────────────────────────────────────────
DOMAIN="noise-tunnel.ddns.net"
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"

if [ -f "$CERT_PATH" ]; then
    warn "TLS сертификат уже существует — пропускаю"
else
    log "Получаю TLS сертификат для $DOMAIN..."

    # Временно останавливаем всё что занимает порт 80
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    fuser -k 80/tcp 2>/dev/null || true

    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --register-unsafely-without-email \
        -d $DOMAIN

    if [ -f "$CERT_PATH" ]; then
        log "Сертификат получен!"
        info "Сертификат: $CERT_PATH"
        info "Ключ:       /etc/letsencrypt/live/$DOMAIN/privkey.pem"
        info "Истекает:   $(openssl x509 -enddate -noout -in $CERT_PATH | cut -d= -f2)"
    else
        err "Не удалось получить сертификат — убедись что домен $DOMAIN указывает на этот сервер"
    fi
fi

# Авторенewал через cron
if ! crontab -l 2>/dev/null | grep -q certbot; then
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --pre-hook 'systemctl stop noise-tunnel' --post-hook 'systemctl start noise-tunnel'") | crontab -
    log "Авторенewал сертификата настроен (каждый день в 3:00)"
fi

# ─── Директории ───────────────────────────────────────────────
log "Создаю директории..."
mkdir -p /etc/noise-tunnel
mkdir -p /var/log/noise-tunnel
mkdir -p ~/noise-tunnel/target/release

# ─── Скрипт запуска ───────────────────────────────────────────
log "Создаю start-server.sh..."
cat > ~/start-server.sh << SCRIPT
#!/bin/bash
IFACE=\$(ip route | grep default | awk '{print \$5}' | head -1)

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -F FORWARD 2>/dev/null
iptables -t nat -A POSTROUTING -o \$IFACE -j MASQUERADE
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT

cd ~/noise-tunnel
./target/release/noise-tunnel server 2>&1 | tee -a /var/log/noise-tunnel/server.log
SCRIPT
chmod +x ~/start-server.sh

# ─── Systemd сервис ───────────────────────────────────────────
log "Создаю systemd сервис..."
cat > /etc/systemd/system/noise-tunnel.service << SERVICE
[Unit]
Description=Noise Tunnel VPN Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/root/start-server.sh
Restart=always
RestartSec=5
StandardOutput=append:/var/log/noise-tunnel/server.log
StandardError=append:/var/log/noise-tunnel/error.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable noise-tunnel > /dev/null
log "Systemd сервис создан и включён в автозапуск"

# ─── Итог ─────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║              ГОТОВО!                     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
info "Интерфейс:     $IFACE"
info "IP forwarding: включён"
info "iptables NAT:  настроен"
info "Порты:         22, 80, 443, 2443"
info "TLS домен:     noise-tunnel.ddns.net"
info "Сертификат:    /etc/letsencrypt/live/noise-tunnel.ddns.net/"
info "Авторенewал:   cron 3:00 ежедневно"
info "Логи:          /var/log/noise-tunnel/"
info "Ключи:         /etc/noise-tunnel/keys"
echo ""
log "Следующий шаг — собери бинарник и запусти:"
echo ""
echo "  cd ~/noise-tunnel && cargo build --release"
echo "  ./target/release/noise-tunnel server"
echo ""
echo ""
