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
echo "║     NOISE TUNNEL — УСТАНОВКА КЛИЕНТА     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

[ "$EUID" -ne 0 ] && err "Запусти от root: sudo bash client-setup.sh"

# Определяем реального пользователя (не root)
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
info "Пользователь: $REAL_USER ($REAL_HOME)"

# Проверяем бинарник
BINARY="$REAL_HOME/noise-tunnel/target/release/noise-tunnel"
[ ! -f "$BINARY" ] && err "Бинарник не найден: $BINARY\nСначала собери: cd ~/noise-tunnel && cargo build --release"

# ─── Зависимости ──────────────────────────────────────────────
log "Устанавливаю зависимости..."
apt update -qq
apt install -y -qq iproute2 dnsutils

# ─── vpn-routes.sh ────────────────────────────────────────────
log "Устанавливаю vpn-routes.sh..."

cat > /usr/local/bin/vpn-routes.sh << 'SCRIPT'
#!/bin/bash
ACTION="$1"

case "$ACTION" in
    up)
        VPS_HOST="$2"
        CLIENT_IP="$3"

        if [ -z "$VPS_HOST" ] || [ -z "$CLIENT_IP" ]; then
            echo "Ошибка: vpn-routes.sh up <vps_host> <client_ip>" >&2
            exit 1
        fi

        # Резолвим домен в IP если передан не IP
        if echo "$VPS_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            VPS_IP="$VPS_HOST"
        else
            VPS_IP=$(getent hosts "$VPS_HOST" | awk '{print $1}' | head -1)
            if [ -z "$VPS_IP" ]; then
                VPS_IP=$(dig +short "$VPS_HOST" | tail -1)
            fi
            if [ -z "$VPS_IP" ]; then
                echo "Ошибка: не удалось резолвить $VPS_HOST" >&2
                exit 1
            fi
        fi

        GATEWAY=$(ip route show default | awk '/default/ {print $3}' | head -1)
        IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)

        if [ -z "$GATEWAY" ] || [ -z "$IFACE" ]; then
            echo "Ошибка: не удалось определить gateway или интерфейс" >&2
            exit 1
        fi

        # Сохраняем для восстановления
        echo "$GATEWAY" > /tmp/vpn.gw
        echo "$IFACE"   > /tmp/vpn.iface
        echo "$VPS_IP"  > /tmp/vpn.vps_ip

        # Маршрут до VPS напрямую — до смены default route
        ip route add "$VPS_IP" via "$GATEWAY" dev "$IFACE" 2>/dev/null || true

        # Ждём появления tun0 (до 5 секунд)
        for i in $(seq 1 10); do
            if ip link show tun0 > /dev/null 2>&1; then
                break
            fi
            sleep 0.5
        done

        if ! ip link show tun0 > /dev/null 2>&1; then
            echo "Ошибка: tun0 не появился за 5 секунд" >&2
            ip route del "$VPS_IP" 2>/dev/null || true
            exit 1
        fi

        # Направляем весь трафик через tun0
        ip route del default 2>/dev/null || true
        ip route add default dev tun0

        # DNS через VPN
        echo "nameserver 8.8.8.8" > /etc/resolv.conf

        echo "OK vps=$VPS_IP gateway=$GATEWAY iface=$IFACE"
        ;;

    down)
        GATEWAY=$(cat /tmp/vpn.gw    2>/dev/null | tr -d '[:space:]')
        IFACE=$(cat /tmp/vpn.iface   2>/dev/null | tr -d '[:space:]')
        VPS_IP=$(cat /tmp/vpn.vps_ip 2>/dev/null | tr -d '[:space:]')

        ip route del default     2>/dev/null || true
        ip route del "$VPS_IP"   2>/dev/null || true

        if [ -n "$GATEWAY" ] && [ -n "$IFACE" ]; then
            ip route add default via "$GATEWAY" dev "$IFACE"
        fi

        echo "nameserver 1.1.1.1" > /etc/resolv.conf

        rm -f /tmp/vpn.gw /tmp/vpn.iface /tmp/vpn.vps_ip

        echo "OK restored gateway=$GATEWAY iface=$IFACE"
        ;;

    *)
        echo "Использование: vpn-routes.sh up <vps_host> <client_ip> | down" >&2
        exit 1
        ;;
esac
SCRIPT

chmod +x /usr/local/bin/vpn-routes.sh
log "vpn-routes.sh установлен в /usr/local/bin/"

# ─── sudoers ──────────────────────────────────────────────────
log "Настраиваю sudoers..."

SUDOERS_FILE="/etc/sudoers.d/noise-tunnel"
echo "$REAL_USER ALL=(ALL) NOPASSWD: /usr/local/bin/vpn-routes.sh" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"

# Проверяем что sudoers валиден
if visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
    log "sudoers настроен: $REAL_USER может запускать vpn-routes.sh без пароля"
else
    err "Ошибка в sudoers файле — удаляю"
    rm -f "$SUDOERS_FILE"
fi

# ─── cap_net_admin ────────────────────────────────────────────
log "Выдаю cap_net_admin бинарнику..."
setcap cap_net_admin+ep "$BINARY"
log "cap_net_admin выдан: $BINARY"

# ─── Итог ─────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║              ГОТОВО!                     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
info "vpn-routes.sh:  /usr/local/bin/vpn-routes.sh"
info "sudoers:        /etc/sudoers.d/noise-tunnel"
info "cap_net_admin:  $BINARY"
echo ""
log "Запускай без sudo:"
echo ""
echo "  ~/noise-tunnel/target/release/noise-tunnel tui"
echo ""
