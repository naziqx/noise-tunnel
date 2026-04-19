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
                # Fallback через /etc/resolv.conf ещё не перезаписан
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

        # Маршрут до VPS напрямую — ОБЯЗАТЕЛЬНО до смены default route
        ip route add "$VPS_IP" via "$GATEWAY" dev "$IFACE" 2>/dev/null || true

        # Направляем весь остальной трафик через tun0
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

        ip route del default       2>/dev/null || true
        ip route del "$VPS_IP"     2>/dev/null || true

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
