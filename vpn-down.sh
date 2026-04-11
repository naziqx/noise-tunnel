#!/bin/bash
VPS_IP="176.124.203.112"

# Останавливаем туннель
if [ -f /tmp/vpn.pid ]; then
    sudo kill $(cat /tmp/vpn.pid) 2>/dev/null
    rm /tmp/vpn.pid
fi

# Восстанавливаем маршруты
GATEWAY=$(cat /tmp/vpn.gw 2>/dev/null)
IFACE=$(cat /tmp/vpn.iface 2>/dev/null)

sudo ip route del default 2>/dev/null
sudo ip route del $VPS_IP 2>/dev/null

if [ -n "$GATEWAY" ]; then
    sudo ip route add default via $GATEWAY dev $IFACE
    echo "Маршрут восстановлен через $GATEWAY ($IFACE)"
else
    echo "⚠ Gateway не найден, восстанови маршрут вручную: sudo ip route add default via <GATEWAY>"
fi

sudo sh -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf'

echo "✓ VPN отключён! IP: $(curl -s --max-time 5 ifconfig.me)"
