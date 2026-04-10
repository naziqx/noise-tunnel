#!/bin/bash
GATEWAY="192.168.0.1"
VPS_IP="176.124.199.31"

# Останавливаем туннель
if [ -f /tmp/vpn.pid ]; then
    sudo kill $(cat /tmp/vpn.pid) 2>/dev/null
    rm /tmp/vpn.pid
fi

# Восстанавливаем маршруты
sudo ip route del default 2>/dev/null
sudo ip route add default via $GATEWAY
sudo sh -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf'

echo "✓ VPN отключён! IP: $(curl -s ifconfig.me)"
