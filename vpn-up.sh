#!/bin/bash
GATEWAY="192.168.0.1"
VPS_IP="176.124.203.112"
KEY_FILE="/tmp/vpn.key"

# Спрашиваем ключ или берём сохранённый
if [ -f "$KEY_FILE" ]; then
    SAVED_KEY=$(cat $KEY_FILE)
    echo "Сохранённый ключ: ${SAVED_KEY:0:16}..."
    read -p "Использовать сохранённый? (y/n): " USE_SAVED
    if [ "$USE_SAVED" != "y" ]; then
        read -p "Введи новый ключ сервера: " SERVER_KEY
    else
        SERVER_KEY=$SAVED_KEY
    fi
else
    read -p "Введи ключ сервера: " SERVER_KEY
fi

# Сохраняем ключ
echo $SERVER_KEY > $KEY_FILE

# Запускаем туннель в фоне
sudo ~/noise-tunnel/target/release/noise-tunnel client --server-key $SERVER_KEY &
TUN_PID=$!
echo $TUN_PID > /tmp/vpn.pid

# Ждём пока поднимется tun0
echo "Подключаюсь..."
sleep 4

# Настраиваем маршруты
sudo ip route add $VPS_IP via $GATEWAY 2>/dev/null
sudo ip route del default 2>/dev/null
sudo ip route add default dev tun0
sudo sh -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'

echo "✓ VPN включён! IP: $(curl -s ifconfig.me)"
