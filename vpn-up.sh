#!/bin/bash
VPS_IP="193.233.209.188"
KEY_FILE="/tmp/vpn.key"

# Определяем gateway и интерфейс динамически
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

echo "Сеть: $IFACE | Gateway: $GATEWAY"

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

echo $SERVER_KEY > $KEY_FILE

# Сохраняем gateway для vpn-down.sh
echo "$GATEWAY" > /tmp/vpn.gw
echo "$IFACE"   > /tmp/vpn.iface

# Чистим старый IP перед запуском
rm -f /tmp/vpn.client_ip

# Запускаем туннель в фоне
sudo ~/noise-tunnel/target/release/noise-tunnel client --server-key $SERVER_KEY &
TUN_PID=$!
echo $TUN_PID > /tmp/vpn.pid

# Ждём пока tun0 поднимется (до 15 секунд)
echo "Подключаюсь..."
for i in $(seq 1 15); do
    ip link show tun0 &>/dev/null && break
    sleep 1
done

if ! ip link show tun0 &>/dev/null; then
    echo "✗ tun0 не поднялся, проверь логи"
    exit 1
fi

# Ждём пока клиент получит IP от сервера (до 10 секунд)
for i in $(seq 1 10); do
    [ -f /tmp/vpn.client_ip ] && break
    sleep 1
done

CLIENT_IP=$(cat /tmp/vpn.client_ip 2>/dev/null)
if [ -z "$CLIENT_IP" ]; then
    echo "✗ Не удалось получить IP от сервера"
    sudo kill $TUN_PID 2>/dev/null
    exit 1
fi

echo "Назначен IP: $CLIENT_IP"

# Настраиваем маршруты
sudo ip route add $VPS_IP via $GATEWAY dev $IFACE 2>/dev/null
sudo ip route del default 2>/dev/null
sudo ip route add default dev tun0
sudo sh -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'

echo "✓ VPN включён! IP: $(curl -s --max-time 5 ifconfig.me)"
