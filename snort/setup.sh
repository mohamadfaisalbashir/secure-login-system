#!/bin/bash

# 1. Update Rule dari Komunitas
echo "Mengunduh rule komunitas terbaru..."
mkdir -p /etc/snort/rules/community
wget -qO- https://www.snort.org/downloads/community/community-rules.tar.gz | tar -xz -C /tmp/
cp /tmp/community-rules/community.rules /etc/snort/rules/community/
echo "include \$RULE_PATH/community/community.rules" >> /etc/snort/snort.conf

# 2. TUNGGU WEB SERVER SIAP (Ini perbaikannya)
echo "Menunggu container web_faisal siap..."
while ! getent hosts web_faisal; do
  sleep 1
done
WEB_IP=$(getent hosts web_faisal | awk '{ print $1 }')
echo "IP web_faisal ditemukan: $WEB_IP"

# 3. IP Forwarding & ACL
sysctl -w net.ipv4.ip_forward=1

iptables -F
iptables -t nat -F

# Pastikan default policy mengizinkan forwarding untuk jalur yang sah
iptables -P FORWARD ACCEPT

# Port Forwarding: Arahkan trafik masuk (port 8080) ke IP Web Server
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination $WEB_IP:8080
iptables -t nat -A POSTROUTING -j MASQUERADE

# ACL untuk mencegah ICMP Flood dari dmz-network
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

iptables -A FORWARD -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
iptables -A FORWARD -p icmp -j DROP

# 4. Jalankan Snort di eth0
echo "Menjalankan Snort IDS..."
snort -q -c /etc/snort/snort.conf -i eth0 -A console