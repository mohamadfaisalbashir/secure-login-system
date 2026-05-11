#!/bin/bash

# 1. Update Rule dari Komunitas
echo "Mengunduh rule komunitas terbaru..."
mkdir -p /etc/snort/rules/community
wget -qO- https://www.snort.org/downloads/community/community-rules.tar.gz | tar -xz -C /tmp/
cp /tmp/community-rules/community.rules /etc/snort/rules/community/
echo "include \$RULE_PATH/community/community.rules" >> /etc/snort/snort.conf

# 2. TUNGGU WEB SERVER SIAP
echo "Menunggu container web_faisal siap..."
while ! getent hosts web_faisal; do
  sleep 1
done
WEB_IP=$(getent hosts web_faisal | awk '{ print $1 }')
echo "IP web_faisal ditemukan: $WEB_IP"

# 3. IP Forwarding & Routing
sysctl -w net.ipv4.ip_forward=1

iptables -F
iptables -t nat -F

# Pastikan default policy mengizinkan forwarding
iptables -P FORWARD ACCEPT

# Port Forwarding: Arahkan trafik masuk port 8080 ke web_faisal
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination $WEB_IP:8080
iptables -t nat -A POSTROUTING -j MASQUERADE

# ============================================================
# IPS: Pemblokiran serangan via iptables string matching
# (Bekerja di level packet FORWARD sebelum sampai ke web server)
# ============================================================

# Blokir SQL Injection
iptables -A FORWARD -p tcp --dport 8080 -m string --string "UNION SELECT" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "UNION select" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "union select" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "OR 1=1" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "or 1=1" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "DROP TABLE" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "'; --" --algo bm --to 65535 -j REJECT --reject-with tcp-reset

# Blokir XSS
iptables -A FORWARD -p tcp --dport 8080 -m string --string "<script" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "<SCRIPT" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "javascript:" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "onerror=" --algo bm --to 65535 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 8080 -m string --string "onload=" --algo bm --to 65535 -j REJECT --reject-with tcp-reset

# Rate-limit Brute Force (>10 koneksi TCP baru dalam 60 detik dari IP yg sama)
iptables -A FORWARD -p tcp --dport 8080 --syn -m recent --name bruteforce --set
iptables -A FORWARD -p tcp --dport 8080 --syn -m recent --name bruteforce --rcheck --seconds 60 --hitcount 10 -j REJECT --reject-with tcp-reset

# Rate-limit ICMP Flood (>20 ping/detik dari IP yg sama)
iptables -A INPUT -p icmp --icmp-type echo-request -m recent --name pingflood --set
iptables -A INPUT -p icmp --icmp-type echo-request -m recent --name pingflood --rcheck --seconds 10 --hitcount 20 -j DROP

iptables -A FORWARD -p icmp --icmp-type echo-request -m recent --name pingfloodfwd --set
iptables -A FORWARD -p icmp --icmp-type echo-request -m recent --name pingfloodfwd --rcheck --seconds 10 --hitcount 20 -j DROP

# ============================================================
# 4. IDS: Cari Interface DMZ dan Jalankan Snort dalam mode pcap (pasif)
# Snort memantau trafik dan mencatat alert ke /var/log/snort/alert
# ============================================================
echo "Mencari interface DMZ..."
INTERNAL_IFACE=$(ip route get $WEB_IP | awk '{print $3; exit}')
DMZ_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^eth' | awk -F'@' '{print $1}' | grep -v "$INTERNAL_IFACE" | head -n 1)
echo "Interface Internal: $INTERNAL_IFACE, Interface DMZ: $DMZ_IFACE"

echo "Menyuntikkan local.rules ke snort.conf..."
grep -q "local.rules" /etc/snort/snort.conf || echo "include /etc/snort/rules/local.rules" >> /etc/snort/snort.conf

echo "Menjalankan Snort IDS (mode pasif, monitoring $DMZ_IFACE)..."
snort -c /etc/snort/snort.conf -i "$DMZ_IFACE" -A fast -k none -D -l /var/log/snort/
echo "Snort IDS berjalan di background. IPS aktif via iptables."
tail -f /var/log/snort/alert