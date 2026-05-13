#!/bin/bash
set -e

WEB_HOST="${WEB_HOST:-web_faisal}"
WEB_PORT="${WEB_PORT:-8080}"
WEB_SCHEME="${WEB_SCHEME:-http}"
COMMUNITY_RULES_INCLUDE="include /etc/snort/rules/community/community.rules"
ABS_LOCAL_INCLUDE="include /etc/snort/rules/local.rules"

echo "Menyiapkan konfigurasi Snort lokal..."
mkdir -p /etc/snort/rules/community
touch /etc/snort/rules/community/community.rules

# Fokus lab pada local.rules agar log live tidak tenggelam oleh rule komunitas.
sed -i "\|${COMMUNITY_RULES_INCLUDE}|d" /etc/snort/snort.conf
sed -i "\|${ABS_LOCAL_INCLUDE}|d" /etc/snort/snort.conf

# Paket Ubuntu Snort sudah memuat local.rules dari $RULE_PATH.
grep -q 'include \$RULE_PATH/local.rules' /etc/snort/snort.conf || echo 'include $RULE_PATH/local.rules' >> /etc/snort/snort.conf

echo "Menunggu DNS ${WEB_HOST} siap..."
while ! getent hosts "$WEB_HOST" >/dev/null; do
  sleep 2
done

WEB_IP=$(getent hosts "$WEB_HOST" | awk '{ print $1; exit }')
echo "IP ${WEB_HOST} ditemukan: ${WEB_IP}"

echo "Menunggu health check backend..."
until curl -kfsS "${WEB_SCHEME}://${WEB_IP}:${WEB_PORT}/health" >/dev/null; do
  sleep 2
done

echo "Backend siap. Mengaktifkan inline IPS/IDS..."
sysctl -w net.ipv4.ip_forward=1

iptables -F
iptables -t nat -F
iptables -P FORWARD ACCEPT

# --- BAGIAN YANG DIPERBAIKI ---
# Arahkan trafik FORWARD (numpang lewat ke web) ke Snort
iptables -I FORWARD -p tcp --dport "${WEB_PORT}" -j NFQUEUE --queue-num 0
iptables -I FORWARD -p tcp --sport "${WEB_PORT}" -j NFQUEUE --queue-num 0
iptables -I FORWARD -p icmp -j NFQUEUE --queue-num 0

# Arahkan trafik INPUT (langsung ke Snort) ke Snort agar Ping terbaca
iptables -I INPUT -p icmp -j NFQUEUE --queue-num 0
# ------------------------------

iptables -t nat -A PREROUTING -p tcp --dport "${WEB_PORT}" -j DNAT --to-destination "${WEB_IP}:${WEB_PORT}"
iptables -t nat -A POSTROUTING -j MASQUERADE

echo "Menjalankan Snort hybrid mode (IDS + IPS inline)..."
mkdir -p /var/log/snort
: > /var/log/snort/alert
tail -n0 -F /var/log/snort/alert &
exec snort -q -c /etc/snort/snort.conf -Q --daq nfq --daq-var queue=0 --daq-mode inline -A fast -l /var/log/snort -k none