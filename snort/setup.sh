#!/bin/bash
set -euo pipefail

# =============================================================================
# setup.sh ? Snort 2 IPS inline NFQUEUE + socat reverse proxy
# Windows host aman: semua command Linux berjalan di dalam container.
# =============================================================================
WEB_HOST="${WEB_HOST:-web_faisal}"
WEB_PORT="${WEB_PORT:-8080}"
WEB_SCHEME="${WEB_SCHEME:-http}"
HTTPS_PORT="${HTTPS_PORT:-443}"
HTTP_PORT="${HTTP_PORT:-80}"
CERT_FILE="${CERT_FILE:-/etc/snort/ssl/cert.pem}"
KEY_FILE="${KEY_FILE:-/etc/snort/ssl/key.pem}"
ACL_FILE="/etc/snort/acl.conf"
SNORT_CONF="/etc/snort/snort.conf"
SNORT_LOG="/var/log/snort/alert"

# FIX: fallback agar tidak error "SNORT_IFACE: unbound variable"
SNORT_IFACE="${SNORT_IFACE:-eth0}"
NFQ_NUM="${NFQ_NUM:-0}"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }

add_nfq_rule() {
    local chain="$1"; shift
    if iptables -I "$chain" 1 "$@" -j NFQUEUE --queue-num "$NFQ_NUM" --queue-bypass 2>/dev/null; then
        log "NFQUEUE aktif: $chain $* -> queue $NFQ_NUM"
    else
        iptables -I "$chain" 1 "$@" -j NFQUEUE --queue-num "$NFQ_NUM"
        log "NFQUEUE aktif tanpa queue-bypass: $chain $* -> queue $NFQ_NUM"
    fi
}

cleanup() {
    log "Shutdown..."
    kill "${TAIL_PID:-}" 2>/dev/null || true
    kill "${SOCAT_PID:-}" 2>/dev/null || true
    kill "${SOCAT_HTTP_PID:-}" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# =============================================================================
# 1. TLS certificate untuk reverse proxy HTTPS
# =============================================================================
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    log "Membuat self-signed certificate..."
    mkdir -p "$(dirname "$CERT_FILE")"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=localhost/O=DevLab/C=ID" 2>/dev/null
    log "Cert dibuat."
else
    log "Cert ditemukan: $CERT_FILE"
fi

# =============================================================================
# 2. Tunggu backend siap
# =============================================================================
log "Menunggu DNS ${WEB_HOST}..."
RETRY=0
until getent hosts "$WEB_HOST" >/dev/null 2>&1; do
    sleep 2
    RETRY=$((RETRY + 1))
    [ "$RETRY" -gt 30 ] && { err "DNS timeout untuk ${WEB_HOST}"; exit 1; }
done
WEB_IP="$(getent hosts "$WEB_HOST" | awk '{print $1; exit}')"
log "IP ${WEB_HOST}: ${WEB_IP}"

log "Menunggu backend siap..."
RETRY=0
until curl -fsS "${WEB_SCHEME}://${WEB_IP}:${WEB_PORT}/health" >/dev/null 2>&1; do
    sleep 3
    RETRY=$((RETRY + 1))
    [ "$RETRY" -gt 20 ] && { err "Backend timeout"; exit 1; }
done
log "Backend siap."

# =============================================================================
# 3. ACL dasar dari acl.conf
# =============================================================================
if [ -f "$ACL_FILE" ]; then
    log "======= ACL ======="
    while IFS= read -r raw; do
        line="$(printf '%s' "$raw" | tr -d '\r' | sed 's/[[:space:]]*$//')"
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        ACTION="$(echo "$line" | awk '{print $1}')"
        VALUE="$(echo "$line"  | awk '{print $2}')"
        [ -z "$ACTION" ] || [ -z "$VALUE" ] && continue

        case "$ACTION" in
            WHITELIST)
                log "  WHITELIST: ${VALUE}"
                ;;
            BLACKLIST|BLOCK_IP)
                log "  ${ACTION}: ${VALUE} -> DROP"
                iptables -I INPUT 1 -s "$VALUE" -j DROP || true
                iptables -I FORWARD 1 -s "$VALUE" -j DROP || true
                ;;
            ALLOW_IP)
                log "  ALLOW_IP: ${VALUE} -> ACCEPT"
                iptables -I INPUT 1 -s "$VALUE" -j ACCEPT || true
                iptables -I FORWARD 1 -s "$VALUE" -j ACCEPT || true
                ;;
            BLOCK_PORT)
                log "  BLOCK_PORT: ${VALUE} -> DROP"
                iptables -I INPUT 1 -p tcp --dport "$VALUE" -j DROP || true
                iptables -I FORWARD 1 -p tcp --dport "$VALUE" -j DROP || true
                ;;
            ALLOW_PORT)
                log "  ALLOW_PORT: ${VALUE} -> ACCEPT"
                iptables -I INPUT 1 -p tcp --dport "$VALUE" -j ACCEPT || true
                iptables -I FORWARD 1 -p tcp --dport "$VALUE" -j ACCEPT || true
                ;;
            RATE_LIMIT|ALLOW_METHOD|BLOCK_METHOD|BLOCK_UA|ALLOW_PATH|BLOCK_PATH)
                log "  ${ACTION}: ${VALUE} -> dicatat, inspeksi utama oleh Snort rules"
                ;;
            *)
                warn "  Direktif tidak dikenal: ${ACTION}"
                ;;
        esac
    done < "$ACL_FILE"
    log "==================="
fi

# =============================================================================
# 4. Start socat reverse proxy
# =============================================================================
if [ "$WEB_SCHEME" = "https" ]; then
    BACKEND_SOCAT="OPENSSL:${WEB_IP}:${WEB_PORT},verify=0"
else
    BACKEND_SOCAT="TCP:${WEB_IP}:${WEB_PORT}"
fi

log "Memulai socat TLS proxy :${HTTPS_PORT} -> ${WEB_IP}:${WEB_PORT}..."
socat "OPENSSL-LISTEN:${HTTPS_PORT},cert=${CERT_FILE},key=${KEY_FILE},verify=0,reuseaddr,fork" "$BACKEND_SOCAT" &
SOCAT_PID=$!
sleep 1

log "Memulai socat HTTP proxy :${HTTP_PORT} -> ${WEB_IP}:${WEB_PORT}..."
socat "TCP-LISTEN:${HTTP_PORT},reuseaddr,fork" "$BACKEND_SOCAT" &
SOCAT_HTTP_PID=$!
sleep 1

# =============================================================================
# 5. Log alert Snort ke stdout Docker logs
# =============================================================================
mkdir -p /var/log/snort
: > "$SNORT_LOG"
chmod 644 "$SNORT_LOG"
tail -n 0 -F "$SNORT_LOG" &
TAIL_PID=$!

# =============================================================================
# 6. Pasang NFQUEUE inline rules
# =============================================================================
# INPUT 80: HTTP plaintext dari client ke proxy, bisa langsung di-drop.
add_nfq_rule INPUT -p tcp --dport "$HTTP_PORT"

# INPUT 443: TLS terenkripsi, tetap masuk IPS untuk basic TCP/DoS, payload HTTP detail dibaca setelah decrypt di OUTPUT 8080.
add_nfq_rule INPUT -p tcp --dport "$HTTPS_PORT"

# OUTPUT 8080: plaintext HTTP dari socat ke backend. Ini jalur utama SQLi/XSS/bruteforce/buffer.
add_nfq_rule OUTPUT -p tcp -d "$WEB_IP" --dport "$WEB_PORT"

# ICMP ke Snort container untuk flood test.
add_nfq_rule INPUT -p icmp --icmp-type echo-request

# =============================================================================
# 6.1 Re-apply BLACKLIST/BLOCK_IP agar DROP source menang sebelum NFQUEUE
# =============================================================================
# Alasan:
# ACL dibaca sebelum NFQUEUE. Setelah itu add_nfq_rule memakai iptables -I ... 1,
# sehingga rule NFQUEUE terdorong ke posisi paling atas. Akibatnya blacklist IP
# bisa kalah prioritas. Block ini memasang ulang BLACKLIST/BLOCK_IP di posisi 1.
if [ -f "$ACL_FILE" ]; then
    log "Re-apply BLACKLIST/BLOCK_IP sebagai prioritas tertinggi..."
    while IFS= read -r raw; do
        line="$(printf '%s' "$raw" | tr -d '\r' | sed 's/#.*$//' | sed 's/[[:space:]]*$//')"
        [ -z "$line" ] && continue

        ACTION="$(echo "$line" | awk '{print $1}')"
        VALUE="$(echo "$line"  | awk '{print $2}')"
        [ -z "$ACTION" ] || [ -z "$VALUE" ] && continue

        case "$ACTION" in
            BLACKLIST|BLOCK_IP)
                iptables -D INPUT   -s "$VALUE" -j DROP 2>/dev/null || true
                iptables -D FORWARD -s "$VALUE" -j DROP 2>/dev/null || true

                iptables -I INPUT   1 -s "$VALUE" -j DROP || true
                iptables -I FORWARD 1 -s "$VALUE" -j DROP || true

                log "  PRIORITY ${ACTION}: ${VALUE} -> DROP sebelum NFQUEUE"
                ;;
        esac
    done < "$ACL_FILE"
fi


log "iptables NFQUEUE summary:"
iptables -S | grep -E "NFQUEUE|DROP|ACCEPT" || true

# =============================================================================
# 7. Validasi konfigurasi Snort
# =============================================================================
log "Validasi konfigurasi Snort..."
VALIDATION_LOG="/tmp/snort-validation.log"

set +e
snort -T \
    -Q \
    --daq nfq \
    --daq-var queue="$NFQ_NUM" \
    -c "$SNORT_CONF" \
    -k none > "$VALIDATION_LOG" 2>&1
SNORT_TEST_EXIT=$?
set -e

cat "$VALIDATION_LOG"

if [ "$SNORT_TEST_EXIT" -eq 0 ] && grep "Snort successfully validated" "$VALIDATION_LOG" >/dev/null 2>&1; then
    log "Konfigurasi valid."
else
    err "Konfigurasi Snort tidak valid. Perbaiki rules sebelum lanjut."
    exit 1
fi

# =============================================================================
# 8. Jalankan Snort IPS inline NFQUEUE
# =============================================================================
log "============================================================"
log " Snort 2 IPS ? INLINE NFQUEUE MODE"
log " Queue     : ${NFQ_NUM}"
log " HTTP      : :${HTTP_PORT} -> ${WEB_IP}:${WEB_PORT}"
log " HTTPS     : :${HTTPS_PORT} -> ${WEB_IP}:${WEB_PORT}"
log " Alert     : ${SNORT_LOG}"
log " IDS msg   : [IDS]"
log " IPS msg   : [IPS-DROP]"
log "============================================================"

exec snort \
    -Q \
    --daq nfq \
    --daq-var queue="$NFQ_NUM" \
    -q \
    -c "$SNORT_CONF" \
    -A fast \
    -l /var/log/snort \
    -k none