#!/bin/bash
# /usr/local/bin/update-cloudflare-ips.sh
set -euo pipefail # остановка при ошибках

LOG_TAG="cloudflare-ip-update"
CF_V4_URL="https://www.cloudflare.com/ips-v4"
CF_V6_URL="https://www.cloudflare.com/ips-v6"
NGINX_CF_CONF="/etc/nginx/snippets/cloudflare-ips.conf"
STATE_FILE="/var/lib/cloudflare-ips/state.txt"

TMP_V4=$(mktemp)
TMP_V6=$(mktemp)
TMP_STATE=$(mktemp)
TMP_NGINX=$(mktemp)

cleanup() {
    rm -f "$TMP_V4" "$TMP_V6" "$TMP_STATE" "$TMP_NGINX"
}
trap cleanup EXIT

# Скачиваем и фильтруем только валидные айпи
curl -sf --max-time 10 "$CF_V4_URL" | grep -E -o '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' > "$TMP_V4" || true
curl -sf --max-time 10 "$CF_V6_URL" | grep -E -o '^([0-9a-fA-F:]+)/[0-9]{1,3}$' > "$TMP_V6" || true

if [[ ! -s "$TMP_V4" ]] || [[ ! -s "$TMP_V6" ]]; then
    logger -t "$LOG_TAG" "ERROR: Failed to fetch or validate Cloudflare IPs."
    exit 1
fi

cat "$TMP_V4" "$TMP_V6" > "$TMP_STATE"

mkdir -p "$(dirname "$STATE_FILE")"
touch "$STATE_FILE"

if cmp -s "$TMP_STATE" "$STATE_FILE"; then
    logger -t "$LOG_TAG" "No changes in Cloudflare IPs."
    exit 0
fi

logger -t "$LOG_TAG" "Changes detected! Updating UFW and Nginx..."

ufw status numbered | grep -i 'Cloudflare' | grep -oP '^\[\s*\K[0-9]+' | sort -rn | while read -r num; do
    ufw --force delete "$num" > /dev/null 2>&1 || true
done

while IFS= read -r ip; do
    ufw allow from "$ip" to any port 443 proto tcp comment 'Cloudflare IPv4' > /dev/null 2>&1
done < "$TMP_V4"

while IFS= read -r ip; do
    ufw allow from "$ip" to any port 443 proto tcp comment 'Cloudflare IPv6' > /dev/null 2>&1
done < "$TMP_V6"

ufw reload > /dev/null 2>&1

cat > "$TMP_NGINX" <<EOF
# Auto-generated — do not edit manually
# Updated: $(date -Iseconds)
EOF

awk '{print "set_real_ip_from " $1 ";"}' "$TMP_V4" >> "$TMP_NGINX"
awk '{print "set_real_ip_from " $1 ";"}' "$TMP_V6" >> "$TMP_NGINX"
echo 'real_ip_header CF-Connecting-IP;' >> "$TMP_NGINX"

cp "$TMP_NGINX" "$NGINX_CF_CONF"
chmod 644 "$NGINX_CF_CONF"

if systemctl reload nginx; then
    cp "$TMP_STATE" "$STATE_FILE"
    logger -t "$LOG_TAG" "Nginx reloaded successfully"
else
    logger -t "$LOG_TAG" "ERROR: Nginx reload failed! Check 'journalctl -u nginx'"
    exit 1
fi
