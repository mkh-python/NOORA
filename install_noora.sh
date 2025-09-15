#!/usr/bin/env bash
set -euo pipefail

# ============ رنگ لاگ ============
g(){ echo -e "\e[32m$*\e[0m"; }
y(){ echo -e "\e[33m$*\e[0m"; }
r(){ echo -e "\e[31m$*\e[0m"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then r "Run as root"; exit 1; fi
}

prompt() {
  local var="$1" msg="$2" def="${3:-}"
  local val
  read -rp "$msg ${def:+[$def]}: " val
  if [[ -z "${val:-}" && -n "$def" ]]; then val="$def"; fi
  if [[ -z "${val:-}" ]]; then r "Value required"; exit 1; fi
  eval "$var=\"\$val\""
}

# ============ ورودی‌ها ============
get_inputs() {
  g "== Inputs =="

  # GitHub raw access info
  prompt GH_OWNER "GitHub owner/org (e.g., your-username)"
  prompt GH_REPO  "GitHub repo name (e.g., noora-vpn)"
  prompt GH_REF   "Git ref (branch/tag/commit, e.g., main)" "main"
  BASE_RAW="https://raw.githubusercontent.com/${GH_OWNER}/${GH_REPO}/${GH_REF}"

  # Domain & CF
  prompt DOMAIN    "Domain (e.g., vpnmkh.com)"
  prompt SUBDOMAIN "Subdomain (e.g., noora1)"
  prompt CF_TOKEN  "Cloudflare API Token"
  FQDN="${SUBDOMAIN}.${DOMAIN}"

  # Bot
  prompt BOT_TOKEN "Telegram Bot Token"
  prompt ADMIN_IDS "Admin IDs (comma-separated)"
  prompt WS_PATH   "WS path" "/cdn-assets-v3"

  # First user (optional quick test)
  prompt FIRST_USER "First user name (e.g., user1)" "user1"

  export BASE_RAW FQDN WS_PATH BOT_TOKEN ADMIN_IDS DOMAIN SUBDOMAIN CF_TOKEN FIRST_USER
}

# ============ نصب پکیج‌ها ============
install_packages() {
  g "[1/9] Installing packages..."
  apt update
  DEBIAN_FRONTEND=noninteractive apt -y upgrade
  apt -y install curl unzip nginx python3-venv python3-pip git sqlite3 jq qrencode socat
}

# ============ نصب grpcurl ============
install_grpcurl() {
  if ! command -v grpcurl >/dev/null 2>&1; then
    g "[2/9] Installing grpcurl..."
    curl -L https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz \
      | tar -xz -C /usr/local/bin grpcurl
    chmod +x /usr/local/bin/grpcurl
  else
    y "grpcurl already installed."
  fi
}

# ============ نصب Xray ============
install_xray() {
  g "[3/9] Installing Xray..."
  bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
}

# ============ Cloudflare: DNS + Origin Cert + SSL Mode + Rule ============
setup_cloudflare() {
  g "[4/9] Configuring Cloudflare for ${FQDN} ..."
  ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
    | jq -r '.result[0].id')

  if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
    r "Zone not found. Ensure domain is in your Cloudflare account."
    exit 1
  fi

  IP=$(curl -s ifconfig.me)
  # Upsert DNS A record (proxied)
  EXIST_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A&name=${FQDN}" \
    -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" | jq -r '.result[0].id')
  if [[ -n "${EXIST_ID}" && "${EXIST_ID}" != "null" ]]; then
    curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${EXIST_ID}" \
      -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${FQDN}\",\"content\":\"${IP}\",\"proxied\":true}" >/dev/null
  else
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${FQDN}\",\"content\":\"${IP}\",\"proxied\":true}" >/dev/null
  fi

  # Create Origin Certificate
  g "Requesting Origin Cert..."
  ORIGIN=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/origin_ca/certificates" \
    -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
    --data "{\"hostnames\":[\"${FQDN}\"],\"requested_validity\":5475,\"request_type\":\"origin-rsa\",\"key_size\":2048}")
  CERT=$(echo "$ORIGIN" | jq -r '.result.certificate')
  KEY=$(echo "$ORIGIN"  | jq -r '.result.private_key')

  mkdir -p /etc/ssl/certs /etc/ssl/private
  echo "${CERT}" >/etc/ssl/certs/noora-origin.pem
  echo "${KEY}"  >/etc/ssl/private/noora-origin.key
  chmod 600 /etc/ssl/private/noora-origin.key

  # (Optional) SSL mode Full(strict) – Cloudflare API v4 for settings is broader; many accounts default ok.
  y "Remember to set Cloudflare SSL/TLS mode to 'Full (strict)' for ${DOMAIN}."

  # (Optional) Add rule for WS path to bypass cache & challenges (can vary per account plan)
  y "Consider adding a Page/Cache rule in Cloudflare to bypass cache for ${FQDN}${WS_PATH}*"
}

# ============ کانفیگ Xray + Nginx (با استفاده از فایل‌های GitHub) ============
configure_xray_nginx() {
  g "[5/9] Configuring Xray + Nginx..."

  # Fetch base Xray config
  curl -fsSL "${BASE_RAW}/xray/base-config.json" -o /usr/local/etc/xray/config.json

  # Customize config with FQDN & WS_PATH
  sed -i "s#/cdn-assets-v3#${WS_PATH}#g" /usr/local/etc/xray/config.json
  sed -i "s#example.com#${FQDN}#g"        /usr/local/etc/xray/config.json

  # Add first user (one UUID)
  UUID=$(cat /proc/sys/kernel/random/uuid)
  # Inject first client into config.json clients array
  python3 - <<PY
import json
p="/usr/local/etc/xray/config.json"
d=json.load(open(p))
for ib in d.get("inbounds",[]):
    if ib.get("protocol")=="vless":
        ib.setdefault("settings",{}).setdefault("clients",[]).append(
            {"id":"${UUID}","level":0,"email":"${FIRST_USER}@${FQDN}"}
        )
open(p,"w").write(json.dumps(d,indent=2,ensure_ascii=False))
PY

  # Nginx site
  cat >/etc/nginx/sites-available/noora.conf <<EOF
server {
    listen 443 ssl http2;
    server_name ${FQDN};

    ssl_certificate     /etc/ssl/certs/noora-origin.pem;
    ssl_certificate_key /etc/ssl/private/noora-origin.key;

    root /var/www/html;
    index index.html;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;

    location ${WS_PATH} {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_pass http://127.0.0.1:10000;
    }
}
server { listen 80; server_name ${FQDN}; return 301 https://\$host\$request_uri; }
EOF

  ln -sf /etc/nginx/sites-available/noora.conf /etc/nginx/sites-enabled/noora.conf
  rm -f /etc/nginx/sites-enabled/default || true
  echo OK > /var/www/html/index.html

  nginx -t
  systemctl restart nginx
  systemctl restart xray

  # Quick front test
  curl -I "https://${FQDN}/" | head -n 1
  # Quick WS (expect 101)
  code=$(curl -sS -o /dev/null -w "%{http_code}" --http1.1 -H "Upgrade: websocket" -H "Connection: Upgrade" "https://${FQDN}${WS_PATH}") || true
  if [[ "$code" != "101" ]]; then y "WS 101 not observed yet (CF DNS may need a minute)."; fi

  # Save UUID for output
  echo "${UUID}" >/var/lib/noora-first-user-uuid
}

# ============ DB ============
setup_database() {
  g "[6/9] Preparing database..."
  mkdir -p /var/lib/noora /var/lib/noora/backups
  cat >/var/lib/noora/noora.db.sql <<'EOF'
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact TEXT,
  quota_bytes INTEGER DEFAULT 0,
  device_limit INTEGER DEFAULT 1,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS user_slots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  uuid TEXT NOT NULL,
  email TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
EOF
  sqlite3 /var/lib/noora/noora.db < /var/lib/noora/noora.db.sql
}

# ============ نصب ربات تلگرام از GitHub ============
install_bot() {
  g "[7/9] Installing Telegram Bot..."

  mkdir -p /opt/noora-bot
  cd /opt/noora-bot

  curl -fsSL "${BASE_RAW}/bot/requirements.txt" -o requirements.txt
  curl -fsSL "${BASE_RAW}/bot/bot.py"          -o bot.py
  curl -fsSL "${BASE_RAW}/bot/.env.example"    -o .env

  # Fill .env from prompts
  sed -i "s#YOUR_TELEGRAM_BOT_TOKEN#${BOT_TOKEN}#g" .env
  sed -i "s#123456789,987654321#${ADMIN_IDS}#g"     .env
  sed -i "s#noora1.vpnmkh.com#${FQDN}#g"            .env
  sed -i "s#/cdn-assets-v3#${WS_PATH}#g"            .env

  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt

  # systemd service
  cat >/etc/systemd/system/noora-bot.service <<EOF
[Unit]
Description=Noora VPN Telegram Bot
After=network.target
[Service]
WorkingDirectory=/opt/noora-bot
ExecStart=/opt/noora-bot/venv/bin/python /opt/noora-bot/bot.py
Restart=always
Environment=PYTHONUNBUFFERED=1
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now noora-bot
  systemctl status noora-bot --no-pager || true
}

# ============ فایروال (اختیاری) ============
setup_firewall() {
  g "[8/9] Firewall (optional)..."
  if command -v ufw >/dev/null 2>&1; then
    ufw allow OpenSSH || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw --force enable || true
  fi
}

# ============ خروجی نهایی ============
finish() {
  g "[9/9] Done."
  UUID=$(cat /var/lib/noora-first-user-uuid)
  LINK="vless://${UUID}@${FQDN}:443?encryption=none&security=tls&type=ws&host=${FQDN}&path=${WS_PATH}#${FIRST_USER}"
  g "First user's link:"
  echo "${LINK}"
  qrencode -t ANSIUTF8 "${LINK}" || true
  y "If CF just changed DNS, give it a minute for WS 101 to appear."
}

main() {
  require_root
  get_inputs
  install_packages
  install_grpcurl
  install_xray
  setup_cloudflare
  configure_xray_nginx
  setup_database
  install_bot
  setup_firewall
  finish
}
main "$@"
