#!/usr/bin/env bash
set -euo pipefail

# ===============================
# NOORA – One-Shot Installer (Final)
# - Cloudflare: DNS + Let's Encrypt (DNS-01 via acme.sh)  → بدون نیاز به Origin CA
# - GitHub source: mkh-python/NOORA@main
# - Prompts only: Domain, Subdomain, CF_TOKEN, BOT_TOKEN, ADMIN_IDS
# ===============================

g(){ echo -e "\e[32m$*\e[0m"; }
y(){ echo -e "\e[33m$*\e[0m"; }
r(){ echo -e "\e[31m$*\e[0m"; }
require_root(){ if [[ $EUID -ne 0 ]]; then r "Run as root"; exit 1; fi; }

prompt() {
  local var="$1" label="$2" def="${3:-}"
  local val; read -rp "$label ${def:+[$def]}: " val
  if [[ -z "${val:-}" && -n "$def" ]]; then val="$def"; fi
  if [[ -z "${val:-}" ]]; then r "Value required for $label"; exit 1; fi
  eval "$var=\"\$val\""
}

# -------- Defaults (do not ask) --------
GH_OWNER="mkh-python"
GH_REPO="NOORA"
GH_REF="main"
BASE_RAW="https://raw.githubusercontent.com/${GH_OWNER}/${GH_REPO}/${GH_REF}"
WS_PATH="/cdn-assets-v3"
FIRST_USER="user1"

# -------- Inputs (ask only these) ------
get_inputs() {
  g "== Inputs =="
  prompt DOMAIN    "Domain (e.g., vpnmkh.com)"
  prompt SUBDOMAIN "Subdomain (e.g., nooraws)"
  prompt CF_TOKEN  "Cloudflare API Token"
  prompt BOT_TOKEN "Telegram Bot Token"
  prompt ADMIN_IDS "Admin IDs (comma-separated)"
  FQDN="${SUBDOMAIN}.${DOMAIN}"
  export DOMAIN SUBDOMAIN FQDN CF_TOKEN BOT_TOKEN ADMIN_IDS WS_PATH FIRST_USER BASE_RAW
}

# -------- Packages ----------
install_packages() {
  g "[1/9] Installing packages..."
  apt update
  DEBIAN_FRONTEND=noninteractive apt -y upgrade
  apt -y install curl unzip nginx python3-venv python3-pip git sqlite3 jq qrencode socat
}

# -------- grpcurl ----------
install_grpcurl() {
  if ! command -v grpcurl >/dev/null 2>&1; then
    g "[2/9] Installing grpcurl..."
    curl -fsSL https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz \
      | tar -xz -C /usr/local/bin grpcurl
    chmod +x /usr/local/bin/grpcurl
  else
    y "grpcurl already present."
  fi
}

# -------- Xray ------------
install_xray() {
  g "[3/9] Installing Xray..."
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
}

# ===== Cloudflare (DNS) + Let's Encrypt (DNS-01) =====
setup_cloudflare() {
  g "[4/9] Configuring Cloudflare (DNS) + Let's Encrypt for ${FQDN} ..."

  # 4-1) Zone ID
  ZONE_ID=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
    | jq -r '.result[0].id')
  if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
    r "Zone not found via API. Enter Zone ID manually:"
    read -rp "Zone ID for ${DOMAIN}: " ZONE_ID
  fi

  # 4-2) Upsert DNS A record (proxied)
  IP=$(curl -fsS ifconfig.me)
  EXIST_ID=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A&name=${FQDN}" \
    -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" | jq -r '.result[0].id')
  if [[ -n "${EXIST_ID}" && "${EXIST_ID}" != "null" ]]; then
    curl -fsS -X PATCH "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${EXIST_ID}" \
      -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${FQDN}\",\"content\":\"${IP}\",\"proxied\":true}" >/dev/null
  else
    curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${FQDN}\",\"content\":\"${IP}\",\"proxied\":true}" >/dev/null
  fi
  y "DNS A ${FQDN} → ${IP} (proxied) set."

  # 4-3) Issue Let's Encrypt cert via acme.sh (DNS-01 with Cloudflare)
  g "Issuing Let's Encrypt certificate via DNS-01..."
  if [[ ! -d "$HOME/.acme.sh" ]]; then
    curl https://get.acme.sh | sh -s email=admin@${DOMAIN}
  fi
  "$HOME/.acme.sh/acme.sh" --upgrade --auto-upgrade

  export CF_Token="${CF_TOKEN}"
  export CF_Zone_ID="${ZONE_ID}"

  "$HOME/.acme.sh/acme.sh" --issue --dns dns_cf -d "${FQDN}" --keylength ec-256

  mkdir -p /etc/ssl/certs /etc/ssl/private
  "$HOME/.acme.sh/acme.sh" --install-cert -d "${FQDN}" --ecc \
    --fullchain-file /etc/ssl/certs/noora-origin.pem \
    --key-file      /etc/ssl/private/noora-origin.key \
    --reloadcmd     "systemctl reload nginx"

  chmod 600 /etc/ssl/private/noora-origin.key
  y "TLS certificate installed at /etc/ssl/certs/noora-origin.pem"
}

# -------- Xray + Nginx --------
configure_xray_nginx() {
  g "[5/9] Configuring Xray + Nginx (pulling files from GitHub)..."

  # Base Xray config from repo
  curl -fsSL "${BASE_RAW}/xray/base-config.json" -o /usr/local/etc/xray/config.json

  # Customize FQDN and WS path
  sed -i "s#/cdn-assets-v3#${WS_PATH}#g" /usr/local/etc/xray/config.json
  sed -i "s#example.com#${FQDN}#g"        /usr/local/etc/xray/config.json

  # Add first client
  UUID=$(cat /proc/sys/kernel/random/uuid)
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
  echo OK >/var/www/html/index.html

  nginx -t
  systemctl restart nginx
  systemctl restart xray

  # Quick checks
  curl -I "https://${FQDN}/" | head -n 1 || true
  code=$(curl -sS -o /dev/null -w "%{http_code}" --http1.1 \
    -H "Upgrade: websocket" -H "Connection: Upgrade" "https://${FQDN}${WS_PATH}") || true
  [[ "$code" != "101" ]] && y "WS 101 not observed yet (DNS/CF may need ~30–90s)."

  echo "${UUID}" >/var/lib/noora-first-user-uuid
}

# -------- Database ----------
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

# -------- Telegram Bot (pull from repo) ----------
install_bot() {
  g "[7/9] Installing Telegram Bot (pulling from GitHub)..."
  mkdir -p /opt/noora-bot
  cd /opt/noora-bot

  curl -fsSL "${BASE_RAW}/bot/requirements.txt" -o requirements.txt
  curl -fsSL "${BASE_RAW}/bot/bot.py"          -o bot.py
  curl -fsSL "${BASE_RAW}/bot/.env.example"    -o .env

  # Fill env
  sed -i "s#YOUR_TELEGRAM_BOT_TOKEN#${BOT_TOKEN}#g" .env
  sed -i "s#123456789,987654321#${ADMIN_IDS}#g"     .env
  sed -i "s#noora1.vpnmkh.com#${FQDN}#g"            .env
  sed -i "s#/cdn-assets-v3#${WS_PATH}#g"            .env

  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt

  # Systemd service
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

# -------- Firewall (optional) ----------
setup_firewall() {
  g "[8/9] Firewall (optional)"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow OpenSSH || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw --force enable || true
  fi
}

# -------- Finish -----------
finish() {
  g "[9/9] Done."
  UUID=$(cat /var/lib/noora-first-user-uuid)
  LINK="vless://${UUID}@${FQDN}:443?encryption=none&security=tls&type=ws&host=${FQDN}&path=${WS_PATH}#${FIRST_USER}"
  g "First user's link:"
  echo "${LINK}"
  qrencode -t ANSIUTF8 "${LINK}" || true
  y "If Cloudflare DNS just changed, give it ~30–90s for WS 101."
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
