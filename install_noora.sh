#!/usr/bin/env bash
set -euo pipefail

# ===============================
# NOORA – One-Shot Installer (No Cloudflare API)
# Inputs: FQDN, BOT_TOKEN, ADMIN_IDS
# Defaults: GitHub=mkh-python/NOORA@main, WS=/cdn-assets-v3, FIRST_USER=user1
# TLS: Try Let's Encrypt (HTTP-01). On failure → Self-Signed (good for CF "Full" mode).
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

# -------- Defaults --------
GH_OWNER="mkh-python"
GH_REPO="NOORA"
GH_REF="main"
BASE_RAW="https://raw.githubusercontent.com/${GH_OWNER}/${GH_REPO}/${GH_REF}"
WS_PATH="/cdn-assets-v3"
FIRST_USER="user1"

FQDN=""
BOT_TOKEN=""
ADMIN_IDS=""

CERT_PATH="/etc/ssl/certs/noora-origin.pem"
KEY_PATH="/etc/ssl/private/noora-origin.key"
WEBROOT="/var/www/html"

get_inputs() {
  g "== Inputs =="
  prompt FQDN "Your FQDN (e.g., nooraws.vpnmkh.com)"
  prompt BOT_TOKEN "Telegram Bot Token"
  prompt ADMIN_IDS "Admin IDs (comma-separated)"
}

install_packages() {
  g "[1/9] Installing packages..."
  apt update
  DEBIAN_FRONTEND=noninteractive apt -y upgrade
  apt -y install curl unzip nginx python3-venv python3-pip git sqlite3 jq qrencode socat openssl
}

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

install_xray() {
  g "[3/9] Installing Xray..."
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
}

# TLS: Try Let's Encrypt (HTTP-01) → fallback self-signed
setup_tls() {
  g "[4/9] TLS setup for ${FQDN}"

  # temporary HTTP server block for ACME challenge
  mkdir -p "${WEBROOT}/.well-known/acme-challenge"
  cat >/etc/nginx/sites-available/noora-acme.conf <<EOF
server {
    listen 80;
    server_name ${FQDN};
    location ^~ /.well-known/acme-challenge/ {
        root ${WEBROOT};
        default_type "text/plain";
    }
    location / { return 200 'OK'; add_header Content-Type text/plain; }
}
EOF
  ln -sf /etc/nginx/sites-available/noora-acme.conf /etc/nginx/sites-enabled/noora-acme.conf
  rm -f /etc/nginx/sites-enabled/default || true
  nginx -t && systemctl reload nginx

  # Try Let's Encrypt via acme.sh (HTTP-01)
  LE_OK=0
  if [[ ! -d "$HOME/.acme.sh" ]]; then
    curl https://get.acme.sh | sh -s email=admin@${FQDN#*.}
  fi
  "$HOME/.acme.sh/acme.sh" --upgrade --auto-upgrade || true

  set +e
  "$HOME/.acme.sh/acme.sh" --issue -d "${FQDN}" -w "${WEBROOT}" --keylength ec-256
  if [[ $? -eq 0 ]]; then
    mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")"
    "$HOME/.acme.sh/acme.sh" --install-cert -d "${FQDN}" --ecc \
      --fullchain-file "${CERT_PATH}" \
      --key-file      "${KEY_PATH}" \
      --reloadcmd     "systemctl reload nginx"
    chmod 600 "${KEY_PATH}"
    LE_OK=1
    g "Let's Encrypt certificate installed."
  else
    y "Let's Encrypt failed (likely CF orange proxy). Falling back to self-signed..."
  fi
  set -e

  if [[ $LE_OK -eq 0 ]]; then
    mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")"
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "${KEY_PATH}" -out "${CERT_PATH}" -days 825 -subj "/CN=${FQDN}" >/dev/null 2>&1 || \
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "${KEY_PATH}" -out "${CERT_PATH}" -days 825 -subj "/CN=${FQDN}" >/dev/null 2>&1
    chmod 600 "${KEY_PATH}"
    y "Self-signed cert generated. Tip: In Cloudflare, set SSL/TLS mode to 'Full' (not Strict)."
  fi

  # remove temp ACME site (we'll create the real site later)
  rm -f /etc/nginx/sites-enabled/noora-acme.conf /etc/nginx/sites-available/noora-acme.conf
  nginx -t && systemctl reload nginx || true
}

configure_xray_nginx() {
  g "[5/9] Configuring Xray + Nginx (pulling files from GitHub)..."

  # Base Xray config from repo
  curl -fsSL "${BASE_RAW}/xray/base-config.json" -o /usr/local/etc/xray/config.json

  # Customize for our FQDN and WS path
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

  # Real HTTPS site with WS → Xray
  echo OK > "${WEBROOT}/index.html"
  cat >/etc/nginx/sites-available/noora.conf <<EOF
server {
    listen 443 ssl http2;
    server_name ${FQDN};

    ssl_certificate     ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};

    root ${WEBROOT};
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

  nginx -t
  systemctl restart nginx
  systemctl restart xray

  # Quick checks
  curl -I "https://${FQDN}/" | head -n 1 || true
  code=$(curl -sS -o /dev/null -w "%{http_code}" --http1.1 \
    -H "Upgrade: websocket" -H "Connection: Upgrade" "https://${FQDN}${WS_PATH}") || true
  [[ "$code" != "101" ]] && y "WS 101 not observed yet (CF/DNS may need ~30–90s)."

  echo "${UUID}" >/var/lib/noora-first-user-uuid
}

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

setup_firewall() {
  g "[8/9] Firewall (optional)"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow OpenSSH || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw --force enable || true
  fi
}

finish() {
  g "[9/9] Done."
  UUID=$(cat /var/lib/noora-first-user-uuid)
  LINK="vless://${UUID}@${FQDN}:443?encryption=none&security=tls&type=ws&host=${FQDN}&path=${WS_PATH}#${FIRST_USER}"
  g "First user's link:"
  echo "${LINK}"
  qrencode -t ANSIUTF8 "${LINK}" || true
  y "If CF proxy just toggled, give it ~30–90s. For self-signed, set Cloudflare SSL/TLS to 'Full' (not Strict)."
}

main() {
  require_root
  get_inputs
  install_packages
  install_grpcurl
  install_xray
  setup_tls
  configure_xray_nginx
  setup_database
  install_bot
  setup_firewall
  finish
}
main "$@"
