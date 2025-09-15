#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Noora VPN - Telegram Admin Bot
- پذیرش و پارس سرورهای OpenVPN (.ovpn)
- پذیرش و پارس سرورهای WireGuard (.conf)
- مدیریت لیست واقعی + فیک
- انتشار manifest به مسیر public برای اپ کلاینت
- اسکریپت fix برای دسترسی NGINX
"""

import os
import io
import json
import re
import html
import unicodedata
import tempfile
import subprocess
import textwrap
from datetime import datetime, timezone
from typing import Dict, Any, List

from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InputFile
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, ConversationHandler,
    filters, ContextTypes
)

# ================== تنظیمات ==================
# نکته: توکن را از ENV بگیرید تا در سورس نماند.
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN env var. Set it like: export BOT_TOKEN=xxxxx:yyyyy")

# آیدی‌های ادمین (دسترسی)
ADMIN_IDS = {671715232, 7819156066}

# فایل پایه (فقط واقعی‌ها) + فایل انتشار برای اپ (واقعی + فیک)
SERVERS_BASE_PATH = "/var/www/noora-cdn/config/servers.base.json"
SERVERS_PUB_PATH  = "/var/www/noora-cdn/config/servers.json"  # همینی که اپ می‌خونه
PUBLIC_URL = "https://cdn.noora.vpnmkh.com/config/servers.json"

# ================== حالات سناریو ==================
MAIN_MENU = 0
ADD_WAIT_OVPN, ADD_WAIT_ID, ADD_WAIT_COUNTRY, ADD_WAIT_CITY, ADD_CONFIRM = range(1, 6)
REMOVE_WAIT_ID, REMOVE_CONFIRM = range(6, 8)
FAKE_WAIT_COUNT = 8

# ================== دکمه‌ها ==================
BTN_ADD = "➕ افزودن سرور"
BTN_LIST = "📄 لیست سرورها"
BTN_REMOVE = "🗑️ حذف سرور"
BTN_GET = "📦 دریافت فایل"
BTN_BACK = "↩️ بازگشت"

# منوی فیک
BTN_FAKE = "🎭 سرورهای فیک"
BTN_FAKE_SET = "🔢 تنظیم تعداد"
BTN_FAKE_PRESET_0  = "0"
BTN_FAKE_PRESET_5  = "5"
BTN_FAKE_PRESET_10 = "10"
BTN_FAKE_PRESET_15 = "15"
BTN_FAKE_PRESET_20 = "20"
BTN_FAKE_LIST = "📄 لیست فیک‌ها"
BTN_FAKE_PUBLISH = "🔁 انتشار"

MAIN_KEYBOARD = ReplyKeyboardMarkup(
    [[KeyboardButton(BTN_ADD)],
     [KeyboardButton(BTN_LIST), KeyboardButton(BTN_GET)],
     [KeyboardButton(BTN_REMOVE), KeyboardButton(BTN_FAKE)]],
    resize_keyboard=True
)

def with_back_keyboard(rows: List[List[str]]) -> ReplyKeyboardMarkup:
    rows = [list(r) for r in rows]
    rows.append([BTN_BACK])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)

def fake_keyboard(current: int) -> ReplyKeyboardMarkup:
    rows = [
        [f"تعداد فعلی: {current}"],
        [BTN_FAKE_SET, BTN_FAKE_PUBLISH],
        [BTN_FAKE_LIST],
        [BTN_FAKE_PRESET_0, BTN_FAKE_PRESET_5, BTN_FAKE_PRESET_10, BTN_FAKE_PRESET_15, BTN_FAKE_PRESET_20],
    ]
    return with_back_keyboard(rows)

# ================== مجوز ==================
def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

# ================== کمک‌های عمومی ==================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _norm_id(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    invisible = [
        "\u200c", "\u200d", "\u200e", "\u200f",
        "\u202a", "\u202b", "\u202c",
        "\ufeff", "\u2066", "\u2067", "\u2069"
    ]
    for ch in invisible:
        s = s.replace(ch, "")
    s = re.sub(r"\s+", " ", s).strip()
    return s.lower()

def atomic_save_json(path: str, data: Dict[str, Any]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".servers_", suffix=".tmp", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            bak = path + ".bak"
            try:
                if os.path.exists(bak):
                    os.remove(bak)
            except Exception:
                pass
            os.replace(path, bak)
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

# ================== Fix Script ==================
FIX_SCRIPT = textwrap.dedent("""
    set -e
    chown -R www-data:www-data /var/www/noora-cdn
    find /var/www/noora-cdn -type d -exec chmod 755 {} \\;
    chmod 644 /var/www/noora-cdn/config/servers.json
    test -r /var/www/noora-cdn/config/servers.json && echo "NGINX can read"
    nginx -t && systemctl reload nginx
""")

def run_fix():
    try:
        p = subprocess.run(
            ["bash", "-lc", FIX_SCRIPT],
            capture_output=True,
            text=True,
            timeout=60
        )
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        return f"【fix】 rc={p.returncode}\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    except Exception as e:
        return f"【fix】 failed: {e}"

# ================== FAKE POOL ==================
# ۲۰ سرور فیک ثابت؛ endpointها از TEST-NETها هستن که وصل نمی‌شن.
def get_fake_pool() -> List[Dict[str, Any]]:
    # لیست رو می‌تونی سفارشی کنی (کشور/شهرِ فیک برای ظاهر)
    pool = []
    test_hosts = [
        "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14",
        "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13", "198.51.100.14",
        "192.0.2.10",   "192.0.2.11",   "192.0.2.12",   "192.0.2.13",   "192.0.2.14",
        "203.0.113.20", "203.0.113.21", "198.51.100.20","198.51.100.21","192.0.2.20",
    ]
    countries = ["Germany","Netherlands","France","UK","Canada","USA","Sweden","Spain","Italy","Turkey",
                 "Poland","Finland","Norway","Austria","Romania","Hungary","Czech Republic","Switzerland","Denmark","Ireland"]
    cities = ["Berlin","Amsterdam","Paris","London","Toronto","New York","Stockholm","Madrid","Milan","Istanbul",
              "Warsaw","Helsinki","Oslo","Vienna","Bucharest","Budapest","Prague","Zurich","Copenhagen","Dublin"]

    for i in range(20):
        host = test_hosts[i]
        country = countries[i]
        city = cities[i]
        pool.append({
            "id": f"fake-{i+1:02d}",
            "country": country,
            "city": city,
            "proto_family": "openvpn",
            "endpoint": f"{host}:65535",   # عمداً پورت نامعتبر/بسته
            "proto": "udp",
            "dev": "tun",
            "cipher": "AES-128-GCM",
            "auth": "SHA256",
            "verify_x509_name": "",
            "tls_cipher": "",
            "ca": "",
            "cert": "",
            "key": "",
            "hmac_mode": "",
            "tls_crypt": "",
            "tls_auth": "",
            "key_direction": "",
        })
    return pool

# ================== Manifest/Parser ==================
def _read_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_base_manifest() -> Dict[str, Any]:
    """
    فقط فایل پایه (واقعی‌ها) را می‌خواند. اگر نبود و servers.json موجود بود،
    اولین بار از همون فایل منتشرشده به‌عنوان پایه استفاده می‌کنیم (مهاجرت ساده).
    """
    if os.path.exists(SERVERS_BASE_PATH):
        data = _read_json(SERVERS_BASE_PATH)
        if "servers" not in data:
            data["servers"] = []
        if "fake_count" not in data:
            data["fake_count"] = 0
        return data

    # مهاجرت: از فایل انتشار موجود بخوان و به‌عنوان پایه ذخیره کن (بدون دست‌کاری)
    if os.path.exists(SERVERS_PUB_PATH):
        pub = _read_json(SERVERS_PUB_PATH)
        base = {
            "version": int(pub.get("version", 1)),
            "updated_at": now_iso(),
            "servers": pub.get("servers", []),   # فرض: فعلاً فیکی داخلش نیست
            "fake_count": 0
        }
        atomic_save_json(SERVERS_BASE_PATH, base)
        return base

    # اگر هیچ‌کدام نبود، یه پایه خالی بساز
    return {"version": 1, "updated_at": "", "servers": [], "fake_count": 0}

def save_base_manifest(base: Dict[str, Any]):
    base["version"] = int(base.get("version", 1)) + 1
    base["updated_at"] = now_iso()
    atomic_save_json(SERVERS_BASE_PATH, base)

def publish_manifest(base: Dict[str, Any]):
    """servers.json (برای اپ) = واقعی‌ها + تعداد fake_count از fake pool"""
    n = int(base.get("fake_count", 0) or 0)
    n = max(0, min(20, n))
    real_servers = list(base.get("servers", []))
    fake_pool = get_fake_pool()[:n]
    pub = {
        "version": int(base.get("version", 1)),
        "updated_at": now_iso(),
        "servers": real_servers + fake_pool
    }
    atomic_save_json(SERVERS_PUB_PATH, pub)

def save_and_publish(base: Dict[str, Any]):
    save_base_manifest(base)
    publish_manifest(base)

def _block(tag: str, text: str) -> str:
    m = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", text, re.DOTALL | re.IGNORECASE)
    if not m:
        return ""
    lines = [ln for ln in m.group(1).splitlines() if not ln.strip().startswith("#")]
    return "\n".join(lines).strip()

def parse_ovpn(ovpn_text: str) -> Dict[str, Any]:
    get = lambda key: re.search(rf"^\s*{re.escape(key)}\s+(.+)$", ovpn_text, re.MULTILINE | re.IGNORECASE)
    def val(key, default=""):
        m = get(key)
        return m.group(1).strip() if m else default

    endpoint_line = val("remote")
    host, port = "", ""
    if endpoint_line:
        parts = endpoint_line.split()
        if len(parts) >= 2:
            host, port = parts[0], parts[1]

    vxn = val("verify-x509-name", "")
    if vxn.endswith(" name"):
        vxn = vxn[:-5].strip()

    tls_crypt = _block("tls-crypt", ovpn_text)
    tls_auth  = _block("tls-auth",  ovpn_text)
    kd_match  = re.search(r"^\s*key-direction\s+(\d+)", ovpn_text, re.MULTILINE | re.IGNORECASE)
    key_dir   = kd_match.group(1) if kd_match else ""

    if tls_crypt:
        hmac_mode = "tls-crypt"
    elif tls_auth:
        hmac_mode = "tls-auth"
    else:
        hmac_mode = ""

    return {
        "proto_family": "openvpn",
        "endpoint": f"{host}:{port}" if host and port else "",
        "proto": val("proto", "udp"),
        "dev": val("dev", "tun"),
        "cipher": val("cipher", "AES-128-GCM"),
        "auth": val("auth", "SHA256"),
        "verify_x509_name": vxn,
        "tls_cipher": val("tls-cipher", ""),
        "ca": _block("ca", ovpn_text),
        "cert": _block("cert", ovpn_text),
        "key": _block("key", ovpn_text),
        "hmac_mode": hmac_mode,
        "tls_crypt": tls_crypt,
        "tls_auth": tls_auth,
        "key_direction": key_dir,
    }

def parse_wg_conf(conf_text: str) -> Dict[str, Any]:
    """
    پارس استاندارد WireGuard client .conf
    [Interface] و [Peer] را می‌خواند.
    PrivateKey سمت کلاینت در manifest منتشر نمی‌شود.
    """

    def parse_section(block: str) -> Dict[str, str]:
        out = {}
        for ln in block.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            out[k.strip().lower()] = v.strip()
        return out

    # جدا کردن بلوک‌ها
    sections = re.split(r"(?im)^\s*\[(interface|peer)\]\s*$", conf_text)
    iface = {}
    peer = {}
    i = 1
    while i < len(sections):
        sec_name = sections[i].strip().lower()
        sec_body = sections[i+1] if (i+1) < len(sections) else ""
        if sec_name == "interface":
            iface = parse_section(sec_body)
        elif sec_name == "peer":
            if not peer:
                peer = parse_section(sec_body)  # فقط اولین Peer
        i += 2

    address = (iface.get("address") or "").split(",")[0].strip()
    dns = [d.strip() for d in (iface.get("dns") or "").split(",") if d.strip()]
    mtu = int(re.sub(r"\D", "", iface.get("mtu", "") or "0") or 0) or 1420

    endpoint = peer.get("endpoint", "")
    peer_public_key = peer.get("publickey", "")
    allowed_ips = [ip.strip() for ip in (peer.get("allowedips") or "").split(",") if ip.strip()]
    keepalive = int(re.sub(r"\D", "", peer.get("persistentkeepalive", "") or "0") or 0) or 25

    if not endpoint or not peer_public_key:
        # حداقل‌های لازم برای ثبت WG
        return {}

    return {
        "proto_family": "wireguard",
        "endpoint": endpoint,                       # مثال: "49.13.216.46:51820"
        "address": address or "10.7.0.2/32",
        "dns": dns,                                 # ["1.1.1.1","8.8.8.8"]
        "allowed_ips": allowed_ips or ["0.0.0.0/0","::/0"],
        "peer_public_key": peer_public_key,
        "persistent_keepalive": keepalive,
        "mtu": mtu
    }

def format_server_line(s: Dict[str, Any]) -> str:
    return (
        f"🆔 {s.get('id','?')}\n"
        f"🌍 {s.get('country','?')} / {s.get('city','?')}\n"
        f"🔗 {s.get('endpoint','?')} | {s.get('proto_family','?')}"
    )

# ================== /start ==================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    await update.message.reply_text("به منوی مدیریت Noora VPN خوش آمدید 👋", reply_markup=MAIN_KEYBOARD)
    return MAIN_MENU

# ================== اکشن‌های ساده ==================
async def handle_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    data = load_base_manifest()
    servers = data.get("servers", [])
    if not servers:
        await update.message.reply_text("لیست خالی است.", reply_markup=MAIN_KEYBOARD)
        return MAIN_MENU
    lines = [format_server_line(s) for s in servers]
    await update.message.reply_text(
        "📄 سرورهای واقعی:\n\n" + "\n\n".join(lines),
        reply_markup=MAIN_KEYBOARD
    )
    return MAIN_MENU

async def handle_get(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    if not os.path.exists(SERVERS_PUB_PATH):
        await update.message.reply_text("servers.json (منتشرشده) یافت نشد.", reply_markup=MAIN_KEYBOARD)
        return MAIN_MENU
    with open(SERVERS_PUB_PATH, "rb") as f:
        bio = io.BytesIO(f.read()); bio.name = "servers.json"
    await update.message.reply_document(InputFile(bio), caption=PUBLIC_URL, reply_markup=MAIN_KEYBOARD)
    return MAIN_MENU

# ================== افزودن ==================
async def add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    context.user_data["add"] = {}
    await update.message.reply_text(
        "فایل اتصال را ارسال کن:\n- OpenVPN: فایل .ovpn\n- WireGuard: فایل .conf (کلاینت)\n(به‌صورت Document بفرست)",
        reply_markup=with_back_keyboard([["ارسال فایل اتصال"]])
    )
    return ADD_WAIT_OVPN

async def add_receive_ovpn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message and update.message.document:
        doc = update.message.document
        fname = (doc.file_name or "").lower()

        if not (fname.endswith(".ovpn") or fname.endswith(".conf")):
            await update.message.reply_text(
                "فقط یکی از این فرمت‌ها را بفرست:\n- .ovpn برای OpenVPN\n- .conf برای WireGuard",
                reply_markup=with_back_keyboard([["ارسال فایل اتصال"]])
            )
            return ADD_WAIT_OVPN

        file = await doc.get_file()
        content = await file.download_as_bytearray()
        text = content.decode("utf-8", errors="ignore")

        if fname.endswith(".ovpn"):
            parsed = parse_ovpn(text)
            if not parsed.get("endpoint"):
                await update.message.reply_text("در فایل .ovpn سطر remote یافت نشد.",
                                                reply_markup=with_back_keyboard([["ارسال فایل اتصال"]]))
                return ADD_WAIT_OVPN
        else:
            parsed = parse_wg_conf(text)
            if not parsed:
                await update.message.reply_text(
                    "فایل WireGuard معتبر نیست؛ حداقل Endpoint و PublicKey لازم است.",
                    reply_markup=with_back_keyboard([["ارسال فایل اتصال"]])
                )
                return ADD_WAIT_OVPN

        context.user_data["add"]["parsed"] = parsed
        await update.message.reply_text(
            "اوکی! حالا شناسه سرور (id) را بنویس (مثلاً de2-ovpn یا de1-wg).",
            reply_markup=with_back_keyboard([["نمونه: de1-wg"]])
        )
        return ADD_WAIT_ID

    await update.message.reply_text("لطفاً فایل را به‌صورت Document بفرست.",
                                    reply_markup=with_back_keyboard([["ارسال فایل اتصال"]]))
    return ADD_WAIT_OVPN

async def add_receive_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sid_raw = (update.message.text or "").strip()
    if sid_raw == BTN_BACK:
        await update.message.reply_text("به منو برگشتی.", reply_markup=MAIN_KEYBOARD)
        return MAIN_MENU
    if not sid_raw or " " in sid_raw:
        await update.message.reply_text("id نامعتبر است (بدون فاصله).",
                                        reply_markup=with_back_keyboard([["نمونه: de2-ovpn"]]))
        return ADD_WAIT_ID
    sid_norm = _norm_id(sid_raw)

    data = load_base_manifest()
    if any(_norm_id(s.get("id", "")) == sid_norm for s in data.get("servers", [])):
        await update.message.reply_text("این id قبلاً وجود دارد. id دیگری بده یا اول حذف کن.",
                                        reply_markup=with_back_keyboard([["نمونه: de3-ovpn"]]))
        return ADD_WAIT_ID

    context.user_data["add"]["id"] = sid_raw
    context.user_data["add"]["id_norm"] = sid_norm
    await update.message.reply_text("کشور را بنویس (مثلاً Germany).",
                                    reply_markup=with_back_keyboard([["نمونه: Germany"]]))
    return ADD_WAIT_COUNTRY

async def add_receive_country(update: Update, context: ContextTypes.DEFAULT_TYPE):
    country = (update.message.text or "").strip()
    if country == BTN_BACK:
        await update.message.reply_text("به منو برگشتی.", reply_markup=MAIN_KEYBOARD)
        return MAIN_MENU
    if not country:
        await update.message.reply_text("کشور خالی نباشد.",
                                        reply_markup=with_back_keyboard([["نمونه: Germany"]]))
        return ADD_WAIT_COUNTRY

    context.user_data["add"]["country"] = country
    await update.message.reply_text("شهر را بنویس (مثلاً Berlin).",
                                    reply_markup=with_back_keyboard([["نمونه: Berlin"]]))
    return ADD_WAIT_CITY

async def add_receive_city(update: Update, context: ContextTypes.DEFAULT_TYPE):
    city = (update.message.text or "").strip()
    if city == BTN_BACK:
        await update.message.reply_text("به منو برگشتی.", reply_markup=MAIN_KEYBOARD)
        return MAIN_MENU
    if not city:
        await update.message.reply_text("شهر خالی نباشد.",
                                        reply_markup=with_back_keyboard([["نمونه: Berlin"]]))
        return ADD_WAIT_CITY

    context.user_data["add"]["city"] = city
    a = context.user_data["add"]
    parsed = a.get("parsed", {})
    preview = f"{a.get('id')} | {a.get('country')}/{a.get('city')} | {parsed.get('endpoint')}"
    await update.message.reply_text(
        f"تأیید نهایی:\n{preview}\n\nثبت کنم؟",
        reply_markup=with_back_keyboard([["✅ تأیید", "❌ انصراف"]])
    )
    return ADD_CONFIRM

async def add_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if txt == BTN_BACK or "❌" in txt:
        await update.message.reply_text("عملیات افزودن لغو شد.", reply_markup=MAIN_KEYBOARD)
        context.user_data.pop("add", None)
        return MAIN_MENU

    if "✅" in txt or txt.lower() in ("yes", "y", "ok"):
        a = context.user_data.get("add", {})
        parsed = a.get("parsed", {})
        server_obj = {
            "id": a.get("id_norm", _norm_id(a.get("id", ""))) or a.get("id", ""),
            "country": a.get("country"),
            "city": a.get("city"),
            **parsed
        }
        base = load_base_manifest()
        if any(_norm_id(s.get("id", "")) == _norm_id(server_obj["id"]) for s in base.get("servers", [])):
            await update.message.reply_text("این id هم‌اکنون وجود دارد. ابتدا حذف کن یا id جدید بده.",
                                            reply_markup=MAIN_KEYBOARD)
            context.user_data.pop("add", None)
            return MAIN_MENU

        base.setdefault("servers", []).append(server_obj)
        save_and_publish(base)
        context.user_data.pop("add", None)

        report = run_fix()
        await update.message.reply_text(report)

        await update.message.reply_html(
            f"افزوده شد:\n<code>{html.escape(server_obj['id'])}</code>\n{html.escape(PUBLIC_URL)}",
            reply_markup=MAIN_KEYBOARD
        )
        return MAIN_MENU

    await update.message.reply_text("یکی از گزینه‌ها را انتخاب کن.",
                                    reply_markup=with_back_keyboard([["✅ تأیید", "❌ انصراف"]]))
    return ADD_CONFIRM

# ================== حذف ==================
async def remove_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    context.user_data["remove"] = {}
    base = load_base_manifest()
    servers = base.get("servers", [])
    sample = servers[0]["id"] if servers else "de1-ovpn"
    await update.message.reply_text(
        f"شناسه (id) سرور برای حذف را بنویس. (مثال: {sample})",
        reply_markup=with_back_keyboard([[sample]]))
    return REMOVE_WAIT_ID

async def remove_receive_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sid_raw = (update.message.text or "").strip()
    if sid_raw == BTN_BACK:
        await update.message.reply_text("به منو برگشتی.", reply_markup=MAIN_KEYBOARD)
        context.user_data.pop("remove", None)
        return MAIN_MENU
    if not sid_raw:
        await update.message.reply_text("id خالی نباشد.",
                                        reply_markup=with_back_keyboard([["نمونه: de1-ovpn"]]))
        return REMOVE_WAIT_ID

    sid = _norm_id(sid_raw)
    base = load_base_manifest()
    servers = base.get("servers", [])
    match = next((s for s in servers if _norm_id(s.get("id", "")) == sid), None)
    if not match:
        await update.message.reply_text("این id پیدا نشد.", reply_markup=with_back_keyboard([[sid_raw]]))
        return REMOVE_WAIT_ID

    context.user_data["remove"]["id"] = match.get("id")
    await update.message.reply_text(
        f"تأیید حذف: {match.get('id')} ؟",
        reply_markup=with_back_keyboard([["✅ حذف", "❌ انصراف"]])
    )
    return REMOVE_CONFIRM

async def remove_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if txt == BTN_BACK or "❌" in txt:
        await update.message.reply_text("عملیات حذف لغو شد.", reply_markup=MAIN_KEYBOARD)
        context.user_data.pop("remove", None)
        return MAIN_MENU

    if "✅" in txt:
        sid_original = (context.user_data.get("remove", {}) or {}).get("id", "")
        sid_norm = _norm_id(sid_original)
        base = load_base_manifest()
        servers = base.get("servers", [])
        before = len(servers)
        kept = [s for s in servers if _norm_id(s.get("id", "")) != sid_norm]
        after = len(kept)

        if after == before:
            await update.message.reply_text("چیزی حذف نشد.", reply_markup=MAIN_KEYBOARD)
            context.user_data.pop("remove", None)
            return MAIN_MENU

        base["servers"] = kept
        save_and_publish(base)
        context.user_data.pop("remove", None)

        report = run_fix()
        await update.message.reply_text(report)

        await update.message.reply_text(
            f"حذف شد: {sid_original}\nکل واقعی‌ها: {after}\n{PUBLIC_URL}",
            reply_markup=MAIN_KEYBOARD
        )
        return MAIN_MENU

    await update.message.reply_text("یکی از گزینه‌ها را انتخاب کن.",
                                    reply_markup=with_back_keyboard([["✅ حذف", "❌ انصراف"]]))
    return REMOVE_CONFIRM

# ================== منوی فیک ==================
async def fake_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    base = load_base_manifest()
    cnt = int(base.get("fake_count", 0) or 0)
    await update.message.reply_text("مدیریت سرورهای فیک:", reply_markup=fake_keyboard(cnt))
    return MAIN_MENU

async def fake_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    pool = get_fake_pool()
    lines = [format_server_line(s) for s in pool]
    await update.message.reply_text("📄 20 فیک:\n\n" + "\n\n".join(lines[:20]), reply_markup=MAIN_KEYBOARD)
    return MAIN_MENU

async def fake_publish(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    base = load_base_manifest()
    publish_manifest(base)
    report = run_fix()
    await update.message.reply_text(f"منتشر شد.\n{PUBLIC_URL}\n\n{report}", reply_markup=MAIN_KEYBOARD)
    return MAIN_MENU

async def fake_set_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    base = load_base_manifest()
    cnt = int(base.get("fake_count", 0) or 0)
    await update.message.reply_text(
        f"تعداد مورد نظر (۰ تا ۲۰) را ارسال کن.\nتعداد فعلی: {cnt}",
        reply_markup=with_back_keyboard([["مثال: 10"]])
    )
    return FAKE_WAIT_COUNT

async def fake_set_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if txt == BTN_BACK:
        return await fake_menu(update, context)
    m = re.match(r"^\s*(\d{1,2})\s*$", txt)
    if not m:
        await update.message.reply_text("یک عدد بین 0 تا 20 بفرست.", reply_markup=with_back_keyboard([["مثال: 10"]]))
        return FAKE_WAIT_COUNT
    val = int(m.group(1))
    if val < 0 or val > 20:
        await update.message.reply_text("بازه مجاز 0..20 هست.", reply_markup=with_back_keyboard([["مثال: 10"]]))
        return FAKE_WAIT_COUNT

    base = load_base_manifest()
    base["fake_count"] = val
    save_and_publish(base)
    report = run_fix()
    await update.message.reply_text(
        f"تنظیم شد: {val}\nمنتشر شد: {PUBLIC_URL}\n\n{report}",
        reply_markup=MAIN_KEYBOARD
    )
    return MAIN_MENU

async def fake_set_preset(update: Update, context: ContextTypes.DEFAULT_TYPE, preset: int):
    base = load_base_manifest()
    base["fake_count"] = max(0, min(20, preset))
    save_and_publish(base)
    report = run_fix()
    await update.message.reply_text(
        f"تنظیم شد: {base['fake_count']}\nمنتشر شد: {PUBLIC_URL}\n\n{report}",
        reply_markup=MAIN_KEYBOARD
    )
    return MAIN_MENU

# ================== مسیریابی ==================
async def route_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await update.message.reply_text("Access denied.")
    txt = (update.message.text or "").strip()

    # منوهای اصلی
    if txt == BTN_ADD:
        return await add_start(update, context)
    if txt == BTN_LIST:
        return await handle_list(update, context)
    if txt == BTN_GET:
        return await handle_get(update, context)
    if txt == BTN_REMOVE:
        return await remove_start(update, context)
    if txt == BTN_FAKE:
        return await fake_menu(update, context)

    # منوی فیک
    if txt == BTN_FAKE_LIST:
        return await fake_list(update, context)
    if txt == BTN_FAKE_PUBLISH:
        return await fake_publish(update, context)
    if txt == BTN_FAKE_SET:
        return await fake_set_prompt(update, context)
    if txt == BTN_FAKE_PRESET_0:
        return await fake_set_preset(update, context, 0)
    if txt == BTN_FAKE_PRESET_5:
        return await fake_set_preset(update, context, 5)
    if txt == BTN_FAKE_PRESET_10:
        return await fake_set_preset(update, context, 10)
    if txt == BTN_FAKE_PRESET_15:
        return await fake_set_preset(update, context, 15)
    if txt == BTN_FAKE_PRESET_20:
        return await fake_set_preset(update, context, 20)

    if txt == BTN_BACK:
        context.user_data.pop("add", None)
        context.user_data.pop("remove", None)
        await update.message.reply_text("به منو برگشتی.", reply_markup=MAIN_KEYBOARD)
        return MAIN_MENU

    await update.message.reply_text("از دکمه‌های منو استفاده کن.", reply_markup=MAIN_KEYBOARD)
    return MAIN_MENU

async def add_receive_ovpn_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    return await add_receive_ovpn(update, context)

# ================== بدنه ==================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            MAIN_MENU: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_ADD)}$"), add_start),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_LIST)}$"), handle_list),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_GET)}$"), handle_get),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_REMOVE)}$"), remove_start),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE)}$"), fake_menu),

                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_LIST)}$"), fake_list),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_PUBLISH)}$"), fake_publish),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_SET)}$"), fake_set_prompt),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_PRESET_0)}$"), lambda u,c: fake_set_preset(u,c,0)),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_PRESET_5)}$"), lambda u,c: fake_set_preset(u,c,5)),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_PRESET_10)}$"), lambda u,c: fake_set_preset(u,c,10)),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_PRESET_15)}$"), lambda u,c: fake_set_preset(u,c,15)),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_FAKE_PRESET_20)}$"), lambda u,c: fake_set_preset(u,c,20)),

                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, route_menu),
            ],
            ADD_WAIT_OVPN: [
                MessageHandler(filters.Document.ALL, add_receive_ovpn_router),
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, add_receive_ovpn),
            ],
            ADD_WAIT_ID: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, add_receive_id),
            ],
            ADD_WAIT_COUNTRY: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, add_receive_country),
            ],
            ADD_WAIT_CITY: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, add_receive_city),
            ],
            ADD_CONFIRM: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, add_confirm),
            ],
            REMOVE_WAIT_ID: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, remove_receive_id),
            ],
            REMOVE_CONFIRM: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, remove_confirm),
            ],
            FAKE_WAIT_COUNT: [
                MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), fake_menu),
                MessageHandler(filters.TEXT & ~filters.COMMAND, fake_set_receive),
            ],
        },
        fallbacks=[MessageHandler(filters.Regex(f"^{re.escape(BTN_BACK)}$"), route_menu)],
        allow_reentry=True
    )
    app.add_handler(conv)
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
