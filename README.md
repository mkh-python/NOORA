# NOORA VPN Installer + Telegram Bot

این ریپو شامل اسکریپت نصب خودکار **Xray (VLESS/WS+TLS پشت Cloudflare)** به همراه **ربات مدیریت تلگرام** برای ساخت/حذف/مدیریت کاربران VPN است.  
همه چیز به صورت اتوماتیک راه‌اندازی می‌شود:  
- اتصال به Cloudflare (DNS + Origin Cert)  
- نصب و کانفیگ Xray و Nginx  
- ساخت دیتابیس SQLite برای کاربران  
- نصب و راه‌اندازی ربات تلگرام (Reply Keyboard, بدون Inline)  
- امکانات مدیریتی: ساخت کاربر با QR/لینک، لیست کاربران، حذف، بکاپ/ریستور  

---

## ⚡ نصب سریع

روی سرور Ubuntu (ترجیحاً 22.04 یا 24.04 LTS):

```bash
curl -fsSL https://raw.githubusercontent.com/mkh-python/NOORA/main/install_noora.sh -o install_noora.sh
sudo bash install_noora.sh
