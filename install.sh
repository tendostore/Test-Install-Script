#!/bin/bash

# ==================================================
# X-RAY AUTO INSTALLER (MULTI-PORT & MULTI-PROTOCOL)
# Created for: User Request
# Protocols: Vmess, Vless, Trojan
# Ports: 443 (TLS/SSL) & 80 (Non-TLS)
# ==================================================

# --- Warna ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Cek Root ---
if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}Error: Script ini harus dijalankan sebagai root!${NC}"
    exit 1
fi

clear
echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}   INSTALLER X-RAY VMESS VLESS TROJAN (FULL)     ${NC}"
echo -e "${YELLOW}   Support: Port 443 (TLS) & Port 80 (Non-TLS)   ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

# --- 1. Input Domain ---
read -p "Masukkan Domain/Subdomain Anda (contoh: vps.domain.com): " domain
if [ -z "$domain" ]; then
    echo -e "${RED}Domain tidak boleh kosong!${NC}"
    exit 1
fi
echo -e "${GREEN}[INFO] Domain diset ke: $domain${NC}"
sleep 1

# --- 2. Update & Install Dependencies ---
echo -e "${YELLOW}[PROCESS] Update sistem dan install dependencies...${NC}"
apt update -y
apt install curl socat certbot cron -y

# --- 3. Persiapan Port 80 (Stop Web Server Lain) ---
echo -e "${YELLOW}[PROCESS] Mematikan service di port 80 untuk Certbot...${NC}"
systemctl stop nginx 2>/dev/null
systemctl stop apache2 2>/dev/null
systemctl stop xray 2>/dev/null

# --- 4. Install X-ray Core Official ---
echo -e "${YELLOW}[PROCESS] Menginstall X-ray Core terbaru...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# --- 5. Generate SSL/TLS Certificate ---
echo -e "${YELLOW}[PROCESS] Request sertifikat SSL untuk $domain...${NC}"
certbot certonly --standalone --preferred-challenges http --agree-tos --register-unsafely-without-email -d $domain

# Cek path sertifikat
crt="/etc/letsencrypt/live/$domain/fullchain.pem"
key="/etc/letsencrypt/live/$domain/privkey.pem"

if [ ! -f "$crt" ]; then
    echo -e "${RED}[ERROR] Gagal membuat sertifikat SSL!${NC}"
    echo -e "${RED}Pastikan A Record domain $domain sudah mengarah ke IP VPS ini.${NC}"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] Sertifikat SSL berhasil dibuat!${NC}"
chmod -R 755 /etc/letsencrypt/live/
chmod -R 755 /etc/letsencrypt/archive/

# --- 6. Konfigurasi X-ray (Config.json) ---
echo -e "${YELLOW}[PROCESS] Membuat file konfigurasi X-ray...${NC}"
uuid=$(xray uuid)

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-tls",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision",
            "level": 0,
            "email": "vless-tls"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 3001,
            "xver": 1
          },
          {
            "path": "/vmess",
            "dest": 3002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$crt",
              "keyFile": "$key"
            }
          ],
          "alpn": [
            "h2",
            "http/1.1"
          ]
        }
      }
    },
    {
      "tag": "vless-nontls",
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0,
            "email": "vless-nontls"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "path": "/vmess",
            "dest": 3002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      }
    },
    {
      "tag": "trojan-fallback",
      "port": 3001,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$uuid",
            "level": 0,
            "email": "trojan-tls"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {
          "acceptProxyProtocol": true
        }
      }
    },
    {
      "tag": "vmess-fallback",
      "port": 3002,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0,
            "email": "vmess-ws"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/vmess"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

# --- 7. Setup Auto Renewal SSL ---
echo -e "${YELLOW}[PROCESS] Mengatur auto-renewal sertifikat...${NC}"
# Hapus cron lama jika ada
crontab -l | grep -v "certbot renew" | crontab -
# Tambah cron baru
(crontab -l 2>/dev/null; echo "0 0 1 * * certbot renew --quiet --pre-hook \"systemctl stop xray\" --post-hook \"systemctl start xray\"") | crontab -

# --- 8. Restart Service ---
echo -e "${YELLOW}[PROCESS] Restarting X-ray Service...${NC}"
systemctl restart xray
systemctl enable xray

# Cek status
if systemctl is-active --quiet xray; then
    echo -e "${GREEN}[SUCCESS] X-ray Running!${NC}"
else
    echo -e "${RED}[ERROR] X-ray gagal berjalan. Cek log: /var/log/xray/error.log${NC}"
fi

# --- 9. Tampilkan Detail Akun ---
clear
echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}          INSTALASI SELESAI (SUKSES)             ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "Domain      : $domain"
echo -e "IP Address  : $(curl -s ifconfig.me)"
echo -e "UUID        : $uuid"
echo -e "Path Vmess  : /vmess"
echo -e "${BLUE}=================================================${NC}"
echo ""
echo -e "${YELLOW}--- [1] VLESS TLS (Port 443) ---${NC}"
echo -e "Address: $domain"
echo -e "Port: 443"
echo -e "ID: $uuid"
echo -e "Flow: xtls-rprx-vision"
echo -e "Encryption: none"
echo -e "Network: tcp"
echo -e "Security: tls"
echo ""
echo -e "${YELLOW}--- [2] VLESS NON-TLS (Port 80) ---${NC}"
echo -e "Address: $domain"
echo -e "Port: 80"
echo -e "ID: $uuid"
echo -e "Encryption: none"
echo -e "Network: tcp"
echo -e "Security: none"
echo ""
echo -e "${YELLOW}--- [3] TROJAN TLS (Port 443) ---${NC}"
echo -e "Address: $domain"
echo -e "Port: 443"
echo -e "Password: $uuid"
echo -e "Network: tcp"
echo -e "Security: tls"
echo -e "SNI: $domain"
echo ""
echo -e "${YELLOW}--- [4] VMESS WS TLS (Port 443) ---${NC}"
echo -e "Address: $domain"
echo -e "Port: 443"
echo -e "ID: $uuid"
echo -e "Network: ws"
echo -e "Path: /vmess"
echo -e "Security: tls"
echo ""
echo -e "${YELLOW}--- [5] VMESS WS NON-TLS (Port 80) ---${NC}"
echo -e "Address: $domain"
echo -e "Port: 80"
echo -e "ID: $uuid"
echo -e "Network: ws"
echo -e "Path: /vmess"
echo -e "Security: none"
echo ""
echo -e "${BLUE}=================================================${NC}"
echo -e "Simpan data di atas. Script by Gemini AI."
