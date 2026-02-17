#!/bin/bash

# ==================================================
# X-RAY INSTALLER (ALL WS) + AUTO LINK GENERATOR
# Created for: User Request
# Protocols: Vmess WS, Vless WS, Trojan WS
# Ports: 443 (TLS) & 80 (Non-TLS)
# Output: Config JSON & Copy-Paste Links (v2rayNG)
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
echo -e "${GREEN}   INSTALLER X-RAY ALL WEBSOCKET (LINK MODE)     ${NC}"
echo -e "${YELLOW}   Modes: Vmess-WS, Vless-WS, Trojan-WS          ${NC}"
echo -e "${YELLOW}   Ports: 443 (SSL) & 80 (HTTP)                  ${NC}"
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
apt install curl socat certbot cron jq -y

# --- 3. Persiapan Port (Stop Service) ---
echo -e "${YELLOW}[PROCESS] Mematikan service yang bentrok...${NC}"
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
    echo -e "${RED}Pastikan IP VPS sudah benar diarahakan di DNS Domain.${NC}"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] Sertifikat SSL berhasil dibuat!${NC}"
chmod -R 755 /etc/letsencrypt/live/
chmod -R 755 /etc/letsencrypt/archive/

# --- 6. Konfigurasi X-ray (Config.json) ---
echo -e "${YELLOW}[PROCESS] Membuat konfigurasi X-ray (ALL WS Mode)...${NC}"
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
      "tag": "inbound-443",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision",
            "level": 0,
            "email": "vless-vision-main"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "path": "/vless",
            "dest": 10001,
            "xver": 1
          },
          {
            "path": "/vmess",
            "dest": 10002,
            "xver": 1
          },
          {
            "path": "/trojan",
            "dest": 10003,
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
      "tag": "inbound-80",
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0,
            "email": "vless-tcp-80"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "path": "/vless",
            "dest": 10001,
            "xver": 1
          },
          {
            "path": "/vmess",
            "dest": 10002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "tag": "vless-ws-service",
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/vless"
        }
      }
    },
    {
      "tag": "vmess-ws-service",
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0
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
    },
    {
      "tag": "trojan-ws-service",
      "port": 10003,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$uuid",
            "level": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/trojan"
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
crontab -l | grep -v "certbot renew" | crontab -
(crontab -l 2>/dev/null; echo "0 0 1 * * certbot renew --quiet --pre-hook \"systemctl stop xray\" --post-hook \"systemctl start xray\"") | crontab -

# --- 8. Restart Service ---
echo -e "${YELLOW}[PROCESS] Restarting X-ray Service...${NC}"
systemctl restart xray
systemctl enable xray

if systemctl is-active --quiet xray; then
    echo -e "${GREEN}[SUCCESS] X-ray Running (All WS Mode)!${NC}"
else
    echo -e "${RED}[ERROR] X-ray gagal berjalan. Cek log: /var/log/xray/error.log${NC}"
fi

# --- 9. Generating Links for Client Apps ---
# VMESS TLS
vmess_tls_config='{
  "v": "2",
  "ps": "VMESS-TLS-443-'${domain}'",
  "add": "'${domain}'",
  "port": "443",
  "id": "'${uuid}'",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "'${domain}'",
  "path": "/vmess",
  "tls": "tls",
  "sni": "'${domain}'"
}'
vmess_tls_link="vmess://$(echo $vmess_tls_config | base64 -w 0)"

# VMESS NON-TLS
vmess_nontls_config='{
  "v": "2",
  "ps": "VMESS-HTTP-80-'${domain}'",
  "add": "'${domain}'",
  "port": "80",
  "id": "'${uuid}'",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "'${domain}'",
  "path": "/vmess",
  "tls": "",
  "sni": ""
}'
vmess_nontls_link="vmess://$(echo $vmess_nontls_config | base64 -w 0)"

# VLESS TLS
vless_tls_link="vless://${uuid}@${domain}:443?security=tls&encryption=none&type=ws&host=${domain}&path=/vless&sni=${domain}#VLESS-TLS-443-${domain}"

# VLESS NON-TLS
vless_nontls_link="vless://${uuid}@${domain}:80?security=none&encryption=none&type=ws&host=${domain}&path=/vless#VLESS-HTTP-80-${domain}"

# TROJAN TLS
trojan_tls_link="trojan://${uuid}@${domain}:443?security=tls&type=ws&host=${domain}&path=/trojan&sni=${domain}#TROJAN-TLS-443-${domain}"


# --- 10. Tampilkan Detail Akun ---
clear
echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}      INSTALASI SELESAI - SILAHKAN COPY LINK     ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "Domain      : $domain"
echo -e "UUID        : $uuid"
echo -e "IP Address  : $(curl -s ifconfig.me)"
echo -e "${BLUE}=================================================${NC}"
echo ""

echo -e "${YELLOW}--- [1] VLESS WS TLS (Port 443) ---${NC}"
echo -e "${GREEN}${vless_tls_link}${NC}"
echo ""

echo -e "${YELLOW}--- [2] VMESS WS TLS (Port 443) ---${NC}"
echo -e "${GREEN}${vmess_tls_link}${NC}"
echo ""

echo -e "${YELLOW}--- [3] TROJAN WS TLS (Port 443) ---${NC}"
echo -e "${GREEN}${trojan_tls_link}${NC}"
echo ""

echo -e "${YELLOW}--- [4] VLESS WS NON-TLS (Port 80) ---${NC}"
echo -e "${GREEN}${vless_nontls_link}${NC}"
echo ""

echo -e "${YELLOW}--- [5] VMESS WS NON-TLS (Port 80) ---${NC}"
echo -e "${GREEN}${vmess_nontls_link}${NC}"
echo ""

echo -e "${BLUE}=================================================${NC}"
echo -e "Tips: Copy link berwarna hijau di atas, lalu"
echo -e "Buka v2rayNG/NekoBox -> Import Config from Clipboard."
