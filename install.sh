#!/bin/bash

# ==========================================
# Auto Installer X-ray (Vmess, Vless, Trojan)
# Created for: Tendo
# Ports: 443 (TLS) & 80 (Non-TLS)
# ==========================================

# Warna untuk output
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# Cek Root
if [ "${EUID}" -ne 0 ]; then
		echo -e "${red}Script ini harus dijalankan sebagai root!${NC}"
		exit 1
fi

clear
echo -e "${green}======================================${NC}"
echo -e "${green}   AUTO INSTALLER X-RAY FOR TENDO     ${NC}"
echo -e "${green}   Vmess | Vless | Trojan (443 & 80)  ${NC}"
echo -e "${green}======================================${NC}"
echo ""

# 1. Input Domain
read -p "Masukkan Domain Anda (contoh: vps.tendo.com): " domain
if [ -z "$domain" ]; then
    echo -e "${red}Domain tidak boleh kosong!${NC}"
    exit 1
fi

echo -e "${green}[+] Memulai Instalasi...${NC}"
sleep 1

# 2. Update & Install Dependencies
echo -e "${green}[+] Update Repository & Install Dependencies...${NC}"
apt update -y
apt install curl socat certbot cron -y

# 3. Stop Port 80 (Untuk Certbot)
echo -e "${green}[+] Menyiapkan Port 80 untuk Certbot...${NC}"
systemctl stop nginx 2>/dev/null
systemctl stop apache2 2>/dev/null
systemctl stop xray 2>/dev/null

# 4. Install X-ray Core (Official)
echo -e "${green}[+] Menginstall X-ray Core Official...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 5. Generate SSL Certificate
echo -e "${green}[+] Request SSL Certificate untuk $domain ...${NC}"
certbot certonly --standalone --preferred-challenges http --agree-tos --register-unsafely-without-email -d $domain

# Cek apakah sertifikat berhasil dibuat
crt_path="/etc/letsencrypt/live/$domain/fullchain.pem"
key_path="/etc/letsencrypt/live/$domain/privkey.pem"

if [ ! -f "$crt_path" ]; then
    echo -e "${red}Gagal membuat sertifikat SSL! Pastikan domain sudah diarahkan ke IP VPS ini.${NC}"
    exit 1
fi

# Beri izin akses ke folder sertifikat
chmod -R 755 /etc/letsencrypt/live/
chmod -R 755 /etc/letsencrypt/archive/

# 6. Generate UUID
uuid=$(xray uuid)
echo -e "${green}[+] UUID Generated: $uuid${NC}"

# 7. Tulis Konfigurasi X-ray (Full Config)
echo -e "${green}[+] Menulis Konfigurasi X-ray...${NC}"
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
            "email": "tendo@vless"
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
          },
          {
            "path": "/trojan-ws",
            "dest": 3003,
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
              "certificateFile": "$crt_path",
              "keyFile": "$key_path"
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
      "tag": "trojan-fallback",
      "port": 3001,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$uuid",
            "level": 0,
            "email": "tendo@trojan"
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
            "email": "tendo@vmess"
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
      "tag": "vmess-nontls",
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0,
            "email": "tendo@vmess80"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
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

# 8. Setup Auto Renewal (Cron)
echo -e "${green}[+] Mengatur Auto-Renewal Sertifikat...${NC}"
# Hapus cron lama jika ada
crontab -l | grep -v "certbot renew" | crontab -
# Tambah cron baru (Stop xray -> Renew -> Start xray)
(crontab -l 2>/dev/null; echo "0 0 1 * * certbot renew --quiet --pre-hook \"systemctl stop xray\" --post-hook \"systemctl start xray\"") | crontab -

# 9. Restart X-ray
echo -e "${green}[+] Merestart Service X-ray...${NC}"
systemctl restart xray
systemctl enable xray

# 10. Output Informasi Akun
clear
echo -e "${green}======================================${NC}"
echo -e "${green}      INSTALASI SELESAI (TENDO)       ${NC}"
echo -e "${green}======================================${NC}"
echo ""
echo -e "Domain     : $domain"
echo -e "UUID       : $uuid"
echo -e "Path Vmess : /vmess"
echo ""
echo -e "${green}[1] VLESS XTLS (Port 443)${NC}"
echo -e "Address: $domain"
echo -e "Port: 443"
echo -e "ID: $uuid"
echo -e "Flow: xtls-rprx-vision"
echo -e "Encryption: none"
echo -e "Network: tcp"
echo -e "Security: tls"
echo ""
echo -e "${green}[2] TROJAN TCP (Port 443 Fallback)${NC}"
echo -e "Address: $domain"
echo -e "Port: 443"
echo -e "Password: $uuid"
echo -e "Network: tcp"
echo -e "Security: tls"
echo -e "Sni: $domain"
echo ""
echo -e "${green}[3] VMESS WS TLS (Port 443 Fallback)${NC}"
echo -e "Address: $domain"
echo -e "Port: 443"
echo -e "ID: $uuid"
echo -e "Network: ws"
echo -e "Path: /vmess"
echo -e "Security: tls"
echo ""
echo -e "${green}[4] VMESS WS Non-TLS (Port 80)${NC}"
echo -e "Address: $domain"
echo -e "Port: 80"
echo -e "ID: $uuid"
echo -e "Network: ws"
echo -e "Path: /vmess"
echo -e "Security: none"
echo ""
echo -e "${green}======================================${NC}"
echo -e "Script Full Install Selesai."
