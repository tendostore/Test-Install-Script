#!/bin/bash
# ==========================================
# Auto Install SSH WS & X-ray (Port 443 & 80)
# ==========================================

# 1. Melewati prompt "Enter" selama instalasi
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get upgrade -y -q
apt-get install -y -q curl jq nginx dropbear uuid-runtime

# 2. Konfigurasi Cloudflare
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

echo "Mengambil informasi domain dari Cloudflare..."
# Mengambil nama domain utama berdasarkan Zone ID
DOMAIN=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r '.result.name')

if [ "$DOMAIN" == "null" ] || [ -z "$DOMAIN" ]; then
    echo "Gagal mengambil domain dari Cloudflare. Periksa API Key dan Zone ID."
    exit 1
fi

# Membuat subdomain acak (5 karakter)
RANDOM_STR=$(tr -dc a-z0-9 </dev/urandom | head -c 5)
SUB_DOMAIN="${RANDOM_STR}.${DOMAIN}"
IP_VPS=$(curl -s ifconfig.me)

echo "Domain acak yang digunakan: $SUB_DOMAIN"
echo "Menambahkan DNS Record ke Cloudflare..."

# Update DNS Record ke Cloudflare
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}'

# 3. Instalasi X-ray Core
echo "Menginstal X-ray Core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta -y

# Generate UUID untuk default admin/user
UUID=$(uuidgen)

# Konfigurasi dasar X-ray (Vless WS Port 443 & 80)
cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": 8080,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/xray"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

systemctl restart xray
systemctl enable xray

# 4. Konfigurasi Nginx sebagai Reverse Proxy untuk Port 80 (Non-TLS) dan 443 (TLS)
# Catatan: Untuk Port 443 yang optimal, kamu perlu menginstal sertifikat SSL (misal: acme.sh).
# Script ini menyiapkan blok server dasar.
cat > /etc/nginx/conf.d/vps.conf <<EOF
server {
    listen 80;
    listen 443 ssl http2;
    server_name ${SUB_DOMAIN};

    # Konfigurasi Dummy SSL (Ganti dengan path sertifikat asli dari acme.sh nantinya jika diperlukan)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    location /xray {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    location /sshws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8880; # Asumsi port websocket python/Go untuk SSH
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

systemctl restart nginx

# 5. Membuat Script Menu Interaktif
echo "Membuat menu manajemen akun..."
cat > /usr/local/bin/menu <<'EOF'
#!/bin/bash
clear
echo "================================="
echo "       MENU MANAJEMEN AKUN       "
echo "================================="
echo "1. Buat Akun SSH"
echo "2. Buat Akun X-ray (Vless)"
echo "3. Keluar"
echo "================================="
read -p "Pilih menu (1-3): " menu_option

case $menu_option in
    1)
        clear
        read -p "Masukkan Username SSH: " user_ssh
        read -p "Masukkan Password SSH: " pass_ssh
        useradd -e `date -d "30 days" +"%Y-%m-%d"` -s /bin/false -M $user_ssh
        echo -e "$pass_ssh\n$pass_ssh" | passwd $user_ssh >/dev/null 2>&1
        echo "================================="
        echo "Akun SSH Berhasil Dibuat!"
        echo "Username : $user_ssh"
        echo "Password : $pass_ssh"
        echo "Expired  : 30 Hari"
        echo "================================="
        ;;
    2)
        clear
        read -p "Masukkan Nama User X-ray: " user_xray
        new_uuid=$(uuidgen)
        # Menambahkan UUID ke config xray menggunakan jq
        jq '.inbounds[0].settings.clients += [{"id": "'${new_uuid}'", "email": "'${user_xray}'"}]' /usr/local/etc/xray/config.json > /tmp/xray_tmp.json && mv /tmp/xray_tmp.json /usr/local/etc/xray/config.json
        systemctl restart xray
        echo "================================="
        echo "Akun X-ray Vless Berhasil Dibuat!"
        echo "Username : $user_xray"
        echo "UUID     : $new_uuid"
        echo "Path     : /xray"
        echo "================================="
        ;;
    3)
        exit 0
        ;;
    *)
        echo "Pilihan tidak valid!"
        ;;
esac
EOF

chmod +x /usr/local/bin/menu

echo "================================================="
echo "Instalasi Selesai!"
echo "Domain yang digunakan : $SUB_DOMAIN"
echo "Untuk mengelola akun, ketik perintah: menu"
echo "================================================="
