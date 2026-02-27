#!/bin/bash
# ==========================================
# Auto Install SSH WS & X-ray (DNS ONLY)
# Dropbear Version: 2019
# Full Script - No Cutting
# ==========================================

# 1. Pastikan Running sebagai Root & Non-Interactive
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get upgrade -y -q
apt-get remove -y dropbear dropbear-run
apt-get install -y -q curl jq nginx uuid-runtime bzip2 zlib1g-dev make gcc build-essential wget python3 python3-pip

# 2. Variabel Cloudflare (Sesuai Key Kamu)
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

echo "Step 1: Pointing Domain (DNS Only)..."
# Ambil Nama Domain Utama
DOMAIN=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r '.result.name')

if [ "$DOMAIN" == "null" ] || [ -z "$DOMAIN" ]; then
    echo "Gagal mengambil domain. Cek API Key/Zone ID!"
    exit 1
fi

# Buat Subdomain Random
RANDOM_STR=$(tr -dc a-z0-9 </dev/urandom | head -c 5)
SUB_DOMAIN="${RANDOM_STR}.${DOMAIN}"
IP_VPS=$(curl -s ifconfig.me)

# Eksekusi Pointing (proxied: false)
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}'

# Simpan Domain ke sistem agar terbaca permanen oleh menu
echo "$SUB_DOMAIN" > /root/domain
echo "$SUB_DOMAIN" > /etc/vps_domain

# 3. Instalasi Dropbear 2019 (Sesuai Permintaan)
echo "Step 2: Install Dropbear 2019..."
cd /usr/local/src
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
tar -xvjf dropbear-2019.78.tar.bz2
cd dropbear-2019.78
./configure --prefix=/usr
make && make install
ln -sf /usr/sbin/dropbear /usr/bin/dropbear

# Konfigurasi Service Dropbear (Port 143)
cat > /etc/systemd/system/dropbear.service <<EOF
[Unit]
Description=Dropbear SSH daemon 2019
After=network.target

[Service]
ExecStart=/usr/sbin/dropbear -F -R -p 143
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dropbear
systemctl restart dropbear

# 4. SSH WebSocket Proxy (Python) - Port 8880
echo "Step 3: Setup WebSocket Proxy..."
cat > /usr/local/bin/ws-ssh << 'EOF'
import socket, threading, threadpoolctl

def handle(client):
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(('127.0.0.1', 143))
        
        # Kirim HTTP 101 Switching Protocols agar HTTP Custom konek
        client.send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        
        def fw(src, dst):
            try:
                while True:
                    d = src.recv(8192)
                    if not d: break
                    dst.send(d)
            except: pass
        
        threading.Thread(target=fw, args=(client, remote)).start()
        threading.Thread(target=fw, args=(remote, client)).start()
    except:
        client.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 8880))
s.listen(100)
while True:
    c, a = s.accept()
    threading.Thread(target=handle, args=(c,)).start()
EOF

cat > /etc/systemd/system/ws-ssh.service <<EOF
[Unit]
Description=Python SSH WS
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ssh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl enable ws-ssh
systemctl restart ws-ssh

# 5. Instalasi X-ray (Port 8081)
echo "Step 4: Install X-ray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -y
cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": 8081,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$(uuidgen)"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/xray"}
      }
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
systemctl restart xray

# 6. Nginx Config (Port 80 & 443)
echo "Step 5: Config Nginx..."
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default
cat > /etc/nginx/conf.d/vps.conf <<EOF
server {
    listen 80;
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    
    # WebSocket SSH
    location / {
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    # WebSocket Xray
    location /xray {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
systemctl restart nginx

# 7. Membuat Menu (LENGKAP DENGAN TAMPILAN DOMAIN)
echo "Step 6: Creating Menu..."
cat > /usr/local/bin/menu <<'EOF'
#!/bin/bash
clear
# Ambil domain dari file yang sudah dibuat saat install
if [ -f /etc/vps_domain ]; then
    MY_DOMAIN=$(cat /etc/vps_domain)
else
    MY_DOMAIN=$(curl -s ifconfig.me)
fi

echo "================================="
echo "   AUTO SCRIPT SSH WS & XRAY     "
echo "================================="
echo "Domain : $MY_DOMAIN"
echo "---------------------------------"
echo "1. Buat Akun SSH & Dropbear"
echo "2. Buat Akun X-ray Vless"
echo "3. Cek Port & Service"
echo "4. Keluar"
echo "================================="
read -p "Pilih Menu [1-4]: " opt

case $opt in
    1)
        read -p "Username: " user
        read -p "Password: " pass
        useradd -e `date -d "30 days" +"%Y-%m-%d"` -s /bin/false -M $user
        echo -e "$pass\n$pass" | passwd $user >/dev/null 2>&1
        clear
        echo "================================="
        echo "   AKUN SSH WS BERHASIL DIBUAT   "
        echo "================================="
        echo "Domain   : $MY_DOMAIN"
        echo "Username : $user"
        echo "Password : $pass"
        echo "Port 80  : 80 (Non-TLS)"
        echo "Port 443 : 443 (TLS)"
        echo "Expired  : 30 Hari"
        echo "Payload  : GET / HTTP/1.1[crlf]Host: $MY_DOMAIN[crlf]Upgrade: websocket[crlf][crlf]"
        echo "================================="
        ;;
    2)
        read -p "User Xray: " userx
        uuid=$(uuidgen)
        jq '.inbounds[0].settings.clients += [{"id": "'$uuid'", "email": "'$userx'"}]' /usr/local/etc/xray/config.json > /tmp/x.json && mv /tmp/x.json /usr/local/etc/xray/config.json
        systemctl restart xray
        clear
        echo "================================="
        echo "   AKUN XRAY BERHASIL DIBUAT     "
        echo "================================="
        echo "Domain   : $MY_DOMAIN"
        echo "User     : $userx"
        echo "UUID     : $uuid"
        echo "Port     : 443 (TLS) / 80 (NT)"
        echo "Path     : /xray"
        echo "================================="
        ;;
    3)
        netstat -ntlp
        ;;
    4)
        exit ;;
esac
EOF
chmod +x /usr/local/bin/menu

# Finalisasi
clear
echo "================================================="
echo "        INSTALLASI SELESAI (DNS ONLY)            "
echo "================================================="
echo "Domain Anda : $SUB_DOMAIN"
echo "Dropbear    : Port 143 (Internal)"
echo "SSH WS      : Port 80, 443"
echo "Xray WS     : Port 80, 443 (Path: /xray)"
echo "-------------------------------------------------"
echo "Ketik 'menu' untuk membuat akun."
echo "================================================="
