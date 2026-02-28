#!/bin/bash
# ==========================================
# Auto Installer Xray Vless & SSH WS + Dropbear 2019 (TLS & Non-TLS)
# ==========================================

# Mematikan semua prompt interaktif selama instalasi
export DEBIAN_FRONTEND=noninteractive

# Konfigurasi Cloudflare dari User
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

echo -e "[INFO] Memulai proses update dan instalasi dependensi dasar..."
apt-get update -yq
apt-get upgrade -yq
apt-get install -yq curl wget jq nginx python3 tar bzip2 make gcc build-essential uuid-runtime stunnel4 net-tools certbot

# ==========================================
# 1. SETUP CLOUDFLARE DOMAIN RANDOM
# ==========================================
echo -e "[INFO] Mengambil nama domain dari Cloudflare Zone ID..."
DOMAIN_INFO=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json")
     
ROOT_DOMAIN=$(echo $DOMAIN_INFO | jq -r .result.name)

if [ "$ROOT_DOMAIN" == "null" ] || [ -z "$ROOT_DOMAIN" ]; then
    echo -e "[ERROR] Gagal mengambil nama domain dari Cloudflare. Cek API Key/Zone ID."
    ROOT_DOMAIN="domain-error.com"
fi

# Generate Subdomain Random (6 Karakter)
RANDOM_STR=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
SUBDOMAIN="${RANDOM_STR}.${ROOT_DOMAIN}"
IP_SERVER=$(curl -sS ifconfig.me)

echo -e "[INFO] Pointing domain acak: ${SUBDOMAIN} ke IP: ${IP_SERVER}..."
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUBDOMAIN}'","content":"'${IP_SERVER}'","ttl":120,"proxied":false}' | jq -r .success

# Simpan domain untuk digunakan sistem
mkdir -p /etc/xray
echo "$SUBDOMAIN" > /etc/xray/domain

# ==========================================
# 2. GENERATE SSL / TLS CERTIFICATE (PORT 443)
# ==========================================
echo -e "[INFO] Membuat Sertifikat SSL Let's Encrypt untuk ${SUBDOMAIN}..."
systemctl stop nginx
certbot certonly --standalone -d ${SUBDOMAIN} --non-interactive --agree-tos --email ${CF_ID}
systemctl start nginx

# ==========================================
# 3. INSTALASI DROPBEAR 2019
# ==========================================
echo -e "[INFO] Mengunduh dan mengkompilasi Dropbear versi 2019.78..."
apt-get remove -yq dropbear
cd /usr/local/src
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
tar -xjf dropbear-2019.78.tar.bz2
cd dropbear-2019.78
./configure --disable-zlib
make 
make install

# Konfigurasi Dropbear
mkdir -p /etc/dropbear
cat > /etc/default/dropbear << END
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
END

# Start manual untuk instalasi dari source
dropbear -p 143 -p 109 -R
echo -e "[INFO] Dropbear 2019 terinstal pada port 143, 109."

# ==========================================
# 4. INSTALASI XRAY (VLESS)
# ==========================================
echo -e "[INFO] Menginstal Xray Core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta
UUID=$(uuidgen)

cat > /usr/local/etc/xray/config.json << END
{
  "inbounds": [
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${UUID}"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vless"}
      }
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
END

systemctl restart xray
systemctl enable xray

# ==========================================
# 5. SSH WEBSOCKET PYTHON SCRIPT
# ==========================================
echo -e "[INFO] Menyiapkan SSH WebSocket Service..."
cat > /usr/local/bin/ssh-ws.py << 'END'
import socket, threading, sys
def handle_client(client_socket):
    try:
        request = client_socket.recv(1024).decode('utf-8')
        if "HTTP" in request:
            response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            client_socket.send(response.encode())
        
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.connect(('127.0.0.1', 143)) # Forward ke Dropbear

        def forward(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data: break
                    destination.send(data)
            except: pass

        threading.Thread(target=forward, args=(client_socket, target)).start()
        threading.Thread(target=forward, args=(target, client_socket)).start()
    except:
        client_socket.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 10002))
server.listen(5)
while True:
    client, addr = server.accept()
    threading.Thread(target=handle_client, args=(client,)).start()
END

cat > /etc/systemd/system/ssh-ws.service << END
[Unit]
Description=SSH WebSocket Python
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ws.py
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable ssh-ws
systemctl start ssh-ws

# ==========================================
# 6. SETUP NGINX (MULTIPLEXER MULTI PORT 80/443 TLS)
# ==========================================
echo -e "[INFO] Konfigurasi Nginx untuk TLS 443 & Non-TLS 80..."
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/vps.conf << END
server {
    listen 80;
    listen 8080;
    listen 443 ssl http2;
    server_name $SUBDOMAIN;

    ssl_certificate /etc/letsencrypt/live/$SUBDOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$SUBDOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # SSH WebSocket Path (Payload Bug -> /)
    location / {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    # Xray Vless Path
    location /vless {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
END

systemctl restart nginx

# ==========================================
# 7. MENU CREATOR SCRIPT
# ==========================================
echo -e "[INFO] Membuat script menu..."
cat > /usr/bin/menu << 'EOF'
#!/bin/bash
DOMAIN=$(cat /etc/xray/domain)
IP=$(curl -sS ifconfig.me)

clear
echo -e "======================================"
echo -e "         MENU CREATE ACCOUNT          "
echo -e "======================================"
echo -e "1. Create Akun SSH / Dropbear WS"
echo -e "2. Create Akun Xray Vless WS"
echo -e "3. Exit"
echo -e "======================================"
read -p "Pilih Menu (1-3): " menu_opt

if [ "$menu_opt" == "1" ]; then
    read -p "Username: " user
    read -p "Password: " pass
    read -p "Expired (Hari): " exp
    
    useradd -e `date -d "$exp days" +"%Y-%m-%d"` -s /bin/false -M $user
    echo -e "$pass\n$pass\n" | passwd $user &> /dev/null
    
    clear
    echo -e "======================================"
    echo -e "        DETAIL AKUN SSH WS            "
    echo -e "======================================"
    echo -e "Domain      : $DOMAIN"
    echo -e "IP Server   : $IP"
    echo -e "Username    : $user"
    echo -e "Password    : $pass"
    echo -e "Port TLS    : 443"
    echo -e "Port Non-TLS: 80, 8080"
    echo -e "Path Payload: /"
    echo -e "Expired     : $exp Hari"
    echo -e "======================================"
    echo -e "Payload WS Non-TLS (Port 80):"
    echo -e "GET / HTTP/1.1[crlf]Host: $DOMAIN[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "Payload WS TLS (Port 443):"
    echo -e "GET wss://$DOMAIN/ HTTP/1.1[crlf]Host: $DOMAIN[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
    
elif [ "$menu_opt" == "2" ]; then
    read -p "Username (Vless): " user
    read -p "Expired (Hari): " exp
    
    uuid=$(uuidgen)
    sed -i '/"clients": \[/a {"id": "'$uuid'", "email": "'$user'" },' /usr/local/etc/xray/config.json
    systemctl restart xray
    
    clear
    echo -e "======================================"
    echo -e "        DETAIL AKUN VLESS WS          "
    echo -e "======================================"
    echo -e "Domain      : $DOMAIN"
    echo -e "IP Server   : $IP"
    echo -e "Username    : $user"
    echo -e "UUID        : $uuid"
    echo -e "Port TLS    : 443"
    echo -e "Port Non-TLS: 80, 8080"
    echo -e "Path        : /vless"
    echo -e "Expired     : $exp Hari"
    echo -e "======================================"
    echo -e "Link Vless TLS (443) :"
    echo -e "vless://${uuid}@${DOMAIN}:443?path=/vless&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${user}"
    echo -e "======================================"
    echo -e "Link Vless Non-TLS (80) :"
    echo -e "vless://${uuid}@${DOMAIN}:80?path=/vless&security=none&encryption=none&host=${DOMAIN}&type=ws#${user}"
    echo -e "======================================"

elif [ "$menu_opt" == "3" ]; then
    exit
else
    echo "Pilihan salah!"
fi
EOF

chmod +x /usr/bin/menu

echo -e "\n\n[SUCCESS] Instalasi Selesai!"
echo -e "Ketik 'menu' di terminal untuk membuat akun SSH atau Vless."
