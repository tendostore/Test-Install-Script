#!/bin/bash
# ==========================================
# Auto Install SSH WS & X-ray (DNS ONLY - NO PROXY)
# Dropbear Version: 2019
# ==========================================

# 1. Melewati prompt "Enter" selama instalasi
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get upgrade -y -q
apt-get remove -y dropbear dropbear-run
apt-get install -y -q curl jq nginx uuid-runtime bzip2 zlib1g-dev make gcc build-essential wget python3

# 2. Konfigurasi Cloudflare (DNS ONLY - TANPA AWAN OREN)
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

echo "Mengambil informasi domain dari Cloudflare..."
DOMAIN=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r '.result.name')

if [ "$DOMAIN" == "null" ] || [ -z "$DOMAIN" ]; then
    echo "Gagal mengambil domain dari Cloudflare."
    exit 1
fi

RANDOM_STR=$(tr -dc a-z0-9 </dev/urandom | head -c 5)
SUB_DOMAIN="${RANDOM_STR}.${DOMAIN}"
IP_VPS=$(curl -s ifconfig.me)

echo "Domain acak: $SUB_DOMAIN"

# Pointing DNS Only (proxied: false)
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}'

echo "$SUB_DOMAIN" > /etc/vps_domain

# 3. Instalasi Dropbear Versi 2019
echo "Menginstal Dropbear 2019..."
cd /usr/local/src
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
tar -xvjf dropbear-2019.78.tar.bz2
cd dropbear-2019.78
./configure --prefix=/usr
make && make install

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

# 4. SSH WebSocket Proxy (Python)
cat > /usr/local/bin/ws-ssh.py << 'EOF'
import socket, threading
def handle(client):
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(('127.0.0.1', 143))
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
    except: client.close()
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
Description=SSH WS Proxy
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ssh.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl enable ws-ssh
systemctl restart ws-ssh

# 5. X-ray Core
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -y
cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [{"port": 8081,"protocol": "vless","settings": {"clients": [{"id": "$(uuidgen)"}],"decryption": "none"},"streamSettings": {"network": "ws","wsSettings": {"path": "/xray"}}}],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
systemctl restart xray

# 6. Nginx Simple Config (Port 80 & 443)
rm /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/vps.conf <<EOF
server {
    listen 80;
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    location / {
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
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

# 7. Menu Manajemen Akun
cat > /usr/local/bin/menu <<'EOF'
#!/bin/bash
clear
MY_DOMAIN=$(cat /etc/vps_domain)
echo "================================="
echo "   MENU SSH WS & XRAY (DIRECT)   "
echo "================================="
echo "Domain: $MY_DOMAIN"
echo "---------------------------------"
echo "1. Buat Akun SSH"
echo "2. Buat Akun X-ray"
echo "3. Keluar"
echo "================================="
read -p "Pilih: " opt
case $opt in
    1)
        read -p "User: " u; read -p "Pass: " p
        useradd -e `date -d "30 days" +"%Y-%m-%d"` -s /bin/false -M $u
        echo -e "$p\n$p" | passwd $u >/dev/null 2>&1
        echo -e "Berhasil!\nDomain: $MY_DOMAIN\nUser: $u\nPass: $p" ;;
    2)
        read -p "User: " u; id=$(uuidgen)
        jq '.inbounds[0].settings.clients += [{"id": "'$id'", "email": "'$u'"}]' /usr/local/etc/xray/config.json > /tmp/x.json && mv /tmp/x.json /usr/local/etc/xray/config.json
        systemctl restart xray
        echo -e "Berhasil!\nDomain: $MY_DOMAIN\nUUID: $id\nPath: /xray" ;;
esac
EOF
chmod +x /usr/local/bin/menu

echo "INSTALASI SELESAI! Ketik 'menu' untuk buat akun."
