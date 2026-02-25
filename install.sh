#!/bin/bash
# ==========================================================
# Tendo-Script-Auto-Installer-X-ray-ZIVPN
# EDITION: FINAL COMPLETE (SSH FIX + XRAY ALL + ZIVPN + UDPGW)
# ==========================================================

# Memastikan eksekusi sebagai root
if [ "${EUID}" -ne 0 ]; then
  echo "Harap jalankan script ini sebagai root."
  exit 1
fi

echo -e "\033[1;32mMulai instalasi Tendo-Script Premium (Mode Full Otomatis)...\033[0m"

# ==========================================================
# 1. UPDATE & INSTALL DEPENDENSI (MODE NON-INTERAKTIF)
# ==========================================================
export DEBIAN_FRONTEND=noninteractive
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

apt-get update -y
apt-get install -yq wget curl iptables iptables-persistent netfilter-persistent squid ufw openssl coreutils net-tools python3 cmake make gcc build-essential zip unzip jq zlib1g-dev bzip2 socat cron uuid-runtime

# ==========================================================
# 2. AUTO CLOUDFLARE DNS & GENERATE RANDOM DOMAIN
# ==========================================================
echo "Mengonfigurasi Domain & Cloudflare API..."
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

IP=$(curl -sS ifconfig.me)

DOMAIN_ROOT=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result.name)

if [ "$DOMAIN_ROOT" == "null" ] || [ -z "$DOMAIN_ROOT" ]; then
    echo -e "\033[1;31mGagal mengambil nama domain dari Cloudflare. Periksa API Key / Zone ID.\033[0m"
    exit 1
fi

RANDOM_STR=$(tr -dc a-z0-9 </dev/urandom | head -c 5)
domain="vpn-${RANDOM_STR}.${DOMAIN_ROOT}"

echo "Membuat DNS Record (A) untuk: ${domain} --> ${IP}"
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${domain}'","content":"'${IP}'","ttl":120,"proxied":false}' > /dev/null

mkdir -p /etc/xray
echo "${domain}" > /etc/xray/domain

# ==========================================================
# 3. INSTALL SERTIFIKAT SSL/TLS ASLI (Let's Encrypt)
# ==========================================================
echo "Menginstal Sertifikat SSL/TLS resmi untuk ${domain}..."
systemctl stop xray &>/dev/null
curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

# Fix Permission
chown -R nobody:nogroup /etc/xray
chmod -R 755 /etc/xray
chmod 644 /etc/xray/xray.crt /etc/xray/xray.key

# 4. Konfigurasi OpenSSH (Port 22, 444)
echo "Mengonfigurasi OpenSSH..."
sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
if ! grep -q "Port 444" /etc/ssh/sshd_config; then
    echo "Port 444" >> /etc/ssh/sshd_config
fi
systemctl restart ssh

# 5. Instalasi & Konfigurasi Dropbear 2019.78
echo "Menginstal Dropbear 2019.78..."
service dropbear stop
apt-get remove --purge dropbear -y
rm -rf /etc/dropbear

wget -qO dropbear-2019.78.tar.bz2 https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
bzip2 -cd dropbear-2019.78.tar.bz2 | tar xvf - &>/dev/null
cd dropbear-2019.78
./configure &>/dev/null
make &>/dev/null
make install &>/dev/null

mv /usr/local/sbin/dropbear /usr/sbin/dropbear
ln -sf /usr/local/sbin/dropbear /usr/bin/dropbear
cd ..
rm -rf dropbear-2019.78 dropbear-2019.78.tar.bz2

# Buat Config Dropbear Manual
mkdir -p /etc/dropbear
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=90
DROPBEAR_EXTRA_ARGS="-p 109 -p 69"
DROPBEAR_BANNER="/etc/issue.net"
EOF

# Buat Service Dropbear Manual
cat > /etc/systemd/system/dropbear.service <<EOF
[Unit]
Description=Dropbear SSH Daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/dropbear -p 90 -p 109 -p 69
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dropbear
systemctl restart dropbear

# 6. Instalasi & Konfigurasi SSH WebSocket Proxy (VERSI ROBUST - FIX SSH)
echo "Menginstal SSH WebSocket Proxy Premium..."
cat > /usr/local/bin/ws-openssh.py << 'EOF'
#!/usr/bin/python3
import socket, threading

def handle_client(client_socket):
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect(('127.0.0.1', 90)) # Connect ke Dropbear 2019

        req = client_socket.recv(8192)
        
        # Logika Smart Handshake
        if b"HTTP" in req or b"GET" in req or b"CONNECT" in req:
            client_socket.send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            # Jika ada payload terselip di paket pertama (jarang terjadi di HTTP Custom tapi antisipasi)
            parts = req.split(b"\r\n\r\n")
            if len(parts) > 1 and parts[1]:
                 remote_socket.send(parts[1])
        else:
            # Jika koneksi direct/non-http
            remote_socket.send(req)

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data: break
                    dst.send(data)
            except: pass
            finally:
                src.close()
                dst.close()

        t1 = threading.Thread(target=forward, args=(client_socket, remote_socket))
        t2 = threading.Thread(target=forward, args=(remote_socket, client_socket))
        t1.start()
        t2.start()
    except:
        client_socket.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 10015))
server.listen(100)

while True:
    try:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client,))
        t.start()
    except: pass
EOF
chmod +x /usr/local/bin/ws-openssh.py

cat > /etc/systemd/system/ws-openssh.service << 'EOF'
[Unit]
Description=Python WS OpenSSH Proxy Premium
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ws-openssh.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ws-openssh
systemctl restart ws-openssh

# 7. Instalasi & Konfigurasi Xray Core (SUPPORT WS, GRPC, UPGRADE)
echo "Menginstal Xray Core..."
echo -e "\n" | bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

cat > /usr/local/etc/xray/config.json << EOF
{
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "dummy@vless"}],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001 },
          { "path": "/vless", "dest": 10002 },
          { "path": "/trojan", "dest": 10003 },
          { "path": "/sshws", "dest": 10015 },
          { "alpn": "h2", "dest": 20002 },
          { "dest": 10015 }
        ]
      },
      "streamSettings": { 
        "network": "tcp", 
        "security": "tls", 
        "tlsSettings": { 
            "certificates": [ { "certificateFile": "/etc/xray/xray.crt", "keyFile": "/etc/xray/xray.key" } ],
            "alpn": ["h2", "http/1.1"]
        } 
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    },
    {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "dummy@vless"}],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001 },
          { "path": "/vless", "dest": 10002 },
          { "path": "/trojan", "dest": 10003 },
          { "path": "/sshws", "dest": 10015 },
          { "dest": 10015 }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    { "port": 10001, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } } },
    { "port": 10002, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } } },
    { "port": 10003, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/trojan" } } },
    { 
      "port": 20002, 
      "listen": "127.0.0.1", 
      "protocol": "vless", 
      "settings": { "clients": [], "decryption": "none" }, 
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "vless-grpc" } } 
    }
  ],
  "outbounds": [ { "protocol": "freedom", "settings": {} } ]
}
EOF

systemctl restart xray

# 8. Konfigurasi Squid Proxy (Port 3128)
cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
acl localnet src 0.0.0.0/0
http_access allow localnet
http_access deny all
EOF
systemctl restart squid

# 9. Instalasi BadVPN UDPGW (7100-7600)
# Dikembalikan ke port 7100-7600 sesuai permintaan
echo "Menginstal BadVPN UDPGW Legacy (7100-7600)..."
cd /usr/local/src
wget -q https://github.com/ambrop72/badvpn/archive/master.zip
unzip -q master.zip
cd badvpn-master
mkdir build && cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &>/dev/null
make install &>/dev/null
for port in {7100..7105} 7600; do
cat > /etc/systemd/system/badvpn-${port}.service << EOF
[Unit]
Description=BadVPN UDPGW Port ${port}
After=network.target
[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${port} --max-clients 500
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable badvpn-${port} &>/dev/null
systemctl start badvpn-${port} &>/dev/null
done

# ==========================================================
# 10. INSTALASI ZIVPN CORE (BINARY ASLI DARI SCRIPT ANDA)
# ==========================================================
echo "Menginstal ZIVPN Core & Config (Port 5667)..."
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
mkdir -p /etc/zivpn

# Konfigurasi JSON ZIVPN (Auth Mode: Passwords)
cat > /etc/zivpn/config.json <<EOF
{ 
  "listen": ":5667", 
  "cert": "/etc/xray/xray.crt", 
  "key": "/etc/xray/xray.key", 
  "obfs": "zivpn", 
  "auth": { 
    "mode": "passwords", 
    "config": [] 
  } 
}
EOF

# Membuat Service ZIVPN
cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn
systemctl restart zivpn

# Konfigurasi IPtables ZIVPN (Sesuai file zivpn-iptables-fix.sh)
IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -D PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save &>/dev/null

# 11. Routing Port Tambahan (NAT PREROUTING)
echo "Mengonfigurasi NAT IPtables untuk Port Custom..."
iptables -t nat -A PREROUTING -p tcp --dport 2082 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -p tcp --dport 2083 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -p tcp --dport 8880 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -p tcp --dport 9080 -j REDIRECT --to-port 90
netfilter-persistent save &>/dev/null

# 12. GENERATE MENU BUILDER
echo "Membangun Panel Menu Manager..."
cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
RESET="\033[0m"
BOLD="\033[1m"
PURPLE="\033[1;35m"

IP=$(curl -sS ifconfig.me)
domain=$(cat /etc/xray/domain 2>/dev/null || echo "$IP")

add_ssh() {
    clear
    echo -e "${CYAN}======================================${RESET}"
    echo -e "${BOLD}          CREATE SSH ACCOUNT          ${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    read -p "Username : " Login
    read -p "Password : " Pass
    read -p "Expired (Hari): " masaaktif

    # Menggunakan useradd biasa (Dropbear systemd kita running sebagai root/system)
    useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
    echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
    
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    
    clear
    echo -e "${GREEN}======================================${RESET}"
    echo -e "${BOLD}            DETAIL AKUN SSH           ${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Host / IP      : $IP"
    echo -e "Domain         : $domain"
    echo -e "Username       : $Login"
    echo -e "Password       : $Pass"
    echo -e "Expired Pada   : $exp"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "${BOLD}PORT SUPPORT:${RESET}"
    echo -e "TLS            : 443, 8443"
    echo -e "None TLS       : 80, 8080"
    echo -e "Any            : 2082, 2083, 8880"
    echo -e "OpenSSH        : 444"
    echo -e "Dropbear       : 90"
    echo -e "SlowDNS        : 53, 5300"
    echo -e "OHP + SSH      : 9080"
    echo -e "Squid Proxy    : 3128"
    echo -e "BadVPN UDPGW   : 7100-7600"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Payload WS TLS :"
    echo -e "GET wss://bug.com/ HTTP/1.1[crlf]Host: $domain[crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "${GREEN}======================================${RESET}"
    read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
    menu
}

add_zivpn() {
    clear
    echo -e "${CYAN}======================================${RESET}"
    echo -e "${BOLD}         CREATE ZIVPN ACCOUNT         ${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    # ZIVPN khusus: Hanya minta Password, simpan ke JSON dengan JQ
    read -p "Password ZIVPN : " Pass
    read -p "Expired (Hari) : " masaaktif

    # Masukkan ke config.json ZIVPN
    jq --arg p "$Pass" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
    systemctl restart zivpn
    
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    
    clear
    echo -e "${GREEN}======================================${RESET}"
    echo -e "${BOLD}           DETAIL AKUN ZIVPN          ${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Host / IP      : $IP"
    echo -e "Password       : $Pass"
    echo -e "Expired Pada   : $exp"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "${CYAN}ZIVPN UDP PORT : 6000-19999${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
    menu
}

add_vmess() {
    clear
    echo -e "${CYAN}======================================${RESET}"
    echo -e "${BOLD}          CREATE VMESS ACCOUNT        ${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    read -p "Username : " user
    read -p "Expired (Hari): " masaaktif
    
    uuid=$(cat /proc/sys/kernel/random/uuid)
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    
    # Injeksi ke inbound 1 (Internal VMess WS)
    jq '.inbounds[1].settings.clients += [{"id": "'${uuid}'","alterId": 0,"email": "'${user}'"}]' /usr/local/etc/xray/config.json > /usr/local/etc/xray/temp.json
    mv /usr/local/etc/xray/temp.json /usr/local/etc/xray/config.json
    systemctl restart xray
    
    clear
    echo -e "${GREEN}======================================${RESET}"
    echo -e "${BOLD}           DETAIL AKUN VMESS          ${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Remarks        : $user"
    echo -e "Host / IP      : $IP"
    echo -e "Domain         : $domain"
    echo -e "UUID           : $uuid"
    echo -e "Expired Pada   : $exp"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "${BOLD}PORT SUPPORT:${RESET}"
    echo -e "Port TLS       : 443, 8443"
    echo -e "Port None TLS  : 80, 8080"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "Network        : ws (WebSocket)"
    echo -e "Path           : /vmess"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Format Vmess WS TLS / None TLS:"
    echo -e "vmess://$(echo -n '{"v":"2","ps":"'"$user"'","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"ws","path":"/vmess","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
    echo -e "${GREEN}======================================${RESET}"
    read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
    menu
}

add_vless() {
    clear
    echo -e "${CYAN}======================================${RESET}"
    echo -e "${BOLD}          CREATE VLESS ACCOUNT        ${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    read -p "Username : " user
    read -p "Expired (Hari): " masaaktif
    
    uuid=$(cat /proc/sys/kernel/random/uuid)
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    
    # Injeksi ke inbound 2 (WS) & inbound 4 (GRPC)
    jq '.inbounds[2].settings.clients += [{"id": "'${uuid}'","email": "'${user}'"}]' /usr/local/etc/xray/config.json > /usr/local/etc/xray/temp.json
    mv /usr/local/etc/xray/temp.json /usr/local/etc/xray/config.json
    jq '.inbounds[4].settings.clients += [{"id": "'${uuid}'","email": "'${user}'"}]' /usr/local/etc/xray/config.json > /usr/local/etc/xray/temp.json
    mv /usr/local/etc/xray/temp.json /usr/local/etc/xray/config.json
    systemctl restart xray
    
    clear
    echo -e "${GREEN}======================================${RESET}"
    echo -e "${BOLD}           DETAIL AKUN VLESS          ${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Remarks        : $user"
    echo -e "Host / IP      : $IP"
    echo -e "Domain         : $domain"
    echo -e "UUID           : $uuid"
    echo -e "Expired Pada   : $exp"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "${BOLD}PORT SUPPORT:${RESET}"
    echo -e "Port TLS       : 443, 8443"
    echo -e "Port None TLS  : 80, 8080"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "Network        : ws (WebSocket) & grpc"
    echo -e "Path (WS)      : /vless"
    echo -e "Service (GRPC) : vless-grpc"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Link VLESS WS TLS:"
    echo -e "vless://${uuid}@${domain}:443?path=/vless&security=tls&encryption=none&type=ws#${user}"
    echo -e "Link VLESS GRPC TLS:"
    echo -e "vless://${uuid}@${domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc#${user}"
    echo -e "Link VLESS WS None TLS:"
    echo -e "vless://${uuid}@${domain}:80?path=/vless&security=none&encryption=none&type=ws#${user}"
    echo -e "${GREEN}======================================${RESET}"
    read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
    menu
}

add_trojan() {
    clear
    echo -e "${CYAN}======================================${RESET}"
    echo -e "${BOLD}          CREATE TROJAN ACCOUNT       ${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    read -p "Username (Password) : " user
    read -p "Expired (Hari)      : " masaaktif
    
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    
    # Injeksi ke inbound 3 (Internal Trojan WS)
    jq '.inbounds[3].settings.clients += [{"password": "'${user}'","email": "'${user}'"}]' /usr/local/etc/xray/config.json > /usr/local/etc/xray/temp.json
    mv /usr/local/etc/xray/temp.json /usr/local/etc/xray/config.json
    systemctl restart xray
    
    clear
    echo -e "${GREEN}======================================${RESET}"
    echo -e "${BOLD}           DETAIL AKUN TROJAN         ${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Remarks        : $user"
    echo -e "Host / IP      : $IP"
    echo -e "Domain         : $domain"
    echo -e "Password       : $user"
    echo -e "Expired Pada   : $exp"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "${BOLD}PORT SUPPORT:${RESET}"
    echo -e "Port TLS       : 443, 8443"
    echo -e "Port Any       : 2052, 2053, 8880"
    echo -e "${YELLOW}--------------------------------------${RESET}"
    echo -e "Network        : ws (WebSocket) / tcp"
    echo -e "Path           : /trojan"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Link Trojan WS TLS:"
    echo -e "trojan://${user}@${domain}:443?path=/trojan&security=tls&type=ws#${user}"
    echo -e "Link Trojan Any Port:"
    echo -e "trojan://${user}@${domain}:2052?path=/trojan&security=tls&type=ws#${user}"
    echo -e "${GREEN}======================================${RESET}"
    read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
    menu
}

menu() {
    clear
    echo -e "${PURPLE}======================================${RESET}"
    echo -e "${BOLD}           PANEL MENU MANAGER         ${RESET}"
    echo -e "${PURPLE}======================================${RESET}"
    echo -e "${CYAN}[1]${RESET} Create SSH Account"
    echo -e "${CYAN}[2]${RESET} Create ZIVPN Account"
    echo -e "${CYAN}[3]${RESET} Create VMESS WS Account"
    echo -e "${CYAN}[4]${RESET} Create VLESS WS/GRPC Account"
    echo -e "${CYAN}[5]${RESET} Create TROJAN WS Account"
    echo -e "${RED}[x]${RESET} Keluar"
    echo -e "${PURPLE}======================================${RESET}"
    echo -e "${GRAY}Tendo Store - Premium Script${RESET}"
    echo -e "${GRAY}Telegram: @tendo_32 | WA: 6282224460678${RESET}"
    echo -e "${PURPLE}======================================${RESET}"
    read -p "Pilih menu (1-5/x): " opt
    
    case $opt in
        1) add_ssh ;;
        2) add_zivpn ;;
        3) add_vmess ;;
        4) add_vless ;;
        5) add_trojan ;;
        x) clear; exit 0 ;;
        *) echo -e "${RED}Pilihan tidak valid!${RESET}"; sleep 2; menu ;;
    esac
}
menu
EOF
chmod +x /usr/local/bin/menu

echo -e "\033[1;32mInstalasi Core & Menu Selesai! Mengaplikasikan script ZIVPN IPtables Anda...\033[0m"
sleep 2

# ==========================================================
# ZIVPN IPTABLES FIXER (INTEGRATED)
# ==========================================================
clear
echo -e "${BOLD}Verifying ZIVPN Rules...${RESET}"

iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -D PREROUTING -i $iface -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
iptables -t nat -A PREROUTING -i $iface -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667

netfilter-persistent save &>/dev/null

echo ""
echo -e "${BOLD}Fix Complete${RESET}"
echo -e "${GRAY}All services installed & configured.${RESET}"
echo ""
