#!/bin/bash
# ==========================================================
# Tendo-Script-Auto-Installer-X-ray-ZIVPN
# FULL VERSION: AUTO CF + TLS + DROPBEAR 2019 + XRAY MULTIPLEXER + ZIVPN
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
apt-get install -yq wget curl iptables iptables-persistent netfilter-persistent squid ufw openssl coreutils net-tools python3 cmake make gcc build-essential zip unzip jq zlib1g-dev bzip2 socat cron

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

# Fix Akses Sertifikat untuk User 'nobody'
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
apt-get install -yq dropbear
systemctl stop dropbear

wget -qO dropbear-2019.78.tar.bz2 https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
bzip2 -cd dropbear-2019.78.tar.bz2 | tar xvf - &>/dev/null
cd dropbear-2019.78
./configure &>/dev/null
make &>/dev/null
make install &>/dev/null

mv /usr/local/sbin/dropbear /usr/sbin/dropbear
cd ..
rm -rf dropbear-2019.78 dropbear-2019.78.tar.bz2

sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=90/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=.*/DROPBEAR_EXTRA_ARGS="-p 109 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
systemctl daemon-reload
systemctl restart dropbear

# 6. Instalasi & Konfigurasi SSH WebSocket Proxy (Fix Premature Close Final)
echo "Menginstal SSH WebSocket Proxy Premium..."
cat > /usr/local/bin/ws-openssh.py << 'EOF'
#!/usr/bin/python3
import socket, threading

def forward(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data: break
            dst.send(data)
    except: pass
    finally:
        src.close()
        dst.close()

def handle_client(client_socket):
    try:
        req = client_socket.recv(8192)
        if not req:
            client_socket.close()
            return

        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect(('127.0.0.1', 90))

        if b"HTTP" in req or b"Upgrade: websocket" in req:
            client_socket.send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            if b"SSH-" in req:
                idx = req.find(b"SSH-")
                remote_socket.send(req[idx:])
        else:
            remote_socket.send(req)

        threading.Thread(target=forward, args=(client_socket, remote_socket)).start()
        threading.Thread(target=forward, args=(remote_socket, client_socket)).start()
    except:
        client_socket.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 10015))
server.listen(100)

while True:
    try:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()
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
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ws-openssh
systemctl restart ws-openssh

# 7. Instalasi & Konfigurasi Xray Core MULTIPLEXER (PORT 443, 80, 8080)
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
          { "dest": 10015 }
        ]
      },
      "streamSettings": { 
        "network": "tcp", "security": "tls", 
        "tlsSettings": { "certificates": [ { "certificateFile": "/etc/xray/xray.crt", "keyFile": "/etc/xray/xray.key" } ] } 
      }
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
          { "dest": 10015 }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "port": 8080,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "dummy@vless"}],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001 },
          { "path": "/vless", "dest": 10002 },
          { "path": "/trojan", "dest": 10003 },
          { "dest": 10015 }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    { "port": 10001, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } } },
    { "port": 10002, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } } },
    { "port": 10003, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/trojan" } } }
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

# 9. Instalasi BadVPN UDPGW (7100-7600) & (5667 KHUSUS ZIVPN)
echo "Menginstal BadVPN & ZIVPN Backend..."
cd /usr/local/src
wget -q https://github.com/ambrop72/badvpn/archive/master.zip
unzip -q master.zip
cd badvpn-master
mkdir build && cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &>/dev/null
make install &>/dev/null

# Port BadVPN Biasa
for port in 7100 7200 7300 7400 7500 7600; do
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

# BACKEND KHUSUS ZIVPN DI PORT 5667 (Untuk menerima trafik dari iptables Anda)
cat > /etc/systemd/system/badvpn-5667.service << EOF
[Unit]
Description=BadVPN UDPGW Port 5667 for ZIVPN
After=network.target
[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:5667 --max-clients 1000
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable badvpn-5667 &>/dev/null
systemctl start badvpn-5667 &>/dev/null

# 10. Routing Port Tambahan dengan IPtables (NAT PREROUTING)
echo "Mengonfigurasi NAT IPtables untuk Port Custom..."
iptables -t nat -A PREROUTING -p tcp --dport 8443 -j REDIRECT --to-port 443
iptables -t nat -A PREROUTING -p tcp --dport 2082 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -p tcp --dport 2083 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -p tcp --dport 8880 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -p tcp --dport 9080 -j REDIRECT --to-port 90
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
netfilter-persistent save &>/dev/null

# 11. GENERATE MENU BUILDER (DENGAN INDEKS JQ YANG BENAR)
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
    read -p "Password ZIVPN : " Pass
    read -p "Expired (Hari) : " masaaktif

    Login="$Pass"
    useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M "$Login"
    echo -e "$Pass\n$Pass\n"|passwd "$Login" &> /dev/null
    
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
    
    jq '.inbounds[3].settings.clients += [{"id": "'${uuid}'","alterId": 0,"email": "'${user}'"}]' /usr/local/etc/xray/config.json > /usr/local/etc/xray/temp.json
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
    echo -e "Network        : ws (WebSocket)"
    echo -e "Path           : /vless"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Link VLESS TLS:"
    echo -e "vless://${uuid}@${domain}:443?path=/vless&security=tls&encryption=none&type=ws#${user}"
    echo -e "Link VLESS None TLS:"
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
    
    jq '.inbounds[5].settings.clients += [{"password": "'${user}'","email": "'${user}'"}]' /usr/local/etc/xray/config.json > /usr/local/etc/xray/temp.json
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
    echo -e "${CYAN}[4]${RESET} Create VLESS WS Account"
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
# ZIVPN IPTABLES FIXER (SCRIPT ORIGINAL TIDAK DIUBAH SAMA SEKALI)
# ==========================================================
#!/bin/bash

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
RESET="\033[0m"
BOLD="\033[1m"
GRAY="\033[1;30m"

print_task() {
  echo -ne "${GRAY}•${RESET} $1..."
}

print_done() {
  echo -e "\r${GREEN}✓${RESET} $1      "
}

run_silent() {
  local msg="$1"
  local cmd="$2"
  
  print_task "$msg"
  bash -c "$cmd" &>/tmp/zivpn_iptables.log
  if [ $? -eq 0 ]; then
    print_done "$msg"
  else
    print_done "$msg" 
  fi
}

clear
echo -e "${BOLD}ZiVPN IPtables Fixer${RESET}"
echo -e "${GRAY}AutoFTbot Edition${RESET}"
echo ""

iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
run_silent "Cleaning old rules" "iptables -t nat -D PREROUTING -i $iface -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null"

run_silent "Applying new rules" "iptables -t nat -A PREROUTING -i $iface -p udp --dport 6000:19999 -j DNAT --to-destination :5667"

if [ -f /etc/iptables/rules.v4 ]; then
    run_silent "Saving to rules.v4" "iptables-save > /etc/iptables/rules.v4"
elif [ -f /etc/iptables.up.rules ]; then
    run_silent "Saving to iptables.up.rules" "iptables-save > /etc/iptables.up.rules"
else
    run_silent "Saving configuration" "netfilter-persistent save &>/dev/null || service iptables save &>/dev/null"
fi

echo ""
echo -e "${BOLD}Fix Complete${RESET}"
echo -e "${GRAY}IPtables rules have been refreshed.${RESET}"
echo ""
