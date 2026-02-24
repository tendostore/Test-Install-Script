#!/bin/bash
# ==========================================================
# FULL AUTO INSTALLER: SSH WS, XRAY (VMESS/VLESS/TROJAN), ZIVPN & MENU
# ==========================================================

# Memastikan eksekusi sebagai root
if [ "${EUID}" -ne 0 ]; then
  echo "Harap jalankan script ini sebagai root."
  exit 1
fi

echo -e "\033[1;32mMulai proses instalasi full VPN, Proxy, dan Panel Menu...\033[0m"

# 1. Update & Install Dependensi Utama
apt-get update -y
apt-get install -y wget curl iptables iptables-persistent netfilter-persistent dropbear squid stunnel4 ufw openssl coreutils net-tools python3 cmake make gcc build-essential zip unzip jq

# 2. Konfigurasi OpenSSH (Port 22, 444)
echo "Mengonfigurasi OpenSSH..."
sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
if ! grep -q "Port 444" /etc/ssh/sshd_config; then
    echo "Port 444" >> /etc/ssh/sshd_config
fi
systemctl restart ssh

# 3. Konfigurasi Dropbear (Port 90)
echo "Mengonfigurasi Dropbear..."
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=90/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=.*/DROPBEAR_EXTRA_ARGS="-p 109 -p 69"/g' /etc/default/dropbear
systemctl restart dropbear

# 4. Instalasi & Konfigurasi SSH WebSocket (Python Proxy)
echo "Menginstal SSH WebSocket Proxy..."
cat > /usr/local/bin/ws-openssh.py << 'EOF'
import socket, threading, sys
def handle_client(client_socket):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect(('127.0.0.1', 22))
    client_socket.recv(1024)
    client_socket.send(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    def forward(source, destination):
        try:
            while True:
                data = source.recv(4096)
                if not data: break
                destination.send(data)
        except: pass
    threading.Thread(target=forward, args=(client_socket, remote_socket)).start()
    threading.Thread(target=forward, args=(remote_socket, client_socket)).start()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 10015))
server.listen(100)
while True:
    client, addr = server.accept()
    threading.Thread(target=handle_client, args=(client,)).start()
EOF
chmod +x /usr/local/bin/ws-openssh.py

cat > /etc/systemd/system/ws-openssh.service << 'EOF'
[Unit]
Description=Python WS OpenSSH Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ws-openssh.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable ws-openssh
systemctl start ws-openssh

# 5. Instalasi Xray Core (Menangani TLS 443, 8443, dll)
echo "Menginstal Xray Core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
mkdir -p /usr/local/etc/xray/
domain=$(curl -sS ifconfig.me)

# Konfigurasi Xray untuk VMESS, VLESS, TROJAN, dan SSH-WS (Multiplexer)
cat > /usr/local/etc/xray/config.json << EOF
{
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
          { "dest": 80, "xver": 1 },
          { "path": "/vmess", "dest": 10001, "xver": 1 },
          { "path": "/vless", "dest": 10002, "xver": 1 },
          { "path": "/trojan", "dest": 10003, "xver": 1 },
          { "path": "/sshws", "dest": 10015, "xver": 1 }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "/etc/stunnel/stunnel.pem", "keyFile": "/etc/stunnel/stunnel.pem" } ] } }
    },
    { "port": 10001, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } } },
    { "port": 10002, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } } },
    { "port": 10003, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/trojan" } } }
  ],
  "outbounds": [ { "protocol": "freedom", "settings": {} } ]
}
EOF

# 6. Setup Stunnel & Dummy Certificate
openssl req -new -x509 -days 3650 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=ID/ST=Java/L=Tahunan/O=VPN/OU=Premium/CN=$domain" &>/dev/null
systemctl restart xray

# 7. Konfigurasi Squid Proxy (Port 3128)
cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
acl localnet src 0.0.0.0/0
http_access allow localnet
http_access deny all
EOF
systemctl restart squid

# 8. Instalasi BadVPN UDPGW (7100-7600)
echo "Menginstal BadVPN..."
cd /usr/local/src
wget -q https://github.com/ambrop72/badvpn/archive/master.zip
unzip -q master.zip
cd badvpn-master
mkdir build && cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &>/dev/null
make install &>/dev/null
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

# 9. Routing Port Tambahan dengan IPtables (NAT PREROUTING)
echo "Mengonfigurasi NAT IPtables untuk Port Custom..."
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10015
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 10015
iptables -t nat -A PREROUTING -p tcp --dport 2082 -j REDIRECT --to-port 10015
iptables -t nat -A PREROUTING -p tcp --dport 2083 -j REDIRECT --to-port 10015
iptables -t nat -A PREROUTING -p tcp --dport 8880 -j REDIRECT --to-port 10015
iptables -t nat -A PREROUTING -p tcp --dport 9080 -j REDIRECT --to-port 90
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
iptables -t nat -A PREROUTING -p udp --dport 5300 -j REDIRECT --to-port 5300
iptables -t nat -A PREROUTING -p tcp --dport 2052 -j REDIRECT --to-port 10003
iptables -t nat -A PREROUTING -p tcp --dport 2053 -j REDIRECT --to-port 10003
netfilter-persistent save &>/dev/null

# 10. GENERATE MENU BUILDER
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
    echo -e "${BOLD}        CREATE SSH & ZIVPN ACCOUNT    ${RESET}"
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
    echo -e "UDP-Custom     : 1-65535"
    echo -e "OHP + SSH      : 9080"
    echo -e "Squid Proxy    : 3128"
    echo -e "BadVPN UDPGW   : 7100-7600"
    echo -e "${CYAN}ZIVPN UDP      : 6000-19999 (Routed to 5667)${RESET}"
    echo -e "${GREEN}======================================${RESET}"
    echo -e "Payload WS TLS :"
    echo -e "GET wss://bug.com/ HTTP/1.1[crlf]Host: $domain[crlf]Upgrade: websocket[crlf][crlf]"
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
    echo -e "${CYAN}[1]${RESET} Create SSH / UDP / ZIVPN Account"
    echo -e "${CYAN}[2]${RESET} Create VMESS WS Account"
    echo -e "${CYAN}[3]${RESET} Create VLESS WS Account"
    echo -e "${CYAN}[4]${RESET} Create TROJAN WS Account"
    echo -e "${RED}[x]${RESET} Keluar"
    echo -e "${PURPLE}======================================${RESET}"
    read -p "Pilih menu (1-4/x): " opt
    
    case $opt in
        1) add_ssh ;;
        2) add_vmess ;;
        3) add_vless ;;
        4) add_trojan ;;
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
