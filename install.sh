#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM LTS FINAL V.105 (REFINED)
#   Optimized BY: Gemini AI for Tendo Store
#   Contact: +6282224460678
# ==================================================

# --- COLORS & STYLING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- PRE-CHECKS ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Script must be run as root!${NC}"
   exit 1
fi

# Cek Arsitektur
if [[ $(uname -m) == "x86_64" ]]; then
    ARCH="amd64"
elif [[ $(uname -m) == "aarch64" ]]; then
    ARCH="arm64"
else
    echo -e "${RED}Error: Architecture $(uname -m) not supported!${NC}"
    exit 1
fi

clear
echo -e "${CYAN}=============================================${NC}"
echo -e "      Auto Script Install X-ray & Zivpn"
echo -e "         ${YELLOW}Platinum LTS Edition V.105${NC}"
echo -e "${CYAN}=============================================${NC}"
sleep 2

# --- 1. SYSTEM OPTIMIZATION ---
echo -e "${GREEN}[+] Optimizing System & Dependencies...${NC}"
apt update -y > /dev/null 2>&1
# Install essential packages silently
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron > /dev/null 2>&1

# Enable TCP BBR
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
fi

# Smart Swap (Hanya buat jika belum ada)
if [ ! -f /swapfile ]; then
    echo -e "${YELLOW}[!] Creating 2GB Swap File...${NC}"
    dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Silent Login & Banner
touch /root/.hushlogin
sed -i '/neofetch/d' /root/.bashrc
echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to access dashboard."' >> /root/.bashrc

# Enable Vnstat
IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat >/dev/null 2>&1
systemctl restart vnstat >/dev/null 2>&1
vnstat -u -i $IFACE_NET >/dev/null 2>&1

# --- 2. CONFIG VARIABLES (USER INPUT / HARDCODED) ---
# NOTE: Isi bagian ini dengan data Cloudflare Anda
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

# Random Subdomain Generator
SUB_DOMAIN="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"
DOMAIN_INIT="${SUB_DOMAIN}.vip3-tendo.my.id"

XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
RULE_LIST="/usr/local/etc/xray/rule_list.txt"
USER_DATA="/usr/local/etc/xray/user_data.txt"

mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $USER_DATA

# --- 3. DOMAIN & SSL ---
echo -e "${GREEN}[+] Setting up Domain & SSL...${NC}"
IP_VPS=$(curl -s ifconfig.me)
# Simpan Info VPS untuk Menu
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# Register ke Cloudflare
RESULT=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${DOMAIN_INIT}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}')

if [[ $(echo $RESULT | jq -r '.success') == "true" ]]; then
    echo -e "${GREEN}Domain Registered: ${DOMAIN_INIT}${NC}"
else
    echo -e "${RED}Cloudflare Error! Using local IP as fallback.${NC}"
fi

echo "$DOMAIN_INIT" > $XRAY_DIR/domain

# Generate Self-Signed Cert (Fast)
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 4. INSTALL XRAY CORE ---
echo -e "${GREEN}[+] Installing X-ray Core...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1

# Download Geosite
rm -f /usr/local/share/xray/geosite.dat
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

# Config Xray (Optimized)
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 443, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } } },
    { "port": 80, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { 
      "domainStrategy": "IPIfNonMatch", 
      "rules": [ 
          { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" },
          { "type": "field", "domain": ["geosite:google"], "outboundTag": "direct" } 
      ] 
  }
}
EOF

# --- 5. INSTALL ZIVPN ---
echo -e "${GREEN}[+] Installing ZIVPN UDP...${NC}"
# Cek arsitektur untuk download binary yang tepat
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn

cat > /etc/zivpn/config.json <<EOF
{ "listen": ":5667", "cert": "$XRAY_DIR/xray.crt", "key": "$XRAY_DIR/xray.key", "obfs": "zivpn", "auth": { "mode": "passwords", "config": [] } }
EOF

cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn >/dev/null 2>&1
systemctl restart zivpn xray >/dev/null 2>&1

# --- 6. IPTABLES & AUTO-FT ---
iptables -t nat -D PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save &>/dev/null

# --- 7. CREATE MENU (PLATINUM UI) ---
echo -e "${GREEN}[+] Generating Dashboard Menu...${NC}"
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
# MENU CONFIGURATION
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"

# Helper Functions
pause() { read -n 1 -s -r -p "Press any key to continue..."; }

function header_main() {
    clear
    DOMAIN=$(cat /usr/local/etc/xray/domain)
    OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $3}'); SWAP=$(free -m | awk '/Swap:/ {print $2}')
    UPTIME=$(uptime -p | sed 's/up //')
    CITY=$(cat /root/tendo/city 2>/dev/null); ISP=$(cat /root/tendo/isp 2>/dev/null)
    
    # Network Stats
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    MON_DATA=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $11}')
    DAY_DATA=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $6}')
    
    # Banner
    echo -e "┌─────────────────────────────────────────────────┐"
    echo -e "          ${BG_RED}     TENDO STORE PLATINUM      ${NC} "
    echo -e "└─────────────────────────────────────────────────┘"
    echo -e "┌─────────────────────────────────────────────────┐"
    echo -e "│ SYSTEM INFO"
    echo -e "│ OS      : $OS"
    echo -e "│ RAM/SWAP: ${RAM}MB / ${SWAP}MB"
    echo -e "│ DOMAIN  : ${YELLOW}$DOMAIN${NC}"
    echo -e "│ ISP     : $ISP ($CITY)"
    echo -e "│ UPTIME  : $UPTIME"
    echo -e "│ —————————————————————————————————————"
    echo -e "│ TRAFFIC : TODAY ($DAY_DATA) | MONTH ($MON_DATA)"
    echo -e "│ —————————————————————————————————————"
    
    # Service Status Check
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"
    SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"
    echo -e "│ STATUS  : XRAY [$X_ST] | ZIVPN [$Z_ST]"
    
    # Account Counts
    C_VLESS=$(jq '.inbounds[0].settings.clients | length' $CONFIG)
    C_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json)
    echo -e "│ —————————————————————————————————————"
    echo -e "│ ACCOUNTS: VLESS [$C_VLESS] | ZIVPN [$C_ZIVPN]"
    echo -e "│ —————————————————————————————————————"
    echo -e "│ [1] Manage VLESS       [4] Speed Test"
    echo -e "│ [2] Manage ZIVPN       [5] Restart Services"
    echo -e "│ [3] Routing Geosite    [x] Exit"
    echo -e "└─────────────────────────────────────────────────┘"
}

function xray_menu() {
    clear; echo -e "${CYAN}--- MANAGE VLESS ---${NC}"
    echo "1. Create Account"
    echo "2. Delete Account"
    echo "3. List Accounts"
    echo "x. Back"
    read -p "Select: " opt
    case $opt in
        1) 
           read -p "Username : " u
           if grep -q "$u" "$U_DATA"; then echo -e "${RED}User already exists!${NC}"; pause; return; fi
           read -p "UUID (Enter for random): " id; [[ -z "$id" ]] && id=$(uuidgen)
           read -p "Expired (Days): " ex; [[ -z "$ex" ]] && ex=30
           exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           
           # Insert to Config
           jq --arg u "$u" --arg id "$id" '.inbounds[].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           echo "$u|$id|$exp_date" >> $U_DATA
           systemctl restart xray
           
           # Show Details
           DMN=$(cat /usr/local/etc/xray/domain)
           link="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
           clear
           echo -e "==============================="
           echo -e "      VLESS ACCOUNT CREATED"
           echo -e "==============================="
           echo -e "Username   : $u"
           echo -e "Domain     : $DMN"
           echo -e "UUID       : $id"
           echo -e "Expired    : $exp_date"
           echo -e "==============================="
           echo -e "LINK TLS: $link"
           echo -e "==============================="
           pause ;;
        2) 
           clear; echo "List of Users:"; echo "----------------"
           jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl
           read -p "Select Number to Delete: " n
           [[ -z "$n" ]] && return
           idx=$((n-1))
           u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG)
           
           # Delete logic
           sed -i "/$u|/d" $U_DATA
           jq "del(.inbounds[].settings.clients[] | select(.email==\"$u\"))" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray
           echo -e "${GREEN}User $u deleted!${NC}"; pause ;;
        3) 
           clear; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; pause ;;
        x) return ;;
    esac
}

function zivpn_menu() {
    clear; echo -e "${CYAN}--- MANAGE ZIVPN UDP ---${NC}"
    echo "1. Create Account"
    echo "2. Delete Account"
    echo "x. Back"
    read -p "Select: " opt
    case $opt in
        1) 
           read -p "Password : " p
           read -p "Expired (Days): " ex; [[ -z "$ex" ]] && ex=30
           exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
           systemctl restart zivpn
           echo -e "${GREEN}ZIVPN Account Created!${NC}"; pause ;;
        2) 
           jq -r '.auth.config[]' /etc/zivpn/config.json | nl
           read -p "Delete No: " n
           idx=$((n-1))
           jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
           systemctl restart zivpn
           echo -e "${GREEN}Deleted!${NC}"; pause ;;
        x) return ;;
    esac
}

# MAIN LOOP
while true; do
    header_main
    read -p "Select Option: " opt
    case $opt in
        1) xray_menu ;;
        2) zivpn_menu ;;
        3) nano /usr/local/etc/xray/rule_list.txt; echo "Please restart service manually or via menu."; pause ;;
        4) speedtest; pause ;;
        5) systemctl restart xray zivpn; echo -e "${GREEN}Services Restarted!${NC}"; sleep 1 ;;
        x) exit 0 ;;
        *) echo "Invalid Option"; sleep 1 ;;
    esac
done
END_MENU

chmod +x /usr/bin/menu

# --- 8. CLEANUP ---
apt autoremove -y >/dev/null 2>&1
apt clean >/dev/null 2>&1
rm -f /root/install.sh

echo -e "${GREEN}=============================================${NC}"
echo -e "   INSTALLATION COMPLETED SUCCESSFULLY!"
echo -e "   Type: ${YELLOW}menu${NC} to start managing VPN"
echo -e "${GREEN}=============================================${NC}"
