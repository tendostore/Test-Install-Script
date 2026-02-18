#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM CLEAN V.6.1 (AUTO XP ADDED)
#   Update: Added Auto Delete Expired Account & Zivpn Tracker
#   Script BY: Tendo Store | WhatsApp: +6282224460678
# ==================================================

# --- WARNA & UI ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; WHITE='\033[1;37m'

# --- ANTI INTERACTIVE ---
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# --- ANIMASI INSTALL ---
function install_spin() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    echo -ne " "
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

function print_msg() { echo -e "${YELLOW}➤ $1...${NC}"; }
function print_ok() { echo -e "${GREEN}✔ $1 Selesai!${NC}"; sleep 0.5; }

clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${PURPLE}      AUTO INSTALLER X-RAY & ZIVPN ONLY          ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           Script by Tendo Store                ${NC}"
echo -e "${CYAN}=================================================${NC}"
sleep 2

# --- 1. OPTIMIZATION ---
print_msg "Optimasi Sistem & Swap"
rm -f /var/lib/apt/lists/lock >/dev/null 2>&1
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1
swapoff -a >/dev/null 2>&1; rm -f /swapfile
dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
chmod 600 /swapfile; mkswap /swapfile >/dev/null 2>&1; swapon /swapfile >/dev/null 2>&1
echo '/swapfile none swap sw 0 0' >> /etc/fstab & install_spin
print_ok "System Optimized"

# --- 2. VARIABLES ---
# Cloudflare Credentials (Used only if Option 1 is selected)
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

XRAY_DIR="/usr/local/etc/xray"; 
CONFIG_FILE="/usr/local/etc/xray/config.json"
DATA_VMESS="/usr/local/etc/xray/vmess.txt"
DATA_VLESS="/usr/local/etc/xray/vless.txt"
DATA_TROJAN="/usr/local/etc/xray/trojan.txt"
DATA_ZIVPN="/usr/local/etc/xray/zivpn.txt"

# --- 3. DEPENDENCIES ---
print_msg "Install Dependencies"
apt-get update -y >/dev/null 2>&1
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl socat jq openssl uuid-runtime net-tools vnstat wget gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron >/dev/null 2>&1 & install_spin
print_ok "Dependencies"

# Install Official Speedtest Ookla
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash >/dev/null 2>&1
apt-get install speedtest -y >/dev/null 2>&1

touch /root/.hushlogin; chmod -x /etc/update-motd.d/* 2>/dev/null
sed -i '/neofetch/d' /root/.bashrc; echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat && systemctl restart vnstat; vnstat -u -i $IFACE_NET >/dev/null 2>&1

# --- 4. DOMAIN SELECTION ---
print_msg "Setup Domain & SSL"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo; touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN $DATA_ZIVPN
IP_VPS=$(curl -s ifconfig.me)

# Get Geo Info
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           PILIHAN JENIS DOMAIN                 ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}│${NC} [1] Gunakan Domain Random Tendo (Gratis/Auto)"
echo -e "${CYAN}│${NC} [2] Gunakan Domain Sendiri (Manual)"
echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
read -p " Pilih Opsi (1/2): " dom_opt

if [[ "$dom_opt" == "1" ]]; then
    # -- OPTION 1: AUTO DOMAIN --
    echo -e "${YELLOW}Menggunakan Domain Random dari Tendo Store...${NC}"
    DOMAIN_VAL="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
    
    # Register to Cloudflare
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
         -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
         -H "Content-Type: application/json" \
         --data '{"type":"A","name":"'${DOMAIN_VAL}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null
         
    echo "$DOMAIN_VAL" > $XRAY_DIR/domain
    echo -e "${GREEN}Domain Terbuat: ${DOMAIN_VAL}${NC}"
else
    # -- OPTION 2: OWN DOMAIN --
    echo -e "${YELLOW}Mode Domain Sendiri${NC}"
    echo -e "${RED}PENTING: Pastikan anda sudah mengarahkan A Record domain ke IP: ${IP_VPS}${NC}"
    read -p " Masukan Domain/Subdomain Anda: " user_dom
    if [[ -z "$user_dom" ]]; then
        echo -e "${RED}Domain tidak boleh kosong! Script berhenti.${NC}"
        exit 1
    fi
    echo "$user_dom" > $XRAY_DIR/domain
    DOMAIN_VAL="$user_dom"
    echo -e "${GREEN}Domain Diset ke: ${DOMAIN_VAL}${NC}"
fi

# SSL Generator (Valid for both options)
echo -e "${YELLOW}Generating SSL Certificate...${NC}"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_VAL" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key; chmod 644 $XRAY_DIR/xray.crt & install_spin
print_ok "SSL Configured"

# --- 5. XRAY CONFIG (CLEAN - NO WARP) ---
print_msg "Install Xray Core & Config"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
UUID_SYS=$(uuidgen)

# Config Tanpa WARP/Routing
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "inbound-443", "port": 443, "protocol": "vless", "settings": { "clients": [ { "id": "$UUID_SYS", "flow": "xtls-rprx-vision", "level": 0, "email": "system" } ], "decryption": "none", "fallbacks": [ { "path": "/vmess", "dest": 10001, "xver": 1 }, { "path": "/vless", "dest": 10002, "xver": 1 }, { "path": "/trojan", "dest": 10003, "xver": 1 } ] }, "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "/usr/local/etc/xray/xray.crt", "keyFile": "/usr/local/etc/xray/xray.key" } ] } } },
    { "tag": "inbound-80", "port": 80, "protocol": "vless", "settings": { "clients": [], "decryption": "none", "fallbacks": [ { "path": "/vmess", "dest": 10001, "xver": 1 }, { "path": "/vless", "dest": 10002, "xver": 1 }, { "path": "/trojan", "dest": 10003, "xver": 1 } ] }, "streamSettings": { "network": "tcp", "security": "none" } },
    { "tag": "vmess_ws", "port": 10001, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "acceptProxyProtocol": true, "path": "/vmess" } } },
    { "tag": "vless_ws", "port": 10002, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "acceptProxyProtocol": true, "path": "/vless" } } },
    { "tag": "trojan_ws", "port": 10003, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "acceptProxyProtocol": true, "path": "/trojan" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "outboundTag": "blocked", "protocol": [ "bittorrent" ] } ] }
}
EOF
print_ok "Xray Configured"

# --- 6. ZIVPN ---
print_msg "Install ZIVPN"
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"; chmod +x /usr/local/bin/zivpn
echo '{"listen":":5667","cert":"/usr/local/etc/xray/xray.crt","key":"/usr/local/etc/xray/xray.key","obfs":"zivpn","auth":{"mode":"passwords","config":[]}}' > /etc/zivpn/config.json
cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZIVPN
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable zivpn && systemctl restart zivpn xray

# IPtables
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save >/dev/null 2>&1
print_ok "ZIVPN Installed"

# --- 7. AUTO XP SCRIPT (NEW FEATURE) ---
print_msg "Setup Auto Delete Expired"
cat > /usr/bin/xp <<'EOF'
#!/bin/bash
# Auto Delete Expired Users (Xray & Zivpn)
# By Tendo Store
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"
ZIVPN_CONF="/etc/zivpn/config.json"
D_ZIVPN="/usr/local/etc/xray/zivpn.txt"
DATE_NOW=$(date +%Y-%m-%d)

# 1. CLEAN VMESS
if [ -f "$D_VMESS" ]; then
    while IFS='|' read -r user uuid exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then
            jq --arg u "$user" 'del(.inbounds[2].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG
            sed -i "/^$user|/d" $D_VMESS
            echo "Vmess Account Deleted: $user (Expired: $exp)"
        fi
    done < $D_VMESS
fi

# 2. CLEAN VLESS
if [ -f "$D_VLESS" ]; then
    while IFS='|' read -r user uuid exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then
            jq --arg u "$user" 'del(.inbounds[3].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG
            sed -i "/^$user|/d" $D_VLESS
            echo "Vless Account Deleted: $user (Expired: $exp)"
        fi
    done < $D_VLESS
fi

# 3. CLEAN TROJAN
if [ -f "$D_TROJAN" ]; then
    while IFS='|' read -r user uuid exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then
            jq --arg u "$user" 'del(.inbounds[4].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG
            sed -i "/^$user|/d" $D_TROJAN
            echo "Trojan Account Deleted: $user (Expired: $exp)"
        fi
    done < $D_TROJAN
fi

# 4. CLEAN ZIVPN UDP
if [ -f "$D_ZIVPN" ]; then
    while IFS='|' read -r pass exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then
            jq --arg p "$pass" 'del(.auth.config[] | select(. == $p))' $ZIVPN_CONF > /tmp/zconf && mv /tmp/zconf $ZIVPN_CONF
            sed -i "/^$pass|/d" $D_ZIVPN
            echo "Zivpn Account Deleted: $pass (Expired: $exp)"
        fi
    done < $D_ZIVPN
fi

systemctl restart xray zivpn
EOF
chmod +x /usr/bin/xp

# Add to Cronjob (Runs every midnight 00:00)
echo "0 0 * * * root /usr/bin/xp" > /etc/cron.d/xp_auto
service cron restart >/dev/null 2>&1
print_ok "Auto Delete Configured"

# --- 8. MENU SCRIPT ---
print_msg "Finalisasi Menu"
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; WHITE='\033[1;37m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"
D_ZIVPN="/usr/local/etc/xray/zivpn.txt"

function show_account_xray() {
    clear
    local proto=$1; local user=$2; local domain=$3; local uuid=$4; local exp=$5; local link_tls=$6; local link_ntls=$7
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city)
    local path="/${proto,,}"; 
    if [[ "$proto" == "VMESS" ]]; then path="/vmess"; fi
    if [[ "$proto" == "VLESS" ]]; then path="/vless"; fi
    if [[ "$proto" == "TROJAN" ]]; then path="/trojan"; fi

    echo -e "————————————————————————————————————"
    echo -e "               ${proto}"
    echo -e "————————————————————————————————————"
    echo -e "Remarks        : ${user}"
    echo -e "CITY           : ${city}"
    echo -e "ISP            : ${isp}"
    echo -e "Domain         : ${domain}"
    echo -e "Port TLS       : 443"
    echo -e "Port none TLS  : 80"
    echo -e "Port any       : 2052,2053,8880"
    if [[ "$proto" == "TROJAN" ]]; then
        echo -e "Password       : ${uuid}"
    else
        echo -e "id             : ${uuid}"
    fi
    echo -e "alterId        : 0"
    echo -e "Security       : auto"
    echo -e "network        : ws"
    echo -e "path ws        : ${path}"
    echo -e "serviceName    : ${proto,,}"
    echo -e "Expired On     : ${exp}"
    echo -e "————————————————————————————————————"
    echo -e "           ${proto} WS TLS"
    echo -e "————————————————————————————————————"
    echo -e "${link_tls}"
    
    if [[ -n "$link_ntls" ]]; then
        echo -e "————————————————————————————————————"
        echo -e "          ${proto} WS NO TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_ntls}"
    fi
    echo -e "————————————————————————————————————"
    echo ""
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function show_account_zivpn() {
    clear
    local pass=$1; local domain=$2; local exp=$3
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city); local ip=$(cat /root/tendo/ip)

    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ACCOUNT ZIVPN UDP"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Password   : ${pass}"
    echo -e "CITY       : ${city}"
    echo -e "ISP        : ${isp}"
    echo -e "IP ISP     : ${ip}"
    echo -e "Domain     : ${domain}"
    echo -e "Expired On : ${exp}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $2}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    CITY=$(cat /root/tendo/city)
    ISP=$(cat /root/tendo/isp)
    UPTIME=$(uptime -p | sed 's/up //')
    
    # Traffic Calculation
    RX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}')
    TX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}')
    RX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}')
    TX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}')
    
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes); sleep 0.4
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
    TRAFFIC=$(echo "scale=2; (($R2 - $R1) + ($T2 - $T1)) * 8 / 409.6 / 1024" | bc)
    
    # Account Counters
    ACC_VMESS=$(wc -l < "/usr/local/etc/xray/vmess.txt" 2>/dev/null || echo 0)
    ACC_VLESS=$(wc -l < "/usr/local/etc/xray/vless.txt" 2>/dev/null || echo 0)
    ACC_TROJAN=$(wc -l < "/usr/local/etc/xray/trojan.txt" 2>/dev/null || echo 0)
    ACC_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json 2>/dev/null || echo 0)

    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│              ${YELLOW}TENDO STORE ULTIMATE${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    printf "${CYAN}│${NC} OS      : ${WHITE}%-s${NC}\n" "$OS"
    printf "${CYAN}│${NC} RAM     : ${WHITE}%-s${NC}\n" "${RAM}MB"
    printf "${CYAN}│${NC} SWAP    : ${WHITE}%-s${NC}\n" "${SWAP}MB"
    printf "${CYAN}│${NC} CITY    : ${WHITE}%-s${NC}\n" "$CITY"
    printf "${CYAN}│${NC} ISP     : ${WHITE}%-s${NC}\n" "$ISP"
    printf "${CYAN}│${NC} IP      : ${WHITE}%-s${NC}\n" "$IP"
    printf "${CYAN}│${NC} DOMAIN  : ${YELLOW}%-s${NC}\n" "$DOMAIN"
    printf "${CYAN}│${NC} UPTIME  : ${WHITE}%-s${NC}\n" "$UPTIME"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│${NC} ${PURPLE}TODAY${NC}   : ${GREEN}RX:${NC} $RX_DAY ${CYAN}|${NC} ${RED}TX:${NC} $TX_DAY"
    echo -e "${CYAN}│${NC} ${PURPLE}MONTH${NC}   : ${GREEN}RX:${NC} $RX_MON ${CYAN}|${NC} ${RED}TX:${NC} $TX_MON"
    printf "${CYAN}│${NC} ${PURPLE}SPEED${NC}   : ${WHITE}%-s${NC}\n" "$TRAFFIC Mbit/s"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if iptables -L >/dev/null 2>&1; then I_ST="${GREEN}ON${NC}"; else I_ST="${RED}OFF${NC}"; fi
    
    printf "${CYAN}│${NC} STATUS  : XRAY: %b ${CYAN}|${NC} ZIVPN: %b ${CYAN}|${NC} IPtables: %b\n" "$X_ST" "$Z_ST" "$I_ST"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
    
    # LIST ACCOUNTS BOX
    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│                   ${YELLOW}LIST ACCOUNTS${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    printf "${CYAN}│${NC} VMESS          : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_VMESS"
    printf "${CYAN}│${NC} VLESS          : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_VLESS"
    printf "${CYAN}│${NC} TROJAN         : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_TROJAN"
    printf "${CYAN}│${NC} ZIVPN          : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_ZIVPN"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
}

function header_sub() {
    clear; echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│              ${YELLOW}TENDO STORE - SUB MENU${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
}

function change_domain_menu() {
    header_sub
    echo -e "${YELLOW}WARNING: Mengganti domain akan memperbarui sertifikat SSL!${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
    read -p "Masukan Domain Baru: " nd
    if [[ -z "$nd" ]]; then return; fi
    echo -e "${YELLOW}Processing...${NC}"
    echo "$nd" > /usr/local/etc/xray/domain
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout /usr/local/etc/xray/xray.key -out /usr/local/etc/xray/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1
    systemctl restart xray
    echo -e "${GREEN}Domain Berhasil Diperbarui menjadi: $nd${NC}"
    sleep 2
}

function features_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Check Bandwidth (Vnstat)"
        echo -e "${CYAN}│${NC} [2] Speedtest by Ookla (Official)"
        echo -e "${CYAN}│${NC} [3] Check Benchmark VPS (YABS)"
        echo -e "${CYAN}│${NC} [4] Restart All Services"
        echo -e "${CYAN}│${NC} [5] Clear Cache RAM"
        echo -e "${CYAN}│${NC} [6] Auto Reboot"
        echo -e "${CYAN}│${NC} [7] Information System"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) vnstat -l -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1);;
            2) speedtest; read -p "Enter...";;
            3) echo -e "${YELLOW}Running Benchmark...${NC}"; wget -qO- bench.sh | bash; read -p "Enter...";;
            4) systemctl restart xray zivpn vnstat; echo -e "${GREEN}Services Restarted!${NC}"; sleep 2;;
            5) sync; echo 3 > /proc/sys/vm/drop_caches; echo -e "${GREEN}Cache Cleared!${NC}"; sleep 1;;
            6) echo -e "Set Auto Reboot (00:00 UTC)"; echo "0 0 * * * root reboot" > /etc/cron.d/autoreboot; service cron restart; echo -e "${GREEN}Done!${NC}"; sleep 1;;
            7) neofetch; read -p "Enter...";;
            x) return;;
        esac
    done
}

function vmess_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Vmess"
        echo -e "${CYAN}│${NC} [2] Delete Account Vmess"
        echo -e "${CYAN}│${NC} [3] Check Config User"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " UUID (Enter for random): " uid_in; [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date" >> $D_VMESS
               DMN=$(cat /usr/local/etc/xray/domain); json_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0); json_none=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "vmess://$json_tls" "vmess://$json_none";;
            2) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); sed -i "${n}d" $D_VMESS; jq --arg u "$u" 'del(.inbounds[2].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
            3) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); id=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f2); exp_date=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f3); DMN=$(cat /usr/local/etc/xray/domain); json_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0); json_none=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "vmess://$json_tls" "vmess://$json_none";;
            x) return;;
        esac; done
}

function vless_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Vless"
        echo -e "${CYAN}│${NC} [2] Delete Account Vless"
        echo -e "${CYAN}│${NC} [3] Check Config User"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " UUID (Enter for random): " uid_in; [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); jq --arg u "$u" --arg id "$id" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date" >> $D_VLESS
               DMN=$(cat /usr/local/etc/xray/domain); ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$ltls" "$lnon";;
            2) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); sed -i "${n}d" $D_VLESS; jq --arg u "$u" 'del(.inbounds[3].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
            3) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); id=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f2); exp_date=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f3); DMN=$(cat /usr/local/etc/xray/domain); ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$ltls" "$lnon";;
            x) return;;
        esac; done
}

function trojan_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Trojan"
        echo -e "${CYAN}│${NC} [2] Delete Account Trojan"
        echo -e "${CYAN}│${NC} [3] Check Config User"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); pass="$u"; jq --arg p "$pass" --arg u "$u" '.inbounds[4].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$pass|$exp_date" >> $D_TROJAN
               DMN=$(cat /usr/local/etc/xray/domain); trlink="trojan://${pass}@${DMN}:443?security=tls&type=ws&host=${DMN}&path=/trojan&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$trlink" "";;
            2) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); sed -i "${n}d" $D_TROJAN; jq --arg u "$u" 'del(.inbounds[4].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
            3) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); pass=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f2); exp_date=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f3); DMN=$(cat /usr/local/etc/xray/domain); trlink="trojan://${pass}@${DMN}:443?security=tls&type=ws&host=${DMN}&path=/trojan&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$trlink" "";;
            x) return;;
        esac; done
}

function zivpn_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account ZIVPN"
        echo -e "${CYAN}│${NC} [2] Delete Account ZIVPN"
        echo -e "${CYAN}│${NC} [3] Check Config User"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Password: " p; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; 
               echo "$p|$exp" >> $D_ZIVPN; systemctl restart zivpn; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            2) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); sed -i "/^$p|/d" $D_ZIVPN; jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
            3) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); DMN=$(cat /usr/local/etc/xray/domain); exp=$(grep "^$p|" $D_ZIVPN | cut -d'|' -f2); [[ -z "$exp" ]] && exp="Unknown"; show_account_zivpn "$p" "$DMN" "$exp";;
            x) return;;
        esac; done
}

function check_services() {
    header_sub
    echo -e "${CYAN}┌───────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│               SERVICES STATUS                 ${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────${NC}"
    
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet vnstat; then V_ST="${GREEN}ON${NC}"; else V_ST="${RED}OFF${NC}"; fi
    if iptables -L >/dev/null 2>&1; then I_ST="${GREEN}ON${NC}"; else I_ST="${RED}OFF${NC}"; fi
    
    printf "${CYAN}│${NC} Xray Core       : %b${NC}\n" "$X_ST"
    printf "${CYAN}│${NC} ZIVPN UDP       : %b${NC}\n" "$Z_ST"
    printf "${CYAN}│${NC} Vnstat Mon      : %b${NC}\n" "$V_ST"
    printf "${CYAN}│${NC} IPtables        : %b${NC}\n" "$I_ST"
    
    echo -e "${CYAN}└───────────────────────────────────────────────${NC}"
    read -p "Enter..."
}

while true; do header_main
    echo -e "${CYAN}│${NC} [1] VMESS ACCOUNT        [5] CHANGE DOMAIN VPS"
    echo -e "${CYAN}│${NC} [2] VLESS ACCOUNT        [6] FEATURES"
    echo -e "${CYAN}│${NC} [3] TROJAN ACCOUNT       [7] CHECK SERVICES"
    echo -e "${CYAN}│${NC} [4] ZIVPN UDP            [x] EXIT"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│${NC}  Version   :  v18.02.26                  ${NC}"
    echo -e "${CYAN}│${NC}  Owner     :  Tendo Store                ${NC}"
    echo -e "${CYAN}│${NC}  Telegram  :  @tendo_32                  ${NC}"
    echo -e "${CYAN}│${NC}  Expiry In :  Lifetime                   ${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
    read -p " Select Menu : " opt
    case $opt in
        1) vmess_menu ;; 2) vless_menu ;; 3) trojan_menu ;;
        4) zivpn_menu ;; 5) change_domain_menu ;; 6) features_menu ;;
        7) check_services ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
# Link XP untuk manual run
ln -s /usr/bin/xp /usr/local/bin/xp 2>/dev/null
install_spin
print_ok "Instalasi Selesai! Ketik: menu"
