#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM COMPLETE V.6.6 (AUTO TIMEZONE)
#   Update: Added Auto Timezone based on Location
#   Script BY: Tendo Store | WhatsApp: +6282224460678
# ==================================================

# --- 1. INITIALIZATION & COLORS ---
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; WHITE='\033[1;37m'

# --- 2. INSTALLATION ANIMATION ---
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
echo -e "${PURPLE}      AUTO INSTALLER X-RAY & ZIVPN FULL          ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           Script by Tendo Store                ${NC}"
echo -e "${CYAN}=================================================${NC}"
sleep 2

# --- 3. SYSTEM OPTIMIZATION (BBR & SWAP) ---
print_msg "Optimasi Sistem & Swap 2GB"
rm -f /var/lib/apt/lists/lock >/dev/null 2>&1
# Enable BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1
# Configure Swap
swapoff -a >/dev/null 2>&1; rm -f /swapfile
dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
chmod 600 /swapfile; mkswap /swapfile >/dev/null 2>&1; swapon /swapfile >/dev/null 2>&1
echo '/swapfile none swap sw 0 0' >> /etc/fstab & install_spin
print_ok "System Optimized"

# --- 4. VARIABLES ---
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

XRAY_DIR="/usr/local/etc/xray"; 
CONFIG_FILE="/usr/local/etc/xray/config.json"
DATA_VMESS="/usr/local/etc/xray/vmess.txt"
DATA_VLESS="/usr/local/etc/xray/vless.txt"
DATA_TROJAN="/usr/local/etc/xray/trojan.txt"
DATA_ZIVPN="/usr/local/etc/xray/zivpn.txt"

# --- 5. DEPENDENCIES ---
print_msg "Install Dependencies & Tools"
apt-get update -y >/dev/null 2>&1
# Install Essential Packages including 'at' for trial scheduling
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    curl socat jq openssl uuid-runtime net-tools vnstat wget gnupg1 bc iproute2 \
    iptables iptables-persistent python3 neofetch cron at >/dev/null 2>&1 & install_spin
systemctl enable --now atd >/dev/null 2>&1
systemctl enable --now cron >/dev/null 2>&1

# Install Official Speedtest Ookla
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash >/dev/null 2>&1
apt-get install speedtest -y >/dev/null 2>&1

# Silent Login & Bashrc
touch /root/.hushlogin; chmod -x /etc/update-motd.d/* 2>/dev/null
sed -i '/neofetch/d' /root/.bashrc; echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

# Vnstat Config
IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat && systemctl restart vnstat; vnstat -u -i $IFACE_NET >/dev/null 2>&1
print_ok "Dependencies Installed"

# --- 6. DOMAIN, SSL & TIMEZONE SETUP ---
print_msg "Setup Domain, SSL & Timezone"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo; touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN $DATA_ZIVPN
IP_VPS=$(curl -s ifconfig.me)

# Get Geo Info & Timezone
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# --- NEW: AUTO TIMEZONE LOGIC ---
TIMEZONE=$(curl -s ipinfo.io/json | jq -r '.timezone')
if [[ -n "$TIMEZONE" && "$TIMEZONE" != "null" ]]; then
    ln -sf /usr/share/zoneinfo/"$TIMEZONE" /etc/localtime
    echo "$TIMEZONE" > /etc/timezone
    print_msg "Timezone detected & set to: $TIMEZONE"
else
    # Fallback to Jakarta if detection fails
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    echo "Asia/Jakarta" > /etc/timezone
    print_msg "Timezone detection failed, defaulting to Asia/Jakarta"
fi

clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           PILIHAN JENIS DOMAIN                 ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}│${NC} [1] Gunakan Domain Random Tendo (Gratis/Auto)"
echo -e "${CYAN}│${NC} [2] Gunakan Domain Sendiri (Manual)"
echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
read -p " Pilih Opsi (1/2): " dom_opt

if [[ "$dom_opt" == "1" ]]; then
    # AUTO DOMAIN
    DOMAIN_VAL="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
    # CF Register
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
         -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
         -H "Content-Type: application/json" \
         --data '{"type":"A","name":"'${DOMAIN_VAL}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null
    echo "$DOMAIN_VAL" > $XRAY_DIR/domain
    echo -e "${GREEN}Domain Random: ${DOMAIN_VAL}${NC}"
else
    # MANUAL DOMAIN
    read -p " Masukan Domain/Subdomain Anda: " user_dom
    if [[ -z "$user_dom" ]]; then echo -e "${RED}Error!${NC}"; exit 1; fi
    echo "$user_dom" > $XRAY_DIR/domain
    DOMAIN_VAL="$user_dom"
    echo -e "${GREEN}Domain Set: ${DOMAIN_VAL}${NC}"
fi

# SSL Generation
echo -e "${YELLOW}Generating SSL...${NC}"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_VAL" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key; chmod 644 $XRAY_DIR/xray.crt & install_spin
print_ok "SSL Configured"

# --- 7. XRAY CORE & CONFIG ---
print_msg "Install Xray Core"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
UUID_SYS=$(uuidgen)

# Config JSON
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

# --- 8. ZIVPN SETUP ---
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

# IPtables Rules for Zivpn
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save >/dev/null 2>&1
print_ok "ZIVPN Installed"

# --- 9. AUTO XP (DELETE) & TRIAL HELPERS ---
print_msg "Setup Auto XP & Trial Helper"

# 9A. HELPER: TRIAL KILLER (Digunakan oleh 'at' untuk hapus spesifik user)
cat > /usr/bin/del-trial <<'EOF'
#!/bin/bash
TYPE=$1
USER=$2
CONFIG="/usr/local/etc/xray/config.json"
ZCONFIG="/etc/zivpn/config.json"

if [[ "$TYPE" == "vmess" ]]; then
    jq --arg u "$USER" 'del(.inbounds[2].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG
    sed -i "/^$USER|/d" /usr/local/etc/xray/vmess.txt
elif [[ "$TYPE" == "vless" ]]; then
    jq --arg u "$USER" 'del(.inbounds[3].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG
    sed -i "/^$USER|/d" /usr/local/etc/xray/vless.txt
elif [[ "$TYPE" == "trojan" ]]; then
    jq --arg u "$USER" 'del(.inbounds[4].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG
    sed -i "/^$USER|/d" /usr/local/etc/xray/trojan.txt
elif [[ "$TYPE" == "zivpn" ]]; then
    jq --arg p "$USER" 'del(.auth.config[] | select(. == $p))' $ZCONFIG > /tmp/zconf && mv /tmp/zconf $ZCONFIG
    sed -i "/^$USER|/d" /usr/local/etc/xray/zivpn.txt
fi
systemctl restart xray zivpn
EOF
chmod +x /usr/bin/del-trial

# 9B. DAILY AUTO XP (Berjalan tiap 00:00 untuk akun harian)
cat > /usr/bin/xp <<'EOF'
#!/bin/bash
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"
D_ZIVPN="/usr/local/etc/xray/zivpn.txt"
DATE_NOW=$(date +%Y-%m-%d)

if [ -f "$D_VMESS" ]; then
    while IFS='|' read -r user uuid exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then /usr/bin/del-trial vmess "$user"; fi
    done < $D_VMESS
fi
if [ -f "$D_VLESS" ]; then
    while IFS='|' read -r user uuid exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then /usr/bin/del-trial vless "$user"; fi
    done < $D_VLESS
fi
if [ -f "$D_TROJAN" ]; then
    while IFS='|' read -r user uuid exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then /usr/bin/del-trial trojan "$user"; fi
    done < $D_TROJAN
fi
if [ -f "$D_ZIVPN" ]; then
    while IFS='|' read -r pass exp; do
        if [[ "$exp" < "$DATE_NOW" ]]; then /usr/bin/del-trial zivpn "$pass"; fi
    done < $D_ZIVPN
fi
EOF
chmod +x /usr/bin/xp

# Cronjob Setup
echo "0 0 * * * root /usr/bin/xp" > /etc/cron.d/xp_auto
service cron restart >/dev/null 2>&1
print_ok "Auto Delete Configured"

# --- 10. MAIN MENU SCRIPT ---
print_msg "Generating Dashboard & Menu"
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; WHITE='\033[1;37m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"
D_ZIVPN="/usr/local/etc/xray/zivpn.txt"

# --- HELPER: DISPLAY ACCOUNT (FULL DETAIL RESTORED) ---
function show_account_xray() {
    clear
    local proto=$1; local user=$2; local domain=$3; local uuid=$4; local exp=$5; local link_tls=$6; local link_ntls=$7
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city)
    
    echo -e "————————————————————————————————————"
    echo -e "               ${proto}"
    echo -e "————————————————————————————————————"
    echo -e "Remarks        : ${user}"
    echo -e "CITY           : ${city}"
    echo -e "ISP            : ${isp}"
    echo -e "Domain         : ${domain}"
    if [[ "$proto" == "TROJAN" ]]; then echo -e "Password       : ${uuid}"; else echo -e "id             : ${uuid}"; fi
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

# --- HELPER: DASHBOARD UI ---
function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $2}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    CITY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); UPTIME=$(uptime -p | sed 's/up //')
    TIMEZONE=$(cat /etc/timezone 2>/dev/null || echo "Unknown")
    
    # Traffic
    RX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}')
    TX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}')
    RX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}')
    TX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}')
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes); sleep 0.4
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
    TRAFFIC=$(echo "scale=2; (($R2 - $R1) + ($T2 - $T1)) * 8 / 409.6 / 1024" | bc)

    # Counters
    ACC_VMESS=$(wc -l < "/usr/local/etc/xray/vmess.txt" 2>/dev/null || echo 0)
    ACC_VLESS=$(wc -l < "/usr/local/etc/xray/vless.txt" 2>/dev/null || echo 0)
    ACC_TROJAN=$(wc -l < "/usr/local/etc/xray/trojan.txt" 2>/dev/null || echo 0)
    ACC_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json 2>/dev/null || echo 0)

    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}              TENDO STORE ULTIMATE${NC}"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "OS      : $OS"
    echo -e "RAM     : ${RAM}MB"
    echo -e "SWAP    : ${SWAP}MB"
    echo -e "CITY    : $CITY"
    echo -e "ISP     : $ISP"
    echo -e "IP      : $IP"
    echo -e "DOMAIN  : $DOMAIN"
    echo -e "TIMEZONE: $TIMEZONE"
    echo -e "UPTIME  : $UPTIME"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "${BLUE}TODAY   :${NC} ${GREEN}RX: $RX_DAY${NC} | ${RED}TX: $TX_DAY${NC}"
    echo -e "${BLUE}MONTH   :${NC} ${GREEN}RX: $RX_MON${NC} | ${RED}TX: $TX_MON${NC}"
    echo -e "${BLUE}SPEED   :${NC} $TRAFFIC Mbit/s"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if iptables -L >/dev/null 2>&1; then I_ST="${GREEN}ON${NC}"; else I_ST="${RED}OFF${NC}"; fi
    
    echo -e "STATUS  : XRAY: $X_ST | ZIVPN: $Z_ST | IPtables: $I_ST"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}                LIST ACCOUNTS${NC}"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "VMESS         : $ACC_VMESS  ACCOUNT"
    echo -e "VLESS         : $ACC_VLESS  ACCOUNT"
    echo -e "TROJAN        : $ACC_TROJAN  ACCOUNT"
    echo -e "ZIVPN         : $ACC_ZIVPN  ACCOUNT"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "[1] VMESS ACCOUNT        [5] CHANGE DOMAIN VPS"
    echo -e "[2] VLESS ACCOUNT        [6] FEATURES"
    echo -e "[3] TROJAN ACCOUNT       [7] CHECK SERVICES"
    echo -e "[4] ZIVPN UDP            [x] EXIT"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "Version   : v6.6 (Auto Timezone)"
    echo -e "Owner     : Tendo Store"
    echo -e "Telegram  : @tendo_32"
    echo -e "Expiry In : Lifetime"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
}

function header_sub() {
    clear; echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}              TENDO STORE - SUB MENU${NC}"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
}

function change_domain_menu() {
    header_sub
    read -p "Masukan Domain Baru: " nd
    [[ -z "$nd" ]] && return
    echo "$nd" > /usr/local/etc/xray/domain
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout /usr/local/etc/xray/xray.key -out /usr/local/etc/xray/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1
    systemctl restart xray
    echo -e "${GREEN}Domain Updated!${NC}"; sleep 1
}

function features_menu() {
    while true; do header_sub
        echo -e "[1] Check Bandwidth (Vnstat)"
        echo -e "[2] Speedtest by Ookla"
        echo -e "[3] Restart All Services"
        echo -e "[4] Information System"
        echo -e "[x] Back"
        echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
        read -p "Select Menu : " opt
        case $opt in
            1) vnstat -l -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1);;
            2) speedtest; read -p "Enter...";;
            3) systemctl restart xray zivpn vnstat; echo -e "${GREEN}Restarted!${NC}"; sleep 1;;
            4) neofetch; read -p "Enter...";;
            x) return;;
        esac
    done
}

# --- TRIAL GENERATOR LOGIC ---
function gen_trial() {
    local type=$1
    echo -e "${YELLOW}Set Trial Duration:${NC}"
    echo -e "[1] Minutes (Menit)"
    echo -e "[2] Hours (Jam)"
    read -p "Select Unit: " unit_opt
    read -p "Amount: " amount
    [[ -z "$amount" ]] && return

    if [[ "$unit_opt" == "1" ]]; then
        MINUTES=$amount; EXP_STR="$amount Minutes"
    elif [[ "$unit_opt" == "2" ]]; then
        MINUTES=$((amount * 60)); EXP_STR="$amount Hours"
    else return; fi
    
    EXP_DATE=$(date -d "+$MINUTES minutes" +"%Y-%m-%d %H:%M:%S")
    USER="trial$(tr -dc 0-9 </dev/urandom | head -c 4)"
    UUID=$(uuidgen)
    DMN=$(cat /usr/local/etc/xray/domain)

    if [[ "$type" == "vmess" ]]; then
        jq --arg u "$USER" --arg id "$UUID" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
        echo "$USER|$UUID|$EXP_DATE" >> $D_VMESS
        echo "/usr/bin/del-trial vmess $USER" | at now + $MINUTES minutes >/dev/null 2>&1
        systemctl restart xray
        json_tls=$(echo "{\"v\":\"2\",\"ps\":\"${USER}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${UUID}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
        json_none=$(echo "{\"v\":\"2\",\"ps\":\"${USER}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${UUID}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
        show_account_xray "VMESS" "$USER" "$DMN" "$UUID" "$EXP_DATE ($EXP_STR)" "vmess://$json_tls" "vmess://$json_none"
    elif [[ "$type" == "vless" ]]; then
        jq --arg u "$USER" --arg id "$UUID" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
        echo "$USER|$UUID|$EXP_DATE" >> $D_VLESS
        echo "/usr/bin/del-trial vless $USER" | at now + $MINUTES minutes >/dev/null 2>&1
        systemctl restart xray
        ltls="vless://${UUID}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${USER}"
        lnon="vless://${UUID}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${USER}"
        show_account_xray "VLESS" "$USER" "$DMN" "$UUID" "$EXP_DATE ($EXP_STR)" "$ltls" "$lnon"
    elif [[ "$type" == "trojan" ]]; then
        jq --arg p "$USER" --arg u "$USER" '.inbounds[4].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
        echo "$USER|$USER|$EXP_DATE" >> $D_TROJAN
        echo "/usr/bin/del-trial trojan $USER" | at now + $MINUTES minutes >/dev/null 2>&1
        systemctl restart xray
        trlink="trojan://${USER}@${DMN}:443?security=tls&type=ws&host=${DMN}&path=/trojan&sni=${DMN}#${USER}"
        show_account_xray "TROJAN" "$USER" "$DMN" "$USER" "$EXP_DATE ($EXP_STR)" "$trlink" ""
    elif [[ "$type" == "zivpn" ]]; then
        jq --arg p "$USER" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
        echo "$USER|$EXP_DATE" >> $D_ZIVPN
        echo "/usr/bin/del-trial zivpn $USER" | at now + $MINUTES minutes >/dev/null 2>&1
        systemctl restart zivpn
        show_account_zivpn "$USER" "$DMN" "$EXP_DATE ($EXP_STR)"
    fi
}

function vmess_menu() {
    while true; do header_sub
    echo -e "[1] Create Account"
    echo -e "[2] Create Trial Account"
    echo -e "[3] Delete Account"
    echo -e "[4] Check Config"
    echo -e "[x] Back"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    read -p "Select: " o
    case $o in
        1) read -p "User: " u; id=$(uuidgen); read -p "Exp: " e; [[ -z "$e" ]] && e=30; ed=$(date -d "+$e days" +"%Y-%m-%d");
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$ed" >> $D_VMESS;
           echo -e "${GREEN}Success!${NC}"; sleep 1;;
        2) gen_trial "vmess" ;;
        3) nl $D_VMESS; read -p "No: " n; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); /usr/bin/del-trial vmess "$u"; echo "Deleted"; sleep 1;;
        4) nl $D_VMESS; read -p "No: " n; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); id=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f2); ed=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f3); DMN=$(cat /usr/local/etc/xray/domain);
           json_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0);
           json_none=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
           show_account_xray "VMESS" "$u" "$DMN" "$id" "$ed" "vmess://$json_tls" "vmess://$json_none";;
        x) return;;
    esac; done
}

function vless_menu() {
    while true; do header_sub
    echo -e "[1] Create Account"
    echo -e "[2] Create Trial Account"
    echo -e "[3] Delete Account"
    echo -e "[4] Check Config"
    echo -e "[x] Back"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    read -p "Select: " o
    case $o in
        1) read -p "User: " u; id=$(uuidgen); read -p "Exp: " e; [[ -z "$e" ]] && e=30; ed=$(date -d "+$e days" +"%Y-%m-%d");
           jq --arg u "$u" --arg id "$id" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$ed" >> $D_VLESS;
           echo -e "${GREEN}Success!${NC}"; sleep 1;;
        2) gen_trial "vless" ;;
        3) nl $D_VLESS; read -p "No: " n; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); /usr/bin/del-trial vless "$u"; echo "Deleted"; sleep 1;;
        4) nl $D_VLESS; read -p "No: " n; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); id=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f2); ed=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f3); DMN=$(cat /usr/local/etc/xray/domain);
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}";
           lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           show_account_xray "VLESS" "$u" "$DMN" "$id" "$ed" "$ltls" "$lnon";;
        x) return;;
    esac; done
}

function trojan_menu() {
    while true; do header_sub
    echo -e "[1] Create Account"
    echo -e "[2] Create Trial Account"
    echo -e "[3] Delete Account"
    echo -e "[4] Check Config"
    echo -e "[x] Back"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    read -p "Select: " o
    case $o in
        1) read -p "User: " u; read -p "Exp: " e; [[ -z "$e" ]] && e=30; ed=$(date -d "+$e days" +"%Y-%m-%d");
           jq --arg u "$u" --arg p "$u" '.inbounds[4].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$u|$ed" >> $D_TROJAN;
           echo -e "${GREEN}Success!${NC}"; sleep 1;;
        2) gen_trial "trojan" ;;
        3) nl $D_TROJAN; read -p "No: " n; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); /usr/bin/del-trial trojan "$u"; echo "Deleted"; sleep 1;;
        4) nl $D_TROJAN; read -p "No: " n; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); ed=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f3); DMN=$(cat /usr/local/etc/xray/domain);
           trlink="trojan://${u}@${DMN}:443?security=tls&type=ws&host=${DMN}&path=/trojan&sni=${DMN}#${u}"
           show_account_xray "TROJAN" "$u" "$DMN" "$u" "$ed" "$trlink" "";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub
    echo -e "[1] Create Account"
    echo -e "[2] Create Trial Account"
    echo -e "[3] Delete Account"
    echo -e "[4] Check Config"
    echo -e "[x] Back"
    echo -e "${BLUE}──────────────────────────────────────────────────${NC}"
    read -p "Select: " o
    case $o in
        1) read -p "Pass: " p; read -p "Exp: " e; [[ -z "$e" ]] && e=30; ed=$(date -d "+$e days" +"%Y-%m-%d");
           jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$ed" >> $D_ZIVPN;
           echo -e "${GREEN}Success!${NC}"; sleep 1;;
        2) gen_trial "zivpn" ;;
        3) nl $D_ZIVPN; read -p "No: " n; p=$(sed -n "${n}p" $D_ZIVPN | cut -d'|' -f1); /usr/bin/del-trial zivpn "$p"; echo "Deleted"; sleep 1;;
        4) nl $D_ZIVPN; read -p "No: " n; p=$(sed -n "${n}p" $D_ZIVPN | cut -d'|' -f1); DMN=$(cat /usr/local/etc/xray/domain); ed=$(grep "^$p|" $D_ZIVPN | cut -d'|' -f2);
           show_account_zivpn "$p" "$DMN" "$ed";;
        x) return;;
    esac; done
}

function check_services() {
    header_sub
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet atd; then A_ST="${GREEN}ON${NC}"; else A_ST="${RED}OFF${NC}"; fi
    echo -e "Xray: $X_ST | Zivpn: $Z_ST | AutoKiller: $A_ST"
    read -p "Enter..."
}

while true; do header_main; read -p "Select Menu : " opt
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
