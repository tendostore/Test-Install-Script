#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM CLEAN V.5.6 (FINAL RELEASE)
#   Update: Removed Upgrade Path/GRPC & Set Version v18.02.26
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
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"
DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
XRAY_DIR="/usr/local/etc/xray"; 
CONFIG_FILE="/usr/local/etc/xray/config.json"
DATA_VMESS="/usr/local/etc/xray/vmess.txt"; DATA_VLESS="/usr/local/etc/xray/vless.txt"; DATA_TROJAN="/usr/local/etc/xray/trojan.txt"

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

# --- 4. DOMAIN ---
print_msg "Setup Domain & SSL"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo; touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN
IP_VPS=$(curl -s ifconfig.me)
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${DOMAIN_INIT}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null

echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key; chmod 644 $XRAY_DIR/xray.crt & install_spin
print_ok "Domain Created: $DOMAIN_INIT"

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

# --- 7. MENU SCRIPT ---
print_msg "Finalisasi Menu"
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; WHITE='\033[1;37m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"

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
    RAM=$(free -m | awk '/Mem:/ {print $3}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    # Traffic Calculation
    RX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}')
    TX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}')
    RX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}')
    TX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}')
    
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes); sleep 0.4
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
    TRAFFIC=$(echo "scale=2; (($R2 - $R1) + ($T2 - $T1)) * 8 / 409.6 / 1024" | bc)

    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│              ${YELLOW}TENDO STORE ULTIMATE${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    printf "${CYAN}│${NC} OS      : ${WHITE}%-s${NC}\n" "$OS"
    printf "${CYAN}│${NC} RAM     : ${WHITE}%-s${NC}\n" "${RAM}MB | SWAP: ${SWAP}MB"
    printf "${CYAN}│${NC} DOMAIN  : ${YELLOW}%-s${NC}\n" "$DOMAIN"
    printf "${CYAN}│${NC} IP VPS  : ${WHITE}%-s${NC}\n" "$IP"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│${NC} ${PURPLE}TODAY${NC}   : ${GREEN}RX:${NC} $RX_DAY ${CYAN}|${NC} ${RED}TX:${NC} $TX_DAY"
    echo -e "${CYAN}│${NC} ${PURPLE}MONTH${NC}   : ${GREEN}RX:${NC} $RX_MON ${CYAN}|${NC} ${RED}TX:${NC} $TX_MON"
    printf "${CYAN}│${NC} ${PURPLE}SPEED${NC}   : ${WHITE}%-s${NC}\n" "$TRAFFIC Mbit/s"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    # Cek IPTables dengan simple command
    if iptables -L >/dev/null 2>&1; then I_ST="${GREEN}ON${NC}"; else I_ST="${RED}OFF${NC}"; fi
    
    printf "${CYAN}│${NC} STATUS  : XRAY: %b ${CYAN}|${NC} ZIVPN: %b ${CYAN}|${NC} IPtables: %b\n" "$X_ST" "$Z_ST" "$I_ST"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
}

function header_sub() {
    clear; echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│              ${YELLOW}TENDO STORE - SUB MENU${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
}

function features_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Check Bandwidth (Vnstat)"
        echo -e "${CYAN}│${NC} [2] Speedtest by Ookla (Official)"
        echo -e "${CYAN}│${NC} [3] Restart All Services"
        echo -e "${CYAN}│${NC} [4] Change Domain VPS"
        echo -e "${CYAN}│${NC} [5] Clear Cache RAM"
        echo -e "${CYAN}│${NC} [6] Auto Reboot"
        echo -e "${CYAN}│${NC} [7] Information System"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) vnstat -l -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1);;
            2) speedtest; read -p "Enter...";;
            3) systemctl restart xray zivpn vnstat; echo -e "${GREEN}Services Restarted!${NC}"; sleep 2;;
            4) read -p "New Domain: " nd; echo "$nd" > /usr/local/etc/xray/domain; openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout /usr/local/etc/xray/xray.key -out /usr/local/etc/xray/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1; systemctl restart xray; echo "Domain Updated!"; sleep 2;;
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
            1) read -p " Password: " p; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            2) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
            3) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "Unknown";;
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
    echo -e "${CYAN}│${NC} [1] VMESS ACCOUNT        [4] ZIVPN UDP"
    echo -e "${CYAN}│${NC} [2] VLESS ACCOUNT        [5] FEATURES"
    echo -e "${CYAN}│${NC} [3] TROJAN ACCOUNT       [6] CHECK SERVICES"
    echo -e "${CYAN}│${NC} [x] EXIT"
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
        4) zivpn_menu ;; 5) features_menu ;; 6) check_services ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
install_spin
print_ok "Instalasi Selesai! Ketik: menu"
