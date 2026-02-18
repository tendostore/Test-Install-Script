#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM COMPLETE V.6.7 (JAKARTA FIXED)
#   Update: Force Timezone Asia/Jakarta (WIB)
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

# --- 6. DOMAIN, SSL & TIMEZONE (FIXED JAKARTA) ---
print_msg "Setup Domain, SSL & Timezone"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo; touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN $DATA_ZIVPN
IP_VPS=$(curl -s ifconfig.me)

# Get Geo Info
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# --- FIXED TIMEZONE: ASIA/JAKARTA ---
ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
echo "Asia/Jakarta" > /etc/timezone
if command -v timedatectl &> /dev/null; then
    timedatectl set-timezone Asia/Jakarta
fi
print_msg "Zona Waktu Set: Asia/Jakarta (WIB)"

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
    read -p " Masukan Domain Anda: " user_dom
    [[ -z "$user_dom" ]] && exit 1
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

# --- 7. XRAY CONFIG ---
print_msg "Install Xray Core"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
UUID_SYS=$(uuidgen)
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
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "blocked" }],
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
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save >/dev/null 2>&1
print_ok "ZIVPN Installed"

# --- 9. AUTO XP & TRIAL ---
cat > /usr/bin/del-trial <<'EOF'
#!/bin/bash
TYPE=$1; USER=$2; CONFIG="/usr/local/etc/xray/config.json"; ZCONFIG="/etc/zivpn/config.json"
if [[ "$TYPE" == "vmess" ]]; then jq --arg u "$USER" 'del(.inbounds[2].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG; sed -i "/^$USER|/d" /usr/local/etc/xray/vmess.txt
elif [[ "$TYPE" == "vless" ]]; then jq --arg u "$USER" 'del(.inbounds[3].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG; sed -i "/^$USER|/d" /usr/local/etc/xray/vless.txt
elif [[ "$TYPE" == "trojan" ]]; then jq --arg u "$USER" 'del(.inbounds[4].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/conf && mv /tmp/conf $CONFIG; sed -i "/^$USER|/
