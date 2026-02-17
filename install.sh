#!/bin/bash
# ==================================================
#   Auto Script Install X-ray Multi-Port
#   EDITION: PLATINUM LTS FINAL V.17.02.26
#   Script BY: Tendo Store
#   Features: VMess, VLESS, Trojan, ZIVPN, Features
#   UI: Original Zero Margin + ZIVPN Main Menu
# ==================================================

# --- COLORS FOR INSTALLATION ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- HELPER FUNCTIONS ---
function print_status() {
    echo -e "${BLUE}[PROCESS]${NC} $1..."
}
function print_success() {
    echo -e "${GREEN}[  OK  ]${NC} $1 Completed."
}

clear
echo -e "${BLUE}=============================================${NC}"
echo -e "      ${YELLOW}AUTO SCRIPT INSTALLER BY TENDO${NC}"
echo -e "      ${GREEN}EDITION: PLATINUM LTS V.17.02.26${NC}"
echo -e "${BLUE}=============================================${NC}"
echo -e "Starting Installation..."
sleep 2

# --- 1. SYSTEM OPTIMIZATION ---
print_status "Optimizing System (BBR & Swap)"
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

# Force Swap 2GB
swapoff -a 2>/dev/null
rm -f /swapfile
dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
chmod 600 /swapfile
mkswap /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '/swapfile/d' /etc/fstab
echo '/swapfile none swap sw 0 0' >> /etc/fstab
print_success "System Optimization"

# --- 2. SETUP VARIABLES ---
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"
DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"

XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
RULE_LIST="/usr/local/etc/xray/rule_list.txt"
USER_DATA="/usr/local/etc/xray/user_data.txt"

# --- 3. INSTALL DEPENDENCIES ---
print_status "Installing Dependencies"
apt update -y >/dev/null 2>&1
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron >/dev/null 2>&1

touch /root/.hushlogin
sed -i '/neofetch/d' /root/.bashrc
echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat >/dev/null 2>&1
systemctl restart vnstat >/dev/null 2>&1
vnstat -u -i $IFACE_NET >/dev/null 2>&1
print_success "Dependencies Installed"

# --- 4. DOMAIN & SSL SETUP ---
print_status "Setting up Domain & SSL"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $USER_DATA
IP_VPS=$(curl -s ifconfig.me)
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# Register Cloudflare (Hidden Output)
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${DOMAIN_INIT}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null

echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt
print_success "Domain: $DOMAIN_INIT"

# --- 5. XRAY CORE & MULTI-PORT CONFIG ---
print_status "Installing X-Ray Core & Applying VMess Fix"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"

echo "google" > $RULE_LIST

# FIXED CONFIG: Removed xver:1 to fix VMess connection
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-tls", "port": 443, "protocol": "vless",
      "settings": {
        "clients": [], "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001 },
          { "path": "/trojan", "dest": 10002 },
          { "dest": 10001 }
        ]
      },
      "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } }
    },
    {
      "tag": "vless-nontls", "port": 80, "protocol": "vless",
      "settings": {
        "clients": [], "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001 },
          { "path": "/trojan", "dest": 10002 },
          { "dest": 10001 }
        ]
      },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } }
    },
    {
      "tag": "vmess", "port": 10001, "listen": "127.0.0.1", "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "trojan", "port": 10002, "listen": "127.0.0.1", "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" }, { "type": "field", "domain": ["geosite:google"], "outboundTag": "direct" } ] }
}
EOF
print_success "X-Ray Core Installed"

# --- 6. ZIVPN CONFIG ---
print_status "Installing ZIVPN UDP"
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
cat > /etc/zivpn/config.json <<EOF
{ "listen": ":5667", "cert": "$XRAY_DIR/xray.crt", "key": "$XRAY_DIR/xray.key", "obfs": "zivpn", "auth": { "mode": "passwords", "config": [] } }
EOF
cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZIVPN
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload >/dev/null 2>&1
systemctl enable zivpn >/dev/null 2>&1
systemctl restart zivpn xray >/dev/null 2>&1

iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save >/dev/null 2>&1
print_success "ZIVPN UDP Installed"

# --- 7. MENU SCRIPT ---
print_status "Generating Menu & Features"
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"
XRAY_DIR="/usr/local/etc/xray"

function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $3}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); UPTIME=$(uptime -p | sed 's/up //')
    CITY=$(cat /root/tendo/city 2>/dev/null); ISP=$(cat /root/tendo/isp 2>/dev/null); IP=$(cat /root/tendo/ip 2>/dev/null)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    MON_DATA=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $11}'); M_RX=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}'); M_TX=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}')
    DAY_DATA=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $6}'); D_RX=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}'); D_TX=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}')
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes); sleep 0.4
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
    TRAFFIC=$(echo "scale=2; (($R2 - $R1) + ($T2 - $T1)) * 8 / 409.6 / 1024" | bc)
    
    echo -e "┌─────────────────────────────────────────────────┐\n          ${BG_RED}          TENDO STORE          ${NC} \n└─────────────────────────────────────────────────┘"
    echo -e "┌─────────────────────────────────────────────────┐\n│ OS      : $OS\n│ RAM     : ${RAM}M\n│ SWAP    : ${SWAP}M\n│ CITY    : $CITY\n│ ISP     : $ISP\n│ IP      : $IP\n│ DOMAIN  : $DOMAIN\n│ UPTIME  : $UPTIME\n│ —————————————————————————————————————\n│ MONTH   : $MON_DATA    [$(date +%B)]\n│ RX      : $M_RX\n│ TX      : $M_TX\n│ —————————————————————————————————————\n│ DAY     : $DAY_DATA    [$(date +%A)]\n│ RX      : $D_RX\n│ TX      : $D_TX\n│ TRAFFIC : $TRAFFIC Mbit/s\n│ —————————————————————————————————————"
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"; SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"; 
    echo -e "│ XRAY : $X_ST | ZIVPN : $Z_ST \n│ —————————————————————————————————————"
    C_VMESS=$(jq '.inbounds[2].settings.clients | length' $CONFIG); C_VLESS=$(jq '.inbounds[0].settings.clients | length' $CONFIG); C_TROJAN=$(jq '.inbounds[3].settings.clients | length' $CONFIG); C_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json)
    echo -e "│              LIST ACCOUNTS\n│ —————————————————————————————————————\n│    VMESS WS      : $C_VMESS  ACCOUNT\n│    VLESS WS      : $C_VLESS  ACCOUNT\n│    TROJAN WS     : $C_TROJAN  ACCOUNT\n│    ZIVPN UDP     : $C_ZIVPN  ACCOUNT"
    echo -e "│ —————————————————————————————————————\n│ Version   : PLATINUM LTS FINAL V.17.02.26\n│ Script BY : Tendo Store\n│ WhatsApp  : +6282224460678\n│ Expiry In : Lifetime\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - $1${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

# --- SUB MENU FUNCTIONS ---
function vmess_menu() {
    while true; do header_sub "VMESS MENU"; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account (Custom UUID + Non-TLS)\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u
           read -p " UUID (Tekan Enter untuk Random): " uid_in
           [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"
           read -p " Expired (Days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u,"alterId":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp|vmess" >> $U_DATA
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
           vmess_tls='{"add":"'$DOMAIN'","aid":"0","host":"'$DOMAIN'","id":"'$id'","net":"ws","path":"/vmess","port":"443","ps":"'$u'","scy":"auto","sni":"'$DOMAIN'","tls":"tls","type":"","v":"2"}'
           vmess_none='{"add":"'$DOMAIN'","aid":"0","host":"'$DOMAIN'","id":"'$id'","net":"ws","path":"/vmess","port":"80","ps":"'$u'","scy":"auto","sni":"","tls":"","type":"","v":"2"}'
           link_tls="vmess://$(echo -n $vmess_tls | base64 -w 0)"
           link_none="vmess://$(echo -n $vmess_none | base64 -w 0)"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT VMESS WS\n━━━━━━━━━━━━━━━━━━━━━\nRemarks    : $u\nCITY       : $CTY\nISP        : $ISP\nDomain     : $DOMAIN\nPort TLS   : 443\nPort None  : 80\nUUID       : $id\nAlterId    : 0\nSecurity   : auto\nNetwork    : ws\nPath       : /vmess\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━\n LINK TLS : $link_tls\n━━━━━━━━━━━━━━━━━━━━━\n LINK HTTP: $link_none\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; sed -i "/^$u|.*|vmess/d" $U_DATA; systemctl restart xray; echo "Deleted $u"; sleep 1;;
        3) header_sub "VMESS LIST"; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        4) header_sub "CHECK VMESS"; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Select No: " n; [[ -z "$n" ]] && continue; idx=$((n-1))
           u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[2].settings.clients[$idx].id" $CONFIG)
           exp=$(grep "^$u|" $U_DATA | grep "|vmess" | cut -d '|' -f 3); [[ -z "$exp" ]] && exp="Unlimited"
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
           vmess_tls='{"add":"'$DOMAIN'","aid":"0","host":"'$DOMAIN'","id":"'$id'","net":"ws","path":"/vmess","port":"443","ps":"'$u'","scy":"auto","sni":"'$DOMAIN'","tls":"tls","type":"","v":"2"}'
           vmess_none='{"add":"'$DOMAIN'","aid":"0","host":"'$DOMAIN'","id":"'$id'","net":"ws","path":"/vmess","port":"80","ps":"'$u'","scy":"auto","sni":"","tls":"","type":"","v":"2"}'
           link_tls="vmess://$(echo -n $vmess_tls | base64 -w 0)"
           link_none="vmess://$(echo -n $vmess_none | base64 -w 0)"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  CHECK VMESS WS\n━━━━━━━━━━━━━━━━━━━━━\nRemarks    : $u\nCITY       : $CTY\nISP        : $ISP\nDomain     : $DOMAIN\nPort TLS   : 443\nPort None  : 80\nUUID       : $id\nAlterId    : 0\nSecurity   : auto\nNetwork    : ws\nPath       : /vmess\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━\n LINK TLS : $link_tls\n━━━━━━━━━━━━━━━━━━━━━\n LINK HTTP: $link_none\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function vless_menu() {
    while true; do header_sub "VLESS MENU"; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account (Custom UUID + Non-TLS)\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u
           read -p " UUID (Tekan Enter untuk Random): " uid_in
           [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"
           read -p " Expired (Days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[0].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[1].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp|vless" >> $U_DATA
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
           ltls="vless://${id}@${DOMAIN}:443?path=/vless&security=tls&encryption=none&type=ws&sni=${DOMAIN}#${u}"; lnon="vless://${id}@${DOMAIN}:80?path=/vless&security=none&encryption=none&type=ws#${u}"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT VLESS WS\n━━━━━━━━━━━━━━━━━━━━━\nRemarks    : $u\nCITY       : $CTY\nISP        : $ISP\nDomain     : $DOMAIN\nPort TLS   : 443\nPort None  : 80\nUUID       : $id\nEncryption : none\nNetwork    : ws\nPath       : /vless\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━\n LINK TLS : $ltls\n━━━━━━━━━━━━━━━━━━━━━\n LINK HTTP: $lnon\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; jq "del(.inbounds[1].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; sed -i "/^$u|.*|vless/d" $U_DATA; systemctl restart xray; echo "Deleted $u"; sleep 1;;
        3) header_sub "VLESS LIST"; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        4) header_sub "CHECK VLESS"; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Select No: " n; [[ -z "$n" ]] && continue; idx=$((n-1))
           u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[0].settings.clients[$idx].id" $CONFIG)
           exp=$(grep "^$u|" $U_DATA | grep "|vless" | cut -d '|' -f 3); [[ -z "$exp" ]] && exp="Unlimited"
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
           ltls="vless://${id}@${DOMAIN}:443?path=/vless&security=tls&encryption=none&type=ws&sni=${DOMAIN}#${u}"; lnon="vless://${id}@${DOMAIN}:80?path=/vless&security=none&encryption=none&type=ws#${u}"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  CHECK VLESS WS\n━━━━━━━━━━━━━━━━━━━━━\nRemarks    : $u\nCITY       : $CTY\nISP        : $ISP\nDomain     : $DOMAIN\nPort TLS   : 443\nPort None  : 80\nUUID       : $id\nEncryption : none\nNetwork    : ws\nPath       : /vless\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━\n LINK TLS : $ltls\n━━━━━━━━━━━━━━━━━━━━━\n LINK HTTP: $lnon\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function trojan_menu() {
    while true; do header_sub "TROJAN MENU"; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account (Custom Password)\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u
           read -p " Password (Enter for same as User): " pass_in
           [[ -z "$pass_in" ]] && pass="$u" || pass="$pass_in"
           read -p " Expired (Days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg p "$pass" '.inbounds[3].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$pass|$exp|trojan" >> $U_DATA
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
           ltls="trojan://${pass}@${DOMAIN}:443?path=/trojan&security=tls&type=ws&sni=${DOMAIN}#${u}"
           lnon="trojan://${pass}@${DOMAIN}:80?path=/trojan&security=none&type=ws#${u}"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT TROJAN WS\n━━━━━━━━━━━━━━━━━━━━━\nRemarks    : $u\nCITY       : $CTY\nISP        : $ISP\nDomain     : $DOMAIN\nPort TLS   : 443\nPort None  : 80\nPassword   : $pass\nNetwork    : ws\nPath       : /trojan\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━\n LINK TLS : $ltls\n━━━━━━━━━━━━━━━━━━━━━\n LINK HTTP: $lnon\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[3].settings.clients[$idx].email" $CONFIG); jq "del(.inbounds[3].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; sed -i "/^$u|.*|trojan/d" $U_DATA; systemctl restart xray; echo "Deleted $u"; sleep 1;;
        3) header_sub "TROJAN LIST"; jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        4) header_sub "CHECK TROJAN"; jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "Select No: " n; [[ -z "$n" ]] && continue; idx=$((n-1))
           u=$(jq -r ".inbounds[3].settings.clients[$idx].email" $CONFIG); pass=$(jq -r ".inbounds[3].settings.clients[$idx].password" $CONFIG)
           exp=$(grep "^$u|" $U_DATA | grep "|trojan" | cut -d '|' -f 3); [[ -z "$exp" ]] && exp="Unlimited"
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
           ltls="trojan://${pass}@${DOMAIN}:443?path=/trojan&security=tls&type=ws&sni=${DOMAIN}#${u}"
           lnon="trojan://${pass}@${DOMAIN}:80?path=/trojan&security=none&type=ws#${u}"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  CHECK TROJAN WS\n━━━━━━━━━━━━━━━━━━━━━\nRemarks    : $u\nCITY       : $CTY\nISP        : $ISP\nDomain     : $DOMAIN\nPort TLS   : 443\nPort None  : 80\nPassword   : $pass\nNetwork    : ws\nPath       : /trojan\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━\n LINK TLS : $ltls\n━━━━━━━━━━━━━━━━━━━━━\n LINK HTTP: $lnon\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu_gui() {
    while true; do
        header_sub "ZIVPN MANAGER"
        echo -e "┌─────────────────────────────────────────────────┐"
        echo -e "│ 1.) Create Account (User & Pass & Exp)"
        echo -e "│ 2.) Delete Account"
        echo -e "│ 3.) Check/List Accounts"
        echo -e "│ x.) Back"
        echo -e "└─────────────────────────────────────────────────┘"
        read -p "Select: " opt
        case $opt in
            1)
                read -p " Username : " u
                read -p " Password : " p
                read -p " Expired (Days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "+$ex days" +"%Y-%m-%d")
                jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
                systemctl restart zivpn
                echo "$u|$p|$exp|zivpn" >> $U_DATA
                CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
                IP=$(cat /root/tendo/ip)
                clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $CTY\nISP        : $ISP\nIP ISP     : $IP\nDomain     : $DOMAIN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
            2)
                echo "List Active Users:"
                grep "|zivpn" $U_DATA | nl
                read -p " Select Number to Delete: " num
                [[ -z "$num" ]] && continue
                raw_line=$(grep "|zivpn" $U_DATA | sed -n "${num}p")
                user_del=$(echo "$raw_line" | cut -d '|' -f 1)
                pass_del=$(echo "$raw_line" | cut -d '|' -f 2)
                jq --arg p "$pass_del" 'del(.auth.config[] | select(. == $p))' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
                sed -i "/^$user_del|$pass_del|/d" $U_DATA
                systemctl restart zivpn
                echo -e "${RED} Account '$user_del' Deleted!${NC}"
                sleep 2
                ;;
            3)
                 echo "Select Account to Check:"
                 grep "|zivpn" $U_DATA | awk -F'|' '{print "User: "$1}' | nl
                 read -p " Select Number: " num
                 [[ -z "$num" ]] && continue
                 raw_line=$(grep "|zivpn" $U_DATA | sed -n "${num}p")
                 u=$(echo "$raw_line" | cut -d '|' -f 1)
                 p=$(echo "$raw_line" | cut -d '|' -f 2)
                 exp=$(echo "$raw_line" | cut -d '|' -f 3)
                 CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
                 IP=$(cat /root/tendo/ip)
                 clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $CTY\nISP        : $ISP\nIP ISP     : $IP\nDomain     : $DOMAIN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -n 1 -s -r -p "Enter...";;
            x) return ;;
        esac
    done
}

function features_menu() {
    while true; do
        header_sub "FEATURES MENU"
        echo -e "┌─────────────────────────────────────────────────┐"
        echo -e "│ 1.) Ganti Domain"
        echo -e "│ 2.) Routing Geosite"
        echo -e "│ 3.) Restart Service"
        echo -e "│ 4.) Speed Test"
        echo -e "│ 5.) Tools (Clean RAM/Cache)"
        echo -e "│ 6.) Informasi System"
        echo -e "│ x.) Back"
        echo -e "└─────────────────────────────────────────────────┘"
        read -p "Select: " opt
        case $opt in
            1) read -p "Domain Baru: " nd; echo "$nd" > /usr/local/etc/xray/domain; openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1; systemctl restart xray; echo "Domain Updated!"; sleep 1;;
            2) routing_menu ;;
            3) systemctl restart xray zivpn; echo "Services Restarted!"; sleep 1 ;;
            4) python3 <(curl -sL https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) --share; read -p "Enter..." ;;
            5) /usr/bin/cleaner; echo "RAM & Cache Cleaned!"; sleep 1 ;;
            6) neofetch; echo "IP Public: $(curl -s ifconfig.me)"; read -p "Enter..." ;;
            x) return ;;
        esac
    done
}

function routing_menu() {
    while true; do header_sub "ROUTING GEOSITE"; echo -e "┌─────────────────────────────────────────────────┐\n│            SUPPORTED GEOSITE LIST               \n│ —————————————————————————————————————\n│ rule-gaming, rule-indo, rule-sosmed, google,    \n│ rule-playstore, rule-streaming, rule-umum, tiktok,\n│ rule-ipcheck, rule-doh, rule-malicious, telegram,\n│ rule-ads, rule-speedtest, ecommerce-id, urltest,\n│ category-porn, bank-id, meta, videoconference,  \n│ geolocation-!cn, facebook, spotify, openai, meta,\n│ ehentai, github, microsoft, apple, netflix, cn, \n│ youtube, twitter, bilibili, category-ads-all,   \n│ private, category-media, category-vpnservices,  \n│ category-dev, category-dev-all, meta, category-media-all\n└─────────────────────────────────────────────────┘"; DOMS=$(cat /usr/local/etc/xray/rule_list.txt | xargs)
        echo -e "┌─────────────────────────────────────────────────┐\n│ Active Rules: ${GREEN}$DOMS${NC}\n│ 1.) Tambah rule geosite\n│ 2.) Hapus rule geosite\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
        case $opt in
            1) read -p "Rule: " d; echo "$d" >> /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "direct" and .type == "field" and .domain != null then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            2) nl /usr/local/etc/xray/rule_list.txt; read -p "No: " n; [[ -z "$n" ]] && continue; sed -i "${n}d" /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "direct" and .type == "field" and .domain != null then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            x) return;;
        esac; done
}

function check_services() {
    header_sub "SERVICE STATUS"; echo -e "┌─────────────────────────────────────────────────┐\n│ SERVICES CHECK\n│ —————————————————————————————————————"; services=("xray" "zivpn" "vnstat" "netfilter-persistent" "cron"); names=("Xray VPN Core   " "ZIVPN UDP Server" "Vnstat Monitor  " "Iptables Rules  " "Cron Scheduler  ")
    for i in "${!services[@]}"; do if systemctl is-active --quiet "${services[$i]}"; then status="${GREEN}ACTIVE (ON)${NC}"; else status="${RED}INACTIVE (OFF)${NC}"; fi; echo -e "│ ${names[$i]} : $status"; done
    echo -e "└─────────────────────────────────────────────────┘"; read -p "Enter...";
}

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) VMESS MENU\n│ 2.) VLESS MENU\n│ 3.) TROJAN MENU\n│ 4.) ZIVPN MENU\n│ 5.) FEATURES MENU\n│ 6.) CEK SERVICE\n│ x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p "Pilih Nomor: " opt
    case $opt in
        1) vmess_menu ;; 
        2) vless_menu ;; 
        3) trojan_menu ;;
        4) zivpn_menu_gui ;;
        5) features_menu ;;
        6) check_services ;;
        x) exit ;;
    esac; done
END_MENU
chmod +x /usr/bin/menu

# --- 8. AUTO XP (Protocol Aware + ZIVPN Support) ---
cat > /usr/bin/xp <<'END_XP'
#!/bin/bash
data_file="/usr/local/etc/xray/user_data.txt"
config_file="/usr/local/etc/xray/config.json"
zivpn_file="/etc/zivpn/config.json"
now=$(date +%Y-%m-%d)

while read -r line; do
    [[ -z "$line" ]] && continue
    user=$(echo "$line" | cut -d '|' -f 1)
    # Password/UUID is in f2
    token=$(echo "$line" | cut -d '|' -f 2) 
    exp_date=$(echo "$line" | cut -d '|' -f 3)
    proto=$(echo "$line" | cut -d '|' -f 4)
    
    exp_sec=$(date -d "$exp_date" +%s)
    now_sec=$(date -d "$now" +%s)
    
    if [[ $exp_sec -lt $now_sec ]]; then
        echo "Deleting $user ($proto)..."
        
        if [[ "$proto" == "vmess" ]]; then
            jq --arg u "$user" 'del(.inbounds[2].settings.clients[] | select(.email == $u))' $config_file > /tmp/x && mv /tmp/x $config_file
        elif [[ "$proto" == "vless" ]]; then
            jq --arg u "$user" 'del(.inbounds[0].settings.clients[] | select(.email == $u))' $config_file > /tmp/x && mv /tmp/x $config_file
            jq --arg u "$user" 'del(.inbounds[1].settings.clients[] | select(.email == $u))' $config_file > /tmp/x && mv /tmp/x $config_file
        elif [[ "$proto" == "trojan" ]]; then
            jq --arg u "$user" 'del(.inbounds[3].settings.clients[] | select(.email == $u))' $config_file > /tmp/x && mv /tmp/x $config_file
        elif [[ "$proto" == "zivpn" ]]; then
            jq --arg p "$token" 'del(.auth.config[] | select(. == $p))' $zivpn_file > /tmp/z && mv /tmp/z $zivpn_file
            systemctl restart zivpn
        fi
        
        sed -i "/^$user|$token|/d" $data_file
        systemctl restart xray
    fi
done < "$data_file"
END_XP
chmod +x /usr/bin/xp

# --- 9. CLEANER & CRON ---
cat > /usr/bin/cleaner <<'END_CLEAN'
#!/bin/bash
sync; echo 3 > /proc/sys/vm/drop_caches; swapoff -a && swapon -a
rm -rf /var/log/syslog /var/log/btmp /var/log/kern.log /var/log/auth.log
history -c
END_CLEAN
chmod +x /usr/bin/cleaner

echo "0 0 * * * root /usr/bin/xp" > /etc/crontab
echo "0 2 * * * root /usr/bin/cleaner" >> /etc/crontab
echo "0 5 * * * root /sbin/reboot" >> /etc/crontab
service cron restart

print_success "Menu & Features Generated"

echo -e "${GREEN}=============================================${NC}"
echo -e "   INSTALLATION SUCCESSFUL!"
echo -e "   COMMAND: menu"
echo -e "${GREEN}=============================================${NC}"
rm -f /root/install.sh
