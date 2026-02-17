#!/bin/bash
# ==================================================
#   Auto Script Install X-ray (WARP Routing) & Zivpn
#   EDITION: PLATINUM CUSTOM WARP V.3.1 (FIX GEOSITE)
#   Update: Fix Geosite Download Location & Custom URL
#   Script BY: Tendo Store | WhatsApp: +6282224460678
# ==================================================

# --- 0. PRE-INSTALLATION: FIX DNS RESOLV.CONF ---
echo -e "\e[1;32m[SYSTEM] Setting up DNS to 9.9.9.9, 1.1.1.1, 8.8.8.8...\e[0m"
# Unlocking file if locked
chattr -i /etc/resolv.conf > /dev/null 2>&1
# Backup existing
cp /etc/resolv.conf /etc/resolv.conf.bak
# Remove symlink if exists
rm -f /etc/resolv.conf
# Create new resolv.conf
cat > /etc/resolv.conf <<EOF
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
# Lock file to prevent changes
chattr +i /etc/resolv.conf

# --- 1. SYSTEM OPTIMIZATION (BBR & SWAP 2GB) ---
echo -e "\e[1;32m[SYSTEM] Optimizing System & Memory...\e[0m"
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
# Enable TCP BBR
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

# --- 2. SETUP VARIABLES ---
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"
DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"

XRAY_DIR="/usr/local/etc/xray"
XRAY_SHARE="/usr/local/share/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
RULE_LIST="/usr/local/etc/xray/rule_list.txt"
# Database Users
DATA_VMESS="/usr/local/etc/xray/vmess.txt"
DATA_VLESS="/usr/local/etc/xray/vless.txt"
DATA_TROJAN="/usr/local/etc/xray/trojan.txt"

clear
echo "============================================="
echo "   Auto Script Install X-ray WARP & Zivpn"
echo "        BY TENDO STORE - CUSTOM MOD"
echo "============================================="

# --- 3. INSTALL DEPENDENCIES & VISUALS ---
echo -e "\e[1;32m[INSTALL] Installing Dependencies...\e[0m"
apt update -y
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron

# Silent Login Configuration
touch /root/.hushlogin
chmod -x /etc/update-motd.d/* 2>/dev/null
sed -i '/neofetch/d' /root/.bashrc
echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat && systemctl restart vnstat
vnstat -u -i $IFACE_NET >/dev/null 2>&1

# --- 4. INSTALL CLOUDFLARE WARP (WIREPROXY) ---
echo -e "\e[1;32m[WARP] Installing WARP WireProxy (Port 40000)...\e[0m"
# Download script
wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh
# Automate Input: 1 (English) -> 13 (Wireproxy) -> 40000 (Port)
# Menggunakan pipe untuk melewati interaktif menu
echo -e "1\n13\n40000" | bash menu.sh
echo -e "\e[1;32m[WARP] Installation logic executed. Proceeding...\e[0m"

# --- 5. DOMAIN & SSL SETUP ---
echo -e "\e[1;32m[DOMAIN] Setting up Domain & SSL...\e[0m"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN
IP_VPS=$(curl -s ifconfig.me)
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# Cloudflare Auto Subdomain
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${DOMAIN_INIT}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null

echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 6. XRAY CORE CONFIGURATION (CUSTOM JSON + WARP) ---
echo -e "\e[1;32m[XRAY] Installing Core & Custom Config...\e[0m"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1

# --- FIX: DOWNLOAD CUSTOM GEOSITE TENDO ---
echo -e "\e[1;32m[GEOSITE] Downloading Custom Geosite Tendo...\e[0m"
mkdir -p $XRAY_SHARE
rm -f $XRAY_SHARE/geosite.dat
# Menggunakan link custom Anda
wget -O $XRAY_SHARE/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
if [ -f "$XRAY_SHARE/geosite.dat" ]; then
    echo -e "\e[1;32m[SUCCESS] Custom Geosite Downloaded Successfully!\e[0m"
else
    echo -e "\e[1;31m[ERROR] Failed to download Geosite. Check URL or Network.\e[0m"
fi

echo "google" > $RULE_LIST

# GENERATE UUID FOR SYSTEM
UUID_SYS=$(uuidgen)
UUID_TENDO=$(uuidgen)
UUID_TYGG=$(uuidgen)
UUID_FHGF=$(uuidgen)
UUID_VLESS_TENDO=$(uuidgen)

# CONFIG JSON: Modified Structure with WARP/Routing
cat > $CONFIG_FILE <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "inbound-443",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_SYS",
            "flow": "xtls-rprx-vision",
            "level": 0,
            "email": "system"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001, "xver": 1 },
          { "path": "/vless", "dest": 10002, "xver": 1 },
          { "path": "/trojan", "dest": 10003, "xver": 1 }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" }
          ]
        }
      }
    },
    {
      "tag": "inbound-80",
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001, "xver": 1 },
          { "path": "/vless", "dest": 10002, "xver": 1 },
          { "path": "/trojan", "dest": 10003, "xver": 1 }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "tag": "vmess_ws",
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          { "id": "$UUID_TENDO", "email": "tendo" },
          { "id": "$UUID_TYGG", "email": "tygg" },
          { "id": "$UUID_FHGF", "email": "fhgf" }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "acceptProxyProtocol": true, "path": "/vmess" }
      }
    },
    {
      "tag": "vless_ws",
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID_VLESS_TENDO", "email": "tendo" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "acceptProxyProtocol": true, "path": "/vless" }
      }
    },
    {
      "tag": "trojan_ws",
      "port": 10003,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          { "password": "fhtggf", "email": "fhtggf" }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "acceptProxyProtocol": true, "path": "/trojan" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    {
      "tag": "WARP",
      "protocol": "socks",
      "settings": {
        "servers": [ { "address": "127.0.0.1", "port": 40000 } ]
      }
    },
    {
      "protocol": "freedom",
      "settings": { "domainStrategy": "ForceIPv4" },
      "proxySettings": { "tag": "WARP" },
      "tag": "routing"
    },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "inboundTag": [ "api" ], "outboundTag": "api", "type": "field" },
      { "type": "field", "port": "443", "network": "udp", "outboundTag": "block" },
      {
        "domain": [ "geosite:rule-playstore", "geosite:youtube", "geosite:twitter" ],
        "outboundTag": "routing",
        "network": "tcp,udp",
        "type": "field"
      },
      { "type": "field", "outboundTag": "blocked", "protocol": [ "bittorrent" ] }
    ]
  }
}
EOF

# --- 7. ZIVPN CONFIGURATION ---
echo -e "\e[1;32m[ZIVPN] Installing ZIVPN Server...\e[0m"
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
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable zivpn && systemctl restart zivpn xray

# IPtables AutoFT Logic
iptables -t nat -D PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save &>/dev/null

# --- 8. MAIN MENU SCRIPT ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"

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
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"; SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"; SW=$(pgrep -f wireproxy > /dev/null && echo "active"); [[ $SW == "active" ]] && W_ST="${GREEN}ON${NC}" || W_ST="${RED}OFF${NC}"
    echo -e "│ XRAY : $X_ST | ZIVPN : $Z_ST | WARP : $W_ST\n│ —————————————————————————————————————"
    C_VMESS=$(wc -l < $D_VMESS); C_VLESS=$(wc -l < $D_VLESS); C_TROJAN=$(wc -l < $D_TROJAN); C_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json)
    echo -e "│              LIST ACCOUNTS\n│ —————————————————————————————————————\n│    VMESS WS      : $C_VMESS  ACCOUNT\n│    VLESS WS      : $C_VLESS  ACCOUNT\n│    TROJAN WS     : $C_TROJAN  ACCOUNT\n│    ZIVPN UDP     : $C_ZIVPN  ACCOUNT"
    echo -e "│ —————————————————————————————————————\n│ Version   : v.3.1 WARP\n│ Script BY : Tendo Store\n│ WhatsApp  : +6282224460678\n│ Expiry In : Lifetime\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - SUB MENU${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

# --- MENU VMESS ---
function vmess_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│           VMESS WEBSOCKET MENU\n│ —————————————————————————————————————\n│ 1.) Create Account Vmess\n│ 2.) Delete Account Vmess\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); id=$(uuidgen)
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date" >> $D_VMESS
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           json_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
           json_none=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
           clear; echo -e "————————————————————————————————————\n            VMESS ACCOUNT\n————————————————————————————————————\nRemarks        : $u\nDomain         : $DMN\nUUID           : $id\nExpired        : $exp_date\n————————————————————————————————————\nLink TLS       : vmess://$json_tls\nLink None TLS  : vmess://$json_none\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); sed -i "${n}d" $D_VMESS
           jq --arg u "$u" 'del(.inbounds[2].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; cat $D_VMESS; read -p "Enter...";;
        x) return;;
    esac; done
}

# --- MENU VLESS ---
function vless_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│           VLESS WEBSOCKET MENU\n│ —————————————————————————————————————\n│ 1.) Create Account Vless\n│ 2.) Delete Account Vless\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); id=$(uuidgen)
           jq --arg u "$u" --arg id "$id" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date" >> $D_VLESS
           DMN=$(cat /usr/local/etc/xray/domain)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
           lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           clear; echo -e "————————————————————————————————————\n            VLESS ACCOUNT\n————————————————————————————————————\nRemarks        : $u\nDomain         : $DMN\nUUID           : $id\nExpired        : $exp_date\n————————————————————————————————————\nLink TLS       : $ltls\nLink None TLS  : $lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); sed -i "${n}d" $D_VLESS
           jq --arg u "$u" 'del(.inbounds[3].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; cat $D_VLESS; read -p "Enter...";;
        x) return;;
    esac; done
}

# --- MENU TROJAN ---
function trojan_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│           TROJAN WEBSOCKET MENU\n│ —————————————————————————————————————\n│ 1.) Create Account Trojan\n│ 2.) Delete Account Trojan\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); pass="$u"
           jq --arg p "$pass" --arg u "$u" '.inbounds[4].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$pass|$exp_date" >> $D_TROJAN
           DMN=$(cat /usr/local/etc/xray/domain)
           trlink="trojan://${pass}@${DMN}:443?security=tls&type=ws&host=${DMN}&path=/trojan&sni=${DMN}#${u}"
           clear; echo -e "————————————————————————————————————\n            TROJAN ACCOUNT\n————————————————————————————————————\nRemarks        : $u\nDomain         : $DMN\nPassword       : $pass\nExpired        : $exp_date\n————————————————————————————————————\nLink TLS       : $trlink\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); sed -i "${n}d" $D_TROJAN
           jq --arg u "$u" 'del(.inbounds[4].settings.clients[] | select(.email == $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; cat $D_TROJAN; read -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│           ZIVPN UDP MENU\n│ —————————————————————————————————————\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Password: " p; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; DMN=$(cat /usr/local/etc/xray/domain)
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nDomain     : $DMN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        2) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
        3) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function routing_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            SUPPORTED GEOSITE LIST               \n│ —————————————————————————————————————\n│ rule-gaming, rule-indo, rule-sosmed, google,    \n│ rule-playstore, rule-streaming, rule-umum, tiktok,\n│ rule-ipcheck, rule-doh, rule-malicious, telegram,\n│ rule-ads, rule-speedtest, ecommerce-id, urltest,\n│ category-porn, bank-id, meta, videoconference,  \n│ geolocation-!cn, facebook, spotify, openai, meta,\n│ ehentai, github, microsoft, apple, netflix, cn, \n│ youtube, twitter, bilibili, category-ads-all,   \n│ private, category-media, category-vpnservices,  \n│ category-dev, category-dev-all, meta, category-media-all\n└─────────────────────────────────────────────────┘"; DOMS=$(cat /usr/local/etc/xray/rule_list.txt | xargs)
        echo -e "┌─────────────────────────────────────────────────┐\n│ Active Rules: ${GREEN}$DOMS${NC}\n│ NOTE: Rules are directed to WARP (Routing)\n│ 1.) Tambah rule geosite\n│ 2.) Hapus rule geosite\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
        case $opt in
            1) read -p "Rule: " d; echo "$d" >> /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "routing" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            2) nl /usr/local/etc/xray/rule_list.txt; read -p "No: " n; [[ -z "$n" ]] && continue; sed -i "${n}d" /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "routing" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            x) return;;
        esac; done
}

function check_services() {
    header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ SERVICES STATUS\n│ —————————————————————————————————————"; services=("xray" "zivpn" "vnstat" "netfilter-persistent"); names=("Xray Core       " "ZIVPN UDP Server" "Vnstat Monitor  " "Iptables Rules  ")
    for i in "${!services[@]}"; do if systemctl is-active --quiet "${services[$i]}"; then status="${GREEN}ACTIVE (ON)${NC}"; else status="${RED}INACTIVE (OFF)${NC}"; fi; echo -e "│ ${names[$i]} : $status"; done
    # Check WARP WireProxy manually
    if pgrep -f wireproxy >/dev/null; then w_status="${GREEN}ACTIVE (ON)${NC}"; else w_status="${RED}INACTIVE (OFF)${NC}"; fi
    echo -e "│ WARP WireProxy  : $w_status"
    echo -e "└─────────────────────────────────────────────────┘"; read -p "Enter...";
}

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) VMESS ACCOUNT      5.) SPEED TEST\n│ 2.) VLESS ACCOUNT      6.) RESTART SERVICES\n│ 3.) TROJAN ACCOUNT     7.) CHECK SERVICES\n│ 4.) ZIVPN UDP          8.) ROUTING GEOSITE\n│ x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p "Pilih Nomor: " opt
    case $opt in
        1) vmess_menu ;; 
        2) vless_menu ;; 
        3) trojan_menu ;;
        4) zivpn_menu ;; 
        5) header_sub; python3 <(curl -sL https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) --share; read -p "Enter...";;
        6) systemctl restart xray zivpn; echo "Restarted!"; sleep 1 ;;
        7) check_services ;;
        8) routing_menu ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo -e "\e[1;32mINSTALASI SUKSES! Config WARP & DNS Applied. Ketik: menu\e[0m"
