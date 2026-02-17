#!/bin/bash
# ==================================================
#   Auto Script Install X-ray (Vless, Vmess, Trojan) & Zivpn
#   EDITION: PLATINUM LTS FINAL V.102 (Multi-Port)
#   Update: Added VMess & Trojan on Port 443/80
#   Script BY: Tendo Store | WhatsApp: +6282224460678
#   Features: BBR, Random UUID, Triple Status, Clean UI
#   Expiry: Lifetime Support
# ==================================================

# --- 1. SYSTEM OPTIMIZATION (BBR & SWAP 2GB) ---
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
CONFIG_FILE="/usr/local/etc/xray/config.json"
RULE_LIST="/usr/local/etc/xray/rule_list.txt"
VLESS_DATA="/usr/local/etc/xray/vless_data.txt"
VMESS_DATA="/usr/local/etc/xray/vmess_data.txt"
TROJAN_DATA="/usr/local/etc/xray/trojan_data.txt"

clear
echo "============================================="
echo "      Auto Script Install X-ray & Zivpn"
echo "      With VLESS, VMESS, TROJAN (MultiPort)"
echo "============================================="

# --- 3. INSTALL DEPENDENCIES & VISUALS ---
apt update -y
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch

# Silent Login Configuration
touch /root/.hushlogin
chmod -x /etc/update-motd.d/* 2>/dev/null
sed -i '/neofetch/d' /root/.bashrc
echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat && systemctl restart vnstat
vnstat -u -i $IFACE_NET >/dev/null 2>&1

# --- 4. DOMAIN & SSL SETUP ---
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $VLESS_DATA $VMESS_DATA $TROJAN_DATA
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
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 5. XRAY CORE CONFIGURATION (MULTI PORT) ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
rm -f /usr/local/share/xray/geosite.dat
# Updated Geosite URL
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

# Config JSON with Fallbacks for Multi-Protocol on Port 443 & 80
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-tls",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001, "xver": 1 },
          { "path": "/trojan", "dest": 10002, "xver": 1 }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ]
        },
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "tag": "vless-nontls",
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10003, "xver": 1 },
          { "path": "/trojan", "dest": 10004, "xver": 1 }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "tag": "vmess-tls",
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "trojan-tls",
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    },
    {
      "tag": "vmess-nontls",
      "port": 10003,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "trojan-nontls",
      "port": 10004,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    {
      "mux": { "concurrency": 8, "enabled": false },
      "protocol": "vless",
      "settings": { "vnext": [ { "address": "vip1-tendo.my.id", "port": 443, "users": [ { "encryption": "none", "id": "714a2529-7ad3-4f3b-9be0-38cf3bdabded", "level": 8, "security": "auto" } ] } ] },
      "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "allowInsecure": true, "serverName": "vip1-tendo.my.id" }, "wsSettings": { "headers": { "Host": "vip1-tendo.my.id" }, "path": "/vless" } },
      "tag": "port443"
    },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" }, { "type": "field", "domain": ["geosite:google"], "outboundTag": "port443" } ] }
}
EOF

# --- 6. ZIVPN CONFIGURATION ---
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

# --- 7. MAIN MENU SCRIPT (PLATINUM UI) ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
VLESS_DATA="/usr/local/etc/xray/vless_data.txt"
VMESS_DATA="/usr/local/etc/xray/vmess_data.txt"
TROJAN_DATA="/usr/local/etc/xray/trojan_data.txt"

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
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"; SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"; SI=$(systemctl is-active netfilter-persistent); [[ $SI == "active" ]] && I_ST="${GREEN}ON${NC}" || I_ST="${RED}OFF${NC}"
    echo -e "│ XRAY : $X_ST | ZIVPN : $Z_ST | IPTABLES : $I_ST\n│ —————————————————————————————————————"
    C_VLESS=$(jq '.inbounds[0].settings.clients | length' $CONFIG)
    C_VMESS=$(jq '.inbounds[2].settings.clients | length' $CONFIG)
    C_TROJAN=$(jq '.inbounds[3].settings.clients | length' $CONFIG)
    C_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json)
    echo -e "│              LIST ACCOUNTS\n│ —————————————————————————————————————\n│    VLESS         : $C_VLESS  ACCOUNT\n│    VMESS         : $C_VMESS  ACCOUNT\n│    TROJAN        : $C_TROJAN  ACCOUNT\n│    ZIVPN UDP     : $C_ZIVPN  ACCOUNT"
    echo -e "│ —————————————————————————————————————\n│ Version   : v.16.02.26 LTS MultiPort\n│ Script BY : Tendo Store\n│ WhatsApp  : +6282224460678\n│ Expiry In : Lifetime\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - SUB MENU${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

function vmess_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            VMESS MENU (Port 443/80)\n│ —————————————————————————————————————\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " UUID (Enter for random): " id; [[ -z "$id" ]] && id=$(uuidgen); read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           # Add to VMess TLS [2] and VMess Non-TLS [4]
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[4].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp_date" >> $VMESS_DATA
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           vmess_json_tls="{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"type\":\"none\",\"host\":\"${DMN}\",\"tls\":\"tls\"}"
           vmess_json_nontls="{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"type\":\"none\",\"host\":\"${DMN}\",\"tls\":\"none\"}"
           ltls="vmess://$(echo -n ${vmess_json_tls} | base64 -w 0)"
           lnon="vmess://$(echo -n ${vmess_json_nontls} | base64 -w 0)"
           clear; echo -e "————————————————————————————————————\n               VMESS\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443\nPort none TLS  : 80\nid             : $id\nAlterID        : 0\nNetwork        : ws\nPath ws        : /vmess\nExpired On     : $ex Days ($exp_date)\n————————————————————————————————————\n            VMESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VMESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); sed -i "/$u|/d" $VMESS_DATA
           jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[4].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        4) header_sub; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[2].settings.clients[$idx].id" $CONFIG); DMN=$(cat /usr/local/etc/xray/domain); exp_d=$(grep "^$u|" $VMESS_DATA | cut -d'|' -f3); [[ -z "$exp_d" ]] && exp_d="Unknown"; CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           vmess_json_tls="{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"type\":\"none\",\"host\":\"${DMN}\",\"tls\":\"tls\"}"
           vmess_json_nontls="{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"type\":\"none\",\"host\":\"${DMN}\",\"tls\":\"none\"}"
           ltls="vmess://$(echo -n ${vmess_json_tls} | base64 -w 0)"
           lnon="vmess://$(echo -n ${vmess_json_nontls} | base64 -w 0)"
           clear; echo -e "————————————————————————————————————\n               VMESS\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443\nPort none TLS  : 80\nid             : $id\nAlterID        : 0\nNetwork        : ws\nPath ws        : /vmess\nExpired On     : $exp_d\n————————————————————————————————————\n            VMESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VMESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function trojan_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            TROJAN MENU (Port 443/80)\n│ —————————————————————————————————————\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Password : " p; [[ -z "$p" ]] && p=$u; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           # Add to Trojan TLS [3] and Trojan Non-TLS [5]
           jq --arg p "$p" --arg u "$u" '.inbounds[3].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg p "$p" --arg u "$u" '.inbounds[5].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$p|$exp_date" >> $TROJAN_DATA
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="trojan://${p}@${DMN}:443?path=/trojan&security=tls&type=ws&sni=${DMN}#${u}"
           lnon="trojan://${p}@${DMN}:80?path=/trojan&security=none&type=ws#${u}"
           clear; echo -e "————————————————————————————————————\n               TROJAN\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443\nPort none TLS  : 80\nPassword       : $p\nNetwork        : ws\nPath ws        : /trojan\nExpired On     : $ex Days ($exp_date)\n————————————————————————————————————\n            TROJAN WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          TROJAN WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[3].settings.clients[$idx].email" $CONFIG); sed -i "/$u|/d" $TROJAN_DATA
           jq "del(.inbounds[3].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[5].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        4) header_sub; jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[3].settings.clients[$idx].email" $CONFIG); p=$(jq -r ".inbounds[3].settings.clients[$idx].password" $CONFIG); DMN=$(cat /usr/local/etc/xray/domain); exp_d=$(grep "^$u|" $TROJAN_DATA | cut -d'|' -f3); [[ -z "$exp_d" ]] && exp_d="Unknown"; CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="trojan://${p}@${DMN}:443?path=/trojan&security=tls&type=ws&sni=${DMN}#${u}"
           lnon="trojan://${p}@${DMN}:80?path=/trojan&security=none&type=ws#${u}"
           clear; echo -e "————————————————————————————————————\n               TROJAN\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443\nPort none TLS  : 80\nPassword       : $p\nNetwork        : ws\nPath ws        : /trojan\nExpired On     : $exp_d\n————————————————————————————————————\n            TROJAN WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          TROJAN WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Password: " p; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; DMN=$(cat /usr/local/etc/xray/domain)
           # Clean Full ZIVPN Details
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $(cat /root/tendo/city)\nISP        : $(cat /root/tendo/isp)\nIP ISP     : $(cat /root/tendo/ip)\nDomain     : $DMN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        2) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
        3) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter...";;
        4) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); DMN=$(cat /usr/local/etc/xray/domain)
           # Clean Full ZIVPN Check
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  CHECK ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $(cat /root/tendo/city)\nISP        : $(cat /root/tendo/isp)\nIP ISP     : $(cat /root/tendo/ip)\nDomain     : $DMN\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        x) return;;
    esac; done
}

function routing_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            SUPPORTED GEOSITE LIST               \n│ —————————————————————————————————————\n│ rule-gaming, rule-indo, rule-sosmed, google,    \n│ rule-playstore, rule-streaming, rule-umum, tiktok,\n│ rule-ipcheck, rule-doh, rule-malicious, telegram,\n│ rule-ads, rule-speedtest, ecommerce-id, urltest,\n│ category-porn, bank-id, meta, videoconference,  \n│ geolocation-!cn, facebook, spotify, openai, meta,\n│ ehentai, github, microsoft, apple, netflix, cn, \n│ youtube, twitter, bilibili, category-ads-all,   \n│ private, category-media, category-vpnservices,  \n│ category-dev, category-dev-all, meta, category-media-all\n└─────────────────────────────────────────────────┘"; DOMS=$(cat /usr/local/etc/xray/rule_list.txt | xargs)
        echo -e "┌─────────────────────────────────────────────────┐\n│ Active Rules: ${GREEN}$DOMS${NC}\n│ 1.) Tambah rule geosite\n│ 2.) Hapus rule geosite\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
        case $opt in
            1) read -p "Rule: " d; echo "$d" >> /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "port443" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            2) nl /usr/local/etc/xray/rule_list.txt; read -p "No: " n; [[ -z "$n" ]] && continue; sed -i "${n}d" /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "port443" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            x) return;;
        esac; done
}

function check_services() {
    header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ SERVICES STATUS\n│ —————————————————————————————————————"; services=("xray" "zivpn" "vnstat" "netfilter-persistent"); names=("Xray VPN Core   " "ZIVPN UDP Server" "Vnstat Monitor  " "Iptables Rules  ")
    for i in "${!services[@]}"; do if systemctl is-active --quiet "${services[$i]}"; then status="${GREEN}ACTIVE (ON)${NC}"; else status="${RED}INACTIVE (OFF)${NC}"; fi; echo -e "│ ${names[$i]} : $status"; done
    echo -e "└─────────────────────────────────────────────────┘"; read -p "Enter...";
}

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) VLESS ACCOUNT      5.) ROUTING GEOSITE\n│ 2.) VMESS ACCOUNT      6.) GANTI DOMAIN\n│ 3.) TROJAN ACCOUNT     7.) SPEED TEST\n│ 4.) ZIVPN UDP          8.) RESTART / CHECK\n│ x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p "Pilih Nomor: " opt
    case $opt in
        1) vless_menu ;; 2) vmess_menu ;; 3) trojan_menu ;; 4) zivpn_menu ;; 5) routing_menu ;;
        6) read -p "Domain Baru: " nd; echo "$nd" > /usr/local/etc/xray/domain; openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1; systemctl restart xray; echo "Domain Updated!"; sleep 1;;
        7) header_sub; python3 <(curl -sL https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) --share; read -p "Enter...";;
        8) check_services ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo "INSTALASI BERHASIL! KETIK: menu"
