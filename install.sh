#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM LTS FINAL V.101
#   Update: Fixed Geosite.dat URL
#   Script BY: Tendo Store | WhatsApp: +6282224460678
#   Features: BBR, Random UUID, Triple Status, Clean UI
#   Expiry: Lifetime Support
# ==================================================

# --- 1. SYSTEM OPTIMIZATION (BBR & SWAP 2GB) ---
timedatectl set-timezone Asia/Jakarta
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
USER_DATA="/usr/local/etc/xray/user_data.txt"

clear
echo "============================================="
echo "      Auto Script Install X-ray & Zivpn"
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
touch $USER_DATA
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

# --- 5. XRAY CORE CONFIGURATION ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
rm -f /usr/local/share/xray/geosite.dat
# Updated Geosite URL
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 443, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } } },
    { "port": 80, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    {
      "mux": { "concurrency": 8, "enabled": false },
      "protocol": "vless",
      "settings": { "vnext": [ { "address": "vip1-tendo.my.id", "port": 443, "users": [ { "encryption": "none", "id": "714a2529-7ad3-4f3b-9be0-38cf3bdabded", "level": 8, "security": "auto" } ] } ] },
      "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "allowInsecure": true, "serverName": "vip1-tendo.my.id" }, "wsSettings": { "headers": { "Host": "vip1-tendo.my.id" }, "path": "/vless" } },
      "tag": "port443"
    }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" }, { "type": "field", "domain": ["geosite:google"], "outboundTag": "port443" } ] }
}
EOF

# --- 6. ZIVPN CONFIGURATION ---
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
touch /etc/zivpn/user_data.txt
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

# --- 7. AUTO DELETE EXPIRED ACCOUNTS SETUP ---
cat > /usr/local/bin/auto-kill.sh <<'EOF'
#!/bin/bash
NOW=$(date +"%s")

# Xray Auto Delete
if [ -f /usr/local/etc/xray/user_data.txt ]; then
    rm -f /tmp/xray_restart_flag
    cat /usr/local/etc/xray/user_data.txt | while IFS="|" read -r user uuid exp; do
        exp_epoch=$(date -d "$exp" +"%s" 2>/dev/null)
        if [[ -n "$exp_epoch" ]] && [[ "$NOW" -ge "$exp_epoch" ]]; then
            idx=$(jq --arg u "$user" '.inbounds[0].settings.clients | map(.email == $u) | index(true)' /usr/local/etc/xray/config.json)
            if [[ "$idx" != "null" ]] && [[ -n "$idx" ]]; then
                jq "del(.inbounds[0].settings.clients[$idx])" /usr/local/etc/xray/config.json > /tmp/x && mv /tmp/x /usr/local/etc/xray/config.json
            fi
            sed -i "/^$user|/d" /usr/local/etc/xray/user_data.txt
            touch /tmp/xray_restart_flag
        fi
    done
    if [ -f /tmp/xray_restart_flag ]; then
        systemctl restart xray
        rm -f /tmp/xray_restart_flag
    fi
fi

# Zivpn Auto Delete
if [ -f /etc/zivpn/user_data.txt ]; then
    rm -f /tmp/zivpn_restart_flag
    cat /etc/zivpn/user_data.txt | while IFS="|" read -r pass exp; do
        exp_epoch=$(date -d "$exp" +"%s" 2>/dev/null)
        if [[ -n "$exp_epoch" ]] && [[ "$NOW" -ge "$exp_epoch" ]]; then
            idx=$(jq --arg p "$pass" '.auth.config | map(. == $p) | index(true)' /etc/zivpn/config.json)
            if [[ "$idx" != "null" ]] && [[ -n "$idx" ]]; then
                jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
            fi
            sed -i "/^$pass|/d" /etc/zivpn/user_data.txt
            touch /tmp/zivpn_restart_flag
        fi
    done
    if [ -f /tmp/zivpn_restart_flag ]; then
        systemctl restart zivpn
        rm -f /tmp/zivpn_restart_flag
    fi
fi
EOF
chmod +x /usr/local/bin/auto-kill.sh
# Check every minute for trial precision
crontab -l 2>/dev/null | grep -v "/usr/local/bin/auto-kill.sh" | crontab -
(crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/auto-kill.sh") | crontab -

# --- 8. MAIN MENU SCRIPT (PLATINUM UI) ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"

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
    COUNT_VLESS=$(jq '.inbounds[0].settings.clients | length' $CONFIG); COUNT_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json)
    echo -e "│              LIST ACCOUNTS\n│ —————————————————————————————————————\n│    VLESS         : $COUNT_VLESS  ACCOUNT\n│    ZIVPN UDP     : $COUNT_ZIVPN  ACCOUNT"
    echo -e "│ —————————————————————————————————————\n│ Version   : v.16.02.26 LTS\n│ Script BY : Tendo Store\n│ WhatsApp  : +6282224460678\n│ Expiry In : Lifetime\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - SUB MENU${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

function xray_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Trial Account\n│ 3.) Delete Account\n│ 4.) List Accounts\n│ 5.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " UUID (Enter for random): " id; [[ -z "$id" ]] && id=$(uuidgen); read -p " Expired (Hari): " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date" >> $U_DATA
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           # Clean Detail with Centered Header
           clear; echo -e "————————————————————————————————————\n               VLESS\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443,8443\nPort none TLS  : 80,8080\nid             : $id\nEncryption     : none\nNetwork        : ws\nPath ws        : /vless\nExpired On     : $ex Hari ($exp_date)\n————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) read -p " Username (Trial): " u; u="trial-${u}"; id=$(uuidgen)
           read -p " Expired (Jam): " ex_h; [[ -z "$ex_h" ]] && ex_h=0
           read -p " Expired (Menit): " ex_m; [[ -z "$ex_m" ]] && ex_m=0
           exp_date=$(date -d "+$ex_h hours +$ex_m minutes" +"%Y-%m-%d %H:%M")
           jq --arg u "$u" --arg id "$id" '.inbounds[].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date" >> $U_DATA
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           # Clean Detail Trial
           clear; echo -e "————————————————————————————————————\n               VLESS TRIAL\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443,8443\nPort none TLS  : 80,8080\nid             : $id\nEncryption     : none\nNetwork        : ws\nPath ws        : /vless\nExpired On     : $ex_h Jam $ex_m Menit ($exp_date)\n————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        3) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); sed -i "/^$u|/d" $U_DATA; jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        4) header_sub; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        5) header_sub; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[0].settings.clients[$idx].id" $CONFIG); DMN=$(cat /usr/local/etc/xray/domain); exp_d=$(grep "^$u|" $U_DATA | cut -d'|' -f3); [[ -z "$exp_d" ]] && exp_d="Unknown"; CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           # Clean Check Detail with Centered Header
           clear; echo -e "————————————————————————————————————\n               VLESS\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443,8443\nPort none TLS  : 80,8080\nid             : $id\nEncryption     : none\nNetwork        : ws\nPath ws        : /vless\nExpired On     : $exp_d\n————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Trial Account\n│ 3.) Delete Account\n│ 4.) List Accounts\n│ 5.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Password: " p; read -p " Expired (Hari): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$exp" >> /etc/zivpn/user_data.txt; DMN=$(cat /usr/local/etc/xray/domain)
           # Clean Full ZIVPN Details
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $(cat /root/tendo/city)\nISP        : $(cat /root/tendo/isp)\nIP ISP     : $(cat /root/tendo/ip)\nDomain     : $DMN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        2) read -p " Password (Trial): " p; p="trial-${p}"
           read -p " Expired (Jam): " ex_h; [[ -z "$ex_h" ]] && ex_h=0
           read -p " Expired (Menit): " ex_m; [[ -z "$ex_m" ]] && ex_m=0
           exp=$(date -d "+$ex_h hours +$ex_m minutes" +"%Y-%m-%d %H:%M")
           jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$exp" >> /etc/zivpn/user_data.txt; DMN=$(cat /usr/local/etc/xray/domain)
           # Clean Trial ZIVPN Details
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ZIVPN UDP TRIAL\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $(cat /root/tendo/city)\nISP        : $(cat /root/tendo/isp)\nIP ISP     : $(cat /root/tendo/ip)\nDomain     : $DMN\nExpired On : $ex_h Jam $ex_m Menit ($exp)\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        3) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); sed -i "/^$p|/d" /etc/zivpn/user_data.txt; jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
        4) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter...";;
        5) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); DMN=$(cat /usr/local/etc/xray/domain); exp_d=$(grep "^$p|" /etc/zivpn/user_data.txt | cut -d'|' -f2); [[ -z "$exp_d" ]] && exp_d="Unknown"
           # Clean Full ZIVPN Check
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  CHECK ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $(cat /root/tendo/city)\nISP        : $(cat /root/tendo/isp)\nIP ISP     : $(cat /root/tendo/ip)\nDomain     : $DMN\nExpired On : $exp_d\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        x) return;;
    esac; done
}

function routing_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            SUPPORTED GEOSITE LIST               \n│ —————————————————————————————————————\n│ rule-gaming, rule-indo, rule-sosmed, google,    \n│ rule-pl
