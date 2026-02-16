#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM LTS FINAL V.101
#   Update: Added VMess & Trojan (Multi-Port 443/80)
#   Script BY: Tendo Store | WhatsApp: +6282224460678
#   Features: BBR, Random UUID, Triple Status, Clean UI
# ==================================================

# --- 1. SYSTEM OPTIMIZATION (BBR & SWAP 2GB) ---
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

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

# --- 5. XRAY CORE CONFIGURATION (MULTI PROTOCOL) ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
rm -f /usr/local/share/xray/geosite.dat
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 443, "protocol": "vless", "tag": "vless-tls", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } } },
    { "port": 80, "protocol": "vless", "tag": "vless-ntls", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } } },
    { "port": 443, "protocol": "vmess", "tag": "vmess-tls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vmess" } } },
    { "port": 80, "protocol": "vmess", "tag": "vmess-ntls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } } },
    { "port": 443, "protocol": "trojan", "tag": "trojan-tls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/trojan" } } },
    { "port": 80, "protocol": "trojan", "tag": "trojan-ntls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } } }
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

# IPtables
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save &>/dev/null

# --- 7. MAIN MENU SCRIPT (PLATINUM UI) ---
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
    C_VM=$(jq '.inbounds[2].settings.clients | length' $CONFIG); C_VL=$(jq '.inbounds[0].settings.clients | length' $CONFIG); C_TR=$(jq '.inbounds[4].settings.clients | length' $CONFIG); C_ZI=$(jq '.auth.config | length' /etc/zivpn/config.json)
    echo -e "│ VMESS: $C_VM | VLESS: $C_VL | TROJAN: $C_TR | UDP: $C_ZI\n│ —————————————————————————————————————\n│ Version   : v.16.02.26 LTS\n│ Script BY : Tendo Store\n│ WhatsApp  : +6282224460678\n│ Expiry In : Lifetime\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - SUB MENU${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

function xray_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) VMess Account\n│ 2.) VLESS Account\n│ 3.) Trojan Account\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) vmess_manager ;; 2) vless_manager ;; 3) trojan_manager ;; x) return ;;
    esac; done
}

function vmess_manager() {
    while true; do header_sub; echo -e "│        [ VMESS ACCOUNT MANAGER ]\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; id=$(uuidgen); read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|vmess|$id|$exp_date" >> $U_DATA; DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           raw='{"v":"2","ps":"'$u'","add":"'$DMN'","port":"443","id":"'$id'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DMN'","path":"/vmess","tls":"tls"}'
           tls="vmess://$(echo -n $raw | base64 -w0)"
           clear; echo -e "————————————————————————————————————\n               VMESS\n————————————————————————————————————\nRemarks   : $u\nDomain    : $DMN\nPort TLS  : 443\nPort NTLS : 80\nUUID      : $id\nPath      : /vmess\nExpired   : $exp_date\n————————————————————————————————————\nVMESS WS TLS:\n$tls\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); sed -i "/$u|vmess/d" $U_DATA; jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && jq "del(.inbounds[3].settings.clients[$idx])" /tmp/x > $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function vless_manager() {
    while true; do header_sub; echo -e "│        [ VLESS ACCOUNT MANAGER ]\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; id=$(uuidgen); read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[0].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[1].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|vless|$id|$exp_date" >> $U_DATA; DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
           clear; echo -e "————————————————————————————————————\n               VLESS\n————————————————————————————————————\nRemarks   : $u\nDomain    : $DMN\nPort TLS  : 443\nPort NTLS : 80\nUUID      : $id\nPath      : /vless\nExpired   : $exp_date\n————————————————————————————————————\nVLESS WS TLS:\n$ltls\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); sed -i "/$u|vless/d" $U_DATA; jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && jq "del(.inbounds[1].settings.clients[$idx])" /tmp/x > $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function trojan_manager() {
    while true; do header_sub; echo -e "│        [ TROJAN ACCOUNT MANAGER ]\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" '.inbounds[4].settings.clients += [{"password":$u,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" '.inbounds[5].settings.clients += [{"password":$u,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|trojan|$u|$exp_date" >> $U_DATA; DMN=$(cat /usr/local/etc/xray/domain)
           link="trojan://${u}@${DMN}:443?path=/trojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
           clear; echo -e "————————————————————————————————————\n               TROJAN\n————————————————————————————————————\nRemarks   : $u\nDomain    : $DMN\nPort TLS  : 443\nPort NTLS : 80\nPassword  : $u\nPath      : /trojan\nExpired   : $exp_date\n————————————————————————————————————\nTROJAN WS TLS:\n$link\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[4].settings.clients[].email' $CONFIG | nl; read -p "No: " n; idx=$((n-1)); u=$(jq -r ".inbounds[4].settings.clients[$idx].email" $CONFIG); sed -i "/$u|trojan/d" $U_DATA; jq "del(.inbounds[4].settings.clients[$idx])" $CONFIG > /tmp/x && jq "del(.inbounds[5].settings.clients[$idx])" /tmp/x > $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[4].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Password: " p; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; DMN=$(cat /usr/local/etc/xray/domain)
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nDomain     : $DMN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        2) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; idx=$((n-1)); jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
        3) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function routing_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            SUPPORTED GEOSITE LIST               \n│ —————————————————————————————————————\n│ rule-gaming, rule-sosmed, google, youtube, netflix\n└─────────────────────────────────────────────────┘"; DOMS=$(cat /usr/local/etc/xray/rule_list.txt | xargs)
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

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) X-RAY MENU (VM/VL/TR) 5.) SPEED TEST\n│ 2.) ZIVPN UDP             6.) RESTART SERVICES\n│ 3.) ROUTING GEOSITE       7.) CHECK SERVICES\n│ 4.) GANTI DOMAIN          x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p "Pilih Nomor: " opt
    case $opt in
        1) xray_menu ;; 2) zivpn_menu ;; 3) routing_menu ;;
        4) read -p "Domain Baru: " nd; echo "$nd" > /usr/local/etc/xray/domain; openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1; systemctl restart xray; echo "Domain Updated!"; sleep 1;;
        5) header_sub; python3 <(curl -sL https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) --share; read -p "Enter...";;
        6) systemctl restart xray zivpn; echo "Restarted!"; sleep 1 ;;
        7) check_services ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo "INSTALASI BERHASIL! KETIK: menu"
