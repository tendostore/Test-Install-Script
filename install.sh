#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM LTS FINAL V.101
#   Update: Custom UUID/Password + Multi-Port + Ookla
#   Script BY: Tendo Store | WhatsApp: +6282224460678
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
USER_DATA="/usr/local/etc/xray/user_data.txt"

clear
echo "============================================="
echo "      Auto Script Install X-ray & Zivpn"
echo "           FINAL PLATINUM EDITION"
echo "============================================="

# --- 3. INSTALL DEPENDENCIES & OOKLA SPEEDTEST ---
apt update -y
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget bc python3 neofetch
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
apt install -y speedtest

mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $USER_DATA

# --- 4. FETCH SYSTEM INFO ---
IP_VPS=$(curl -s ifconfig.me)
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# --- 5. DOMAIN & SSL ---
echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1

# --- 6. XRAY CORE CONFIGURATION (MULTI PROTOCOL/PORT) ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 443, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } } },
    { "port": 80, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } } },
    { "port": 443, "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vmess" } } },
    { "port": 80, "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } } },
    { "port": 443, "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/trojan" } } },
    { "port": 80, "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } } }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF

# --- 7. START SERVICES ---
systemctl restart xray && systemctl enable xray

# --- 8. BUILD THE FINAL MENU SYSTEM ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"

function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); RAM=$(free -m | awk '/Mem:/ {print $3}'); UPTIME=$(uptime -p | sed 's/up //')
    CITY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    TRAFFIC=$(vnstat -i $IFACE --oneline | awk -F';' '{print $11}')
    echo -e "┌─────────────────────────────────────────────────┐\n          ${BG_RED}          TENDO STORE          ${NC} \n└─────────────────────────────────────────────────┘"
    echo -e "│ OS      : $(cat /etc/os-release | grep -w PRETTY_NAME | cut -d'"' -f2)\n│ CITY    : $CITY | ISP : $ISP\n│ DOMAIN  : $DOMAIN | TRAFFIC : $TRAFFIC\n│ UPTIME  : $UPTIME\n└─────────────────────────────────────────────────┘"
}

function display_style() {
    local proto=$1; local u=$2; local id=$3; local exp=$4
    local DMN=$(cat /usr/local/etc/xray/domain); local CTY=$(cat /root/tendo/city); local ISP=$(cat /root/tendo/isp)
    echo -e "————————————————————————————————————————"
    echo -e "             TENDO STORE"
    echo -e " ————————————————————————————————————————"
    echo -e "                XRAY ${proto^^}"
    echo -e " ————————————————————————————————————————"
    echo -e " Remarks       : $u"
    echo -e " CITY          : $CTY"
    echo -e " ISP           : $ISP"
    echo -e " Domain        : $DMN"
    echo -e " Port TLS      : 443,8443"
    echo -e " Port none TLS : 80,8080"
    echo -e " Port any      : 2052,2053,8880"
    echo -e " id            : $id"
    [[ "$proto" == "vmess" ]] && echo -e " alterId       : 0"
    echo -e " Security      : auto"
    echo -e " network       : ws,grpc,upgrade"
    echo -e " path ws       : /${proto} - /whatever"
    echo -e " ————————————————————————————————————————"
    if [[ "$proto" == "vmess" ]]; then
        local tls='{"v":"2","ps":"'$u'","add":"'$DMN'","port":"443","id":"'$id'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DMN'","path":"/vmess","tls":"tls"}'
        local ntls='{"v":"2","ps":"'$u'","add":"'$DMN'","port":"80","id":"'$id'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DMN'","path":"/vmess","tls":"none"}'
        echo -e " link TLS          : vmess://$(echo -n $tls | base64 -w0)"
        echo -e " ————————————————————————————————————————"
        echo -e " link none TLS     : vmess://$(echo -n $ntls | base64 -w0)"
    elif [[ "$proto" == "vless" ]]; then
        echo -e " link TLS          : vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&type=ws&sni=${DMN}#${u}"
        echo -e " ————————————————————————————————————————"
        echo -e " link none TLS     : vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&type=ws&host=${DMN}#${u}"
    else
        echo -e " link TLS          : trojan://${id}@${DMN}:443?path=/trojan&security=tls&type=ws&sni=${DMN}#${u}"
        echo -e " ————————————————————————————————————————"
        echo -e " link none TLS     : trojan://${id}@${DMN}:80?path=/trojan&security=none&type=ws&host=${DMN}#${u}"
    fi
    echo -e " ————————————————————————————————————————\n         Expired  :  $exp\n ————————————————————————————————————————"
}

function xray_menu() {
    while true; do clear; echo -e "┌────────────────────────────────────────┐\n│           X-RAY MASTER MENU            │\n├────────────────────────────────────────┤\n│ 1.) VMess Account Manager              │\n│ 2.) VLESS Account Manager              │\n│ 3.) Trojan Account Manager             │\n│ x.) Back                               │\n└────────────────────────────────────────┘"
    read -p " Pilih: " opt
    case $opt in
        1) proto_manager "vmess" 2 3 ;;
        2) proto_manager "vless" 0 1 ;;
        3) proto_manager "trojan" 4 5 ;;
        x) return ;;
    esac; done
}

function proto_manager() {
    local p=$1; local in_tls=$2; local in_ntls=$3
    while true; do clear; echo -e "${p^^} MANAGER\n1. Create | 2. Delete | 3. Check Details | x. Back"
    read -p " Pilih: " opt
    case $opt in
        1) 
           read -p " Username : " u
           if [[ "$p" == "trojan" ]]; then
               read -p " Password (Enter for same as user): " id
               [[ -z "$id" ]] && id=$u
           else
               read -p " UUID (Enter for random): " id
               [[ -z "$id" ]] && id=$(uuidgen)
           fi
           read -p " Exp (days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           
           jq --arg u "$u" --arg id "$id" ".inbounds[$in_tls].settings.clients += [{\"id\":\"$id\",\"password\":\"$id\",\"email\":\"$u\"}]" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" ".inbounds[$in_ntls].settings.clients += [{\"id\":\"$id\",\"password\":\"$id\",\"email\":\"$u\"}]" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$p|$id|$exp" >> $U_DATA; display_style "$p" "$u" "$id" "$exp"; read -p "Enter..." ;;
        2) jq -r ".inbounds[$in_tls].settings.clients[].email" $CONFIG | nl; read -p "No: " n; idx=$((n-1))
           u=$(jq -r ".inbounds[$in_tls].settings.clients[$idx].email" $CONFIG); sed -i "/$u|$p|/d" $U_DATA
           jq "del(.inbounds[$in_tls].settings.clients[$idx])" $CONFIG > /tmp/x && jq "del(.inbounds[$in_ntls].settings.clients[$idx])" /tmp/x > $CONFIG
           systemctl restart xray; echo "Deleted!"; sleep 1 ;;
        3) jq -r ".inbounds[$in_tls].settings.clients[].email" $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1))
           u=$(jq -r ".inbounds[$in_tls].settings.clients[$idx].email" $CONFIG)
           id=$(jq -r ".inbounds[$in_tls].settings.clients[$idx].id // .inbounds[$in_tls].settings.clients[$idx].password" $CONFIG)
           exp=$(grep "$u|$p|" $U_DATA | cut -d'|' -f4); display_style "$p" "$u" "$id" "$exp"; read -p "Enter..." ;;
        x) return ;;
    esac; done
}

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) X-RAY MENU            5.) SPEED TEST\n│ 2.) ZIVPN UDP             6.) RESTART SERVICES\n│ 3.) ROUTING GEOSITE       7.) CHECK SERVICES\n│ 4.) GANTI DOMAIN          x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p " Nomor: " opt
case $opt in
    1) xray_menu ;; 4) read -p "Domain: " nd; echo "$nd" > /usr/local/etc/xray/domain; systemctl restart xray ;;
    5) clear; speedtest --accept-license --accept-gdpr; read -p "Enter..." ;;
    6) systemctl restart xray; echo "Restarted!"; sleep 1 ;;
    x) exit ;;
esac; done
END_MENU

chmod +x /usr/bin/menu
echo "INSTALASI FINAL SELESAI! KETIK: menu"
