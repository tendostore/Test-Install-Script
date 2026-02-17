#!/bin/bash
# ==================================================
#    Auto Script Install X-ray & Zivpn
#    EDITION: PLATINUM LTS FINAL V.102
#    Protokol: VLESS, VMESS, TROJAN, ZIVPN
#    Script BY: Tendo Store | Fixed by AI
# ==================================================

# --- 1. PRE-INSTALL & OPTIMIZATION ---
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

# Swap 2GB
swapoff -a 2>/dev/null
rm -f /swapfile
dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
chmod 600 /swapfile
mkswap /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '/swapfile/d' /etc/fstab
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# --- 2. INSTALL DEPENDENCIES (FIXED) ---
apt update -y
# Menghapus 'base64' dari list apt untuk menghindari error
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch coreutils

# --- 3. SETUP VARIABLES ---
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"
DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"

XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
RULE_LIST="/usr/local/etc/xray/rule_list.txt"
USER_DATA="/usr/local/etc/xray/user_data.txt"

mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $USER_DATA
IP_VPS=$(curl -s ifconfig.me)

# Get Geo Info
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

# SSL & Domain Setup
echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1

# --- 4. XRAY CORE & CONFIG (VLESS, VMESS, TROJAN) ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 443, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } } },
    { "port": 80, "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } } },
    { "port": 8443, "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vmess" } } },
    { "port": 8080, "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } } },
    { "port": 2096, "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/trojan" } } },
    { "port": 2052, "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" } ] }
}
EOF

# --- 5. ZIVPN CONFIG ---
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

systemctl daemon-reload
systemctl enable xray zivpn vnstat
systemctl restart xray zivpn vnstat

# --- 6. MENU SCRIPT (FULL VERSION) ---
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
    echo -e "┌─────────────────────────────────────────────────┐\n          ${BG_RED}          TENDO STORE          ${NC} \n└─────────────────────────────────────────────────┘"
    echo -e "│ IP      : $IP\n│ DOMAIN  : $DOMAIN\n│ UPTIME  : $UPTIME\n│ —————————————————————————————————————"
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"; SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"
    echo -e "│ XRAY : $X_ST | ZIVPN : $Z_ST\n│ —————————————————————————————————————"
    C1=$(jq '.inbounds[0].settings.clients | length' $CONFIG)
    C2=$(jq '.inbounds[2].settings.clients | length' $CONFIG)
    C3=$(jq '.inbounds[4].settings.clients | length' $CONFIG)
    echo -e "│ VLESS: $C1 | VMESS: $C2 | TROJAN: $C3\n└─────────────────────────────────────────────────┘"
}

function vless_menu() {
    while true; do clear; echo -e "VLESS MENU\n1. Create\n2. Delete\nx. Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p "User: " u; id=$(uuidgen); read -p "Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[0].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[1].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp" >> $U_DATA
           echo -e "VLESS TLS: vless://${id}@$(cat /usr/local/etc/xray/domain):443?path=/vless&security=tls&encryption=none&type=ws#${u}"; read -p "Enter..." ;;
        2) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG)
           jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[1].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/$u|/d" $U_DATA ;;
        x) return ;;
    esac; done
}

function vmess_menu() {
    while true; do clear; echo -e "VMESS MENU\n1. Create\n2. Delete\nx. Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p "User: " u; id=$(uuidgen); read -p "Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp" >> $U_DATA
           vm_tls="{\"v\":\"2\",\"ps\":\"$u\",\"add\":\"$(cat /usr/local/etc/xray/domain)\",\"port\":\"8443\",\"id\":\"$id\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}"
           echo -e "VMESS TLS: vmess://$(echo -n $vm_tls | base64 -w 0)"; read -p "Enter..." ;;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG)
           jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[3].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/$u|/d" $U_DATA ;;
        x) return ;;
    esac; done
}

function trojan_menu() {
    while true; do clear; echo -e "TROJAN MENU\n1. Create\n2. Delete\nx. Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p "User: " u; read -p "Pass: " id; read -p "Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[4].settings.clients += [{"password":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[5].settings.clients += [{"password":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp" >> $U_DATA
           echo -e "TROJAN TLS: trojan://${id}@$(cat /usr/local/etc/xray/domain):2096?path=/trojan&security=tls&type=ws#${u}"; read -p "Enter..." ;;
        2) jq -r '.inbounds[4].settings.clients[].email' $CONFIG | nl; read -p "No: " n; idx=$((n-1)); u=$(jq -r ".inbounds[4].settings.clients[$idx].email" $CONFIG)
           jq "del(.inbounds[4].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[5].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/$u|/d" $U_DATA ;;
        x) return ;;
    esac; done
}

while true; do header_main; echo -e "1. VLESS\n2. VMESS\n3. TROJAN\n4. ZIVPN\n5. RESTART\nx. EXIT"; read -p "Pilih: " opt
    case $opt in
        1) vless_menu ;; 2) vmess_menu ;; 3) trojan_menu ;; 
        4) clear; echo "ZIVPN UDP"; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter..." ;;
        5) systemctl restart xray zivpn; echo "Done!"; sleep 1 ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo "INSTALASI BERHASIL! KETIK: menu"
