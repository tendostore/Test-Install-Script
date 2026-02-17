#!/bin/bash
# ==================================================
#    Auto Script Install X-ray & Zivpn
#    EDITION: PLATINUM LTS FINAL V.104
#    Protocols: VLESS, VMESS, TROJAN, ZIVPN (UDP)
#    Script BY: Tendo Store | Fixed: Full Menu Logic
# ==================================================

# --- 1. OPTIMASI & CLEANUP ---
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

# --- 2. INSTALL DEPENDENCIES ---
apt update -y
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch coreutils

# --- 3. SETUP VARIABLES ---
DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
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
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 4. XRAY CORE & CONFIG ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1

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
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF

# --- 5. ZIVPN CONFIG ---
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
cat > /etc/zivpn/config.json <<EOF
{ "listen": ":5667", "cert": "$XRAY_DIR/xray.crt", "key": "$XRAY_DIR/xray.key", "obfs": "zivpn", "auth": { "mode": "passwords", "config": [] } }
EOF

systemctl daemon-reload
systemctl enable xray zivpn vnstat
systemctl restart xray zivpn vnstat

# --- 6. FULL MENU SCRIPT ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"
DMN=$(cat /usr/local/etc/xray/domain)

function header_sub() {
    clear
    echo -e "${YELLOW}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "          ${YELLOW}TENDO STORE - SUB MENU${NC}"
    echo -e "   Domain : $DMN"
    echo -e "${YELLOW}└─────────────────────────────────────────────────┘${NC}"
}

function vless_menu() {
    while true; do header_sub; echo -e "1.) Create VLESS\n2.) Delete VLESS\n3.) List VLESS\n4.) Account Details\nx.) Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p "Username: " u; id=$(uuidgen); read -p "Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[0].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[1].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "vless|$u|$id|$exp" >> $U_DATA
           echo -e "\nVLESS TLS: vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&type=ws#${u}"; read -p "Enter..." ;;
        2) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Hapus Nomor: " n; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG)
           jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[1].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/vless|$u|/d" $U_DATA ;;
        3) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter..." ;;
        4) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Nomor: " n; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[0].settings.clients[$idx].id" $CONFIG)
           echo -e "TLS: vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&type=ws#${u}\nNon-TLS: vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&type=ws#${u}"; read -p "Enter..." ;;
        x) return ;;
    esac; done
}

function vmess_menu() {
    while true; do header_sub; echo -e "1.) Create VMESS\n2.) Delete VMESS\n3.) List VMESS\n4.) Account Details\nx.) Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p "Username: " u; id=$(uuidgen); read -p "Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[3].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "vmess|$u|$id|$exp" >> $U_DATA
           vj="{\"v\":\"2\",\"ps\":\"$u\",\"add\":\"$DMN\",\"port\":\"8443\",\"id\":\"$id\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}"
           echo -e "\nVMESS TLS: vmess://$(echo -n $vj | base64 -w 0)"; read -p "Enter..." ;;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Hapus Nomor: " n; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG)
           jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[3].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/vmess|$u|/d" $U_DATA ;;
        3) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Enter..." ;;
        4) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Nomor: " n; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[2].settings.clients[$idx].id" $CONFIG)
           vj="{\"v\":\"2\",\"ps\":\"$u\",\"add\":\"$DMN\",\"port\":\"8443\",\"id\":\"$id\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}"
           echo -e "VMESS TLS: vmess://$(echo -n $vj | base64 -w 0)"; read -p "Enter..." ;;
        x) return ;;
    esac; done
}

function trojan_menu() {
    while true; do header_sub; echo -e "1.) Create TROJAN\n2.) Delete TROJAN\n3.) List TROJAN\n4.) Account Details\nx.) Back"; read -p "Pilih: " opt
    case $opt in
        1) read -p "Username: " u; read -p "Password: " id; read -p "Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[4].settings.clients += [{"password":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[5].settings.clients += [{"password":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "trojan|$u|$id|$exp" >> $U_DATA
           echo -e "\nTROJAN TLS: trojan://${id}@${DMN}:2096?path=/trojan&security=tls&type=ws#${u}"; read -p "Enter..." ;;
        2) jq -r '.inbounds[4].settings.clients[].email' $CONFIG | nl; read -p "Hapus Nomor: " n; idx=$((n-1)); u=$(jq -r ".inbounds[4].settings.clients[$idx].email" $CONFIG)
           jq "del(.inbounds[4].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[5].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/trojan|$u|/d" $U_DATA ;;
        3) jq -r '.inbounds[4].settings.clients[].email' $CONFIG | nl; read -p "Enter..." ;;
        4) jq -r '.inbounds[4].settings.clients[].email' $CONFIG | nl; read -p "Nomor: " n; idx=$((n-1)); u=$(jq -r ".inbounds[4].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[4].settings.clients[$idx].password" $CONFIG)
           echo -e "TROJAN: trojan://${id}@${DMN}:2096?path=/trojan&security=tls&type=ws#${u}"; read -p "Enter..." ;;
        x) return ;;
    esac; done
}

while true; do clear
    echo -e "${CYAN}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "          ${GREEN}TENDO STORE PLATINUM MENU${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────┤${NC}"
    echo -e " 1.) VLESS MENU        3.) TROJAN MENU"
    echo -e " 2.) VMESS MENU        4.) ZIVPN UDP"
    echo -e " 5.) RESTART SERVICES  6.) CHECK STATUS"
    echo -e " x.) EXIT"
    echo -e "${CYAN}└─────────────────────────────────────────────────┘${NC}"
    read -p " Pilih Nomor: " opt
    case $opt in
        1) vless_menu ;; 2) vmess_menu ;; 3) trojan_menu ;;
        4) clear; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter..." ;;
        5) systemctl restart xray zivpn; echo "Restarted!"; sleep 1 ;;
        6) systemctl status xray zivpn; read -p "Enter..." ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo "INSTALASI BERHASIL! Ketik: menu"
