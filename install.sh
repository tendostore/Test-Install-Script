#!/bin/bash
# ==================================================
#    Auto Script Install X-ray & Zivpn
#    EDITION: PLATINUM LTS FINAL V.106
#    Protocols: VLESS, VMESS, TROJAN, ZIVPN (UDP)
#    Script BY: Tendo Store | Status: Final Fixed
# ==================================================

# --- 1. PRE-INSTALL & OPTIMIZATION ---
# Membersihkan lock agar tidak ada error apt
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
# Optimasi BBR & Swap 2GB
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1
swapoff -a 2>/dev/null
rm -f /swapfile
dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
chmod 600 /swapfile
mkswap /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1

# --- 2. INSTALL DEPENDENCIES (FIXED) ---
apt update -y
# Mencegah error 'base64' dengan menghapusnya dari list apt
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget bc neofetch coreutils

# --- 3. SETUP VARIABLES ---
DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
USER_DATA="/usr/local/etc/xray/user_data.txt"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $USER_DATA

# --- 4. DOMAIN & SSL (FIX PERMISSIONS) ---
echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
# Memberikan izin baca agar Xray tidak error Permission Denied
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 5. XRAY CORE & CONFIG (MULTI-PROTOCOL) ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 443, "protocol": "vless", "tag": "vless-tls", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } } },
    { "port": 80, "protocol": "vless", "tag": "vless-ntls", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } } },
    { "port": 8443, "protocol": "vmess", "tag": "vmess-tls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vmess" } } },
    { "port": 8080, "protocol": "vmess", "tag": "vmess-ntls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } } },
    { "port": 2096, "protocol": "trojan", "tag": "trojan-tls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/trojan" } } },
    { "port": 2052, "protocol": "trojan", "tag": "trojan-ntls", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } } }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF

# --- 6. ZIVPN SETUP ---
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
cat > /etc/zivpn/config.json <<EOF
{ "listen": ":5667", "cert": "$XRAY_DIR/xray.crt", "key": "$XRAY_DIR/xray.key", "obfs": "zivpn", "auth": { "mode": "passwords", "config": [] } }
EOF
systemctl daemon-reload && systemctl enable xray zivpn && systemctl restart xray zivpn

# --- 7. PLATINUM MENU (FULL LOGIC) ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"
DMN=$(cat /usr/local/etc/xray/domain)

function header() {
    clear
    echo -e "${CYAN}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "          ${GREEN}TENDO STORE - PLATINUM UI${NC}"
    echo -e "   Domain : $DMN"
    echo -e "${CYAN}└─────────────────────────────────────────────────┘${NC}"
}

function vless_menu() {
    while true; do header; echo -e " 1. Create VLESS\n 2. Delete VLESS\n x. Back"; read -p " Pilih: " opt
    case $opt in
        1) read -p " User: " u; id=$(uuidgen); read -p " Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol=="vless").settings.clients) += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "vless|$u|$id|$exp" >> $U_DATA
           echo -e "\nVLESS TLS: vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&type=ws#${u}"; read -p "Enter..." ;;
        2) jq -r '.inbounds[] | select(.protocol=="vless") | .settings.clients[].email' $CONFIG | sort -u | nl; read -p " Nomor: " n; [[ -z $n ]] && continue
           u=$(jq -r '.inbounds[] | select(.protocol=="vless") | .settings.clients[].email' $CONFIG | sort -u | sed -n "${n}p")
           jq --arg u "$u" '(.inbounds[] | select(.protocol=="vless").settings.clients) |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/vless|$u|/d" $U_DATA ;;
        x) return ;;
    esac; done
}

function vmess_menu() {
    while true; do header; echo -e " 1. Create VMESS\n 2. Delete VMESS\n x. Back"; read -p " Pilih: " opt
    case $opt in
        1) read -p " User: " u; id=$(uuidgen); read -p " Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol=="vmess").settings.clients) += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "vmess|$u|$id|$exp" >> $U_DATA
           vj="{\"v\":\"2\",\"ps\":\"$u\",\"add\":\"$DMN\",\"port\":\"8443\",\"id\":\"$id\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}"
           echo -e "\nVMESS TLS: vmess://$(echo -n $vj | base64 -w 0)"; read -p "Enter..." ;;
        2) jq -r '.inbounds[] | select(.protocol=="vmess") | .settings.clients[].email' $CONFIG | sort -u | nl; read -p " Nomor: " n; [[ -z $n ]] && continue
           u=$(jq -r '.inbounds[] | select(.protocol=="vmess") | .settings.clients[].email' $CONFIG | sort -u | sed -n "${n}p")
           jq --arg u "$u" '(.inbounds[] | select(.protocol=="vmess").settings.clients) |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/vmess|$u|/d" $U_DATA ;;
        x) return ;;
    esac; done
}

function trojan_menu() {
    while true; do header; echo -e " 1. Create TROJAN\n 2. Delete TROJAN\n x. Back"; read -p " Pilih: " opt
    case $opt in
        1) read -p " User: " u; read -p " Password: " id; read -p " Exp (hari): " ex; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol=="trojan").settings.clients) += [{"password":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "trojan|$u|$id|$exp" >> $U_DATA
           echo -e "\nTROJAN TLS: trojan://${id}@${DMN}:2096?path=/trojan&security=tls&type=ws#${u}"; read -p "Enter..." ;;
        2) jq -r '.inbounds[] | select(.protocol=="trojan") | .settings.clients[].email' $CONFIG | sort -u | nl; read -p " Nomor: " n; [[ -z $n ]] && continue
           u=$(jq -r '.inbounds[] | select(.protocol=="trojan") | .settings.clients[].email' $CONFIG | sort -u | sed -n "${n}p")
           jq --arg u "$u" '(.inbounds[] | select(.protocol=="trojan").settings.clients) |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; sed -i "/trojan|$u|/d" $U_DATA ;;
        x) return ;;
    esac; done
}

while true; do header
    echo -e " 1.) VLESS MENU        3.) TROJAN MENU"
    echo -e " 2.) VMESS MENU        4.) ZIVPN UDP"
    echo -e " 5.) RESTART SERVICE   x.) EXIT"
    read -p " Pilih Nomor: " opt
    case $opt in
        1) vless_menu ;; 2) vmess_menu ;; 3) trojan_menu ;;
        4) clear; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter..." ;;
        5) systemctl restart xray zivpn; echo "Restarted!"; sleep 1 ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo -e "Instalasi Berhasil! Silakan ketik: menu"
