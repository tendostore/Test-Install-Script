#!/bin/bash
# ==================================================
#   Auto Script Install X-ray (Vless, Vmess, Trojan)
#   EDITION: PLATINUM LTS FINAL V.103 (Fixed Connect)
#   Inspiration: Dugong Logic (Fallback Path Routing)
#   Script BY: Tendo Store | WhatsApp: +6282224460678
#   Features: Multi-Protocol on Port 443/80 via VLESS Gateway
# ==================================================

# --- 1. SYSTEM OPTIMIZATION ---
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

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
echo "      FIXED: VMESS & TROJAN CONNECTION"
echo "============================================="

# --- 3. INSTALL DEPENDENCIES ---
apt update -y
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch

# Silent Login & Visuals
touch /root/.hushlogin
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

# Cloudflare Auto-Subdomain
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${DOMAIN_INIT}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null

echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 5. XRAY CORE CONFIGURATION (THE FIX) ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
rm -f /usr/local/share/xray/geosite.dat
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

# NOTE: Inbound 0 (443) acts as the GATEWAY.
# It decrypts traffic and routes to internal ports (10001, 10002) based on PATH.
# This mimics the logic in the 'Dugong' script but simplifies it without Unix Sockets.

cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-tls-gateway",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
            { "path": "/vmess", "dest": 10001 },
            { "path": "/trojan", "dest": 10002 }
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
      "tag": "vless-nontls-gateway",
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
            { "path": "/vmess", "dest": 10003 },
            { "path": "/trojan", "dest": 10004 }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "tag": "vmess-internal",
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "trojan-internal",
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    },
    {
      "tag": "vmess-internal-nontls",
      "port": 10003,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "trojan-internal-nontls",
      "port": 10004,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" }, { "type": "field", "domain": ["geosite:google"], "outboundTag": "vless-tls-gateway" } ] }
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
    echo -e "┌─────────────────────────────────────────────────┐\n          ${BG_RED}          TENDO STORE          ${NC} \n└─────────────────────────────────────────────────┘"
    echo -e "┌─────────────────────────────────────────────────┐\n│ OS      : $OS\n│ RAM     : ${RAM}M\n│ CITY    : $CITY\n│ DOMAIN  : $DOMAIN\n│ —————————————————————————————————————\n│ TRAFFIC : $DAY_DATA (RX: $D_RX | TX: $D_TX)\n│ —————————————————————————————————————"
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"; SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"
    echo -e "│ XRAY : $X_ST | ZIVPN : $Z_ST \n│ —————————————————————————————————————"
    C_VLESS=$(jq '.inbounds[0].settings.clients | length' $CONFIG)
    C_VMESS=$(jq '.inbounds[2].settings.clients | length' $CONFIG)
    C_TROJAN=$(jq '.inbounds[3].settings.clients | length' $CONFIG)
    echo -e "│              LIST ACCOUNTS\n│ —————————————————————————————————————\n│    VLESS         : $C_VLESS  ACCOUNT\n│    VMESS         : $C_VMESS  ACCOUNT\n│    TROJAN        : $C_TROJAN  ACCOUNT"
    echo -e "│ —————————————————————————————————————\n│ Version   : v.103 LTS (Fixed)\n│ Script BY : Tendo Store\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - SUB MENU${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

function vless_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            VLESS MENU (Port 443/80)\n│ —————————————————————————————————————\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " UUID (Random): " id; [[ -z "$id" ]] && id=$(uuidgen); read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           # Add to Gateway TLS [0] and Gateway Non-TLS [1]
           jq --arg u "$u" --arg id "$id" '.inbounds[0].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[1].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp_date" >> $VLESS_DATA
           DMN=$(cat /usr/local/etc/xray/domain)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
           lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           clear; echo -e "————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); sed -i "/$u|/d" $VLESS_DATA
           jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[1].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function vmess_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            VMESS MENU (Port 443/80)\n│ —————————————————————————————————————\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " UUID (Random): " id; [[ -z "$id" ]] && id=$(uuidgen); read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           # Add to VMess Internal [2] and VMess Internal Non-TLS [4]
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[4].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp_date" >> $VMESS_DATA
           DMN=$(cat /usr/local/etc/xray/domain)
           vmess_json_tls="{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"type\":\"none\",\"host\":\"${DMN}\",\"tls\":\"tls\"}"
           vmess_json_nontls="{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"type\":\"none\",\"host\":\"${DMN}\",\"tls\":\"none\"}"
           ltls="vmess://$(echo -n ${vmess_json_tls} | base64 -w 0)"
           lnon="vmess://$(echo -n ${vmess_json_nontls} | base64 -w 0)"
           clear; echo -e "————————————————————————————————————\n            VMESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VMESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); sed -i "/$u|/d" $VMESS_DATA
           jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[4].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function trojan_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│            TROJAN MENU (Port 443/80)\n│ —————————————————————————————————————\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Password : " p; [[ -z "$p" ]] && p=$u; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           # Add to Trojan Internal [3] and Trojan Internal Non-TLS [5]
           jq --arg p "$p" --arg u "$u" '.inbounds[3].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg p "$p" --arg u "$u" '.inbounds[5].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$p|$exp_date" >> $TROJAN_DATA
           DMN=$(cat /usr/local/etc/xray/domain)
           ltls="trojan://${p}@${DMN}:443?path=/trojan&security=tls&type=ws&sni=${DMN}#${u}"
           lnon="trojan://${p}@${DMN}:80?path=/trojan&security=none&type=ws#${u}"
           clear; echo -e "————————————————————————————————————\n            TROJAN WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          TROJAN WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[3].settings.clients[$idx].email" $CONFIG); sed -i "/$u|/d" $TROJAN_DATA
           jq "del(.inbounds[3].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq "del(.inbounds[5].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        3) header_sub; jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Password: " p; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; DMN=$(cat /usr/local/etc/xray/domain)
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nDomain     : $DMN\nExpired On : $exp\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        2) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); jq "del(.auth.config[$idx])" /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
        3) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function routing_menu() {
    while true; do header_sub; echo -e "┌─────────────────────────────────────────────────┐\n│ Active Rules: $(cat /usr/local/etc/xray/rule_list.txt | xargs)\n│ 1.) Tambah rule geosite\n│ 2.) Hapus rule geosite\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
        case $opt in
            1) read -p "Rule: " d; echo "$d" >> /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "vless-tls-gateway" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            2) nl /usr/local/etc/xray/rule_list.txt; read -p "No: " n; [[ -z "$n" ]] && continue; sed -i "${n}d" /usr/local/etc/xray/rule_list.txt; LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//'); jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "vless-tls-gateway" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG; systemctl restart xray;;
            x) return;;
        esac; done
}

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) VLESS ACCOUNT      5.) ROUTING GEOSITE\n│ 2.) VMESS ACCOUNT      6.) GANTI DOMAIN\n│ 3.) TROJAN ACCOUNT     7.) SPEED TEST\n│ 4.) ZIVPN UDP          x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p "Pilih Nomor: " opt
    case $opt in
        1) vless_menu ;; 2) vmess_menu ;; 3) trojan_menu ;; 4) zivpn_menu ;; 5) routing_menu ;;
        6) read -p "Domain Baru: " nd; echo "$nd" > /usr/local/etc/xray/domain; openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1; systemctl restart xray; echo "Domain Updated!"; sleep 1;;
        7) header_sub; python3 <(curl -sL https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) --share; read -p "Enter...";;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
echo "FIXED SUCCESS! KETIK: menu"
