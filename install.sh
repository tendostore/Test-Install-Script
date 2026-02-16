#!/bin/bash
# ==================================================
#   Auto Script Install X-ray Multi-Port
#   EDITION: PLATINUM LTS FINAL V.205 (UI RESTORED)
#   Script BY: Tendo Store
#   Features: VMess, VLESS, Trojan (Port 443/80 Shared)
#   UI: Original Zero Margin Platinum
# ==================================================

# --- 1. SYSTEM OPTIMIZATION ---
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
echo "   Auto Script Install X-ray Multi-Port"
echo "        VMESS - VLESS - TROJAN"
echo "============================================="

# --- 3. INSTALL DEPENDENCIES ---
apt update -y
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron

touch /root/.hushlogin
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

# --- 5. XRAY CORE & MULTI-PORT CONFIG ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"

# CONFIGURATION MULTI-PORT (FALLBACK)
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-tls", "port": 443, "protocol": "vless",
      "settings": {
        "clients": [], "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001, "xver": 1 },
          { "path": "/trojan", "dest": 10002, "xver": 1 }
        ]
      },
      "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "certificates": [ { "certificateFile": "$XRAY_DIR/xray.crt", "keyFile": "$XRAY_DIR/xray.key" } ] }, "wsSettings": { "path": "/vless" } }
    },
    {
      "tag": "vless-nontls", "port": 80, "protocol": "vless",
      "settings": {
        "clients": [], "decryption": "none",
        "fallbacks": [
          { "path": "/vmess", "dest": 10001, "xver": 1 },
          { "path": "/trojan", "dest": 10002, "xver": 1 }
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

# --- 6. ZIVPN CONFIG ---
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
systemctl daemon-reload && systemctl enable zivpn && systemctl restart zivpn xray

iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save &>/dev/null

# --- 7. MENU SCRIPT (ORIGINAL PLATINUM UI) ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BG_RED='\033[41;1;37m'; WHITE='\033[1;37m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"
DOMAIN=$(cat /usr/local/etc/xray/domain)

function header_main() {
    clear; OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
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
    echo -e "│ —————————————————————————————————————\n│ Version   : v.205 LTS Multi-Port\n│ Script BY : Tendo Store\n│ WhatsApp  : +6282224460678\n│ Expiry In : Lifetime\n└─────────────────────────────────────────────────┘"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "┌─────────────────────────────────────────────────┐\n          ${YELLOW}TENDO STORE - $1${NC}        \n  Current Domain : $DMN\n└─────────────────────────────────────────────────┘"
}

# --- VMESS MENU (Inbound Index 2) ---
function vmess_menu() {
    while true; do header_sub "VMESS MENU"; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; id=$(uuidgen); exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[2].settings.clients += [{"id":$id,"email":$u,"alterId":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp|vmess" >> $U_DATA
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           vmess_json='{"add":"'$DOMAIN'","aid":"0","host":"'$DOMAIN'","id":"'$id'","net":"ws","path":"/vmess","port":"443","ps":"'$u'","scy":"auto","sni":"'$DOMAIN'","tls":"tls","type":"","v":"2"}'
           link="vmess://$(echo -n $vmess_json | base64 -w 0)"
           clear; echo -e "————————————————————————————————————\n               VMESS\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DOMAIN\nPort TLS       : 443\nPort none TLS  : 80\nid             : $id\nalterId        : 0\nSecurity       : auto\nNetwork        : ws\nPath           : /vmess\nExpired On     : $exp\n————————————————————————————————————\n            LINK VMESS\n————————————————————————————————————\n$link\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[2].settings.clients[$idx].email" $CONFIG); jq "del(.inbounds[2].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; sed -i "/^$u|.*|vmess/d" $U_DATA; systemctl restart xray; echo "Deleted $u"; sleep 1;;
        3) header_sub "VMESS LIST"; jq -r '.inbounds[2].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

# --- VLESS MENU (Inbound Index 0 & 1) ---
function vless_menu() {
    while true; do header_sub "VLESS MENU"; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; id=$(uuidgen); exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[0].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           jq --arg u "$u" --arg id "$id" '.inbounds[1].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
           systemctl restart xray; echo "$u|$id|$exp|vless" >> $U_DATA
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DOMAIN}:443?path=/vless&security=tls&encryption=none&type=ws&sni=${DOMAIN}#${u}"; lnon="vless://${id}@${DOMAIN}:80?path=/vless&security=none&encryption=none&type=ws#${u}"
           clear; echo -e "————————————————————————————————————\n               VLESS\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DOMAIN\nPort TLS       : 443\nPort none TLS  : 80\nid             : $id\nEncryption     : none\nNetwork        : ws\nPath           : /vless\nExpired On     : $exp\n————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n$ltls\n————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n$lnon\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); jq "del(.inbounds[0].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; jq "del(.inbounds[1].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; sed -i "/^$u|.*|vless/d" $U_DATA; systemctl restart xray; echo "Deleted $u"; sleep 1;;
        3) header_sub "VLESS LIST"; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

# --- TROJAN MENU (Inbound Index 3) ---
function trojan_menu() {
    while true; do header_sub "TROJAN MENU"; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) Create Account\n│ 2.) Delete Account\n│ 3.) List Accounts\n│ 4.) Check Account Details\n│ x.) Back\n└─────────────────────────────────────────────────┘"; read -p "Pilih: " opt
    case $opt in
        1) read -p " Username : " u; read -p " Expired: " ex; [[ -z "$ex" ]] && ex=30; pass=$u; exp=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg p "$pass" '.inbounds[3].settings.clients += [{"password":$p,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$pass|$exp|trojan" >> $U_DATA
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="trojan://${pass}@${DOMAIN}:443?path=/trojan&security=tls&type=ws&sni=${DOMAIN}#${u}"
           clear; echo -e "————————————————————————————————————\n               TROJAN\n————————————————————————————————————\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DOMAIN\nPort TLS       : 443\nPort none TLS  : 80\nPassword       : $pass\nNetwork        : ws\nPath           : /trojan\nExpired On     : $exp\n————————————————————————————————————\n            LINK TROJAN\n————————————————————————————————————\n$ltls\n————————————————————————————————————"; read -n 1 -s -r -p "Enter...";;
        2) jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[3].settings.clients[$idx].email" $CONFIG); jq "del(.inbounds[3].settings.clients[$idx])" $CONFIG > /tmp/x && mv /tmp/x $CONFIG; sed -i "/^$u|.*|trojan/d" $U_DATA; systemctl restart xray; echo "Deleted $u"; sleep 1;;
        3) header_sub "TROJAN LIST"; jq -r '.inbounds[3].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    header_sub "ZIVPN UDP"; echo "Manage via simple menu logic..."; read -p "Press Enter to return..."
}

while true; do header_main; echo -e "┌─────────────────────────────────────────────────┐\n│ 1.) VMESS MENU         5.) UTILITIES (Speedtest)\n│ 2.) VLESS MENU         6.) RESTART SERVICES\n│ 3.) TROJAN MENU        7.) AUTO XP / CLEANER\n│ 4.) ZIVPN UDP          x.) EXIT\n└─────────────────────────────────────────────────┘"; read -p "Pilih Nomor: " opt
    case $opt in
        1) vmess_menu ;; 
        2) vless_menu ;; 
        3) trojan_menu ;;
        4) nano /etc/zivpn/config.json; systemctl restart zivpn ;;
        5) python3 <(curl -sL https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) --share; read -p "Enter...";;
        6) systemctl restart xray zivpn; echo "Restarted!"; sleep 1 ;;
        7) /usr/bin/xp; /usr/bin/cleaner; echo "Done!"; sleep 1 ;;
        x) exit ;;
    esac; done
END_MENU
chmod +x /usr/bin/menu

# --- 8. AUTO XP (Protocol Aware) ---
cat > /usr/bin/xp <<'END_XP'
#!/bin/bash
data_file="/usr/local/etc/xray/user_data.txt"
config_file="/usr/local/etc/xray/config.json"
now=$(date +%Y-%m-%d)
while read -r line; do
    [[ -z "$line" ]] && continue
    user=$(echo "$line" | cut -d '|' -f 1)
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
        fi
        sed -i "/^$user|/d" $data_file
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

echo "INSTALASI BERHASIL! KETIK: menu"
