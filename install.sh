#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM CLEAN V.6.0 (ACCOUNT COUNTER)
#   Update: Added List Accounts (Count) on Dashboard
#           + Added WS, GRPC, HTTPUpgrade Networks
#           + Added IP Limit Enforcer
#           + Added Auto-Delete Expired Accounts
#           + Custom Detailed Format for VMESS, VLESS, TROJAN
#           + Added Bandwidth Limit (Quota GB) via Xray API
#           + Added Renew Account Feature
#           + Added Trial Feature (Minutes/Hours)
#           + Added ZIVPN Tracking & Renew
#           + Guaranteed Full Deletion (TLS/NTLS/GRPC/UPG)
#   Script BY: Tendo Store | WhatsApp: +6282224460678
# ==================================================

# --- WARNA & UI ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; WHITE='\033[1;37m'

# --- ANTI INTERACTIVE ---
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# --- ANIMASI INSTALL ---
function install_spin() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    echo -ne " "
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

function print_msg() { echo -e "${YELLOW}➤ $1...${NC}"; }
function print_ok() { echo -e "${GREEN}✔ $1 Selesai!${NC}"; sleep 0.5; }

clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${PURPLE}      AUTO INSTALLER X-RAY & ZIVPN ONLY          ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           Script by Tendo Store                ${NC}"
echo -e "${CYAN}=================================================${NC}"
sleep 2

# --- 1. OPTIMIZATION ---
print_msg "Optimasi Sistem & Swap"
rm -f /var/lib/apt/lists/lock >/dev/null 2>&1
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1
swapoff -a >/dev/null 2>&1; rm -f /swapfile
dd if=/dev/zero of=/swapfile bs=1024 count=2097152 >/dev/null 2>&1
chmod 600 /swapfile; mkswap /swapfile >/dev/null 2>&1; swapon /swapfile >/dev/null 2>&1
echo '/swapfile none swap sw 0 0' >> /etc/fstab & install_spin
print_ok "System Optimized"

# --- 2. VARIABLES ---
# Cloudflare Credentials (Used only if Option 1 is selected)
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

XRAY_DIR="/usr/local/etc/xray"; 
CONFIG_FILE="/usr/local/etc/xray/config.json"
DATA_VMESS="/usr/local/etc/xray/vmess.txt"; DATA_VLESS="/usr/local/etc/xray/vless.txt"; DATA_TROJAN="/usr/local/etc/xray/trojan.txt"
DATA_ZIVPN="/etc/zivpn/zivpn.txt"

# --- 3. DEPENDENCIES ---
print_msg "Install Dependencies"
apt-get update -y >/dev/null 2>&1
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl socat jq openssl uuid-runtime net-tools vnstat wget gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron >/dev/null 2>&1 & install_spin
print_ok "Dependencies"

# Install Official Speedtest Ookla
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash >/dev/null 2>&1
apt-get install speedtest -y >/dev/null 2>&1

touch /root/.hushlogin; chmod -x /etc/update-motd.d/* 2>/dev/null
sed -i '/neofetch/d' /root/.bashrc; echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat && systemctl restart vnstat; vnstat -u -i $IFACE_NET >/dev/null 2>&1

# --- 4. DOMAIN SELECTION ---
print_msg "Setup Domain & SSL"
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo; touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN $DATA_ZIVPN
mkdir -p /var/log/xray; touch /var/log/xray/access.log /var/log/xray/error.log
IP_VPS=$(curl -s ifconfig.me)

# Get Geo Info
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           PILIHAN JENIS DOMAIN                 ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}│${NC} [1] Gunakan Domain Random Tendo (Gratis/Auto)"
echo -e "${CYAN}│${NC} [2] Gunakan Domain Sendiri (Manual)"
echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
read -p " Pilih Opsi (1/2): " dom_opt

if [[ "$dom_opt" == "1" ]]; then
    # -- OPTION 1: AUTO DOMAIN --
    echo -e "${YELLOW}Menggunakan Domain Random dari Tendo Store...${NC}"
    DOMAIN_VAL="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
    
    # Register to Cloudflare
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
         -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
         -H "Content-Type: application/json" \
         --data '{"type":"A","name":"'${DOMAIN_VAL}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null
         
    echo "$DOMAIN_VAL" > $XRAY_DIR/domain
    echo -e "${GREEN}Domain Terbuat: ${DOMAIN_VAL}${NC}"
else
    # -- OPTION 2: OWN DOMAIN --
    echo -e "${YELLOW}Mode Domain Sendiri${NC}"
    echo -e "${RED}PENTING: Pastikan anda sudah mengarahkan A Record domain ke IP: ${IP_VPS}${NC}"
    read -p " Masukan Domain/Subdomain Anda: " user_dom
    if [[ -z "$user_dom" ]]; then
        echo -e "${RED}Domain tidak boleh kosong! Script berhenti.${NC}"
        exit 1
    fi
    echo "$user_dom" > $XRAY_DIR/domain
    DOMAIN_VAL="$user_dom"
    echo -e "${GREEN}Domain Diset ke: ${DOMAIN_VAL}${NC}"
fi

# SSL Generator (Valid for both options)
echo -e "${YELLOW}Generating SSL Certificate...${NC}"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_VAL" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key; chmod 644 $XRAY_DIR/xray.crt & install_spin
print_ok "SSL Configured"

# --- 5. XRAY CONFIG (UPGRADED WITH WS, GRPC, UPGRADE, LOGS & API QUOTA) ---
print_msg "Install Xray Core & Config"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
UUID_SYS=$(uuidgen)

cat > $CONFIG_FILE <<EOF
{
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "api": { "tag": "api", "services": [ "StatsService" ] },
  "stats": {},
  "policy": { "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } }, "system": { "statsInboundUplink": true, "statsInboundDownlink": true } },
  "inbounds": [
    { "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1" }, "tag": "api" },
    { "tag": "inbound-443", "port": 443, "protocol": "vless", "settings": { "clients": [ { "id": "$UUID_SYS", "flow": "xtls-rprx-vision", "level": 0, "email": "system" } ], "decryption": "none", "fallbacks": [ 
        { "path": "/vmess", "dest": 10001, "xver": 1 }, { "path": "/vless", "dest": 10002, "xver": 1 }, { "path": "/trojan", "dest": 10003, "xver": 1 },
        { "path": "/vmess-upg", "dest": 10004, "xver": 1 }, { "path": "/vless-upg", "dest": 10005, "xver": 1 }, { "path": "/trojan-upg", "dest": 10006, "xver": 1 },
        { "alpn": "h2", "path": "vmess-grpc", "dest": 10007, "xver": 1 }, { "alpn": "h2", "path": "vless-grpc", "dest": 10008, "xver": 1 }, { "alpn": "h2", "path": "trojan-grpc", "dest": 10009, "xver": 1 }
    ] }, "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "alpn": ["h2", "http/1.1"], "certificates": [ { "certificateFile": "/usr/local/etc/xray/xray.crt", "keyFile": "/usr/local/etc/xray/xray.key" } ] } } },
    { "tag": "inbound-80", "port": 80, "protocol": "vless", "settings": { "clients": [], "decryption": "none", "fallbacks": [ 
        { "path": "/vmess", "dest": 10001, "xver": 1 }, { "path": "/vless", "dest": 10002, "xver": 1 }, { "path": "/trojan", "dest": 10003, "xver": 1 },
        { "path": "/vmess-upg", "dest": 10004, "xver": 1 }, { "path": "/vless-upg", "dest": 10005, "xver": 1 }, { "path": "/trojan-upg", "dest": 10006, "xver": 1 }
    ] }, "streamSettings": { "network": "tcp", "security": "none" } },
    { "tag": "vmess_ws", "port": 10001, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "acceptProxyProtocol": true, "path": "/vmess" } } },
    { "tag": "vless_ws", "port": 10002, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "acceptProxyProtocol": true, "path": "/vless" } } },
    { "tag": "trojan_ws", "port": 10003, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "acceptProxyProtocol": true, "path": "/trojan" } } },
    { "tag": "vmess_upg", "port": 10004, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "httpupgrade", "security": "none", "httpupgradeSettings": { "acceptProxyProtocol": true, "path": "/vmess-upg" } } },
    { "tag": "vless_upg", "port": 10005, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "httpupgrade", "security": "none", "httpupgradeSettings": { "acceptProxyProtocol": true, "path": "/vless-upg" } } },
    { "tag": "trojan_upg", "port": 10006, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "httpupgrade", "security": "none", "httpupgradeSettings": { "acceptProxyProtocol": true, "path": "/trojan-upg" } } },
    { "tag": "vmess_grpc", "port": 10007, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [] }, "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "acceptProxyProtocol": true, "serviceName": "vmess-grpc" } } },
    { "tag": "vless_grpc", "port": 10008, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [], "decryption": "none" }, "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "acceptProxyProtocol": true, "serviceName": "vless-grpc" } } },
    { "tag": "trojan_grpc", "port": 10009, "listen": "127.0.0.1", "protocol": "trojan", "settings": { "clients": [] }, "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "acceptProxyProtocol": true, "serviceName": "trojan-grpc" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" },
    { "protocol": "freedom", "tag": "api" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "inboundTag": ["api"], "outboundTag": "api", "type": "field" }, { "type": "field", "outboundTag": "blocked", "protocol": [ "bittorrent" ] } ] }
}
EOF
print_ok "Xray Configured"

# --- 6. ZIVPN ---
print_msg "Install ZIVPN"
wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"; chmod +x /usr/local/bin/zivpn
echo '{"listen":":5667","cert":"/usr/local/etc/xray/xray.crt","key":"/usr/local/etc/xray/xray.key","obfs":"zivpn","auth":{"mode":"passwords","config":[]}}' > /etc/zivpn/config.json
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
netfilter-persistent save >/dev/null 2>&1
print_ok "ZIVPN Installed"

# --- 6.5 AUTO-KILL, EXP CHECKER & QUOTA MONITOR (NEW) ---
print_msg "Setting up Cron & Auto-Kill Systems"
cat > /usr/local/bin/xray-exp <<'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
NOW=$(date +%s)

for proto in vmess vless trojan; do
    FILE="/usr/local/etc/xray/${proto}.txt"
    if [[ -f "$FILE" ]]; then
        while IFS="|" read -r user id exp limit status quota; do
            EXP_S=$(date -d "$exp" +%s 2>/dev/null)
            if [[ -n "$EXP_S" && "$NOW" -ge "$EXP_S" ]]; then
                jq --arg u "$user" '(.inbounds[] | select(.protocol == "'$proto'")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                sed -i "/^$user|/d" $FILE
                systemctl restart xray
            fi
        done < "$FILE"
    fi
done

Z_FILE="/etc/zivpn/zivpn.txt"
Z_CONF="/etc/zivpn/config.json"
if [[ -f "$Z_FILE" ]]; then
    while IFS="|" read -r pass exp; do
        EXP_S=$(date -d "$exp" +%s 2>/dev/null)
        if [[ -n "$EXP_S" && "$NOW" -ge "$EXP_S" ]]; then
            jq --arg p "$pass" 'del(.auth.config[] | select(. == $p))' $Z_CONF > /tmp/z && mv /tmp/z $Z_CONF
            sed -i "/^$pass|/d" $Z_FILE
            systemctl restart zivpn
        fi
    done < "$Z_FILE"
fi
EOF
chmod +x /usr/local/bin/xray-exp

cat > /usr/local/bin/xray-limit <<'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
LOG_FILE="/var/log/xray/access.log"
[[ ! -f "$LOG_FILE" ]] && exit 0
tail -n 1000 "$LOG_FILE" | grep "accepted" | awk '{print $3, $7}' | sed 's/tcp://g' | awk -F: '{print $1" "$2}' > /tmp/xray_active.log

for proto in vmess vless trojan; do
    FILE="/usr/local/etc/xray/${proto}.txt"
    [[ ! -f "$FILE" ]] && continue
    while IFS="|" read -r user id exp limit status quota; do
        [[ -z "$limit" || "$limit" == "0" || "$status" == "LOCKED" ]] && continue
        active_ips=$(grep -w "$user" /tmp/xray_active.log | awk '{print $1}' | sort -u | wc -l)
        if [[ "$active_ips" -gt "$limit" ]]; then
            jq --arg u "$user" '(.inbounds[] | select(.protocol == "'$proto'")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
            sed -i "s/^$user|.*/$user|$id|$exp|$limit|LOCKED|$quota/g" "$FILE"
            systemctl restart xray
        fi
    done < "$FILE"
done
EOF
chmod +x /usr/local/bin/xray-limit

cat > /usr/local/bin/xray-quota <<'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
for proto in vmess vless trojan; do
    FILE="/usr/local/etc/xray/${proto}.txt"
    [[ ! -f "$FILE" ]] && continue
    while IFS="|" read -r user id exp limit status quota; do
        [[ -z "$quota" || "$quota" == "0" || "$status" == "LOCKED" ]] && continue
        down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${user}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"')
        up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${user}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"')
        [[ -z "$down" ]] && down=0
        [[ -z "$up" ]] && up=0
        total_bytes=$((down + up))
        quota_bytes=$(awk "BEGIN {printf \"%.0f\", $quota * 1073741824}")
        if [ "$total_bytes" -ge "$quota_bytes" ]; then
            jq --arg u "$user" '(.inbounds[] | select(.protocol == "'$proto'")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
            sed -i "s/^$user|.*/$user|$id|$exp|$limit|LOCKED|$quota/g" "$FILE"
            systemctl restart xray
        fi
    done < "$FILE"
done
EOF
chmod +x /usr/local/bin/xray-quota

(crontab -l 2>/dev/null | grep -v "xray-exp"; echo "* * * * * /usr/local/bin/xray-exp") | crontab -
(crontab -l 2>/dev/null | grep -v "xray-limit"; echo "* * * * * /usr/local/bin/xray-limit") | crontab -
(crontab -l 2>/dev/null | grep -v "xray-quota"; echo "* * * * * /usr/local/bin/xray-quota") | crontab -
print_ok "Cron Jobs Installed"

# --- 7. MENU SCRIPT ---
print_msg "Finalisasi Menu"
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; WHITE='\033[1;37m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"
D_ZIVPN="/etc/zivpn/zivpn.txt"

function show_account_xray() {
    clear
    local proto=$1; local user=$2; local domain=$3; local uuid=$4; local exp=$5; local limit=$6; local quota=$7; local usage=$8
    local link_ws_tls=$9; local link_ws_ntls=${10}; local link_grpc_tls=${11}; local link_upg_tls=${12}; local link_upg_ntls=${13}
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city)
    [[ "$quota" == "0" ]] && str_quota="Unlimited" || str_quota="${quota} GB"

    if [[ "$proto" == "VMESS" ]]; then
        echo -e "————————————————————————————————————"
        echo -e "               VMESS"
        echo -e "————————————————————————————————————"
        echo -e "Remarks        : ${user}"
        echo -e "CITY           : ${city}"
        echo -e "ISP            : ${isp}"
        echo -e "Domain         : ${domain}"
        echo -e "Port TLS       : 443"
        echo -e "Port none TLS  : 80"
        echo -e "id             : ${uuid}"
        echo -e "alterId        : 0"
        echo -e "Security       : auto"
        echo -e "network        : ws, grpc, upgrade"
        echo -e "path ws        : /vmess"
        echo -e "serviceName    : vmess-grpc"
        echo -e "path upgrade   : /vmess-upg"
        echo -e "Limit IP       : ${limit} IP"
        echo -e "Quota Bandwidth: ${str_quota}"
        echo -e "Usage Bandwidth: ${usage} GB"
        echo -e "Expired On     : ${exp}"
        echo -e "————————————————————————————————————"
        echo -e "           VMESS WS TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_ws_tls}"
        echo -e "————————————————————————————————————"
        echo -e "          VMESS WS NO TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_ws_ntls}"
        echo -e "————————————————————————————————————"
        echo -e "             VMESS GRPC"
        echo -e "————————————————————————————————————"
        echo -e "${link_grpc_tls}"
        echo -e "————————————————————————————————————"
        echo -e "         VMESS Upgrade TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_upg_tls}"
        echo -e "————————————————————————————————————"
        echo -e "        VMESS Upgrade NO TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_upg_ntls}"
        echo -e "————————————————————————————————————"
    elif [[ "$proto" == "VLESS" ]]; then
        echo -e "————————————————————————————————————"
        echo -e "               VLESS"
        echo -e "————————————————————————————————————"
        echo -e "Remarks        : ${user}"
        echo -e "CITY           : ${city}"
        echo -e "ISP            : ${isp}"
        echo -e "Domain         : ${domain}"
        echo -e "Port TLS       : 443"
        echo -e "Port none TLS  : 80"
        echo -e "id             : ${uuid}"
        echo -e "Encryption     : none"
        echo -e "Network        : ws, grpc, upgrade"
        echo -e "Path ws        : /vless"
        echo -e "serviceName    : vless-grpc"
        echo -e "Path upgrade   : /vless-upg"
        echo -e "Limit IP       : ${limit} IP"
        echo -e "Quota Bandwidth: ${str_quota}"
        echo -e "Usage Bandwidth: ${usage} GB"
        echo -e "Expired On     : ${exp}"
        echo -e "————————————————————————————————————"
        echo -e "            VLESS WS TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_ws_tls}"
        echo -e "————————————————————————————————————"
        echo -e "          VLESS WS NO TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_ws_ntls}"
        echo -e "————————————————————————————————————"
        echo -e "             VLESS GRPC"
        echo -e "————————————————————————————————————"
        echo -e "${link_grpc_tls}"
        echo -e "————————————————————————————————————"
        echo -e "          VLESS Upgrade TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_upg_tls}"
        echo -e "————————————————————————————————————"
        echo -e "        VLESS Upgrade NO TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_upg_ntls}"
        echo -e "————————————————————————————————————"
    elif [[ "$proto" == "TROJAN" ]]; then
        echo -e "————————————————————————————————————"
        echo -e "               TROJAN"
        echo -e "————————————————————————————————————"
        echo -e "Remarks      : ${user}"
        echo -e "CITY         : ${city}"
        echo -e "ISP          : ${isp}"
        echo -e "Domain       : ${domain}"
        echo -e "Port         : 443"
        echo -e "Key          : ${uuid}"
        echo -e "Network      : ws, grpc, upgrade"
        echo -e "Path ws      : /trojan"
        echo -e "serviceName  : trojan-grpc"
        echo -e "Path upgrade : /trojan-upg"
        echo -e "Limit IP     : ${limit} IP"
        echo -e "Quota Limit  : ${str_quota}"
        echo -e "Usage Traffic: ${usage} GB"
        echo -e "Expired On   : ${exp}"
        echo -e "————————————————————————————————————"
        echo -e "           TROJAN WS TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_ws_tls}"
        echo -e "————————————————————————————————————"
        echo -e "            TROJAN GRPC"
        echo -e "————————————————————————————————————"
        echo -e "${link_grpc_tls}"
        echo -e "————————————————————————————————————"
        echo -e "         TROJAN Upgrade TLS"
        echo -e "————————————————————————————————————"
        echo -e "${link_upg_tls}"
        echo -e "——————————"
        echo -e "——————————————————————————"
    fi
    echo ""
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function show_account_zivpn() {
    clear
    local pass=$1; local domain=$2; local exp=$3
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city); local ip=$(cat /root/tendo/ip)

    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ACCOUNT ZIVPN UDP"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Password   : ${pass}"
    echo -e "CITY       : ${city}"
    echo -e "ISP        : ${isp}"
    echo -e "IP ISP     : ${ip}"
    echo -e "Domain     : ${domain}"
    echo -e "Expired On : ${exp}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $2}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    CITY=$(cat /root/tendo/city)
    ISP=$(cat /root/tendo/isp)
    UPTIME=$(uptime -p | sed 's/up //')
    
    # Traffic Calculation
    RX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}')
    TX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}')
    RX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}')
    TX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}')
    
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes); sleep 0.4
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
    TRAFFIC=$(echo "scale=2; (($R2 - $R1) + ($T2 - $T1)) * 8 / 409.6 / 1024" | bc)
    
    # Account Counters
    ACC_VMESS=$(wc -l < "$D_VMESS" 2>/dev/null || echo 0)
    ACC_VLESS=$(wc -l < "$D_VLESS" 2>/dev/null || echo 0)
    ACC_TROJAN=$(wc -l < "$D_TROJAN" 2>/dev/null || echo 0)
    ACC_ZIVPN=$(wc -l < "$D_ZIVPN" 2>/dev/null || echo 0)

    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│              ${YELLOW}TENDO STORE ULTIMATE${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    printf "${CYAN}│${NC} OS      : ${WHITE}%-s${NC}\n" "$OS"
    printf "${CYAN}│${NC} RAM     : ${WHITE}%-s${NC}\n" "${RAM}MB"
    printf "${CYAN}│${NC} SWAP    : ${WHITE}%-s${NC}\n" "${SWAP}MB"
    printf "${CYAN}│${NC} CITY    : ${WHITE}%-s${NC}\n" "$CITY"
    printf "${CYAN}│${NC} ISP     : ${WHITE}%-s${NC}\n" "$ISP"
    printf "${CYAN}│${NC} IP      : ${WHITE}%-s${NC}\n" "$IP"
    printf "${CYAN}│${NC} DOMAIN  : ${YELLOW}%-s${NC}\n" "$DOMAIN"
    printf "${CYAN}│${NC} UPTIME  : ${WHITE}%-s${NC}\n" "$UPTIME"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│${NC} ${PURPLE}TODAY${NC}   : ${GREEN}RX:${NC} $RX_DAY ${CYAN}|${NC} ${RED}TX:${NC} $TX_DAY"
    echo -e "${CYAN}│${NC} ${PURPLE}MONTH${NC}   : ${GREEN}RX:${NC} $RX_MON ${CYAN}|${NC} ${RED}TX:${NC} $TX_MON"
    printf "${CYAN}│${NC} ${PURPLE}SPEED${NC}   : ${WHITE}%-s${NC}\n" "$TRAFFIC Mbit/s"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if iptables -L >/dev/null 2>&1; then I_ST="${GREEN}ON${NC}"; else I_ST="${RED}OFF${NC}"; fi
    
    printf "${CYAN}│${NC} STATUS  : XRAY: %b ${CYAN}|${NC} ZIVPN: %b ${CYAN}|${NC} IPtables: %b\n" "$X_ST" "$Z_ST" "$I_ST"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
    
    # LIST ACCOUNTS BOX
    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│                   ${YELLOW}LIST ACCOUNTS${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────${NC}"
    printf "${CYAN}│${NC} VMESS          : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_VMESS"
    printf "${CYAN}│${NC} VLESS          : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_VLESS"
    printf "${CYAN}│${NC} TROJAN         : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_TROJAN"
    printf "${CYAN}│${NC} ZIVPN          : ${WHITE}%-4s${NC} ACCOUNT\n" "$ACC_ZIVPN"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
}

function header_sub() {
    clear; echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│              ${YELLOW}TENDO STORE - SUB MENU${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
}

function change_domain_menu() {
    header_sub
    echo -e "${YELLOW}WARNING: Mengganti domain akan memperbarui sertifikat SSL!${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
    read -p "Masukan Domain Baru: " nd
    if [[ -z "$nd" ]]; then return; fi
    echo -e "${YELLOW}Processing...${NC}"
    echo "$nd" > /usr/local/etc/xray/domain
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout /usr/local/etc/xray/xray.key -out /usr/local/etc/xray/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1
    systemctl restart xray
    echo -e "${GREEN}Domain Berhasil Diperbarui menjadi: $nd${NC}"
    sleep 2
}

function features_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Check Bandwidth (Vnstat)"
        echo -e "${CYAN}│${NC} [2] Speedtest by Ookla (Official)"
        echo -e "${CYAN}│${NC} [3] Check Benchmark VPS (YABS)"
        echo -e "${CYAN}│${NC} [4] Restart All Services"
        echo -e "${CYAN}│${NC} [5] Clear Cache RAM"
        echo -e "${CYAN}│${NC} [6] Auto Reboot"
        echo -e "${CYAN}│${NC} [7] Information System"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) vnstat -l -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1);;
            2) speedtest; read -p "Enter...";;
            3) echo -e "${YELLOW}Running Benchmark...${NC}"; wget -qO- bench.sh | bash; read -p "Enter...";;
            4) systemctl restart xray zivpn vnstat; echo -e "${GREEN}Services Restarted!${NC}"; sleep 2;;
            5) sync; echo 3 > /proc/sys/vm/drop_caches; echo -e "${GREEN}Cache Cleared!${NC}"; sleep 1;;
            6) echo -e "Set Auto Reboot (00:00 UTC)"; echo "0 0 * * * root reboot" > /etc/cron.d/autoreboot; service cron restart; echo -e "${GREEN}Done!${NC}"; sleep 1;;
            7) neofetch; read -p "Enter...";;
            x) return;;
        esac
    done
}

function vmess_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Vmess"
        echo -e "${CYAN}│${NC} [2] Delete Account Vmess"
        echo -e "${CYAN}│${NC} [3] Renew Account Vmess"
        echo -e "${CYAN}│${NC} [4] Check Config User"
        echo -e "${CYAN}│${NC} [5] Trial Account Vmess"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " UUID (Enter for random): " uid_in; [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP (0 for unlimited): " limit; [[ -z "$limit" ]] && limit=0; read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] && quota=0; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vmess")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VMESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "vmess://$ws_tls" "vmess://$ws_ntls" "vmess://$grpc_tls" "vmess://$upg_tls" "vmess://$upg_ntls";;
            2) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); sed -i "${n}d" $D_VMESS; jq --arg u "$u" '(.inbounds[] | select(.protocol == "vmess")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
            3) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VMESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$id|$exp_new|$limit|$stat|$quota/" $D_VMESS; echo -e "${GREEN}Account $u Renewed until $exp_new!${NC}"; systemctl restart xray; sleep 2;;
            4) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VMESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); quota=$(echo "$line" | cut -d'|' -f6); [[ -z "$quota" ]] && quota=0; DMN=$(cat /usr/local/etc/xray/domain)
               down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); [[ -z "$down" ]] && down=0; [[ -z "$up" ]] && up=0; usage_gb=$(awk "BEGIN {printf \"%.2f\", ($down + $up)/1073741824}")
               ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "$usage_gb" "vmess://$ws_tls" "vmess://$ws_ntls" "vmess://$grpc_tls" "vmess://$upg_tls" "vmess://$upg_ntls";;
            5) read -p " Username (Trial): " u; id=$(uuidgen); read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp_date=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); limit=1; quota=0; jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vmess")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VMESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "vmess://$ws_tls" "vmess://$ws_ntls" "vmess://$grpc_tls" "vmess://$upg_tls" "vmess://$upg_ntls";;
            x) return;;
        esac; done
}

function vless_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Vless"
        echo -e "${CYAN}│${NC} [2] Delete Account Vless"
        echo -e "${CYAN}│${NC} [3] Renew Account Vless"
        echo -e "${CYAN}│${NC} [4] Check Config User"
        echo -e "${CYAN}│${NC} [5] Trial Account Vless"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " UUID (Enter for random): " uid_in; [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP (0 for unlimited): " limit; [[ -z "$limit" ]] && limit=0; read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] && quota=0; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vless")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VLESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="vless://${id}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="vless://${id}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               grpc_tls="vless://${id}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${u}"
               upg_tls="vless://${id}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               upg_ntls="vless://${id}@${DMN}:80?path=%2Fvless-upg&security=none&encryption=none&host=${DMN}&type=httpupgrade#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "$upg_ntls";;
            2) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); sed -i "${n}d" $D_VLESS; jq --arg u "$u" '(.inbounds[] | select(.protocol == "vless")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
            3) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VLESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$id|$exp_new|$limit|$stat|$quota/" $D_VLESS; echo -e "${GREEN}Account $u Renewed until $exp_new!${NC}"; systemctl restart xray; sleep 2;;
            4) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VLESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); quota=$(echo "$line" | cut -d'|' -f6); [[ -z "$quota" ]] && quota=0; DMN=$(cat /usr/local/etc/xray/domain)
               down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); [[ -z "$down" ]] && down=0; [[ -z "$up" ]] && up=0; usage_gb=$(awk "BEGIN {printf \"%.2f\", ($down + $up)/1073741824}")
               ws_tls="vless://${id}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="vless://${id}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               grpc_tls="vless://${id}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${u}"
               upg_tls="vless://${id}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               upg_ntls="vless://${id}@${DMN}:80?path=%2Fvless-upg&security=none&encryption=none&host=${DMN}&type=httpupgrade#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "$usage_gb" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "$upg_ntls";;
            5) read -p " Username (Trial): " u; id=$(uuidgen); read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp_date=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); limit=1; quota=0; jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vless")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VLESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="vless://${id}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="vless://${id}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               grpc_tls="vless://${id}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${u}"
               upg_tls="vless://${id}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               upg_ntls="vless://${id}@${DMN}:80?path=%2Fvless-upg&security=none&encryption=none&host=${DMN}&type=httpupgrade#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "$upg_ntls";;
            x) return;;
        esac; done
}

function trojan_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Trojan"
        echo -e "${CYAN}│${NC} [2] Delete Account Trojan"
        echo -e "${CYAN}│${NC} [3] Renew Account Trojan"
        echo -e "${CYAN}│${NC} [4] Check Config User"
        echo -e "${CYAN}│${NC} [5] Trial Account Trojan"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP (0 for unlimited): " limit; [[ -z "$limit" ]] && limit=0; read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] && quota=0; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); pass="$u"; jq --arg p "$pass" --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$pass|$exp_date|$limit|ACTIVE|$quota" >> $D_TROJAN
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="trojan://${pass}@${DMN}:80?path=%2Ftrojan&security=none&host=${DMN}&type=ws#${u}"
               grpc_tls="trojan://${pass}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${u}"
               upg_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "";;
            2) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); sed -i "${n}d" $D_TROJAN; jq --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
            3) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_TROJAN); u=$(echo "$line" | cut -d'|' -f1); pass=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$pass|$exp_new|$limit|$stat|$quota/" $D_TROJAN; echo -e "${GREEN}Account $u Renewed until $exp_new!${NC}"; systemctl restart xray; sleep 2;;
            4) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_TROJAN); u=$(echo "$line" | cut -d'|' -f1); pass=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); quota=$(echo "$line" | cut -d'|' -f6); [[ -z "$quota" ]] && quota=0; DMN=$(cat /usr/local/etc/xray/domain)
               down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); [[ -z "$down" ]] && down=0; [[ -z "$up" ]] && up=0; usage_gb=$(awk "BEGIN {printf \"%.2f\", ($down + $up)/1073741824}")
               ws_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="trojan://${pass}@${DMN}:80?path=%2Ftrojan&security=none&host=${DMN}&type=ws#${u}"
               grpc_tls="trojan://${pass}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${u}"
               upg_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$limit" "$quota" "$usage_gb" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "";;
            5) read -p " Username (Trial): " u; pass="$u"; read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp_date=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); limit=1; quota=0; jq --arg p "$pass" --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$pass|$exp_date|$limit|ACTIVE|$quota" >> $D_TROJAN
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="trojan://${pass}@${DMN}:80?path=%2Ftrojan&security=none&host=${DMN}&type=ws#${u}"
               grpc_tls="trojan://${pass}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${u}"
               upg_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "";;
            x) return;;
        esac; done
}

function zivpn_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account ZIVPN"
        echo -e "${CYAN}│${NC} [2] Delete Account ZIVPN"
        echo -e "${CYAN}│${NC} [3] Renew Account ZIVPN"
        echo -e "${CYAN}│${NC} [4] Check Config User"
        echo -e "${CYAN}│${NC} [5] Trial Account ZIVPN"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Password: " p; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$exp" >> $D_ZIVPN; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            2) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; p=$(sed -n "${n}p" $D_ZIVPN | cut -d'|' -f1); sed -i "${n}d" $D_ZIVPN; jq --arg p "$p" 'del(.auth.config[] | select(. == $p))' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
            3) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); p=$(echo "$line" | cut -d'|' -f1); exp_old=$(echo "$line" | cut -d'|' -f2); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$p|$exp_new/" $D_ZIVPN; echo -e "${GREEN}ZIVPN Account $p Renewed until $exp_new!${NC}"; sleep 2;;
            4) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); p=$(echo "$line" | cut -d'|' -f1); exp=$(echo "$line" | cut -d'|' -f2); DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            5) read -p " Password (Trial): " p; read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$exp" >> $D_ZIVPN; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            x) return;;
        esac; done
}

function check_services() {
    header_sub
    echo -e "${CYAN}┌───────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│               SERVICES STATUS                 ${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────${NC}"
    
    if systemctl is-active --quiet xray; then X_ST="${GREEN}ON${NC}"; else X_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet vnstat; then V_ST="${GREEN}ON${NC}"; else V_ST="${RED}OFF${NC}"; fi
    if iptables -L >/dev/null 2>&1; then I_ST="${GREEN}ON${NC}"; else I_ST="${RED}OFF${NC}"; fi
    
    printf "${CYAN}│${NC} Xray Core       : %b${NC}\n" "$X_ST"
    printf "${CYAN}│${NC} ZIVPN UDP       : %b${NC}\n" "$Z_ST"
    printf "${CYAN}│${NC} Vnstat Mon      : %b${NC}\n" "$V_ST"
    printf "${CYAN}│${NC} IPtables        : %b${NC}\n" "$I_ST"
    
    echo -e "${CYAN}└───────────────────────────────────────────────${NC}"
    read -p "Enter..."
}

while true; do header_main
    echo -e "${CYAN}│${NC} [1] VMESS ACCOUNT        [5] CHANGE DOMAIN VPS"
    echo -e "${CYAN}│${NC} [2] VLESS ACCOUNT        [6] FEATURES"
    echo -e "${CYAN}│${NC} [3] TROJAN ACCOUNT       [7] CHECK SERVICES"
    echo -e "${CYAN}│${NC} [4] ZIVPN UDP            [x] EXIT"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}┌───────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}│${NC}  Version   :  v18.02.26                  ${NC}"
    echo -e "${CYAN}│${NC}  Owner     :  Tendo Store                ${NC}"
    echo -e "${CYAN}│${NC}  Telegram  :  @tendo_32                  ${NC}"
    echo -e "${CYAN}│${NC}  Expiry In :  Lifetime                   ${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────${NC}"
    read -p " Select Menu : " opt
    case $opt in
        1) vmess_menu ;; 2) vless_menu ;; 3) trojan_menu ;;
        4) zivpn_menu ;; 5) change_domain_menu ;; 6) features_menu ;;
        7) check_services ;;
        x) exit ;;
    esac; done
END_MENU

chmod +x /usr/bin/menu
install_spin
print_ok "Instalasi Selesai! Ketik: menu"
