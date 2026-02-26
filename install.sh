#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM CLEAN V.6.0 (ULTIMATE FINAL)
#   Update: Added List Accounts (Count) on Dashboard
#           + Added WS, GRPC, HTTPUpgrade Networks
#           + Added IP Limit Enforcer
#           + Added Auto-Delete Expired Accounts
#           + Custom Detailed Format for VMESS, VLESS, TROJAN
#           + Added Bandwidth Limit (Quota GB) via Xray API
#           + Added Renew Account Feature
#           + Added Trial Feature (Random User & Minutes/Hours)
#           + Added ZIVPN Tracking & Renew
#           + Fixed X-Ray Fallback Path Error
#           + UI Update: Early Domain Prompt & Bouncing Scanner Spinner
#           + Full Telegram Bot Integration (Mono link, Login Notif Fix)
#           + Backup & Restore Data (Direct Link & Telegram Auto-Send)
#           + Multi-Login Auto Lock (10 mins) + Telegram Notif
#           + Quota Exceeded Auto Delete + Telegram Notif
#           + Manual Lock / Unlock Features
#   Script BY: Tendo Store | WhatsApp: +6282224460678
# ==================================================

# --- WARNA & UI ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; WHITE='\033[1;37m'

# --- ANTI INTERACTIVE ---
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# --- ANIMASI INSTALL (BOUNCING SCANNER) ---
function install_spin() {
    local pid=$!
    local delay=0.08
    local frames=(
        "[\e[1;32m=\e[1;36m       ]"
        "[\e[1;32m==\e[1;36m      ]"
        "[\e[1;32m===\e[1;36m     ]"
        "[ \e[1;32m===\e[1;36m    ]"
        "[  \e[1;32m===\e[1;36m   ]"
        "[   \e[1;32m===\e[1;36m  ]"
        "[    \e[1;32m===\e[1;36m ]"
        "[     \e[1;32m===\e[1;36m]"
        "[      \e[1;32m==\e[1;36m]"
        "[       \e[1;32m=\e[1;36m]"
        "[      \e[1;32m==\e[1;36m]"
        "[     \e[1;32m===\e[1;36m]"
        "[    \e[1;32m===\e[1;36m ]"
        "[   \e[1;32m===\e[1;36m  ]"
        "[  \e[1;32m===\e[1;36m   ]"
        "[ \e[1;32m===\e[1;36m    ]"
        "[\e[1;32m===\e[1;36m     ]"
        "[\e[1;32m==\e[1;36m      ]"
    )
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        for frame in "${frames[@]}"; do
            printf "\r\e[1;36m %b\e[0m \e[1;33mSedang memproses, mohon tunggu...\e[0m" "$frame"
            sleep $delay
        done
    done
    printf "\r\e[K"
}

function print_msg() { 
    echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}➤ $1...${NC}"
}
function print_ok() { 
    echo -e "${GREEN}✔ $1 Berhasil!${NC}"
    sleep 0.5
}

# --- 1. PROMPT DOMAIN DI AWAL ---
clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${PURPLE}      AUTO INSTALLER X-RAY & ZIVPN ONLY          ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           Script by Tendo Store                 ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}           PILIHAN JENIS DOMAIN                  ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}│${NC} [1] Gunakan Domain Random Tendo (Gratis/Auto)"
echo -e "${CYAN}│${NC} [2] Gunakan Domain Sendiri (Manual)"
echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
read -p " Pilih Opsi (1/2): " dom_opt

if [[ "$dom_opt" == "1" ]]; then
    echo -e "${YELLOW}Mode Domain Auto terpilih. Domain akan di-generate otomatis.${NC}"
else
    echo -e "${YELLOW}Mode Domain Sendiri${NC}"
    echo -e "${RED}PENTING: Pastikan anda sudah mengarahkan A Record domain ke IP VPS anda!${NC}"
    read -p " Masukan Domain/Subdomain Anda: " user_dom
    if [[ -z "$user_dom" ]]; then
        echo -e "${RED}Domain tidak boleh kosong! Script berhenti.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Domain diatur ke: $user_dom${NC}"
fi
echo -e "${CYAN}=================================================${NC}"
echo -e "${GREEN}Konfigurasi diterima. Memulai proses instalasi...${NC}"
sleep 2
clear

# --- 2. VARIABLES ---
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"
XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
DATA_VMESS="/usr/local/etc/xray/vmess.txt"; DATA_VLESS="/usr/local/etc/xray/vless.txt"; DATA_TROJAN="/usr/local/etc/xray/trojan.txt"
DATA_ZIVPN="/etc/zivpn/zivpn.txt"

# --- 3. OPTIMIZATION ---
print_msg "Optimasi Sistem & Swap"
(
    rm -f /var/lib/apt/lists/lock
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    swapoff -a; rm -f /swapfile
    dd if=/dev/zero of=/swapfile bs=1024 count=2097152
    chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
) >/dev/null 2>&1 & install_spin
print_ok "Optimasi Sistem"

# --- 4. DEPENDENCIES ---
print_msg "Install Dependencies"
(
    apt-get update -y
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl socat jq openssl uuid-runtime net-tools vnstat wget gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch cron zip unzip
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
    apt-get install speedtest -y
    touch /root/.hushlogin; chmod -x /etc/update-motd.d/* 2>/dev/null
    sed -i '/neofetch/d' /root/.bashrc; echo "neofetch" >> /root/.bashrc
    echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc
) >/dev/null 2>&1 & install_spin
print_ok "Dependencies"

# Setup IP & IFACE variables for next steps
IP_VPS=$(curl -s ifconfig.me)
IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

# --- 5. DOMAIN SELECTION EXECUTION & SSL ---
print_msg "Setup Domain & SSL Cert"
(
    systemctl enable vnstat && systemctl restart vnstat; vnstat -u -i $IFACE_NET
    mkdir -p $XRAY_DIR /etc/zivpn /root/tendo /etc/tendo_bot; touch $DATA_VMESS $DATA_VLESS $DATA_TROJAN $DATA_ZIVPN
    mkdir -p /var/log/xray; touch /var/log/xray/access.log /var/log/xray/error.log

    curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
    curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
    curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

    if [[ "$dom_opt" == "1" ]]; then
        DOMAIN_VAL="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
             -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
             -H "Content-Type: application/json" \
             --data '{"type":"A","name":"'${DOMAIN_VAL}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null
    else
        DOMAIN_VAL="$user_dom"
    fi
    echo "$DOMAIN_VAL" > $XRAY_DIR/domain

    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
        -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_VAL"
    chmod 644 $XRAY_DIR/xray.key; chmod 644 $XRAY_DIR/xray.crt
) >/dev/null 2>&1 & install_spin
print_ok "Domain & SSL"

# --- 6. XRAY CONFIG (UPGRADED WITH WS, GRPC, UPGRADE, LOGS & API QUOTA) ---
print_msg "Install Xray Core & Config"
(
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
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
        { "alpn": "h2", "path": "/vmess-grpc", "dest": 10007, "xver": 1 }, { "alpn": "h2", "path": "/vless-grpc", "dest": 10008, "xver": 1 }, { "alpn": "h2", "path": "/trojan-grpc", "dest": 10009, "xver": 1 }
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
) >/dev/null 2>&1 & install_spin
print_ok "Xray Configured"

# --- 7. ZIVPN ---
print_msg "Install ZIVPN"
(
    wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
    chmod +x /usr/local/bin/zivpn
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
    iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
    netfilter-persistent save
) >/dev/null 2>&1 & install_spin
print_ok "ZIVPN Installed"

# --- 8. AUTO-KILL, QUOTA & TELEGRAM SCRIPTS ---
print_msg "Setting up Cron & Telegram Bots"
(
# Script Expiry Auto-Kill
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

# Script Limit IP (Auto Lock 10 Mins)
cat > /usr/local/bin/xray-limit <<'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
LOG_FILE="/var/log/xray/access.log"
TOKEN=$(cat /etc/tendo_bot/bot_token 2>/dev/null | tr -d '\r\n ')
CHATID=$(cat /etc/tendo_bot/chat_id 2>/dev/null | tr -d '\r\n ')
NOW=$(date +%s)

[[ ! -f "$LOG_FILE" ]] && exit 0
tail -n 1000 "$LOG_FILE" | grep "accepted" | awk '{print $3, $7}' | sed 's/tcp://g' | awk -F: '{print $1" "$2}' > /tmp/xray_active.log

for proto in vmess vless trojan; do
    FILE="/usr/local/etc/xray/${proto}.txt"
    [[ ! -f "$FILE" ]] && continue
    while IFS="|" read -r user id exp limit status quota; do
        if [[ "$status" == LOCKED_IP_* ]]; then
            lock_time=${status#LOCKED_IP_}
            if [[ $((NOW - lock_time)) -ge 600 ]]; then
                if [[ "$proto" == "trojan" ]]; then
                    jq --arg p "$id" --arg u "$user" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                else
                    jq --arg id "$id" --arg u "$user" '(.inbounds[] | select(.protocol == "'$proto'")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                fi
                sed -i "s/^$user|.*/$user|$id|$exp|$limit|ACTIVE|$quota/g" "$FILE"
                systemctl restart xray
                if [[ -n "$TOKEN" && -n "$CHATID" ]]; then
                    MSG="<b>✅ ACCOUNT UNLOCKED</b>%0A👤 User: <code>$user</code>%0A🔓 Status: Active (10 mins penalty over)"
                    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHATID}" -d text="${MSG}" -d parse_mode="HTML" > /dev/null
                fi
            fi
            continue
        elif [[ "$status" == "LOCKED" ]]; then
            continue
        fi
        
        [[ -z "$limit" || "$limit" == "0" ]] && continue
        
        active_ips=$(grep -w "$user" /tmp/xray_active.log | awk '{print $1}' | sort -u | wc -l)
        if [[ "$active_ips" -gt "$limit" ]]; then
            jq --arg u "$user" '(.inbounds[] | select(.protocol == "'$proto'")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
            sed -i "s/^$user|.*/$user|$id|$exp|$limit|LOCKED_IP_${NOW}|$quota/g" "$FILE"
            systemctl restart xray
            if [[ -n "$TOKEN" && -n "$CHATID" ]]; then
                MSG="<b>⚠️ MULTI-LOGIN DETECTED</b>%0A👤 User: <code>$user</code>%0A🌐 Limit: $limit IP%0A🚨 Login: $active_ips IP%0A⛔ Status: Locked for 10 Mins"
                curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHATID}" -d text="${MSG}" -d parse_mode="HTML" > /dev/null
            fi
        fi
    done < "$FILE"
done
EOF
chmod +x /usr/local/bin/xray-limit

# Script Quota (Auto Delete)
cat > /usr/local/bin/xray-quota <<'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
TOKEN=$(cat /etc/tendo_bot/bot_token 2>/dev/null | tr -d '\r\n ')
CHATID=$(cat /etc/tendo_bot/chat_id 2>/dev/null | tr -d '\r\n ')

for proto in vmess vless trojan; do
    FILE="/usr/local/etc/xray/${proto}.txt"
    [[ ! -f "$FILE" ]] && continue
    while IFS="|" read -r user id exp limit status quota; do
        [[ -z "$quota" || "$quota" == "0" || "$status" == "LOCKED" || "$status" == LOCKED_IP_* ]] && continue
        down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${user}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"')
        up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${user}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"')
        [[ -z "$down" ]] && down=0
        [[ -z "$up" ]] && up=0
        total_bytes=$((down + up))
        quota_bytes=$(awk "BEGIN {printf \"%.0f\", $quota * 1073741824}")
        if [ "$total_bytes" -ge "$quota_bytes" ]; then
            jq --arg u "$user" '(.inbounds[] | select(.protocol == "'$proto'")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
            sed -i "/^$user|/d" "$FILE"
            systemctl restart xray
            if [[ -n "$TOKEN" && -n "$CHATID" ]]; then
                MSG="<b>🚫 QUOTA EXCEEDED</b>%0A👤 User: <code>$user</code>%0A📊 Limit: ${quota} GB%0A⛔ Status: Account Deleted"
                curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHATID}" -d text="${MSG}" -d parse_mode="HTML" > /dev/null
            fi
        fi
    done < "$FILE"
done
EOF
chmod +x /usr/local/bin/xray-quota

# Script Telegram Login Notif (FIXED)
cat > /usr/local/bin/bot-login-notif <<'EOF'
#!/bin/bash
TOKEN=$(cat /etc/tendo_bot/bot_token 2>/dev/null | tr -d '\r\n ')
CHATID=$(cat /etc/tendo_bot/chat_id 2>/dev/null | tr -d '\r\n ')
[[ -z "$TOKEN" || -z "$CHATID" ]] && exit 0
LOG_FILE="/var/log/xray/access.log"

awk '{ip=$3; gsub(/:.*/, "", ip); print ip, $NF}' "$LOG_FILE" | sort -u > /tmp/bot_active.log

MSG="<b>📊 LAPORKAN PENGGUNA AKTIF (LOGIN)</b>"$'\n'
FOUND=0
for proto in vmess vless trojan; do
    FILE="/usr/local/etc/xray/${proto}.txt"
    [[ ! -f "$FILE" ]] && continue
    while IFS="|" read -r user id exp limit status quota; do
        active_ips=$(grep -w "$user" /tmp/bot_active.log | wc -l)
        if [[ "$active_ips" -gt 0 ]]; then
            MSG+=$'\n'"👤 User: <code>$user</code> | 🌐 Login: $active_ips IP (dipakek $active_ips user)"
            FOUND=1
        fi
    done < "$FILE"
done

if [[ "$FOUND" -eq 1 ]]; then
    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
        -d "chat_id=${CHATID}" \
        --data-urlencode "text=${MSG}" \
        -d "parse_mode=HTML" > /dev/null
fi
EOF
chmod +x /usr/local/bin/bot-login-notif

# Script Telegram Backup Notif (FIXED FILE UPLOAD)
cat > /usr/local/bin/bot-backup <<'EOF'
#!/bin/bash
if ! command -v zip &> /dev/null; then apt-get install -y zip >/dev/null 2>&1; fi
TOKEN=$(cat /etc/tendo_bot/bot_token 2>/dev/null | tr -d '\r\n ')
CHATID=$(cat /etc/tendo_bot/chat_id 2>/dev/null | tr -d '\r\n ')
[[ -z "$TOKEN" || -z "$CHATID" ]] && exit 0
DATE=$(date +"%Y-%m-%d_%H-%M")
ZIP_FILE="/tmp/Backup_${DATE}.zip"
cd /
zip -r $ZIP_FILE usr/local/etc/xray/ etc/zivpn/ etc/tendo_bot/ >/dev/null 2>&1
cd - >/dev/null 2>&1
[[ ! -f "$ZIP_FILE" ]] && exit 0

curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendDocument" \
    -F "chat_id=${CHATID}" \
    -F "document=@${ZIP_FILE}" \
    -F "caption=📦 AUTOBACKUP VPS

📅 Date: ${DATE}
✅ Backup Successfully generated." > /dev/null
rm -f $ZIP_FILE
EOF
chmod +x /usr/local/bin/bot-backup

(crontab -l 2>/dev/null | grep -v "xray-exp"; echo "* * * * * /usr/local/bin/xray-exp") | crontab -
(crontab -l 2>/dev/null | grep -v "xray-limit"; echo "* * * * * /usr/local/bin/xray-limit") | crontab -
(crontab -l 2>/dev/null | grep -v "xray-quota"; echo "* * * * * /usr/local/bin/xray-quota") | crontab -
) >/dev/null 2>&1 & install_spin
print_ok "Sistem Auto & Cron Jobs"

# --- 9. MENU SCRIPT ---
print_msg "Finalisasi Menu"
(
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; WHITE='\033[1;37m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
D_VMESS="/usr/local/etc/xray/vmess.txt"
D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"
D_ZIVPN="/etc/zivpn/zivpn.txt"

# ---------------------------------------------
# PENGIRIM TELEGRAM BOT (FIXED MONO & NEWLINE)
# ---------------------------------------------
function send_tele() {
    local bot_tok=$(cat /etc/tendo_bot/bot_token 2>/dev/null | tr -d '\r\n ')
    local chat_id=$(cat /etc/tendo_bot/chat_id 2>/dev/null | tr -d '\r\n ')
    [[ -z "$bot_tok" || -z "$chat_id" ]] && return
    
    # Render string menjadi format multi-line yg aman untuk curl
    local msg=$(echo -e "$1")
    local full_msg="<b>✅ NEW ACCOUNT CREATED</b>"$'\n\n'"$msg"
    
    curl -s -X POST "https://api.telegram.org/bot${bot_tok}/sendMessage" \
        -d "chat_id=${chat_id}" \
        --data-urlencode "text=${full_msg}" \
        -d "parse_mode=HTML" > /dev/null &
}

# ---------------------------------------------
# FUNGSI OUTPUT DETAIL AKUN XRAY & TELEGRAM BOT
# ---------------------------------------------
function show_account_xray() {
    clear
    local proto=$1; local user=$2; local domain=$3; local uuid=$4; local exp=$5; local limit=$6; local quota=$7; local usage=$8
    local link_ws_tls=$9; local link_ws_ntls=${10}; local link_grpc_tls=${11}; local link_upg_tls=${12}; local link_upg_ntls=${13}
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city)
    [[ "$quota" == "0" ]] && str_quota="Unlimited" || str_quota="${quota} GB"

    local MSG=""
    local MSG_BOT=""
    
    if [[ "$proto" == "VMESS" ]]; then
        MSG+="————————————————————————————————————\n               VMESS\n————————————————————————————————————\n"
        MSG+="Remarks        : ${user}\nCITY           : ${city}\nISP            : ${isp}\nDomain         : ${domain}\n"
        MSG+="Port TLS       : 443\nPort none TLS  : 80\nid             : ${uuid}\nalterId        : 0\n"
        MSG+="Security       : auto\nnetwork        : ws, grpc, upgrade\npath ws        : /vmess\n"
        MSG+="serviceName    : vmess-grpc\npath upgrade   : /vmess-upg\nLimit IP       : ${limit} IP\n"
        MSG+="Quota Bandwidth: ${str_quota}\nUsage Bandwidth: ${usage} GB\nExpired On     : ${exp}\n"
        MSG+="————————————————————————————————————\n           VMESS WS TLS\n————————————————————————————————————\n${link_ws_tls}\n"
        MSG+="————————————————————————————————————\n          VMESS WS NO TLS\n————————————————————————————————————\n${link_ws_ntls}\n"
        MSG+="————————————————————————————————————\n             VMESS GRPC\n————————————————————————————————————\n${link_grpc_tls}\n"
        MSG+="————————————————————————————————————\n         VMESS Upgrade TLS\n————————————————————————————————————\n${link_upg_tls}\n"
        MSG+="————————————————————————————————————\n        VMESS Upgrade NO TLS\n————————————————————————————————————\n${link_upg_ntls}\n————————————————————————————————————\n"
    elif [[ "$proto" == "VLESS" ]]; then
        MSG+="————————————————————————————————————\n               VLESS\n————————————————————————————————————\n"
        MSG+="Remarks        : ${user}\nCITY           : ${city}\nISP            : ${isp}\nDomain         : ${domain}\n"
        MSG+="Port TLS       : 443\nPort none TLS  : 80\nid             : ${uuid}\nEncryption     : none\n"
        MSG+="Network        : ws, grpc, upgrade\nPath ws        : /vless\nserviceName    : vless-grpc\n"
        MSG+="Path upgrade   : /vless-upg\nLimit IP       : ${limit} IP\nQuota Bandwidth: ${str_quota}\n"
        MSG+="Usage Bandwidth: ${usage} GB\nExpired On     : ${exp}\n"
        MSG+="————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n${link_ws_tls}\n"
        MSG+="————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n${link_ws_ntls}\n"
        MSG+="————————————————————————————————————\n             VLESS GRPC\n————————————————————————————————————\n${link_grpc_tls}\n"
        MSG+="————————————————————————————————————\n          VLESS Upgrade TLS\n————————————————————————————————————\n${link_upg_tls}\n"
        MSG+="————————————————————————————————————\n        VLESS Upgrade NO TLS\n————————————————————————————————————\n${link_upg_ntls}\n————————————————————————————————————\n"
    elif [[ "$proto" == "TROJAN" ]]; then
        MSG+="————————————————————————————————————\n               TROJAN\n————————————————————————————————————\n"
        MSG+="Remarks      : ${user}\nCITY         : ${city}\nISP          : ${isp}\nDomain       : ${domain}\n"
        MSG+="Port         : 443\nKey          : ${uuid}\nNetwork      : ws, grpc, upgrade\n"
        MSG+="Path ws      : /trojan\nserviceName  : trojan-grpc\nPath upgrade : /trojan-upg\n"
        MSG+="Limit IP     : ${limit} IP\nQuota Limit  : ${str_quota}\nUsage Traffic: ${usage} GB\nExpired On   : ${exp}\n"
        MSG+="————————————————————————————————————\n           TROJAN WS TLS\n————————————————————————————————————\n${link_ws_tls}\n"
        MSG+="————————————————————————————————————\n            TROJAN GRPC\n————————————————————————————————————\n${link_grpc_tls}\n"
        MSG+="————————————————————————————————————\n         TROJAN Upgrade TLS\n————————————————————————————————————\n${link_upg_tls}\n"
        MSG+="——————————\n——————————————————————————\n"
    fi

    # Format Telegram Bot (Mono Links & Detail)
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="               <b>${proto}</b>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="Remarks        : <code>${user}</code>\n"
    MSG_BOT+="CITY           : ${city}\n"
    MSG_BOT+="ISP            : ${isp}\n"
    MSG_BOT+="Domain         : <code>${domain}</code>\n"
    MSG_BOT+="Port TLS       : 443\n"
    MSG_BOT+="Port none TLS  : 80\n"
    if [[ "$proto" == "TROJAN" ]]; then MSG_BOT+="Key          : <code>${uuid}</code>\n"; else MSG_BOT+="id             : <code>${uuid}</code>\n"; fi
    if [[ "$proto" == "VMESS" ]]; then MSG_BOT+="alterId        : 0\nSecurity       : auto\n"; elif [[ "$proto" == "VLESS" ]]; then MSG_BOT+="Encryption     : none\n"; fi
    MSG_BOT+="network        : ws, grpc, upgrade\n"
    MSG_BOT+="path ws        : /${proto,,}\n"
    MSG_BOT+="serviceName    : ${proto,,}-grpc\n"
    MSG_BOT+="path upgrade   : /${proto,,}-upg\n"
    MSG_BOT+="Limit IP       : ${limit} IP\n"
    MSG_BOT+="Quota Bandwidth: ${str_quota}\n"
    MSG_BOT+="Usage Bandwidth: ${usage} GB\n"
    MSG_BOT+="Expired On     : ${exp}\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="           <b>${proto} WS TLS</b>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="<code>${link_ws_tls}</code>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    if [[ -n "$link_ws_ntls" ]]; then
        MSG_BOT+="          <b>${proto} WS NO TLS</b>\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n"
        MSG_BOT+="<code>${link_ws_ntls}</code>\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n"
    fi
    MSG_BOT+="             <b>${proto} GRPC</b>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="<code>${link_grpc_tls}</code>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="         <b>${proto} Upgrade TLS</b>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    MSG_BOT+="<code>${link_upg_tls}</code>\n"
    MSG_BOT+="<b>————————————————————————————————————</b>\n"
    if [[ -n "$link_upg_ntls" ]]; then
        MSG_BOT+="        <b>${proto} Upgrade NO TLS</b>\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n"
        MSG_BOT+="<code>${link_upg_ntls}</code>\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n"
    fi

    echo -e "$MSG"
    send_tele "$MSG_BOT"
    echo ""
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function show_account_zivpn() {
    clear
    local pass=$1; local domain=$2; local exp=$3
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city); local ip=$(cat /root/tendo/ip)

    local MSG=""
    MSG+="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    MSG+="  ACCOUNT ZIVPN UDP\n"
    MSG+="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    MSG+="Password   : ${pass}\n"
    MSG+="CITY       : ${city}\n"
    MSG+="ISP        : ${isp}\n"
    MSG+="IP ISP     : ${ip}\n"
    MSG+="Domain     : ${domain}\n"
    MSG+="Expired On : ${exp}\n"
    MSG+="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    
    local MSG_BOT=""
    MSG_BOT+="<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
    MSG_BOT+="  <b>ACCOUNT ZIVPN UDP</b>\n"
    MSG_BOT+="<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
    MSG_BOT+="Password   : <code>${pass}</code>\n"
    MSG_BOT+="CITY       : ${city}\n"
    MSG_BOT+="ISP        : ${isp}\n"
    MSG_BOT+="IP ISP     : <code>${ip}</code>\n"
    MSG_BOT+="Domain     : <code>${domain}</code>\n"
    MSG_BOT+="Expired On : ${exp}\n"
    MSG_BOT+="<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"

    echo -e "$MSG"
    send_tele "$MSG_BOT"
    echo ""
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

# ---------------------------------------------
# FUNGSI HEADER & DASHBOARD UTAMA
# ---------------------------------------------
function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $2}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    CITY=$(cat /root/tendo/city)
    ISP=$(cat /root/tendo/isp)
    UPTIME=$(uptime -p | sed 's/up //')
    
    # Traffic Calculation (Detailed Bandwidth)
    MONTH_NAME=$(date +%B)
    DAY_NAME=$(date +%A)
    RX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}' 2>/dev/null || echo "0 B")
    TX_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}' 2>/dev/null || echo "0 B")
    TOT_DAY=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $6}' 2>/dev/null || echo "0 B")
    RX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}' 2>/dev/null || echo "0 B")
    TX_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}' 2>/dev/null || echo "0 B")
    TOT_MON=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $11}' 2>/dev/null || echo "0 B")
    
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
    echo -e "${CYAN}│${NC}  MONTH   : $TOT_MON   [$MONTH_NAME]"
    echo -e "${CYAN}│${NC}   RX      : $RX_MON"
    echo -e "${CYAN}│${NC}   TX      : $TX_MON"
    echo -e "${CYAN}│${NC}  —————————————————————————————————————"
    echo -e "${CYAN}│${NC}  DAY     : $TOT_DAY    [$DAY_NAME]"
    echo -e "${CYAN}│${NC}   RX      : $RX_DAY"
    echo -e "${CYAN}│${NC}   TX      : $TX_DAY"
    echo -e "${CYAN}│${NC}   TRAFFIC : $TRAFFIC Mbit/s"
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

# ---------------------------------------------
# MENU TELEGRAM BOT SETUP
# ---------------------------------------------
function menu_login_notif() {
    while true; do header_sub
        local st=$(cat /etc/tendo_bot/log_stat 2>/dev/null || echo "OFF")
        echo -e " ————————————————————————————————————————"
        echo -e "        Status [${st}]"
        echo -e "   1.)  OFF"
        echo -e "   2.)  Set Time Notif (h) untuk jam dan (m) untuk meniit"
        echo -e "   x.)  Exit"
        echo -e " ————————————————————————————————————————"
        read -p " Pilihan: " opt2
        case $opt2 in
            1) echo "OFF" > /etc/tendo_bot/log_stat; crontab -l | grep -v "bot-login-notif" > /tmp/c.tmp; crontab /tmp/c.tmp; echo -e "${GREEN}Turned OFF${NC}"; sleep 1;;
            2) read -p " Durasi (e.g., 10m, 1h): " dur; 
               if [[ "$dur" == *m ]]; then c="*/${dur%m} * * * *"; elif [[ "$dur" == *h ]]; then c="0 */${dur%h} * * *"; else echo "Invalid"; sleep 1; continue; fi
               echo "ON (${dur})" > /etc/tendo_bot/log_stat
               crontab -l | grep -v "bot-login-notif" > /tmp/c.tmp; echo "$c /usr/local/bin/bot-login-notif" >> /tmp/c.tmp; crontab /tmp/c.tmp
               echo -e "${GREEN}Cron set to $dur${NC}"; sleep 1;;
            x) return;;
        esac
    done
}

function menu_backup_notif() {
    while true; do header_sub
        local st=$(cat /etc/tendo_bot/bak_stat 2>/dev/null || echo "OFF")
        echo -e " ————————————————————————————————————————"
        echo -e "        Status [${st}]"
        echo -e "   1.)  OFF"
        echo -e "   2.)  Set Time Backup (h) untuk jam dan (m) untuk meniit"
        echo -e "   x.)  Exit"
        echo -e " ————————————————————————————————————————"
        read -p " Pilihan: " opt3
        case $opt3 in
            1) echo "OFF" > /etc/tendo_bot/bak_stat; crontab -l | grep -v "bot-backup" > /tmp/c.tmp; crontab /tmp/c.tmp; echo -e "${GREEN}Turned OFF${NC}"; sleep 1;;
            2) read -p " Durasi (e.g., 10m, 12h): " dur; 
               if [[ "$dur" == *m ]]; then c="*/${dur%m} * * * *"; elif [[ "$dur" == *h ]]; then c="0 */${dur%h} * * *"; else echo "Invalid"; sleep 1; continue; fi
               echo "ON (${dur})" > /etc/tendo_bot/bak_stat
               crontab -l | grep -v "bot-backup" > /tmp/c.tmp; echo "$c /usr/local/bin/bot-backup" >> /tmp/c.tmp; crontab /tmp/c.tmp
               echo -e "${GREEN}Cron set to $dur${NC}"; sleep 1;;
            x) return;;
        esac
    done
}

function bot_menu() {
    while true; do header_sub
        local st_log=$(cat /etc/tendo_bot/log_stat 2>/dev/null || echo "OFF")
        local st_bak=$(cat /etc/tendo_bot/bak_stat 2>/dev/null || echo "OFF")
        echo -e "${CYAN}│${NC} [1] Change BOT API & CHATID"
        echo -e "${CYAN}│${NC} [2] Set notifikasi User login"
        echo -e "${CYAN}│${NC} [3] Set notifikasi backup"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Bot Token: " bt; read -p " Chat ID: " ci; echo "$bt" > /etc/tendo_bot/bot_token; echo "$ci" > /etc/tendo_bot/chat_id; echo -e "${GREEN}Saved Successfully!${NC}"; sleep 1;;
            2) menu_login_notif ;;
            3) menu_backup_notif ;;
            x) return;;
        esac
    done
}

# ---------------------------------------------
# MENU FEATURES UTAMA (TERMASUK DOMAIN & BACKUP)
# ---------------------------------------------
function features_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Check Bandwidth (Vnstat)"
        echo -e "${CYAN}│${NC} [2] Speedtest by Ookla (Official)"
        echo -e "${CYAN}│${NC} [3] Check Benchmark VPS (YABS)"
        echo -e "${CYAN}│${NC} [4] Change Domain VPS"
        echo -e "${CYAN}│${NC} [5] Restart All Services"
        echo -e "${CYAN}│${NC} [6] Clear Cache RAM"
        echo -e "${CYAN}│${NC} [7] Auto Reboot"
        echo -e "${CYAN}│${NC} [8] Information System"
        echo -e "${CYAN}│${NC} [9] Backup Data VPS (Auto Telegram & Link)"
        echo -e "${CYAN}│${NC} [10] Restore Data VPS (Direct Link)"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) vnstat -l -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1); read -p "Enter...";;
            2) speedtest; read -p "Enter...";;
            3) echo -e "${YELLOW}Running Benchmark...${NC}"; wget -qO- bench.sh | bash; read -p "Enter...";;
            4) header_sub
               echo -e "${YELLOW}WARNING: Mengganti domain akan memperbarui sertifikat SSL!${NC}"
               echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
               read -p "Masukan Domain Baru: " nd
               if [[ -z "$nd" ]]; then continue; fi
               echo -e "${YELLOW}Processing...${NC}"
               echo "$nd" > /usr/local/etc/xray/domain
               openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout /usr/local/etc/xray/xray.key -out /usr/local/etc/xray/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1
               systemctl restart xray
               echo -e "${GREEN}Domain Berhasil Diperbarui menjadi: $nd${NC}"
               sleep 2;;
            5) systemctl restart xray zivpn vnstat; echo -e "${GREEN}Services Restarted!${NC}"; sleep 2;;
            6) sync; echo 3 > /proc/sys/vm/drop_caches; echo -e "${GREEN}Cache Cleared!${NC}"; sleep 1;;
            7) echo -e "Set Auto Reboot (00:00 UTC)"; echo "0 0 * * * root reboot" > /etc/cron.d/autoreboot; service cron restart; echo -e "${GREEN}Done!${NC}"; sleep 1;;
            8) neofetch; read -p "Enter...";;
            9) 
               clear; echo -e "${YELLOW}Memproses Backup Data VPS...${NC}"
               if ! command -v zip &> /dev/null; then apt-get install -y zip >/dev/null 2>&1; fi
               DATE=$(date +"%Y-%m-%d_%H-%M")
               ZIP_FILE="/root/Backup_${DATE}.zip"
               cd /
               zip -r $ZIP_FILE usr/local/etc/xray/ etc/zivpn/ etc/tendo_bot/ >/dev/null 2>&1
               cd - >/dev/null 2>&1
               
               if [[ ! -f "$ZIP_FILE" ]]; then
                   echo -e "${RED}Gagal membuat file backup!${NC}"
                   read -p "Tekan Enter untuk kembali..."
                   continue
               fi

               echo -e "${GREEN}File Backup tersimpan di VPS: ${ZIP_FILE}${NC}"
               echo -e "${YELLOW}Mengunggah ke server cloud (Mencari Direct Link)...${NC}"
               LINK=$(curl -s --upload-file $ZIP_FILE https://transfer.sh/Backup_${DATE}.zip)
               echo -e "\n${CYAN}=================================================${NC}"
               echo -e "${GREEN}Sukses! Simpan link di bawah ini untuk Restore:${NC}"
               echo -e "${WHITE}${LINK}${NC}"
               echo -e "${CYAN}=================================================${NC}\n"
               
               local bot_tok=$(cat /etc/tendo_bot/bot_token 2>/dev/null | tr -d '\r\n ')
               local chat_id=$(cat /etc/tendo_bot/chat_id 2>/dev/null | tr -d '\r\n ')
               if [[ -n "$bot_tok" && -n "$chat_id" ]]; then
                   echo -e "${YELLOW}Mengirim backup ke Telegram Bot...${NC}"
                   curl -s -X POST "https://api.telegram.org/bot${bot_tok}/sendDocument" \
                       -F "chat_id=${chat_id}" \
                       -F "document=@${ZIP_FILE}" \
                       -F "caption=📦 MANUAL BACKUP VPS
                       
📅 Date: ${DATE}
✅ Backup Successfully generated.
🔗 Direct Link: ${LINK}" > /dev/null
                   echo -e "${GREEN}File backup berhasil dikirim ke Telegram!${NC}"
               fi
               read -p "Tekan Enter untuk kembali..."
               ;;
            10) 
               clear; echo -e "${YELLOW}--- RESTORE DATA VPS ---${NC}"
               echo -e "${RED}Warning: Data saat ini akan ditimpa dengan data dari Backup!${NC}"
               read -p " Masukkan Link Direct Backup (.zip) : " link_res
               if [[ -n "$link_res" ]]; then
                   echo -e "${YELLOW}Mengunduh file backup...${NC}"
                   wget -qO /root/restore.zip "$link_res"
                   if [[ -f "/root/restore.zip" ]]; then
                       echo -e "${YELLOW}Mengekstrak dan memulihkan data (X-ray, ZIVPN, Domain, Bot)...${NC}"
                       cd /
                       unzip -o /root/restore.zip >/dev/null 2>&1
                       cd - >/dev/null 2>&1
                       rm -f /root/restore.zip
                       systemctl restart xray zivpn
                       echo -e "${GREEN}Restore Berhasil! Semua konfigurasi dan akun telah dipulihkan.${NC}"
                   else
                       echo -e "${RED}Gagal mengunduh file! Pastikan link direct yang dimasukkan valid.${NC}"
                   fi
               fi
               read -p "Tekan Enter untuk kembali..."
               ;;
            x) return;;
        esac
    done
}

# ---------------------------------------------
# FUNGSI MENU PROTOKOL (XRAY & ZIVPN)
# ---------------------------------------------
function vmess_menu() {
    while true; do header_sub
        echo -e "${CYAN}│${NC} [1] Create Account Vmess"
        echo -e "${CYAN}│${NC} [2] Delete Account Vmess"
        echo -e "${CYAN}│${NC} [3] Renew Account Vmess"
        echo -e "${CYAN}│${NC} [4] Check Config User"
        echo -e "${CYAN}│${NC} [5] Trial Account Vmess"
        echo -e "${CYAN}│${NC} [6] Lock Account Vmess"
        echo -e "${CYAN}│${NC} [7] Unlock Account Vmess"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " UUID (Enter for random): " uid_in; [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP (0 for unlimited): " limit; [[ -z "$limit" ]] && limit=0; read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] && quota=0; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vmess")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 & echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VMESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "vmess://$ws_tls" "vmess://$ws_ntls" "vmess://$grpc_tls" "vmess://$upg_tls" "vmess://$upg_ntls";;
            2) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VMESS | cut -d'|' -f1); sed -i "${n}d" $D_VMESS; jq --arg u "$u" '(.inbounds[] | select(.protocol == "vmess")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 &;;
            3) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VMESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$id|$exp_new|$limit|$stat|$quota/" $D_VMESS; echo -e "${GREEN}Account $u Renewed until $exp_new!${NC}"; systemctl restart xray >/dev/null 2>&1 & sleep 2;;
            4) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VMESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); quota=$(echo "$line" | cut -d'|' -f6); [[ -z "$quota" ]] && quota=0; DMN=$(cat /usr/local/etc/xray/domain)
               down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); [[ -z "$down" ]] && down=0; [[ -z "$up" ]] && up=0; usage_gb=$(awk "BEGIN {printf \"%.2f\", ($down + $up)/1073741824}")
               ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "$usage_gb" "vmess://$ws_tls" "vmess://$ws_ntls" "vmess://$grpc_tls" "vmess://$upg_tls" "vmess://$upg_ntls";;
            5) u="trial-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"; echo -e " Username (Trial): ${GREEN}$u${NC}"; id=$(uuidgen); read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp_date=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); limit=1; quota=0; jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vmess")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 & echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VMESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
               upg_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${u}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${id}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
               show_account_xray "VMESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "vmess://$ws_tls" "vmess://$ws_ntls" "vmess://$grpc_tls" "vmess://$upg_tls" "vmess://$upg_ntls";;
            6) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VMESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6)
               if [[ "$stat" == "ACTIVE" ]]; then
                   jq --arg u "$u" '(.inbounds[] | select(.protocol == "vmess")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                   sed -i "${n}s/.*/$u|$id|$exp|$limit|LOCKED|$quota/" $D_VMESS
                   systemctl restart xray >/dev/null 2>&1 &
                   echo -e "${GREEN}Account $u Locked Successfully!${NC}"; sleep 2
               else
                   echo -e "${RED}Account is already locked!${NC}"; sleep 2
               fi;;
            7) nl $D_VMESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VMESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6)
               if [[ "$stat" != "ACTIVE" ]]; then
                   jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vmess")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                   sed -i "${n}s/.*/$u|$id|$exp|$limit|ACTIVE|$quota/" $D_VMESS
                   systemctl restart xray >/dev/null 2>&1 &
                   echo -e "${GREEN}Account $u Unlocked Successfully!${NC}"; sleep 2
               else
                   echo -e "${YELLOW}Account is already Active!${NC}"; sleep 2
               fi;;
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
        echo -e "${CYAN}│${NC} [6] Lock Account Vless"
        echo -e "${CYAN}│${NC} [7] Unlock Account Vless"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " UUID (Enter for random): " uid_in; [[ -z "$uid_in" ]] && id=$(uuidgen) || id="$uid_in"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP (0 for unlimited): " limit; [[ -z "$limit" ]] && limit=0; read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] && quota=0; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vless")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 & echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VLESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="vless://${id}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="vless://${id}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               grpc_tls="vless://${id}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${u}"
               upg_tls="vless://${id}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               upg_ntls="vless://${id}@${DMN}:80?path=%2Fvless-upg&security=none&encryption=none&host=${DMN}&type=httpupgrade#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "$upg_ntls";;
            2) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_VLESS | cut -d'|' -f1); sed -i "${n}d" $D_VLESS; jq --arg u "$u" '(.inbounds[] | select(.protocol == "vless")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 &;;
            3) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VLESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$id|$exp_new|$limit|$stat|$quota/" $D_VLESS; echo -e "${GREEN}Account $u Renewed until $exp_new!${NC}"; systemctl restart xray >/dev/null 2>&1 & sleep 2;;
            4) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VLESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); quota=$(echo "$line" | cut -d'|' -f6); [[ -z "$quota" ]] && quota=0; DMN=$(cat /usr/local/etc/xray/domain)
               down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); [[ -z "$down" ]] && down=0; [[ -z "$up" ]] && up=0; usage_gb=$(awk "BEGIN {printf \"%.2f\", ($down + $up)/1073741824}")
               ws_tls="vless://${id}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="vless://${id}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               grpc_tls="vless://${id}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${u}"
               upg_tls="vless://${id}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               upg_ntls="vless://${id}@${DMN}:80?path=%2Fvless-upg&security=none&encryption=none&host=${DMN}&type=httpupgrade#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "$usage_gb" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "$upg_ntls";;
            5) u="trial-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"; echo -e " Username (Trial): ${GREEN}$u${NC}"; id=$(uuidgen); read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp_date=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); limit=1; quota=0; jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vless")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 & echo "$u|$id|$exp_date|$limit|ACTIVE|$quota" >> $D_VLESS
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="vless://${id}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="vless://${id}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
               grpc_tls="vless://${id}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${u}"
               upg_tls="vless://${id}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               upg_ntls="vless://${id}@${DMN}:80?path=%2Fvless-upg&security=none&encryption=none&host=${DMN}&type=httpupgrade#${u}"
               show_account_xray "VLESS" "$u" "$DMN" "$id" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "$upg_ntls";;
            6) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VLESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6)
               if [[ "$stat" == "ACTIVE" ]]; then
                   jq --arg u "$u" '(.inbounds[] | select(.protocol == "vless")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                   sed -i "${n}s/.*/$u|$id|$exp|$limit|LOCKED|$quota/" $D_VLESS
                   systemctl restart xray >/dev/null 2>&1 &
                   echo -e "${GREEN}Account $u Locked Successfully!${NC}"; sleep 2
               else
                   echo -e "${RED}Account is already locked!${NC}"; sleep 2
               fi;;
            7) nl $D_VLESS; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_VLESS); u=$(echo "$line" | cut -d'|' -f1); id=$(echo "$line" | cut -d'|' -f2); exp=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6)
               if [[ "$stat" != "ACTIVE" ]]; then
                   jq --arg u "$u" --arg id "$id" '(.inbounds[] | select(.protocol == "vless")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                   sed -i "${n}s/.*/$u|$id|$exp|$limit|ACTIVE|$quota/" $D_VLESS
                   systemctl restart xray >/dev/null 2>&1 &
                   echo -e "${GREEN}Account $u Unlocked Successfully!${NC}"; sleep 2
               else
                   echo -e "${YELLOW}Account is already Active!${NC}"; sleep 2
               fi;;
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
        echo -e "${CYAN}│${NC} [6] Lock Account Trojan"
        echo -e "${CYAN}│${NC} [7] Unlock Account Trojan"
        echo -e "${CYAN}│${NC} [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username : " u; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP (0 for unlimited): " limit; [[ -z "$limit" ]] && limit=0; read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] && quota=0; exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); pass="$u"; jq --arg p "$pass" --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 & echo "$u|$pass|$exp_date|$limit|ACTIVE|$quota" >> $D_TROJAN
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="trojan://${pass}@${DMN}:80?path=%2Ftrojan&security=none&host=${DMN}&type=ws#${u}"
               grpc_tls="trojan://${pass}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${u}"
               upg_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "";;
            2) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_TROJAN | cut -d'|' -f1); sed -i "${n}d" $D_TROJAN; jq --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 &;;
            3) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_TROJAN); u=$(echo "$line" | cut -d'|' -f1); pass=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$pass|$exp_new|$limit|$stat|$quota/" $D_TROJAN; echo -e "${GREEN}Account $u Renewed until $exp_new!${NC}"; systemctl restart xray >/dev/null 2>&1 & sleep 2;;
            4) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_TROJAN); u=$(echo "$line" | cut -d'|' -f1); pass=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); quota=$(echo "$line" | cut -d'|' -f6); [[ -z "$quota" ]] && quota=0; DMN=$(cat /usr/local/etc/xray/domain)
               down=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>downlink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); up=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -name "user>>>${u}>>>traffic>>>uplink" 2>/dev/null | grep value | awk '{print $2}' | tr -d '"'); [[ -z "$down" ]] && down=0; [[ -z "$up" ]] && up=0; usage_gb=$(awk "BEGIN {printf \"%.2f\", ($down + $up)/1073741824}")
               ws_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="trojan://${pass}@${DMN}:80?path=%2Ftrojan&security=none&host=${DMN}&type=ws#${u}"
               grpc_tls="trojan://${pass}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${u}"
               upg_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$limit" "$quota" "$usage_gb" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "";;
            5) u="trial-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"; echo -e " Username (Trial): ${GREEN}$u${NC}"; pass="$u"; read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp_date=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); limit=1; quota=0; jq --arg p "$pass" --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray >/dev/null 2>&1 & echo "$u|$pass|$exp_date|$limit|ACTIVE|$quota" >> $D_TROJAN
               DMN=$(cat /usr/local/etc/xray/domain)
               ws_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${u}"
               ws_ntls="trojan://${pass}@${DMN}:80?path=%2Ftrojan&security=none&host=${DMN}&type=ws#${u}"
               grpc_tls="trojan://${pass}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${u}"
               upg_tls="trojan://${pass}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${u}"
               show_account_xray "TROJAN" "$u" "$DMN" "$pass" "$exp_date" "$limit" "$quota" "0.00" "$ws_tls" "$ws_ntls" "$grpc_tls" "$upg_tls" "";;
            6) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_TROJAN); u=$(echo "$line" | cut -d'|' -f1); pass=$(echo "$line" | cut -d'|' -f2); exp=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6)
               if [[ "$stat" == "ACTIVE" ]]; then
                   jq --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                   sed -i "${n}s/.*/$u|$pass|$exp|$limit|LOCKED|$quota/" $D_TROJAN
                   systemctl restart xray >/dev/null 2>&1 &
                   echo -e "${GREEN}Account $u Locked Successfully!${NC}"; sleep 2
               else
                   echo -e "${RED}Account is already locked!${NC}"; sleep 2
               fi;;
            7) nl $D_TROJAN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_TROJAN); u=$(echo "$line" | cut -d'|' -f1); pass=$(echo "$line" | cut -d'|' -f2); exp=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); quota=$(echo "$line" | cut -d'|' -f6)
               if [[ "$stat" != "ACTIVE" ]]; then
                   jq --arg p "$pass" --arg u "$u" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
                   sed -i "${n}s/.*/$u|$pass|$exp|$limit|ACTIVE|$quota/" $D_TROJAN
                   systemctl restart xray >/dev/null 2>&1 &
                   echo -e "${GREEN}Account $u Unlocked Successfully!${NC}"; sleep 2
               else
                   echo -e "${YELLOW}Account is already Active!${NC}"; sleep 2
               fi;;
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
            1) read -p " Password: " p; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn >/dev/null 2>&1 & echo "$p|$exp" >> $D_ZIVPN; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            2) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; p=$(sed -n "${n}p" $D_ZIVPN | cut -d'|' -f1); sed -i "${n}d" $D_ZIVPN; jq --arg p "$p" 'del(.auth.config[] | select(. == $p))' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn >/dev/null 2>&1 &;;
            3) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); p=$(echo "$line" | cut -d'|' -f1); exp_old=$(echo "$line" | cut -d'|' -f2); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$p|$exp_new/" $D_ZIVPN; echo -e "${GREEN}ZIVPN Account $p Renewed until $exp_new!${NC}"; systemctl restart zivpn >/dev/null 2>&1 & sleep 2;;
            4) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); p=$(echo "$line" | cut -d'|' -f1); exp=$(echo "$line" | cut -d'|' -f2); DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
            5) p="trial-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"; echo -e " Password (Trial): ${GREEN}$p${NC}"; read -p " Duration (e.g., 10m, 1h): " dur;
               if [[ "$dur" == *m ]]; then add_str="+${dur%m} minutes"; elif [[ "$dur" == *h ]]; then add_str="+${dur%h} hours"; else add_str="+1 hours"; fi
               exp=$(date -d "$add_str" +"%Y-%m-%d %H:%M:%S"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn >/dev/null 2>&1 & echo "$p|$exp" >> $D_ZIVPN; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$p" "$DMN" "$exp";;
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
    echo -e "${CYAN}│${NC} [1] VMESS ACCOUNT        [5] BOT TELEGRAM SETUP"
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
        4) zivpn_menu ;; 5) bot_menu ;; 6) features_menu ;;
        7) check_services ;;
        x) exit ;;
    esac; done
END_MENU
chmod +x /usr/bin/menu
) >/dev/null 2>&1 & install_spin
print_ok "Finalisasi Script"

echo -e "\n${GREEN}=================================================${NC}"
echo -e "${YELLOW}   Instalasi Selesai! Ketik: ${WHITE}menu${YELLOW} untuk mulai  ${NC}"
echo -e "${GREEN}=================================================${NC}\n"
