#!/bin/bash
# ==================================================
#   Auto Script Install X-ray & Zivpn
#   EDITION: PLATINUM LTS FINAL V.101 (UPDATED UI & FEATURES)
#   Update: Custom Domain, Left Pipe UI, Auto Random Trial, Cron Notifs
#   Script BY: Tendo Store | WhatsApp: +6282224460678
#   Features: BBR, Random UUID, Triple Status, Clean UI, Auto Bot Telegram, Auto Kill IP
#   Expiry: Lifetime Support
# ==================================================

export DEBIAN_FRONTEND=noninteractive

clear
echo -e "\033[0;36m─────────────────────────────────────────────────\033[0m"
echo -e "      \033[0;33mAuto Script Install X-ray & Zivpn\033[0m"
echo -e "\033[0;36m─────────────────────────────────────────────────\033[0m"

# --- PILIHAN DOMAIN AWAL ---
echo -e "               \033[0;32mSETUP DOMAIN VPS\033[0m"
echo -e "\033[0;36m─────────────────────────────────────────────────\033[0m"
echo -e " [1] Gunakan Domain Sendiri (Custom Domain)"
echo -e " [2] Gunakan Domain Bawaan Script (Auto Random)"
echo -e "\033[0;36m─────────────────────────────────────────────────\033[0m"
read -p " Pilih Opsi (1/2): " dom_opt

if [[ "$dom_opt" == "1" ]]; then
    read -p " Masukkan Domain Anda: " custom_domain
    DOMAIN_INIT="$custom_domain"
    USE_CF="false"
    echo -e "\033[0;32m[ INFO ]\033[0m Pastikan domain $DOMAIN_INIT sudah di-pointing ke IP VPS ini!"
    sleep 3
else
    DOMAIN_INIT="vpn-$(tr -dc a-z0-9 </dev/urandom | head -c 5).vip3-tendo.my.id"
    USE_CF="true"
    echo -e "\033[0;32m[ INFO ]\033[0m Auto Domain akan dibuat: $DOMAIN_INIT"
    sleep 2
fi
echo -e "\033[0;36m─────────────────────────────────────────────────\033[0m"

# --- 1. SYSTEM OPTIMIZATION (BBR & SWAP 2GB) ---
echo -e "\033[0;32m[ INFO ]\033[0m System Optimization (Timezone, BBR, Swap 2GB)..."
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

# --- TELEGRAM BOT SETTINGS (DEFAULT) ---
TG_BOT_TOKEN="ISI_TOKEN_BOT_DISINI"
TG_CHAT_ID="ISI_CHAT_ID_DISINI"
# -------------------------------------------

XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
RULE_LIST="/usr/local/etc/xray/rule_list.txt"
USER_DATA="/usr/local/etc/xray/user_data.txt"

# --- 3. INSTALL DEPENDENCIES & VISUALS ---
echo -e "\033[0;32m[ INFO ]\033[0m Installing Dependencies (Please wait, no pop-ups)..."
apt-get update -y >/dev/null 2>&1
apt-get install -y --allow-downgrades --allow-remove-essential --allow-change-held-packages curl socat jq openssl uuid-runtime net-tools vnstat wget gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch zip unzip >/dev/null 2>&1

# Silent Login Configuration
touch /root/.hushlogin
chmod -x /etc/update-motd.d/* 2>/dev/null
sed -i '/neofetch/d' /root/.bashrc
echo "neofetch" >> /root/.bashrc
echo 'echo -e "Welcome Tendo! Type \e[1;32mmenu\e[0m to start."' >> /root/.bashrc

IFACE_NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
systemctl enable vnstat >/dev/null 2>&1
systemctl restart vnstat >/dev/null 2>&1
vnstat -u -i $IFACE_NET >/dev/null 2>&1

# --- 4. DOMAIN & SSL SETUP ---
echo -e "\033[0;32m[ INFO ]\033[0m Configuring Domain & Requesting SSL..."
mkdir -p $XRAY_DIR /etc/zivpn /root/tendo
touch $USER_DATA
IP_VPS=$(curl -s ifconfig.me)
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip

if [[ "$USE_CF" == "true" ]]; then
    echo -e "\033[0;32m[ INFO ]\033[0m Pointing Auto Domain to Cloudflare..."
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
         -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" \
         -H "Content-Type: application/json" \
         --data '{"type":"A","name":"'${DOMAIN_INIT}'","content":"'${IP_VPS}'","ttl":120,"proxied":false}' > /dev/null
else
    echo -e "\033[0;32m[ INFO ]\033[0m Menggunakan Custom Domain: $DOMAIN_INIT"
fi

echo "$DOMAIN_INIT" > $XRAY_DIR/domain
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key \
    -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$DOMAIN_INIT" >/dev/null 2>&1
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt

# --- 5. XRAY CORE CONFIGURATION ---
echo -e "\033[0;32m[ INFO ]\033[0m Installing Xray Core & Geosite..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
rm -f /usr/local/share/xray/geosite.dat
# Updated Geosite URL
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/tendostore/File-Geo/raw/refs/heads/main/geosite.dat"
echo "google" > $RULE_LIST

# PERBAIKAN PERMISSION LOG XRAY DI SINI
touch $XRAY_DIR/access.log $XRAY_DIR/error.log
chown nobody:nogroup $XRAY_DIR/access.log $XRAY_DIR/error.log
chmod 644 $XRAY_DIR/access.log $XRAY_DIR/error.log

cat > $CONFIG_FILE <<EOF
{
  "log": { "access": "$XRAY_DIR/access.log", "error": "$XRAY_DIR/error.log", "loglevel": "warning" },
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
echo -e "\033[0;32m[ INFO ]\033[0m Installing ZIVPN UDP..."
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
systemctl daemon-reload && systemctl enable zivpn >/dev/null 2>&1 && systemctl restart zivpn xray >/dev/null 2>&1

# IPtables AutoFT Logic
iptables -t nat -D PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
iptables -t nat -A PREROUTING -i $IFACE_NET -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save &>/dev/null

# --- 7. AUTO DELETE EXPIRED ACCOUNTS & LIMIT IP SETUP ---
echo -e "\033[0;32m[ INFO ]\033[0m Configuring Cronjobs & Telegram Bots..."
cat > /usr/local/bin/auto-kill.sh <<'EOF'
#!/bin/bash
export TZ="Asia/Jakarta"
NOW=$(date +"%s")

# Xray Auto Delete Expired & Multi Login
if [ -f /usr/local/etc/xray/user_data.txt ]; then
    rm -f /tmp/xray_restart_flag
    cat /usr/local/etc/xray/user_data.txt | tr -d '\r' | while IFS="|" read -r user uuid exp iplimit; do
        # 1. Check Expiry
        exp_epoch=$(date -d "$exp" +"%s" 2>/dev/null)
        if [[ -n "$exp_epoch" ]] && [[ "$NOW" -ge "$exp_epoch" ]]; then
            jq --arg u "$user" '(.inbounds[].settings.clients) |= map(select(.email != $u))' /usr/local/etc/xray/config.json > /tmp/x && mv /tmp/x /usr/local/etc/xray/config.json
            sed -i "/^$user|/d" /usr/local/etc/xray/user_data.txt
            touch /tmp/xray_restart_flag
            continue # Skip to next user if expired
        fi

        # 2. Check Multi Login (Limit IP)
        if [[ -n "$iplimit" && "$iplimit" =~ ^[0-9]+$ && "$iplimit" -gt 0 ]]; then
            if [ -f /tmp/xray_logged_in.txt ]; then
                ip_count=$(awk -v u="$user" '$1 == u {print $2}' /tmp/xray_logged_in.txt | sort -u | wc -l)
                if [[ "$ip_count" -gt "$iplimit" ]]; then
                    jq --arg u "$user" '(.inbounds[].settings.clients) |= map(select(.email != $u))' /usr/local/etc/xray/config.json > /tmp/x && mv /tmp/x /usr/local/etc/xray/config.json
                    sed -i "/^$user|/d" /usr/local/etc/xray/user_data.txt
                    touch /tmp/xray_restart_flag
                    
                    # Notifikasi Auto Kill
                    TOKEN=$(cat /root/tendo/bot_token 2>/dev/null)
                    CHAT_ID=$(cat /root/tendo/chat_id 2>/dev/null)
                    if [[ -n "$TOKEN" && -n "$CHAT_ID" && "$TOKEN" != "ISI_TOKEN_BOT_DISINI" ]]; then
MSG_KILL="❌ <b>XRAY AUTO KILL</b> ❌
────────────────
Username : ${user}
Max IP   : ${iplimit}
Login IP : ${ip_count}
Status   : DELETED
────────────────
Akun dihapus otomatis karena melebihi batas login IP!"
                        curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" --data-urlencode text="$MSG_KILL" > /dev/null 2>&1
                    fi
                fi
            fi
        fi
    done
    if [ -f /tmp/xray_restart_flag ]; then
        systemctl restart xray
        rm -f /tmp/xray_restart_flag
    fi
fi

# Zivpn Auto Delete Expired
if [ -f /etc/zivpn/user_data.txt ]; then
    rm -f /tmp/zivpn_restart_flag
    cat /etc/zivpn/user_data.txt | tr -d '\r' | while IFS="|" read -r pass exp; do
        exp_epoch=$(date -d "$exp" +"%s" 2>/dev/null)
        if [[ -n "$exp_epoch" ]] && [[ "$NOW" -ge "$exp_epoch" ]]; then
            jq --arg p "$pass" '.auth.config |= map(select(. != $p))' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
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
crontab -l 2>/dev/null | grep -v "/usr/local/bin/auto-kill.sh" | crontab -
(crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/auto-kill.sh") | crontab -


# --- 8. TELEGRAM NOTIFICATION & BACKUP CRON SCRIPTS ---
touch /root/tendo/bot_token
touch /root/tendo/chat_id

# Daemon untuk mencatat IP login Xray tanpa mengirim notifikasi (hanya logging)
cat > /usr/local/bin/xray-login-notif.sh <<'EOF'
#!/bin/bash
touch /tmp/xray_logged_in.txt
tail -F /usr/local/etc/xray/access.log | while read line; do
    if echo "$line" | grep -q "accepted"; then
        user=$(echo "$line" | awk '{print $NF}')
        ip=$(echo "$line" | awk '{print $3}' | sed 's/:[0-9]*$//')
        if [[ -n "$user" && -n "$ip" ]]; then
            echo "${user} ${ip}" >> /tmp/xray_logged_in.txt
        fi
    fi
done
EOF
chmod +x /usr/local/bin/xray-login-notif.sh

cat > /etc/systemd/system/xray-login-notif.service <<EOF
[Unit]
Description=Telegram Xray Login Logger
After=network.target xray.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray-login-notif.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable xray-login-notif >/dev/null 2>&1 && systemctl restart xray-login-notif >/dev/null 2>&1

# Script Notifikasi Login Baru yang sangat akurat
cat > /usr/local/bin/login-report.sh <<'EOF'
#!/bin/bash
TOKEN=$(cat /root/tendo/bot_token 2>/dev/null)
CHAT_ID=$(cat /root/tendo/chat_id 2>/dev/null)
if [[ -z "$TOKEN" || -z "$CHAT_ID" || "$TOKEN" == "ISI_TOKEN_BOT_DISINI" ]]; then exit 0; fi

IP_VPS=$(cat /root/tendo/ip 2>/dev/null)
DOMAIN=$(cat /usr/local/etc/xray/domain 2>/dev/null)
ISP=$(cat /root/tendo/isp 2>/dev/null)

MSG="📊 <b>LAPORAN LOGIN XRAY</b> 📊
────────────────
<b>IP VPS  :</b> <code>${IP_VPS}</code>
<b>Domain  :</b> ${DOMAIN}
<b>ISP     :</b> ${ISP}
────────────────
<b>List User Aktif:</b>
"
TOTAL_USERS=0

# Pastikan file log ada
touch /tmp/xray_logged_in.txt
VALID_USERS=$(jq -r '.inbounds[0].settings.clients[].email' /usr/local/etc/xray/config.json 2>/dev/null | tr -d '\r')

for user in $VALID_USERS; do
    # Hitung jumlah IP unik & Total Koneksi
    conn_count=$(awk -v u="$user" '$1 == u' /tmp/xray_logged_in.txt | wc -l)
    ip_count=$(awk -v u="$user" '$1 == u {print $2}' /tmp/xray_logged_in.txt | sort -u | wc -l)
    
    if [[ "$conn_count" -gt 0 ]]; then
        MSG+="👤 <b>${user}</b> : ${ip_count} IP (${conn_count} Koneksi)
"
        ((TOTAL_USERS++))
    fi
done

if [[ "$TOTAL_USERS" -gt 0 ]]; then
    MSG+="────────────────
<b>Total Akun Aktif : ${TOTAL_USERS}</b>"
    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" --data-urlencode text="$MSG" > /dev/null 2>&1
fi

# Bersihkan file log login setelah dilaporkan
> /tmp/xray_logged_in.txt
EOF
chmod +x /usr/local/bin/login-report.sh

# Script Auto Backup (berjalan sesuai cron jam 'h')
cat > /usr/local/bin/auto-backup.sh <<'EOF'
#!/bin/bash
TOKEN=$(cat /root/tendo/bot_token 2>/dev/null)
CHAT_ID=$(cat /root/tendo/chat_id 2>/dev/null)
if [[ -z "$TOKEN" || -z "$CHAT_ID" || "$TOKEN" == "ISI_TOKEN_BOT_DISINI" ]]; then exit 0; fi

rm -f /root/tendo/backup.zip
zip -r -q /root/tendo/backup.zip /usr/local/etc/xray/config.json /usr/local/etc/xray/user_data.txt /etc/zivpn/config.json /etc/zivpn/user_data.txt /usr/local/etc/xray/domain > /dev/null 2>&1
DOMAIN=$(cat /usr/local/etc/xray/domain 2>/dev/null)

CAPTION="✅ Auto Backup VPS
📅 Tanggal: $(date)
🌐 Domain: ${DOMAIN}"

curl -s -F chat_id="$CHAT_ID" -F document=@"/root/tendo/backup.zip" -F caption="$CAPTION" "https://api.telegram.org/bot${TOKEN}/sendDocument" > /dev/null 2>&1
EOF
chmod +x /usr/local/bin/auto-backup.sh

# --- 8.1 TELEGRAM BOT AUTO CREATE DAEMON (INTERACTIVE UI) ---
echo -e "\033[0;32m[ INFO ]\033[0m Configuring Telegram Auto-Create Bot Daemon..."
cat > /usr/local/bin/tendo-autobot.sh <<'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"
Z_CONF="/etc/zivpn/config.json"
Z_DATA="/etc/zivpn/user_data.txt"

OFFSET_FILE="/tmp/tendo_bot_offset"
touch $OFFSET_FILE

function send_msg() {
    local chat="$1"
    local msg="$2"
    local token=$(cat /root/tendo/bot_token 2>/dev/null)
    # Tidak memakai echo -e di sini lagi karena format MSG sudah dibuat rapi multi-line di bawah
    curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" -d chat_id="${chat}" -d parse_mode="HTML" --data-urlencode text="$msg" > /dev/null 2>&1
}

while true; do
    TOKEN=$(cat /root/tendo/bot_token 2>/dev/null)
    if [[ -z "$TOKEN" || "$TOKEN" == "ISI_TOKEN_BOT_DISINI" ]]; then
        sleep 10
        continue
    fi

    OFFSET=$(cat $OFFSET_FILE)
    [[ -z "$OFFSET" ]] && OFFSET=0

    UPDATES=$(curl -s -X GET "https://api.telegram.org/bot${TOKEN}/getUpdates?offset=${OFFSET}&timeout=10" 2>/dev/null)
    OK=$(echo "$UPDATES" | jq -r '.ok' 2>/dev/null)

    if [[ "$OK" == "true" ]]; then
        UPDATE_COUNT=$(echo "$UPDATES" | jq '.result | length' 2>/dev/null)
        if [[ "$UPDATE_COUNT" -gt 0 ]]; then
            for ((i=0; i<UPDATE_COUNT; i++)); do
                UPDATE_ID=$(echo "$UPDATES" | jq -r ".result[$i].update_id")
                
                # Cek apakah ini pesan text biasa atau callback dari inline keyboard
                IS_CB=$(echo "$UPDATES" | jq -r ".result[$i] | has(\"callback_query\")")
                
                if [[ "$IS_CB" == "true" ]]; then
                    CHAT_ID=$(echo "$UPDATES" | jq -r ".result[$i].callback_query.message.chat.id")
                    TEXT=$(echo "$UPDATES" | jq -r ".result[$i].callback_query.data")
                    CB_ID=$(echo "$UPDATES" | jq -r ".result[$i].callback_query.id")
                    
                    # Hilangkan status loading di tombol
                    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/answerCallbackQuery" -d callback_query_id="${CB_ID}" > /dev/null 2>&1
                else
                    CHAT_ID=$(echo "$UPDATES" | jq -r ".result[$i].message.chat.id")
                    TEXT=$(echo "$UPDATES" | jq -r ".result[$i].message.text")
                fi
                
                # File state untuk mengingat langkah percakapan (State Machine)
                STATE_FILE="/tmp/tendo_state_${CHAT_ID}"
                USER_STATE=$(cat "$STATE_FILE" 2>/dev/null)

                # 1. COMMAND START (Main Menu)
                if [[ "$TEXT" == "/start" ]]; then
                    rm -f "$STATE_FILE"
                    KEYBOARD='{"inline_keyboard":[[{"text":"➕ Create XRAY","callback_data":"btn_create_xray"},{"text":"➕ Create ZIVPN","callback_data":"btn_create_zivpn"}],[{"text":"💳 Donasi","callback_data":"btn_donasi"},{"text":"📞 Hubungi Admin","url":"https://t.me/tendo_32"}]]}'
MSG="🤖 <b>BOT TENDO STORE</b>

Selamat datang! Silakan pilih menu interaktif di bawah ini untuk membuat akun VPN."
                    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" -d reply_markup="${KEYBOARD}" --data-urlencode text="$MSG" > /dev/null 2>&1

                # 2. KLIK TOMBOL: CREATE XRAY
                elif [[ "$TEXT" == "btn_create_xray" ]]; then
                    echo "xray_user" > "$STATE_FILE"
MSG="💬 <b>MEMBUAT AKUN XRAY</b>

Silakan ketik <b>Username</b> yang Anda inginkan (tanpa spasi):"
                    send_msg "$CHAT_ID" "$MSG"

                # 3. KLIK TOMBOL: CREATE ZIVPN
                elif [[ "$TEXT" == "btn_create_zivpn" ]]; then
                    echo "zivpn_pass" > "$STATE_FILE"
MSG="💬 <b>MEMBUAT AKUN ZIVPN</b>

Silakan ketik <b>Password</b> yang Anda inginkan (tanpa spasi):"
                    send_msg "$CHAT_ID" "$MSG"

                # 4. KLIK TOMBOL: DONASI
                elif [[ "$TEXT" == "btn_donasi" ]]; then
MSG="🙏 <b>TERIMA KASIH ATAS DUKUNGANNYA</b> 🙏

•────────────────────•
❑ 082224460678 𝗢𝗩𝗢 
❑ 082224460678 𝗗𝗔𝗡𝗔
❑ 082224460678 𝗟𝗜𝗡𝗞 𝗔𝗝𝗔
❑ 082224460678 𝗚𝗢𝗣𝗔𝗬
❑ 082224460678 𝗦𝗛𝗢𝗣𝗘𝗘𝗣𝗔𝗬
•────────────────────•

<i>Dukungan Anda sangat berarti untuk pengembangan ini.</i>"
                    
                    QRIS_URL="https://i.postimg.cc/XqjdvXpb/Kode-QRIS-Tendo-Store-Jepara.png"
                    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendPhoto" -d chat_id="${CHAT_ID}" -d photo="${QRIS_URL}" -d parse_mode="HTML" --data-urlencode caption="$MSG" > /dev/null 2>&1

                # 5. TERIMA KETIKAN TEXT: USERNAME XRAY
                elif [[ "$USER_STATE" == "xray_user" && "$IS_CB" == "false" ]]; then
                    u="$TEXT"
                    exist=$(grep -w "^$u" $U_DATA)
                    if [[ -n "$exist" ]]; then
MSG="❌ Username <b>$u</b> sudah terdaftar!
Silakan ketik username lain:"
                        send_msg "$CHAT_ID" "$MSG"
                    elif [[ "$u" =~ [^a-zA-Z0-9_-] ]]; then
MSG="❌ Username tidak valid! Jangan gunakan spasi atau simbol khusus.
Silakan ketik ulang:"
                        send_msg "$CHAT_ID" "$MSG"
                    else
                        echo "xray_exp_${u}" > "$STATE_FILE"
                        KEYBOARD='{"inline_keyboard":[[{"text":"1 Hari","callback_data":"xray_exp_1"},{"text":"2 Hari","callback_data":"xray_exp_2"}],[{"text":"3 Hari","callback_data":"xray_exp_3"},{"text":"5 Hari (MAX)","callback_data":"xray_exp_5"}]]}'
MSG="Username <b>$u</b> tersedia! ✅

Silakan pilih <b>Masa Aktif</b> akun dengan menekan tombol di bawah:"
                        curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" -d reply_markup="${KEYBOARD}" --data-urlencode text="$MSG" > /dev/null 2>&1
                    fi

                # 6. TERIMA KETIKAN TEXT: PASSWORD ZIVPN
                elif [[ "$USER_STATE" == "zivpn_pass" && "$IS_CB" == "false" ]]; then
                    p="$TEXT"
                    exist=$(grep -w "^$p" $Z_DATA)
                    if [[ -n "$exist" ]]; then
MSG="❌ Password <b>$p</b> sudah terdaftar!
Silakan ketik password lain:"
                        send_msg "$CHAT_ID" "$MSG"
                    elif [[ "$p" =~ [^a-zA-Z0-9_-] ]]; then
MSG="❌ Password tidak valid! Jangan gunakan spasi atau simbol khusus.
Silakan ketik ulang:"
                        send_msg "$CHAT_ID" "$MSG"
                    else
                        echo "zivpn_exp_${p}" > "$STATE_FILE"
                        KEYBOARD='{"inline_keyboard":[[{"text":"1 Hari","callback_data":"zivpn_exp_1"},{"text":"2 Hari","callback_data":"zivpn_exp_2"}],[{"text":"3 Hari","callback_data":"zivpn_exp_3"},{"text":"5 Hari (MAX)","callback_data":"zivpn_exp_5"}]]}'
MSG="Password <b>$p</b> tersedia! ✅

Silakan pilih <b>Masa Aktif</b> akun dengan menekan tombol di bawah:"
                        curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" -d reply_markup="${KEYBOARD}" --data-urlencode text="$MSG" > /dev/null 2>&1
                    fi

                # 7. KLIK TOMBOL DURASI: FINALISASI XRAY
                elif [[ "$TEXT" == xray_exp_* && "$USER_STATE" == xray_exp_* ]]; then
                    ex=$(echo "$TEXT" | awk -F'_' '{print $3}')
                    u=$(echo "$USER_STATE" | awk -F'_' '{print $3}')
                    rm -f "$STATE_FILE"
                    
                    id=$(uuidgen)
                    exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
                    iplim=2 # LIMIT IP MAX 2 UNTUK BOT XRAY
                    
                    jq --arg u "$u" --arg id "$id" '.inbounds[].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/xa && mv /tmp/xa $CONFIG
                    systemctl restart xray
                    echo "$u|$id|$exp_date|$iplim" >> $U_DATA
                    
                    DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
                    ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"
                    lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
                    
MSG="✅ <b>NEW XRAY ACCOUNT</b>
────────────────────────────────────
Remarks        : $u
CITY           : $CTY
ISP            : $ISP
Domain         : $DMN
Port TLS       : 443,8443
Port none TLS  : 80,8080
id             : $id
Encryption     : none
Network        : ws
Path ws        : /vless
Max IP Login   : $iplim IP
Expired On     : $ex Hari ($exp_date)
────────────────────────────────────
            XRAY WS TLS
────────────────────────────────────
<code>$ltls</code>
────────────────────────────────────
          XRAY WS NO TLS
────────────────────────────────────
<code>$lnon</code>
────────────────────────────────────"
                    send_msg "$CHAT_ID" "$MSG"

                # 8. KLIK TOMBOL DURASI: FINALISASI ZIVPN
                elif [[ "$TEXT" == zivpn_exp_* && "$USER_STATE" == zivpn_exp_* ]]; then
                    ex=$(echo "$TEXT" | awk -F'_' '{print $3}')
                    p=$(echo "$USER_STATE" | awk -F'_' '{print $3}')
                    rm -f "$STATE_FILE"
                    
                    exp=$(date -d "+$ex days" +"%Y-%m-%d")
                    jq --arg p "$p" '.auth.config += [$p]' $Z_CONF > /tmp/za && mv /tmp/za $Z_CONF
                    systemctl restart zivpn
                    echo "$p|$exp" >> $Z_DATA
                    DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); IP_ISP=$(cat /root/tendo/ip)
                    
MSG="✅ <b>NEW ZIVPN ACCOUNT</b>
━━━━━━━━━━━━━━━━━━━━━
  ACCOUNT ZIVPN UDP
━━━━━━━━━━━━━━━━━━━━━
Password   : $p
CITY       : $CTY
ISP        : $ISP
IP ISP     : $IP_ISP
Domain     : $DMN
Expired On : $ex Hari ($exp)
━━━━━━━━━━━━━━━━━━━━━"
                    send_msg "$CHAT_ID" "$MSG"

                fi
                
                NEXT_OFFSET=$((UPDATE_ID + 1))
                echo "$NEXT_OFFSET" > $OFFSET_FILE
            done
        fi
    fi
    sleep 3
done
EOF
chmod +x /usr/local/bin/tendo-autobot.sh

cat > /etc/systemd/system/tendo-autobot.service <<EOF
[Unit]
Description=Telegram Auto Create Bot Daemon by Tendo Store
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tendo-autobot.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable tendo-autobot >/dev/null 2>&1 && systemctl restart tendo-autobot >/dev/null 2>&1


# --- 9. MAIN MENU SCRIPT (PLATINUM UI) ---
cat > /usr/bin/menu <<'EOF'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; PURPLE='\033[0;35m'; NC='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
U_DATA="/usr/local/etc/xray/user_data.txt"

function send_tg_notif() {
    local msg="$1"
    local token=$(cat /root/tendo/bot_token 2>/dev/null)
    local chat_id=$(cat /root/tendo/chat_id 2>/dev/null)
    if [[ -n "$token" && -n "$chat_id" && "$token" != "ISI_TOKEN_BOT_DISINI" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
             -d chat_id="${chat_id}" \
             -d parse_mode="HTML" \
             --data-urlencode text="$msg" > /dev/null 2>&1
    fi
}

function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $3}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); UPTIME=$(uptime -p | sed 's/up //')
    CITY=$(cat /root/tendo/city 2>/dev/null); ISP=$(cat /root/tendo/isp 2>/dev/null); IP=$(cat /root/tendo/ip 2>/dev/null)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    M_RX=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $9}'); M_TX=$(vnstat -m -i $IFACE --oneline | awk -F';' '{print $10}')
    D_RX=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $4}'); D_TX=$(vnstat -d -i $IFACE --oneline | awk -F';' '{print $5}')
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes); sleep 0.4
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes); T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
    TRAFFIC=$(echo "scale=2; (($R2 - $R1) + ($T2 - $T1)) * 8 / 409.6 / 1024" | bc)
    
    SX=$(systemctl is-active xray); [[ $SX == "active" ]] && X_ST="${GREEN}ON${NC}" || X_ST="${RED}OFF${NC}"
    SZ=$(systemctl is-active zivpn); [[ $SZ == "active" ]] && Z_ST="${GREEN}ON${NC}" || Z_ST="${RED}OFF${NC}"
    SI=$(systemctl is-active netfilter-persistent); [[ $SI == "active" ]] && I_ST="${GREEN}ON${NC}" || I_ST="${RED}OFF${NC}"
    
    COUNT_VLESS=$(jq '.inbounds[0].settings.clients | length' $CONFIG); COUNT_ZIVPN=$(jq '.auth.config | length' /etc/zivpn/config.json)

    echo -e "┌───────────────────────────────────────────────────────"
    echo -e "│              ${YELLOW}TENDO STORE PRIVATE${NC}"
    echo -e "├───────────────────────────────────────────────────────"
    echo -e "│ OS      : $OS"
    echo -e "│ RAM     : ${RAM}MB"
    echo -e "│ SWAP    : ${SWAP}MB"
    echo -e "│ CITY    : $CITY"
    echo -e "│ ISP     : $ISP"
    echo -e "│ IP      : $IP"
    echo -e "│ DOMAIN  : ${YELLOW}$DOMAIN${NC}"
    echo -e "│ UPTIME  : $UPTIME"
    echo -e "├───────────────────────────────────────────────────────"
    echo -e "│ TODAY   : ${GREEN}RX:${NC} $D_RX | ${RED}TX:${NC} $D_TX"
    echo -e "│ MONTH   : ${GREEN}RX:${NC} $M_RX | ${RED}TX:${NC} $M_TX"
    echo -e "│ SPEED   : $TRAFFIC Mbit/s"
    echo -e "├───────────────────────────────────────────────────────"
    echo -e "│ STATUS  : XRAY: $X_ST | ZIVPN: $Z_ST | IPtables: $I_ST"
    echo -e "└───────────────────────────────────────────────────────"
    echo -e "┌───────────────────────────────────────────────────────"
    echo -e "│                   ${YELLOW}LIST ACCOUNTS${NC}"
    echo -e "├───────────────────────────────────────────────────────"
    echo -e "│  XRAY          : $COUNT_VLESS ACCOUNT"
    echo -e "│  ZIVPN UDP     : $COUNT_ZIVPN ACCOUNT"
    echo -e "└───────────────────────────────────────────────────────"
    echo -e "│  [1] XRAY ACCOUNT          [4] FEATURES"
    echo -e "│  [2] ZIVPN UDP             [5] CHECK SERVICES"
    echo -e "│  [3] SET BOT TELEGRAM      [x] EXIT"
    echo -e "────────────────────────────────────────────────────────"
    echo -e "┌───────────────────────────────────────────────────────"
    echo -e "│  Version   :  v21.02.26"
    echo -e "│  Owner     :  Tendo Store"
    echo -e "│  Telegram  :  @tendo_32"
    echo -e "│  Expiry In :  Lifetime"
    echo -e "└───────────────────────────────────────────────────────"
}

function header_sub() {
    clear; DMN=$(cat /usr/local/etc/xray/domain)
    echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
    echo -e "            ${YELLOW}TENDO STORE - SUB MENU${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
}

function backup_restore_menu() {
    while true; do
        header_sub
        echo -e " [1] Backup Data VPS (Lokal & Telegram)"
        echo -e " [2] Restore Data VPS (Dari Lokal)"
        echo -e " [3] Restore Data VPS (Dari Link Direct)"
        echo -e " [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1)
                clear; echo -e "${YELLOW}BACKUP DATA VPS${NC}\n"
                rm -f /root/tendo/backup.zip
                echo -e "Mempersiapkan file backup..."
                zip -r -q /root/tendo/backup.zip /usr/local/etc/xray/config.json /usr/local/etc/xray/user_data.txt /etc/zivpn/config.json /etc/zivpn/user_data.txt /usr/local/etc/xray/domain
                echo -e "${GREEN}✅ Backup lokal tersimpan di: /root/tendo/backup.zip${NC}"

                TOKEN=$(cat /root/tendo/bot_token 2>/dev/null)
                CHAT_ID=$(cat /root/tendo/chat_id 2>/dev/null)
                if [[ -n "$TOKEN" && -n "$CHAT_ID" && "$TOKEN" != "ISI_TOKEN_BOT_DISINI" ]]; then
                    echo -e "Mengirim file backup ke Telegram..."
                    CAPTION="✅ VPS Backup Data Manual
📅 Tanggal: $(date)
🌐 Domain: $(cat /usr/local/etc/xray/domain)"
                    curl -s -F chat_id="$CHAT_ID" -F document=@"/root/tendo/backup.zip" -F caption="$CAPTION" "https://api.telegram.org/bot${TOKEN}/sendDocument" > /dev/null
                    echo -e "${GREEN}✅ Backup juga berhasil dikirim ke Telegram!${NC}"
                fi
                read -n 1 -s -r -p "Enter..."
                ;;
            2)
                clear; echo -e "${YELLOW}RESTORE DATA VPS (LOKAL)${NC}\n"
                echo -e "Pastikan file backup bernama ${YELLOW}backup.zip${NC} sudah"
                echo -e "berada di dalam folder direktori ${YELLOW}/root/tendo/${NC}\n"
                read -p "Apakah kamu yakin ingin me-restore data? (y/n): " ans
                if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
                    if [ -f /root/tendo/backup.zip ]; then
                        echo -e "Mengekstrak file backup ke dalam sistem..."
                        unzip -o /root/tendo/backup.zip -d / > /dev/null 2>&1
                        systemctl restart xray zivpn
                        echo -e "${GREEN}✅ Restore data berhasil diselesaikan! Service telah di-restart.${NC}"
                    else
                        echo -e "${RED}❌ File backup (/root/tendo/backup.zip) tidak ditemukan pada sistem!${NC}"
                    fi
                else
                    echo -e "${RED}❌ Proses restore dibatalkan oleh pengguna.${NC}"
                fi
                read -n 1 -s -r -p "Enter..."
                ;;
            3)
                clear; echo -e "${YELLOW}RESTORE DATA VPS (LINK DIRECT)${NC}\n"
                read -p "Masukkan URL/Link Direct file backup (.zip): " link_url
                if [[ -n "$link_url" ]]; then
                    echo -e "Mendownload file backup..."
                    wget -qO /tmp/backup_direct.zip "$link_url"
                    if unzip -t /tmp/backup_direct.zip &>/dev/null; then
                        echo -e "Mengekstrak file backup ke dalam sistem..."
                        unzip -o /tmp/backup_direct.zip -d / > /dev/null 2>&1
                        systemctl restart xray zivpn
                        echo -e "${GREEN}✅ Restore data berhasil diselesaikan! Service telah di-restart.${NC}"
                    else
                        echo -e "${RED}❌ File backup korup atau link tidak valid!${NC}"
                    fi
                    rm -f /tmp/backup_direct.zip
                else
                    echo -e "${RED}❌ Link tidak boleh kosong!${NC}"
                fi
                read -n 1 -s -r -p "Enter..."
                ;;
            x) return ;;
        esac
    done
}

function notif_login_menu() {
    while true; do
        clear
        local cur_cron=$(crontab -l 2>/dev/null | grep "/usr/local/bin/login-report.sh")
        if [[ -n "$cur_cron" ]]; then
            ST="ON"
            TG="OFF"
            cur_m=$(echo "$cur_cron" | awk '{print $1}' | sed 's|^\*/||')
            [[ "$cur_m" == "*" ]] && cur_m="1"
        else
            ST="OFF"
            TG="ON"
            cur_m="-"
        fi
        
        echo -e " ————————————————————————————————————————"
        echo -e "        Status [$ST]"
        echo -e "   1.)  $TG"
        echo -e "   2.)  Set Time Notif (${cur_m}m)"
        echo -e "   3.)  Back to Menu"
        echo -e "   x.)  Exit"
        echo -e " ————————————————————————————————————————"
        read -p " Pilih: " opt
        case $opt in
            1)
                if [[ "$ST" == "ON" ]]; then
                    crontab -l 2>/dev/null | grep -v "/usr/local/bin/login-report.sh" | crontab -
                else
                    (crontab -l 2>/dev/null; echo "*/60 * * * * /usr/local/bin/login-report.sh") | crontab -
                fi
                ;;
            2)
                read -p " Masukkan Waktu (Menit): " m
                if [[ "$m" =~ ^[0-9]+$ ]]; then
                    crontab -l 2>/dev/null | grep -v "/usr/local/bin/login-report.sh" | crontab -
                    (crontab -l 2>/dev/null; echo "*/$m * * * * /usr/local/bin/login-report.sh") | crontab -
                    echo " Berhasil diatur ke $m menit!"; sleep 1
                else
                    echo " Input tidak valid!"; sleep 1
                fi
                ;;
            3) return ;;
            x) exit ;;
        esac
    done
}

function notif_backup_menu() {
    while true; do
        clear
        local cur_cron=$(crontab -l 2>/dev/null | grep "/usr/local/bin/auto-backup.sh")
        if [[ -n "$cur_cron" ]]; then
            ST="ON"
            TG="OFF"
            cur_h=$(echo "$cur_cron" | awk '{print $2}' | sed 's|^\*/||')
            [[ "$cur_h" == "*" ]] && cur_h="1"
        else
            ST="OFF"
            TG="ON"
            cur_h="-"
        fi
        
        echo -e " ————————————————————————————————————————"
        echo -e "        Status [$ST]"
        echo -e "   1.)  $TG"
        echo -e "   2.)  Set Time Backup (${cur_h}h)"
        echo -e "   3.)  Back to Menu"
        echo -e "   x.)  Exit"
        echo -e " ————————————————————————————————————————"
        read -p " Pilih: " opt
        case $opt in
            1)
                if [[ "$ST" == "ON" ]]; then
                    crontab -l 2>/dev/null | grep -v "/usr/local/bin/auto-backup.sh" | crontab -
                else
                    (crontab -l 2>/dev/null; echo "0 */1 * * * /usr/local/bin/auto-backup.sh") | crontab -
                fi
                ;;
            2)
                read -p " Masukkan Waktu (Jam): " h
                if [[ "$h" =~ ^[0-9]+$ ]]; then
                    crontab -l 2>/dev/null | grep -v "/usr/local/bin/auto-backup.sh" | crontab -
                    (crontab -l 2>/dev/null; echo "0 */$h * * * /usr/local/bin/auto-backup.sh") | crontab -
                    echo " Berhasil diatur ke $h jam!"; sleep 1
                else
                    echo " Input tidak valid!"; sleep 1
                fi
                ;;
            3) return ;;
            x) exit ;;
        esac
    done
}

function telegram_bot_menu() {
    while true; do
        header_sub
        echo -e " [1] Make BOT API & CHATID"
        echo -e " [2] User Login Notification"
        echo -e " [3] Auto Backup Notification"
        echo -e " [4] Manual Backup VPS to BOT"
        echo -e " [5] Change BOT API & CHATID"
        echo -e " [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) clear; echo -e "${YELLOW}TUTORIAL MAKE BOT API & CHAT ID${NC}\n1. Buka Telegram dan cari bot: @BotFather\n2. Ketik /newbot lalu ikuti langkahnya sampai\n   kamu mendapatkan token HTTP API.\n3. Cari bot: @userinfobot atau @get_id_bot\n4. Klik Start untuk mendapatkan CHAT ID kamu.\n5. Kembali ke menu ini, pilih opsi 5 untuk\n   memasukkan Token dan Chat ID.\n"; read -n 1 -s -r -p "Enter..." ;;
            2) notif_login_menu ;;
            3) notif_backup_menu ;;
            4) clear; echo -e "${YELLOW}MANUAL BACKUP VPS TO TELEGRAM${NC}\n"; TOKEN=$(cat /root/tendo/bot_token 2>/dev/null); CHAT_ID=$(cat /root/tendo/chat_id 2>/dev/null)
               if [[ -z "$TOKEN" || -z "$CHAT_ID" || "$TOKEN" == "ISI_TOKEN_BOT_DISINI" ]]; then echo -e "${RED}Gagal! Token atau Chat ID belum disetting.${NC}"; else rm -f /root/tendo/backup.zip; zip -r -q /root/tendo/backup.zip /usr/local/etc/xray/config.json /usr/local/etc/xray/user_data.txt /etc/zivpn/config.json /etc/zivpn/user_data.txt /usr/local/etc/xray/domain; CAPTION="✅ VPS Backup Data
📅 Tanggal: $(date)
🌐 Domain: $(cat /usr/local/etc/xray/domain)"; curl -s -F chat_id="$CHAT_ID" -F document=@"/root/tendo/backup.zip" -F caption="$CAPTION" "https://api.telegram.org/bot${TOKEN}/sendDocument" > /dev/null; echo -e "${GREEN}Backup berhasil dikirim ke Telegram kamu!${NC}"; fi; read -n 1 -s -r -p "Enter..." ;;
            5) clear; echo -e "${YELLOW}CHANGE BOT API & CHAT ID${NC}\n"; read -p " Masukkan Bot Token : " b_token; read -p " Masukkan Chat ID   : " c_id; echo "$b_token" > /root/tendo/bot_token; echo "$c_id" > /root/tendo/chat_id; systemctl restart xray-login-notif tendo-autobot; echo -e "\n ${GREEN}Berhasil menyimpan Token & Chat ID!${NC}"; sleep 2 ;;
            x) return ;;
        esac
    done
}

function xray_menu() {
    while true; do header_sub; echo -e " [1] Create Account\n [2] Trial Account\n [3] Delete Account\n [4] List Accounts\n [5] Check Account Details\n [x] Back\n${CYAN}─────────────────────────────────────────────────${NC}"; read -p " Select Menu : " opt
    case $opt in
        1) read -p " Username : " u; read -p " UUID (Enter for random): " id; [[ -z "$id" ]] && id=$(uuidgen); read -p " Expired (Hari): " ex; [[ -z "$ex" ]] && ex=30; read -p " Max IP Login (Ketik 0 untuk unlimited): " iplim; [[ -z "$iplim" ]] && iplim=0
           exp_date=$(date -d "+$ex days" +"%Y-%m-%d")
           jq --arg u "$u" --arg id "$id" '.inbounds[].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date|$iplim" >> $U_DATA
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           [[ "$iplim" == "0" ]] && show_iplim="Unlimited" || show_iplim="$iplim IP"
msg="✅ <b>NEW XRAY ACCOUNT</b>
────────────────────────────────────
Remarks        : $u
CITY           : $CTY
ISP            : $ISP
Domain         : $DMN
Port TLS       : 443,8443
Port none TLS  : 80,8080
id             : $id
Encryption     : none
Network        : ws
Path ws        : /vless
Max IP Login   : $show_iplim
Expired On     : $ex Hari ($exp_date)
────────────────────────────────────
            XRAY WS TLS
────────────────────────────────────
<code>$ltls</code>
────────────────────────────────────
          XRAY WS NO TLS
────────────────────────────────────
<code>$lnon</code>
────────────────────────────────────"
           send_tg_notif "$msg"
           clear; echo -e "$msg" | sed 's/<b>//g; s/<\/b>//g; s/<code>//g; s/<\/code>//g'; read -n 1 -s -r -p "Enter...";;
        2) id=$(uuidgen); u="trial-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"; iplim=1
           echo -e " \n Username (Auto-Random): ${GREEN}$u${NC}"
           read -p " Expired (Menit): " ex_m; [[ -z "$ex_m" ]] && ex_m=10
           exp_date=$(date -d "+$ex_m minutes" +"%Y-%m-%d %H:%M")
           jq --arg u "$u" --arg id "$id" '.inbounds[].settings.clients += [{"id":$id,"email":$u}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray; echo "$u|$id|$exp_date|$iplim" >> $U_DATA
           DMN=$(cat /usr/local/etc/xray/domain); CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
msg="⏳ <b>NEW XRAY TRIAL</b>
────────────────────────────────────
Remarks        : $u
CITY           : $CTY
ISP            : $ISP
Domain         : $DMN
Port TLS       : 443,8443
Port none TLS  : 80,8080
id             : $id
Encryption     : none
Network        : ws
Path ws        : /vless
Max IP Login   : $iplim IP
Expired On     : $ex_m Menit ($exp_date)
────────────────────────────────────
            XRAY WS TLS
────────────────────────────────────
<code>$ltls</code>
────────────────────────────────────
          XRAY WS NO TLS
────────────────────────────────────
<code>$lnon</code>
────────────────────────────────────"
           send_tg_notif "$msg"
           clear; echo -e "$msg" | sed 's/<b>//g; s/<\/b>//g; s/<code>//g; s/<\/code>//g'; read -n 1 -s -r -p "Enter...";;
        3) jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); sed -i "/^$u|/d" $U_DATA; jq --arg u "$u" '(.inbounds[].settings.clients) |= map(select(.email != $u))' $CONFIG > /tmp/x && mv /tmp/x $CONFIG; systemctl restart xray;;
        4) header_sub; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "Enter...";;
        5) header_sub; jq -r '.inbounds[0].settings.clients[].email' $CONFIG | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); u=$(jq -r ".inbounds[0].settings.clients[$idx].email" $CONFIG); id=$(jq -r ".inbounds[0].settings.clients[$idx].id" $CONFIG); DMN=$(cat /usr/local/etc/xray/domain); 
           exp_d=$(grep "^$u|" $U_DATA | cut -d'|' -f3); [[ -z "$exp_d" ]] && exp_d="Unknown"
           iplim_d=$(grep "^$u|" $U_DATA | cut -d'|' -f4); [[ -z "$iplim_d" || "$iplim_d" == "0" ]] && iplim_d="Unlimited" || iplim_d="$iplim_d IP"
           CTY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp)
           ltls="vless://${id}@${DMN}:443?path=/vless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${u}"; lnon="vless://${id}@${DMN}:80?path=/vless&security=none&encryption=none&host=${DMN}&type=ws#${u}"
           clear; echo -e "────────────────────────────────────\n               XRAY\n────────────────────────────────────\nRemarks        : $u\nCITY           : $CTY\nISP            : $ISP\nDomain         : $DMN\nPort TLS       : 443,8443\nPort none TLS  : 80,8080\nid             : $id\nEncryption     : none\nNetwork        : ws\nPath ws        : /vless\nMax IP Login   : $iplim_d\nExpired On     : $exp_d\n────────────────────────────────────\n            XRAY WS TLS\n────────────────────────────────────\n$ltls\n────────────────────────────────────\n          XRAY WS NO TLS\n────────────────────────────────────\n$lnon\n────────────────────────────────────"; read -n 1 -s -r -p "Enter...";;
        x) return;;
    esac; done
}

function zivpn_menu() {
    while true; do header_sub; echo -e " [1] Create Account\n [2] Trial Account\n [3] Delete Account\n [4] List Accounts\n [5] Check Account Details\n [x] Back\n${CYAN}─────────────────────────────────────────────────${NC}"; read -p " Select Menu : " opt
    case $opt in
        1) read -p " Password: " p; read -p " Expired (Hari): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$exp" >> /etc/zivpn/user_data.txt; DMN=$(cat /usr/local/etc/xray/domain)
msg="✅ <b>NEW ZIVPN ACCOUNT</b>
━━━━━━━━━━━━━━━━━━━━━
  ACCOUNT ZIVPN UDP
━━━━━━━━━━━━━━━━━━━━━
Password   : $p
CITY       : $(cat /root/tendo/city)
ISP        : $(cat /root/tendo/isp)
IP ISP     : $(cat /root/tendo/ip)
Domain     : $DMN
Expired On : $exp
━━━━━━━━━━━━━━━━━━━━━"
           send_tg_notif "$msg"
           clear; echo -e "$msg" | sed 's/<b>//g; s/<\/b>//g'; read -p "Enter...";;
        2) p="trial-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"
           echo -e " \n Password (Auto-Random): ${GREEN}$p${NC}"
           read -p " Expired (Menit): " ex_m; [[ -z "$ex_m" ]] && ex_m=10
           exp=$(date -d "+$ex_m minutes" +"%Y-%m-%d %H:%M")
           jq --arg p "$p" '.auth.config += [$p]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn; echo "$p|$exp" >> /etc/zivpn/user_data.txt; DMN=$(cat /usr/local/etc/xray/domain)
msg="⏳ <b>NEW ZIVPN TRIAL</b>
━━━━━━━━━━━━━━━━━━━━━
  ZIVPN UDP TRIAL
━━━━━━━━━━━━━━━━━━━━━
Password   : $p
CITY       : $(cat /root/tendo/city)
ISP        : $(cat /root/tendo/isp)
IP ISP     : $(cat /root/tendo/ip)
Domain     : $DMN
Expired On : $ex_m Menit ($exp)
━━━━━━━━━━━━━━━━━━━━━"
           send_tg_notif "$msg"
           clear; echo -e "$msg" | sed 's/<b>//g; s/<\/b>//g'; read -p "Enter...";;
        3) jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); sed -i "/^$p|/d" /etc/zivpn/user_data.txt; jq --arg p "$p" '.auth.config |= map(select(. != $p))' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; systemctl restart zivpn;;
        4) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "Enter...";;
        5) header_sub; jq -r '.auth.config[]' /etc/zivpn/config.json | nl; read -p "No: " n; [[ -z "$n" ]] && continue; idx=$((n-1)); p=$(jq -r ".auth.config[$idx]" /etc/zivpn/config.json); DMN=$(cat /usr/local/etc/xray/domain); exp_d=$(grep "^$p|" /etc/zivpn/user_data.txt | cut -d'|' -f2); [[ -z "$exp_d" ]] && exp_d="Unknown"
           clear; echo -e "━━━━━━━━━━━━━━━━━━━━━\n  CHECK ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : $p\nCITY       : $(cat /root/tendo/city)\nISP        : $(cat /root/tendo/isp)\nIP ISP     : $(cat /root/tendo/ip)\nDomain     : $DMN\nExpired On : $exp_d\n━━━━━━━━━━━━━━━━━━━━━"; read -p "Enter...";;
        x) return;;
    esac; done
}

function routing_menu() {
    geosites=( "rule-gaming" "rule-indo" "rule-sosmed" "google" "rule-playstore" "rule-streaming" "rule-umum" "tiktok" "rule-ipcheck" "rule-doh" "rule-malicious" "telegram" "rule-ads" "rule-speedtest" "ecommerce-id" "urltest" "category-porn" "bank-id" "meta" "videoconference" "geolocation-!cn" "facebook" "spotify" "openai" "ehentai" "github" "microsoft" "apple" "netflix" "cn" "youtube" "twitter" "bilibili" "category-ads-all" "private" "category-media" "category-vpnservices" "category-dev" "category-dev-all" "category-media-all" )
    while true; do
        header_sub
        echo -e "             ${YELLOW}SUPPORTED GEOSITE LIST${NC}"
        echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
        for (( i=0; i<${#geosites[@]}; i+=2 )); do
            item1=$(printf " [%-2d] %-18s" "$((i+1))" "${geosites[$i]}")
            if [[ -n "${geosites[$i+1]}" ]]; then
                item2=$(printf " [%-2d] %-18s" "$((i+2))" "${geosites[$i+1]}")
            else
                item2=""
            fi
            echo -e "$item1 $item2"
        done
        echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
        DOMS=$(cat /usr/local/etc/xray/rule_list.txt | xargs)
        echo -e " Active Rules: ${GREEN}$DOMS${NC}"
        echo -e " [1] Tambah rule geosite"
        echo -e " [2] Hapus rule geosite"
        echo -e " [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1)
                read -p " Masukkan Nomor/Nama Rule: " d
                if [[ "$d" =~ ^[0-9]+$ ]] && [ "$d" -ge 1 ] && [ "$d" -le "${#geosites[@]}" ]; then
                    d="${geosites[$((d-1))]}"
                fi
                echo "$d" >> /usr/local/etc/xray/rule_list.txt
                LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//')
                jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "port443" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG
                systemctl restart xray
                echo -e "${GREEN}Rule $d berhasil ditambahkan!${NC}"; sleep 1;;
            2)
                echo -e " ${YELLOW}List Rule Aktif:${NC}"
                nl /usr/local/etc/xray/rule_list.txt
                read -p " Hapus Nomor: " n
                [[ -z "$n" ]] && continue
                sed -i "${n}d" /usr/local/etc/xray/rule_list.txt
                LIST=$(cat /usr/local/etc/xray/rule_list.txt | awk '{printf "\"geosite:%s\",", $1}' | sed 's/,$//')
                jq --argjson d "[$LIST]" '.routing.rules[] |= (if .outboundTag == "port443" then .domain = $d else . end)' $CONFIG > /tmp/r && mv /tmp/r $CONFIG
                systemctl restart xray
                echo -e "${GREEN}Rule berhasil dihapus!${NC}"; sleep 1;;
            x) return;;
        esac
    done
}

function check_services() {
    header_sub; echo -e " SERVICES STATUS\n─────────────────────────────────────────────────"; services=("xray" "zivpn" "vnstat" "netfilter-persistent" "xray-login-notif" "tendo-autobot"); names=("Xray VPN Core   " "ZIVPN UDP Server" "Vnstat Monitor  " "Iptables Rules  " "Login Logger    " "Telegram AutoBot")
    for i in "${!services[@]}"; do if systemctl is-active --quiet "${services[$i]}"; then status="${GREEN}ACTIVE (ON)${NC}"; else status="${RED}INACTIVE (OFF)${NC}"; fi; echo -e " ${names[$i]} : $status"; done
    echo -e "${CYAN}─────────────────────────────────────────────────${NC}"; read -p "Enter...";
}

function features_menu() {
    while true; do
        header_sub
        echo -e " [1] Routing Geosite            [7] Clear Cache RAM"
        echo -e " [2] Backup & Restore           [8] Auto Reboot"
        echo -e " [3] Speedtest by Ookla         [9] Information System"
        echo -e " [4] Ganti Domain VPS           [10] Rebuild VPS"
        echo -e " [5] Check Bandwidth (Vnstat)   [11] Restart Services"
        echo -e " [6] Check Benchmark VPS (YABS) [x] Back"
        echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) routing_menu ;;
            2) backup_restore_menu ;;
            3) header_sub
               if ! command -v speedtest &> /dev/null; then
                   echo -e "${YELLOW}Menginstall Official Ookla Speedtest...${NC}"
                   ARCH=$(uname -m)
                   if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
                       DL_URL="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
                   else
                       DL_URL="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
                   fi
                   curl -sL "$DL_URL" | tar -xz -C /usr/bin speedtest
               fi
               echo -e "${GREEN}Running Ookla Speedtest...${NC}\n"
               speedtest --accept-license --accept-gdpr
               read -p "Enter..." ;;
            4) read -p "Domain Baru: " nd; echo "$nd" > /usr/local/etc/xray/domain; openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout $XRAY_DIR/xray.key -out $XRAY_DIR/xray.crt -days 3650 -subj "/CN=$nd" >/dev/null 2>&1; systemctl restart xray; echo "Domain Updated!"; sleep 1 ;;
            5) header_sub; IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1); vnstat -i $IFACE; read -p "Enter..." ;;
            6) header_sub; echo -e "${YELLOW}Running YABS (This will take a while)...${NC}"; curl -sL yabs.sh | bash; read -p "Enter..." ;;
            7) echo 3 > /proc/sys/vm/drop_caches; swapoff -a && swapon -a; echo -e "${GREEN}RAM Cache Cleared!${NC}"; read -p "Enter..." ;;
            8) clear; echo -e "${YELLOW}AUTO REBOOT SETTING${NC}\n"; read -p "Set Jam Auto Reboot (HH:MM, contoh: 05:00): " rb_time
               if [[ "$rb_time" =~ ^[0-9]{2}:[0-9]{2}$ ]]; then hr=$(echo $rb_time | cut -d: -f1); mn=$(echo $rb_time | cut -d: -f2); crontab -l 2>/dev/null | grep -v "/sbin/reboot" | crontab -; (crontab -l 2>/dev/null; echo "$mn $hr * * * /sbin/reboot") | crontab -; echo -e "${GREEN}Auto reboot set for $rb_time daily!${NC}"; else echo -e "${RED}Invalid format!${NC}"; fi; read -p "Enter..." ;;
            9) header_sub; neofetch; read -p "Enter..." ;;
            10) clear; echo -e "${YELLOW}REBUILD VPS${NC}\n1. Ubuntu 22.04\n2. Ubuntu 20.04\n3. Debian 12\n4. Debian 11\n"
                read -p "Pilih OS [1-4]: " os_choice
                case $os_choice in
                    1) os_cmd="ubuntu"; os_ver="22.04" ;;
                    2) os_cmd="ubuntu"; os_ver="20.04" ;;
                    3) os_cmd="debian"; os_ver="12" ;;
                    4) os_cmd="debian"; os_ver="11" ;;
                    *) echo "Pilihan tidak valid"; read -p "Enter..."; continue ;;
                esac
                read -p "Masukkan password root baru: " new_pass
                if [[ -n "$new_pass" ]]; then
                    echo -e "${GREEN}Memulai proses Reinstall OS... VPS akan otomatis reboot.${NC}"
                    sleep 2
                    curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh "$os_cmd" "$os_ver" --password "$new_pass"
                else
                    echo -e "${RED}Password tidak boleh kosong!${NC}"; read -p "Enter..."
                fi ;;
            11) header_sub; echo -e "${YELLOW}Restarting All Services...${NC}"; systemctl restart xray zivpn vnstat netfilter-persistent xray-login-notif cron tendo-autobot; echo -e "${GREEN}✅ Services Restarted Successfully!${NC}"; read -p "Enter..." ;;
            x) return ;;
        esac
    done
}

while true; do header_main; read -p " Select Menu : " opt
    case $opt in
        1) xray_menu ;;
        2) zivpn_menu ;;
        3) telegram_bot_menu ;;
        4) features_menu ;;
        5) check_services ;;
        x) exit ;;
    esac; done
EOF

chmod +x /usr/bin/menu
echo -e "\033[0;32m[ INFO ]\033[0m INSTALASI BERHASIL! KETIK: \033[1;32mmenu\033[0m"
