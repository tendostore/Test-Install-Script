#!/bin/bash
# ==================================================
#    Auto Script Install X-ray & Zivpn
#    EDITION: SUPER PLATINUM LTS FINAL V.103
#    Protocols: VLESS, VMESS, TROJAN, ZIVPN (UDP)
#    Script BY: Tendo Store | Fixed: Full Permissions
# ==================================================

# --- 1. OPTIMASI & CLEANUP ---
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

# --- 2. INSTALL DEPENDENCIES (FIXED LIST) ---
apt update -y
# Hapus 'base64' (sudah ada di coreutils) untuk mencegah error instalasi
apt install -y curl socat jq openssl uuid-runtime net-tools vnstat wget \
gnupg1 bc iproute2 iptables iptables-persistent python3 neofetch coreutils

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
# Memberikan izin akses agar Xray bisa membaca file sertifikat
chmod 644 $XRAY_DIR/xray.key
chmod 644 $XRAY_DIR/xray.crt
chown -R nobody:nobody $XRAY_DIR

# --- 5. XRAY CORE & CONFIG (MULTI-PROTOCOL) ---
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

# --- 6. ZIVPN UDP CONFIG ---
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

# Restart & Enable All Services
systemctl daemon-reload
systemctl enable xray zivpn vnstat
systemctl restart xray zivpn vnstat

# --- 7. CREATE MENU ---
cat > /usr/bin/menu <<'END_MENU'
#!/bin/bash
clear
echo -e "=============================="
echo -e "    TENDO STORE MENU V.103"
echo -e "=============================="
echo -e " 1. VLESS Menu"
echo -e " 2. VMESS Menu"
echo -e " 3. TROJAN Menu"
echo -e " 4. ZIVPN Menu"
echo -e " 5. Check Services"
echo -e " x. Exit"
echo -e "=============================="
read -p " Pilih nomor: " opt
case $opt in
    1) # VLESS logic here
    ;;
    2) # VMESS logic here
    ;;
    3) # TROJAN logic here
    ;;
    5) systemctl status xray zivpn ;;
    x) exit ;;
esac
END_MENU
chmod +x /usr/bin/menu

echo "INSTALASI BERHASIL! Ketik: menu"
