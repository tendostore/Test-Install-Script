cat > /usr/local/bin/client-bot-helper.sh << 'EOF'
#!/bin/bash
ACTION=$1; PROTO=$2; USER=$3; PASS=$4; DAYS=$5
CONFIG="/usr/local/etc/xray/config.json"
D_SSH="/usr/local/etc/xray/ssh.txt"; D_VMESS="/usr/local/etc/xray/vmess.txt"; D_VLESS="/usr/local/etc/xray/vless.txt"
D_TROJAN="/usr/local/etc/xray/trojan.txt"; D_ZIVPN="/etc/zivpn/zivpn.txt"
DMN=$(cat /usr/local/etc/xray/domain 2>/dev/null); CITY=$(cat /root/tendo/city 2>/dev/null)
ISP=$(cat /root/tendo/isp 2>/dev/null); IP=$(cat /root/tendo/ip 2>/dev/null)

if [[ "$ACTION" == "check" ]]; then
    if grep -q "^$USER|" $D_SSH $D_VMESS $D_VLESS $D_TROJAN $D_ZIVPN 2>/dev/null || id "$USER" &>/dev/null; then echo "EXISTS"; else echo "OK"; fi
    exit 0
fi

if [[ "$ACTION" == "info" ]]; then
    echo "<b>📊 INFORMASI JUMLAH USER AKTIF</b>"
    echo "<b>--------------------------------</b>"
    if [[ -f "$D_SSH" ]]; then c=$(wc -l < "$D_SSH" 2>/dev/null || echo 0); echo "<b>[ 🔹 SSH / WS ] : $c User</b>"; fi
    if [[ -f "$D_VMESS" ]]; then c=$(wc -l < "$D_VMESS" 2>/dev/null || echo 0); echo "<b>[ 🔹 VMESS ] : $c User</b>"; fi
    if [[ -f "$D_VLESS" ]]; then c=$(wc -l < "$D_VLESS" 2>/dev/null || echo 0); echo "<b>[ 🔹 VLESS ] : $c User</b>"; fi
    if [[ -f "$D_TROJAN" ]]; then c=$(wc -l < "$D_TROJAN" 2>/dev/null || echo 0); echo "<b>[ 🔹 TROJAN ] : $c User</b>"; fi
    if [[ -f "$D_ZIVPN" ]]; then c=$(wc -l < "$D_ZIVPN" 2>/dev/null || echo 0); echo "<b>[ 🔹 ZIVPN ] : $c User</b>"; fi
    exit 0
fi

if [[ "$ACTION" == "create" ]]; then
    if (( DAYS > 5 )); then DAYS=5; fi
    exp_date=$(date -d "+$DAYS days" +"%Y-%m-%d")
    limit=2; usage="0.00"
    
    # --- FITUR OTOMATIS 100 GB KHUSUS BOT TETAP ADA ---
    if [[ "$PROTO" == "vmess" || "$PROTO" == "vless" || "$PROTO" == "trojan" ]]; then
        quota=100
        str_quota="100 GB"
    else
        quota=0
        str_quota="Unlimited"
    fi

    MSG_BOT=""
    
    if [[ "$PROTO" == "ssh" ]]; then
        grep -q "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
        useradd -e $(date -d "$DAYS days" +"%Y-%m-%d") -s /bin/false -M $USER; echo "$USER:$PASS" | chpasswd
        echo "$USER|$PASS|$exp_date|$limit|ACTIVE" >> $D_SSH
        MSG_BOT+="<b>————————————————————————————————————</b>\n          <b>ACCOUNT SSH / WS</b>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="Username       : <code>${USER}</code>\nPassword       : <code>${PASS}</code>\nCITY           : ${CITY}\nISP            : ${ISP}\nDomain         : <code>${DMN}</code>\n"
        MSG_BOT+="Port TLS       : 443, 8443\nPort none TLS  : 80, 8080\nPort any       : 2082, 2083, 8880\n"
        MSG_BOT+="Port OpenSSH   : 22, 444\nPort Dropbear  : 90\nPort UDPGW     : 7100-7600\nLimit IP       : ${limit} IP\n"
        MSG_BOT+="Payload WS     : <code>GET / HTTP/1.1[crlf]Host: ${DMN}[crlf]Upgrade: websocket[crlf][crlf]</code>\n"
        MSG_BOT+="Expired On     : ${exp_date}\n<b>————————————————————————————————————</b>\n"
    elif [[ "$PROTO" == "vmess" ]]; then
        uuid=$(uuidgen)
        jq --arg u "$USER" --arg id "$uuid" '(.inbounds[] | select(.protocol == "vmess")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
        echo "$USER|$uuid|$exp_date|$limit|ACTIVE|$quota" >> $D_VMESS; echo "0 0" > "/usr/local/etc/xray/quota/$USER"
        link_ws_tls=$(echo "{\"v\":\"2\",\"ps\":\"${USER}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
        link_ws_ntls=$(echo "{\"v\":\"2\",\"ps\":\"${USER}\",\"add\":\"${DMN}\",\"port\":\"80\",\"id\":\"${uuid}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess\",\"tls\":\"\",\"sni\":\"\"}" | base64 -w 0)
        link_grpc_tls=$(echo "{\"v\":\"2\",\"ps\":\"${USER}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
        link_upg_tls=$(echo "{\"v\":\"2\",\"ps\":\"${USER}\",\"add\":\"${DMN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"httpupgrade\",\"type\":\"none\",\"host\":\"${DMN}\",\"path\":\"/vmess-upg\",\"tls\":\"tls\",\"sni\":\"${DMN}\"}" | base64 -w 0)
        MSG_BOT+="<b>————————————————————————————————————</b>\n               <b>VMESS</b>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="Username       : <code>${USER}</code>\nCITY           : ${CITY}\nISP            : ${ISP}\nDomain         : <code>${DMN}</code>\nPort TLS       : 443\nPort none TLS  : 80\n"
        MSG_BOT+="Password / ID  : <code>${uuid}</code>\nalterId        : 0\nSecurity       : auto\n"
        MSG_BOT+="network        : ws, grpc, upgrade\npath ws        : /vmess\nserviceName    : vmess-grpc\npath upgrade   : /vmess-upg\n"
        MSG_BOT+="Limit IP       : ${limit} IP\nQuota Bandwidth: ${str_quota}\nUsage Bandwidth: ${usage} GB\nExpired On     : ${exp_date}\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n           <b>VMESS WS TLS</b>\n<b>————————————————————————————————————</b>\n<code>vmess://${link_ws_tls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="          <b>VMESS WS NO TLS</b>\n<b>————————————————————————————————————</b>\n<code>vmess://${link_ws_ntls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="             <b>VMESS GRPC</b>\n<b>————————————————————————————————————</b>\n<code>vmess://${link_grpc_tls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="         <b>VMESS Upgrade TLS</b>\n<b>————————————————————————————————————</b>\n<code>vmess://${link_upg_tls}</code>\n<b>————————————————————————————————————</b>\n"
    elif [[ "$PROTO" == "vless" ]]; then
        uuid=$(uuidgen)
        jq --arg u "$USER" --arg id "$uuid" '(.inbounds[] | select(.protocol == "vless")).settings.clients += [{"id":$id,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
        echo "$USER|$uuid|$exp_date|$limit|ACTIVE|$quota" >> $D_VLESS; echo "0 0" > "/usr/local/etc/xray/quota/$USER"
        link_ws_tls="vless://${uuid}@${DMN}:443?path=%2Fvless&security=tls&encryption=none&host=${DMN}&type=ws&sni=${DMN}#${USER}"
        link_ws_ntls="vless://${uuid}@${DMN}:80?path=%2Fvless&security=none&encryption=none&host=${DMN}&type=ws#${USER}"
        link_grpc_tls="vless://${uuid}@${DMN}:443?security=tls&encryption=none&host=${DMN}&type=grpc&serviceName=vless-grpc&sni=${DMN}#${USER}"
        link_upg_tls="vless://${uuid}@${DMN}:443?path=%2Fvless-upg&security=tls&encryption=none&host=${DMN}&type=httpupgrade&sni=${DMN}#${USER}"
        MSG_BOT+="<b>————————————————————————————————————</b>\n               <b>VLESS</b>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="Username       : <code>${USER}</code>\nCITY           : ${CITY}\nISP            : ${ISP}\nDomain         : <code>${DMN}</code>\nPort TLS       : 443\nPort none TLS  : 80\n"
        MSG_BOT+="Password / ID  : <code>${uuid}</code>\nEncryption     : none\n"
        MSG_BOT+="network        : ws, grpc, upgrade\npath ws        : /vless\nserviceName    : vless-grpc\npath upgrade   : /vless-upg\n"
        MSG_BOT+="Limit IP       : ${limit} IP\nQuota Bandwidth: ${str_quota}\nUsage Bandwidth: ${usage} GB\nExpired On     : ${exp_date}\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n           <b>VLESS WS TLS</b>\n<b>————————————————————————————————————</b>\n<code>${link_ws_tls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="          <b>VLESS WS NO TLS</b>\n<b>————————————————————————————————————</b>\n<code>${link_ws_ntls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="             <b>VLESS GRPC</b>\n<b>————————————————————————————————————</b>\n<code>${link_grpc_tls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="         <b>VLESS Upgrade TLS</b>\n<b>————————————————————————————————————</b>\n<code>${link_upg_tls}</code>\n<b>————————————————————————————————————</b>\n"
    elif [[ "$PROTO" == "trojan" ]]; then
        uuid="$USER"
        jq --arg p "$uuid" --arg u "$USER" '(.inbounds[] | select(.protocol == "trojan")).settings.clients += [{"password":$p,"email":$u,"level":0}]' $CONFIG > /tmp/x && mv /tmp/x $CONFIG
        echo "$USER|$uuid|$exp_date|$limit|ACTIVE|$quota" >> $D_TROJAN; echo "0 0" > "/usr/local/etc/xray/quota/$USER"
        link_ws_tls="trojan://${uuid}@${DMN}:443?path=%2Ftrojan&security=tls&host=${DMN}&type=ws&sni=${DMN}#${USER}"
        link_grpc_tls="trojan://${uuid}@${DMN}:443?security=tls&host=${DMN}&type=grpc&serviceName=trojan-grpc&sni=${DMN}#${USER}"
        link_upg_tls="trojan://${uuid}@${DMN}:443?path=%2Ftrojan-upg&security=tls&host=${DMN}&type=httpupgrade&sni=${DMN}#${USER}"
        MSG_BOT+="<b>————————————————————————————————————</b>\n               <b>TROJAN</b>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="Username       : <code>${USER}</code>\nCITY           : ${CITY}\nISP            : ${ISP}\nDomain         : <code>${DMN}</code>\nPort TLS       : 443\nPort none TLS  : 80\n"
        MSG_BOT+="Password       : <code>${uuid}</code>\n"
        MSG_BOT+="network        : ws, grpc, upgrade\npath ws        : /trojan\nserviceName    : trojan-grpc\npath upgrade   : /trojan-upg\n"
        MSG_BOT+="Limit IP       : ${limit} IP\nQuota Bandwidth: ${str_quota}\nUsage Traffic: ${usage} GB\nExpired On     : ${exp_date}\n"
        MSG_BOT+="<b>————————————————————————————————————</b>\n           <b>TROJAN WS TLS</b>\n<b>————————————————————————————————————</b>\n<code>${link_ws_tls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="             <b>TROJAN GRPC</b>\n<b>————————————————————————————————————</b>\n<code>${link_grpc_tls}</code>\n<b>————————————————————————————————————</b>\n"
        MSG_BOT+="         <b>TROJAN Upgrade TLS</b>\n<b>————————————————————————————————————</b>\n<code>${link_upg_tls}</code>\n<b>————————————————————————————————————</b>\n"
    elif [[ "$PROTO" == "zivpn" ]]; then
        jq --arg pwd "$USER" '.auth.config += [$pwd]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json
        echo "$USER|$USER|$exp_date" >> $D_ZIVPN
        MSG_BOT+="<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>\n  <b>ACCOUNT ZIVPN UDP</b>\n<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
        MSG_BOT+="Password   : <code>${USER}</code>\nCITY       : ${CITY}\nISP        : ${ISP}\nIP ISP     : <code>${IP}</code>\nDomain     : <code>${DMN}</code>\nExpired On : ${exp_date}\n<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
    fi
    
    # 1. Tampilkan output ke Python Bot
    echo -e "$MSG_BOT"
    
    # 2. TRIGGER RESTART DI BACKGROUND (Agar tidak tertahan/gagal)
    if [[ "$PROTO" == "vmess" || "$PROTO" == "vless" || "$PROTO" == "trojan" ]]; then
        nohup bash -c "sleep 1 && systemctl restart xray" >/dev/null 2>&1 &
    elif [[ "$PROTO" == "zivpn" ]]; then
        nohup bash -c "sleep 1 && systemctl restart zivpn" >/dev/null 2>&1 &
    fi
    
    exit 0
fi
EOF

chmod +x /usr/local/bin/client-bot-helper.sh
echo "Fix Auto-Restart Background Berhasil Diterapkan!"
