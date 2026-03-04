cat > install-hybrid.sh << 'EOF'
#!/bin/bash
# ==================================================
#   HYBRID INSTALLER: MARZBAN + SSH WS + ZIVPN + TENDO MENU
# ==================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

clear
echo -e "${CYAN}=================================================${NC}"
echo -e "${YELLOW}      INSTALLER HYBRID (MARZBAN + SSH + ZIVPN)   ${NC}"
echo -e "${CYAN}=================================================${NC}"
read -p " Masukkan Domain Marzban Anda (ex: free-tendo.store): " DOMAIN
[[ -z "$DOMAIN" ]] && DOMAIN="free-tendo.store"

# 1. Install Dependencies
echo -e "${GREEN}➤ Menginstal Dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q curl socat jq openssl net-tools vnstat wget python3 python3-pip neofetch cron zip unzip stunnel4 dropbear sqlite3
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
apt-get install -y -q speedtest

# 2. Setup Directories & Env
mkdir -p /usr/local/etc/xray/quota /etc/zivpn /root/tendo /etc/tendo_bot
touch /usr/local/etc/xray/ssh.txt /etc/zivpn/zivpn.txt
curl -s ipinfo.io/json | jq -r '.city' > /root/tendo/city
curl -s ipinfo.io/json | jq -r '.org' > /root/tendo/isp
curl -s ipinfo.io/json | jq -r '.ip' > /root/tendo/ip
echo "$DOMAIN" > /usr/local/etc/xray/domain

# 3. Install SSH, Dropbear & Python WS
echo -e "${GREEN}➤ Menginstal SSH WS & Dropbear...${NC}"
cat > /etc/issue.net << 'BANNER'
<font color="#00FFFF">──────────────────────────────</font><br>
<font color="#00FF00"><b> AUTO SCRIPT TENDO STORE</b></font><br>
<font color="#00FFFF">──────────────────────────────</font><br>
<font color="#FFD700">Version :</font> <font color="#FFFFFF">HYBRID v7.0</font><br>
<font color="#FFD700">Owner   :</font> <font color="#FFFFFF">Tendo Store</font><br>
<font color="#FFD700">Telegram:</font> <font color="#FFFFFF">@tendo_32</font><br>
<font color="#00FFFF">──────────────────────────────</font><br>
<font color="#FF0000"><b> No Spam, DDOS, Hacking!</b></font><br>
BANNER

sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 444' /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
systemctl restart ssh sshd

sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=90/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=.*/DROPBEAR_EXTRA_ARGS="-p 90 -W 65536 -b \/etc\/issue.net"/g' /etc/default/dropbear
systemctl restart dropbear

cat > /usr/local/bin/ws-proxy.py << 'PY'
import socket, select, threading
def handle_client(client_socket):
    remote_socket = None
    try:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote_socket.connect(('127.0.0.1', 22))
        request = client_socket.recv(4096)
        if b"HTTP/" in request:
            client_socket.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            parts = request.split(b"\r\n\r\n", 1)
            if len(parts) == 2 and len(parts[1]) > 0: remote_socket.sendall(parts[1])
        else: remote_socket.sendall(request)
        sockets = [client_socket, remote_socket]
        while True:
            r, _, _ = select.select(sockets, [], [])
            if not r: break
            if client_socket in r:
                data = client_socket.recv(100)
                if not data: break
                remote_socket.sendall(data)
            if remote_socket in r:
                data = remote_socket.recv(100)
                if not data: break
                client_socket.sendall(data)
    except: pass
    finally:
        if remote_socket:
            try: remote_socket.close()
            except: pass
        try: client_socket.close()
        except: pass

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 10015))
server.listen(100)
while True:
    try:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client,))
        t.daemon = True
        t.start()
    except: pass
PY
cat > /etc/systemd/system/ws-proxy.service << 'SVC'
[Unit]
Description=SSH WebSocket Proxy
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ws-proxy.py
Restart=always
[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload && systemctl enable ws-proxy && systemctl start ws-proxy

# 4. Install UDPGW & ZIVPN
echo -e "${GREEN}➤ Menginstal UDPGW & ZIVPN...${NC}"
wget -qO /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/prem/main/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
cat > /etc/systemd/system/badvpn-7100.service << 'SVC2'
[Unit]
Description=BadVPN UDPGW
After=network.target
[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
Restart=always
[Install]
WantedBy=multi-user.target
SVC2
systemctl daemon-reload && systemctl enable badvpn-7100 && systemctl start badvpn-7100

wget -qO /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
echo '{"listen":":5667","cert":"","key":"","obfs":"zivpn","auth":{"mode":"passwords","config":[]}}' > /etc/zivpn/config.json
cat > /etc/systemd/system/zivpn.service << 'SVC3'
[Unit]
Description=ZIVPN
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
[Install]
WantedBy=multi-user.target
SVC3
systemctl daemon-reload && systemctl enable zivpn && systemctl restart zivpn

IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A PREROUTING -i $IFACE -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5667
netfilter-persistent save >/dev/null 2>&1

# 5. Hybrid Menu Tendo Store
echo -e "${GREEN}➤ Menginstal Menu Terminal Tendo Store...${NC}"
cat > /usr/bin/menu << 'END_MENU'
#!/bin/bash
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; WHITE='\033[1;37m'; NC='\033[0m'
D_SSH="/usr/local/etc/xray/ssh.txt"
D_ZIVPN="/etc/zivpn/zivpn.txt"

print_line() {
    local text="$1"
    local clean_text=$(echo -e "$text" | sed -r 's/\x1b\[[0-9;]*m//g' | sed -r 's/\x1b\[[0-9;]*K//g')
    local len=${#clean_text}
    local spaces=$(( 54 - len ))
    local pad=""
    if (( spaces > 0 )); then pad=$(printf '%*s' "$spaces" ""); fi
    echo -e "${CYAN}│${NC}${text}${pad}${CYAN}│${NC}"
}
print_line_open() { echo -e "${CYAN}│${NC}$1"; }
print_center() {
    local text="$1"
    local clean_text=$(echo -e "$text" | sed -r 's/\x1b\[[0-9;]*m//g' | sed -r 's/\x1b\[[0-9;]*K//g')
    local len=${#clean_text}
    local spaces=$(( 54 - len ))
    local pad_l=$(( spaces / 2 ))
    local pad_r=$(( spaces - pad_l ))
    local str_l=$(printf '%*s' "$pad_l" "")
    local str_r=$(printf '%*s' "$pad_r" "")
    echo -e "${CYAN}│${NC}${str_l}${text}${str_r}${CYAN}│${NC}"
}

function show_account_ssh() {
    clear
    local user=$1; local pass=$2; local domain=$3; local exp=$4; local limit=$5
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city)
    echo -e "————————————————————————————————————\n          ACCOUNT SSH / WS\n————————————————————————————————————"
    echo -e "Username       : ${user}\nPassword       : ${pass}\nCITY           : ${city}\nISP            : ${isp}\nDomain         : ${domain}"
    echo -e "Port OpenSSH   : 22, 444\nPort Dropbear  : 90\nPort WS Proxy  : 10015\nPort UDPGW     : 7100\nLimit IP       : ${limit} IP"
    echo -e "Payload WS     : GET / HTTP/1.1[crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "Expired On     : ${exp}\n————————————————————————————————————\n"
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function show_account_zivpn() {
    clear
    local user=$1; local pass=$2; local domain=$3; local exp=$4
    local isp=$(cat /root/tendo/isp); local city=$(cat /root/tendo/city); local ip=$(cat /root/tendo/ip)
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Password   : ${pass}\nCITY       : ${city}\nISP        : ${isp}\nIP ISP     : ${ip}\nDomain     : ${domain}\nExpired On : ${exp}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

function header_main() {
    clear; DOMAIN=$(cat /usr/local/etc/xray/domain); OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME="//g' | sed 's/"//g')
    RAM=$(free -m | awk '/Mem:/ {print $2}'); SWAP=$(free -m | awk '/Swap:/ {print $2}'); IP=$(cat /root/tendo/ip)
    IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    CITY=$(cat /root/tendo/city); ISP=$(cat /root/tendo/isp); UPTIME=$(uptime -p | sed 's/up //')
    
    ACC_SSH=$(wc -l < "$D_SSH" 2>/dev/null || echo 0)
    ACC_ZIVPN=$(wc -l < "$D_ZIVPN" 2>/dev/null || echo 0)
    
    # HYBRID: Membaca Database SQLite Marzban
    DB_PATH="/var/lib/marzban/db.sqlite3"
    if command -v sqlite3 &> /dev/null && [ -f "$DB_PATH" ]; then
        ACC_MZB=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users;")
    else
        ACC_MZB="0"
    fi

    echo -e "${CYAN}┌──────────────────────────────────────────────────────┐${NC}"
    print_center "${YELLOW}AUTO SCRIPT TENDO STORE ( HYBRID )${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────┐${NC}"
    print_line_open "  OS      : ${WHITE}${OS}${NC}"
    print_line_open "  RAM     : ${WHITE}${RAM}MB${NC}"
    print_line_open "  CITY    : ${WHITE}${CITY}${NC}"
    print_line_open "  ISP     : ${WHITE}${ISP}${NC}"
    print_line_open "  IP      : ${WHITE}${IP}${NC}"
    print_line_open "  DOMAIN  : ${YELLOW}${DOMAIN}${NC}"
    print_line_open "  UPTIME  : ${WHITE}${UPTIME}${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
    
    if docker ps | grep -q marzban; then M_ST="${GREEN}ON${NC}"; else M_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet zivpn; then Z_ST="${GREEN}ON${NC}"; else Z_ST="${RED}OFF${NC}"; fi
    if systemctl is-active --quiet ws-proxy; then D_ST="${GREEN}ON${NC}"; else D_ST="${RED}OFF${NC}"; fi
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────┐${NC}"
    print_line "  STATUS  : MARZBAN: ${M_ST} | SSH WS: ${D_ST} | ZIVPN: ${Z_ST}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────┐${NC}"
    print_center "${YELLOW}LIST USER${NC}"
    print_center "————————————————————————————"
    print_center "SSH/WS : ${WHITE}${ACC_SSH}${NC} USR   |   ZIVPN : ${WHITE}${ACC_ZIVPN}${NC} USR"
    print_center "MARZBAN (X-RAY) : ${GREEN}${ACC_MZB}${NC} USR"
    echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
}

function header_sub() { clear; echo -e "${CYAN}┌──────────────────────────────────────────────────────┐${NC}"; print_center "${YELLOW}TENDO STORE - SUB MENU${NC}"; echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"; }

function ssh_menu() {
    while true; do header_sub
        print_line " [1] Create Account SSH"
        print_line " [2] Delete Account SSH"
        print_line " [3] Renew Account SSH"
        print_line " [4] Check Config User"
        print_line " [x] Back"
        echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Username: " u; read -p " Password: " p; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; read -p " Limit IP: " limit; [[ -z "$limit" ]] && limit=0
               exp_date=$(date -d "+$ex days" +"%Y-%m-%d"); grep -q "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells; useradd -e $(date -d "$ex days" +"%Y-%m-%d") -s /bin/false -M $u; echo "$u:$p" | chpasswd; echo "$u|$p|$exp_date|$limit|ACTIVE" >> $D_SSH; DMN=$(cat /usr/local/etc/xray/domain); show_account_ssh "$u" "$p" "$DMN" "$exp_date" "$limit";;
            2) nl $D_SSH; read -p "No: " n; [[ -z "$n" ]] && continue; u=$(sed -n "${n}p" $D_SSH | cut -d'|' -f1); sed -i "${n}d" $D_SSH; userdel -f $u 2>/dev/null; echo -e "${GREEN}Deleted!${NC}"; sleep 2;;
            3) nl $D_SSH; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_SSH); u=$(echo "$line" | cut -d'|' -f1); p=$(echo "$line" | cut -d'|' -f2); exp_old=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); stat=$(echo "$line" | cut -d'|' -f5); read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); sed -i "${n}s/.*/$u|$p|$exp_new|$limit|$stat/" $D_SSH; chage -E $(date -d "$exp_new" +"%Y-%m-%d") $u 2>/dev/null; echo -e "${GREEN}Renewed!${NC}"; sleep 2;;
            4) nl $D_SSH; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_SSH); u=$(echo "$line" | cut -d'|' -f1); p=$(echo "$line" | cut -d'|' -f2); exp_date=$(echo "$line" | cut -d'|' -f3); limit=$(echo "$line" | cut -d'|' -f4); DMN=$(cat /usr/local/etc/xray/domain); show_account_ssh "$u" "$p" "$DMN" "$exp_date" "$limit";;
            x) return;;
        esac
    done
}

function zivpn_menu() {
    while true; do header_sub
        print_line " [1] Create Account ZIVPN"
        print_line " [2] Delete Account ZIVPN"
        print_line " [3] Renew Account ZIVPN"
        print_line " [4] Check Config User"
        print_line " [x] Back"
        echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
        read -p " Select Menu : " opt
        case $opt in
            1) read -p " Password: " p; u="$p"; read -p " Expired (days): " ex; [[ -z "$ex" ]] && ex=30; exp=$(date -d "$ex days" +"%Y-%m-%d"); jq --arg pwd "$p" '.auth.config += [$pwd]' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; echo "$u|$p|$exp" >> $D_ZIVPN; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$u" "$p" "$DMN" "$exp"
               systemd-run --on-active=1 /bin/systemctl restart zivpn >/dev/null 2>&1;;
            2) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); IFS="|" read -r f1 f2 f3 <<< "$line"; if [[ -z "$f3" ]]; then p="$f1"; else p="$f2"; fi; sed -i "${n}d" $D_ZIVPN; jq --arg pwd "$p" 'del(.auth.config[] | select(. == $pwd))' /etc/zivpn/config.json > /tmp/z && mv /tmp/z /etc/zivpn/config.json; echo -e "${GREEN}Deleted!${NC}"; systemd-run --on-active=1 /bin/systemctl restart zivpn >/dev/null 2>&1; sleep 2;;
            3) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); IFS="|" read -r f1 f2 f3 <<< "$line"; if [[ -z "$f3" ]]; then u="unknown"; p="$f1"; exp_old="$f2"; else u="$f1"; p="$f2"; exp_old="$f3"; fi; read -p " Add Days: " add_days; exp_new=$(date -d "$exp_old + $add_days days" +"%Y-%m-%d"); if [[ "$u" == "unknown" ]]; then sed -i "${n}s/.*/$p|$exp_new/" $D_ZIVPN; else sed -i "${n}s/.*/$u|$p|$exp_new/" $D_ZIVPN; fi; echo -e "${GREEN}Renewed!${NC}"; systemd-run --on-active=1 /bin/systemctl restart zivpn >/dev/null 2>&1; sleep 2;;
            4) nl $D_ZIVPN; read -p "No: " n; [[ -z "$n" ]] && continue; line=$(sed -n "${n}p" $D_ZIVPN); IFS="|" read -r f1 f2 f3 <<< "$line"; if [[ -z "$f3" ]]; then u="unknown"; p="$f1"; exp="$f2"; else u="$f1"; p="$f2"; exp="$f3"; fi; DMN=$(cat /usr/local/etc/xray/domain); show_account_zivpn "$u" "$p" "$DMN" "$exp";;
            x) return;;
        esac
    done
}

function xray_hybrid_notice() {
    clear
    header_sub
    echo -e "${YELLOW}====================================================${NC}"
    echo -e "${GREEN}  FITUR X-RAY TELAH DITINGKATKAN KE PANEL MARZBAN!  ${NC}"
    echo -e "${YELLOW}====================================================${NC}"
    echo -e "Untuk membuat akun VLESS, VMESS, dan TROJAN secara"
    echo -e "${GREEN}ANTI-DISCONNECT${NC} (Koneksi tidak akan putus), "
    echo -e "silakan gunakan Web Dashboard atau Bot Telegram Marzban."
    echo -e ""
    echo -e "🔗 Link Panel : ${CYAN}https://$(cat /usr/local/etc/xray/domain):8000/dashboard/${NC}"
    echo -e "${YELLOW}====================================================${NC}"
    read -n 1 -s -r -p "Tekan enter untuk kembali..."
}

while true; do header_main
    echo -e "${CYAN}┌──────────────────────────────────────────────────────┐${NC}"
    print_line " [1] SSH ACCOUNT          [3] ZIVPN UDP"
    print_line " [2] X-RAY MANAGER        [x] EXIT"
    echo -e "${CYAN}└──────────────────────────────────────────────────────┘${NC}"
    read -p " Select Menu : " opt
    case $opt in
        1) ssh_menu ;;
        2) xray_hybrid_notice ;;
        3) zivpn_menu ;;
        x) exit ;;
    esac; done
END_MENU
chmod +x /usr/bin/menu
sed -i '/menu/d' /root/.bashrc; echo "clear" >> /root/.bashrc; echo "menu" >> /root/.bashrc

echo -e "${GREEN}=================================================${NC}"
echo -e "${YELLOW} Hybrid Menu Berhasil Diinstal! Ketik: menu${NC}"
echo -e "${GREEN}=================================================${NC}"
EOF

bash install-hybrid.sh

