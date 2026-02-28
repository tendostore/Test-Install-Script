#!/bin/bash
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

clear
echo -e "\e[32mMenyiapkan package dasar terlebih dahulu...\e[0m"
apt-get update -y
apt-get install -y curl wget lsof jq psmisc unzip cron bash-completion tar xz-utils iptables
clear

export IP=$( curl -sS ipv4.icanhazip.com )

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Developer » AutoScript Custom Edition"
echo -e "  » Xray VLESS & SSH WebSocket Only"
echo -e "  » Dropbear 2019 + Auto Random Domain CF"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported"
    exit 1
fi

if [[ $IP == "" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi

echo -e "\e[32mMemulai Instalasi Otomatis...\e[0m"
sleep 2
clear

# Kredensial Cloudflare
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

REPO="https://raw.githubusercontent.com/Kucrut-jr/instalasi/main/"
start=$(date +%s)

secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

function print_install() {
	echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
	echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}

function print_success() {
    if [[ 0 -eq $? ]]; then
		echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        echo -e "${Green} » $1 berhasil dipasang"
		echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        sleep 2
    fi
}

function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    apt-get update -y
    apt-get install --no-install-recommends software-properties-common -y
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        # Menghapus penambahan PPA karena error 404 di Ubuntu Jammy
        apt-get install haproxy -y
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        apt-get install haproxy -y
    fi
    print_success "Dependencies"
}

function nginx_install() {
    print_install "Setup Nginx"
    apt-get install nginx -y 
    print_success "Nginx"
}

function base_package() {
    print_install "Menginstall Packet Yang Dibutuhkan"
    apt-get update -y
    apt-get upgrade -y
    apt-get install zip pwgen openssl netcat socat cron bash-completion figlet jq -y
    systemctl enable chronyd
    systemctl restart chronyd
    apt-get install ntpdate -y
    ntpdate pool.ntp.org
    apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa bzip2 psmisc
    print_success "Packet Yang Dibutuhkan"
}

function make_folder_xray() {
    print_install "Membuat direktori instalasi"
    mkdir -p /etc/xray
    mkdir -p /var/log/xray
    mkdir -p /usr/bin/xray/
    mkdir -p /var/www/html
    mkdir -p /var/lib/kyt
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/vless
    mkdir -p /etc/ssh
    mkdir -p /etc/user-create
    
    chown www-data:www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/xray/domain
    touch /etc/vless/.vless.db
    touch /etc/ssh/.ssh.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    
    curl -s ifconfig.me > /etc/xray/ipvps
    print_success "Direktori Berhasil Dibuat"
}

function pasang_domain_otomatis() {
    print_install "Menyiapkan Domain Acak via Cloudflare"
    
    DOMAIN_INFO=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID" \
        -H "X-Auth-Email: $CF_ID" \
        -H "X-Auth-Key: $CF_KEY" \
        -H "Content-Type: application/json")
        
    ROOT_DOMAIN=$(echo $DOMAIN_INFO | jq -r '.result.name')
    if [[ "$ROOT_DOMAIN" == "null" || -z "$ROOT_DOMAIN" ]]; then
        ROOT_DOMAIN="vpn-server.site" # Fallback sementara
    fi
    
    SUB=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
    DOMAIN="${SUB}.${ROOT_DOMAIN}"
    
    echo "Membuat Record DNS untuk $DOMAIN"
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
        -H "X-Auth-Email: $CF_ID" \
        -H "X-Auth-Key: $CF_KEY" \
        -H "Content-Type: application/json" \
        --data '{"type":"A","name":"'${DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' > /dev/null 2>&1
        
    echo "IP=" >> /var/lib/kyt/ipvps.conf
    echo $DOMAIN > /etc/xray/domain
    echo $DOMAIN > /root/domain
    print_success "Domain $DOMAIN berhasil dikonfigurasi"
}

function pasang_ssl() {
    print_install "Memasang SSL Pada Domain"
    
    # Membunuh process yang memakai port 80 agar acme.sh berjalan lancar
    echo -e "Membersihkan port 80..."
    fuser -k 80/tcp >/dev/null 2>&1 || true
    lsof -t -i tcp:80 -s tcp:listen | xargs kill -9 >/dev/null 2>&1 || true
    
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    if [[ ! -z "$STOPWEBSERVER" ]]; then
        systemctl stop $STOPWEBSERVER >/dev/null 2>&1
    fi
    systemctl stop nginx >/dev/null 2>&1
    
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

function install_xray() {
    print_install "Core Xray 1.8.1 Latest Version"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data:www-data $domainSock_dir
    
    xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v1.8.1/xray-linux-64.zip"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.1

    mkdir -p /usr/bin/xray
    mkdir -p /etc/xray
    mkdir -p /usr/local/etc/xray
    
    cd `mktemp -d`
    curl -sL "$xraycore_link" -o xray.zip
    unzip -q xray.zip && rm -rf xray.zip
    mv xray /usr/local/bin/xray
    chmod +x /usr/local/bin/xray

    systemctl restart xray
    sleep 0.5
 
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    chmod +x /etc/systemd/system/runn.service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    print_success "Konfigurasi Packet"
}

function ssh(){
    print_install "Memasang Password SSH & Konfigurasi Dasar"
    wget -O /etc/pam.d/common-password "${REPO}files/password" >/dev/null 2>&1
    chmod +x /etc/pam.d/common-password

    cd
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

    cat > /etc/rc.local <<-END
#!/bin/sh -e
exit 0
END

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service

    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "Password SSH"
}

function ins_SSHD(){
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
    print_success "SSHD"
}

function ins_dropbear(){
    print_install "Menginstall Dropbear 2019"
    apt-get remove dropbear -y > /dev/null 2>&1
    apt-get install zlib1g-dev -y > /dev/null 2>&1
    
    cd /usr/src
    wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2 > /dev/null 2>&1
    tar xjf dropbear-2019.78.tar.bz2
    cd dropbear-2019.78
    ./configure > /dev/null 2>&1
    make && make install > /dev/null 2>&1
    
    # Konfigurasi Dropbear
    mkdir -p /etc/dropbear
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    
    cat > /etc/systemd/system/dropbear.service << 'EOF'
[Unit]
Description=Dropbear SSH daemon
After=network.target

[Service]
EnvironmentFile=-/etc/default/dropbear
ExecStart=/usr/local/sbin/dropbear -F -R $DROPBEAR_EXTRA_ARGS
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dropbear
    systemctl start dropbear
    cd
    print_success "Dropbear 2019.78"
}

function ins_epro(){
    print_install "Menginstall ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    
    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws
    
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "BitTorrent" --algo bm -j DROP
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    apt-get autoclean -y >/dev/null 2>&1
    apt-get autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy"
}

function build_menu() {
    print_install "Membuat Local Menu System"
    cat > /usr/local/sbin/menu << 'EOF'
#!/bin/bash
clear
domain=$(cat /etc/xray/domain)
echo "================================================="
echo "               MENU PREMIUM SCRIPT               "
echo "           (Xray VLESS & SSH WebSocket)          "
echo "================================================="
echo " 1. Create SSH WebSocket Account"
echo " 2. Create Xray VLESS Account"
echo " 3. Exit"
echo "================================================="
read -p "Pilih menu [1-3]: " opt
echo ""

case $opt in
    1)
        read -p "Username : " user
        read -p "Password : " pass
        read -p "Expired (Hari): " masaaktif
        exp=$(date -d "+$masaaktif days" +"%Y-%m-%d")
        useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $user
        echo -e "$pass\n$pass" | passwd $user &> /dev/null
        
        clear
        echo "================================================="
        echo "          Detail Akun SSH WebSocket              "
        echo "================================================="
        echo "Domain     : $domain"
        echo "Username   : $user"
        echo "Password   : $pass"
        echo "Port TLS   : 443"
        echo "Port NTLS  : 80"
        echo "Dropbear   : 109, 143"
        echo "Path WS    : /"
        echo "Expired    : $exp"
        echo "================================================="
        ;;
    2)
        read -p "Username : " user
        read -p "Expired (Hari): " masaaktif
        uuid=$(cat /proc/sys/kernel/random/uuid)
        exp=$(date -d "+$masaaktif days" +"%Y-%m-%d")
        
        # Inject to Xray Config (Contoh logic standar)
        sed -i '/#vless$/a\### '"$user $exp"'\n},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
        systemctl restart xray
        
        clear
        echo "================================================="
        echo "             Detail Akun Xray VLESS              "
        echo "================================================="
        echo "Remarks    : $user"
        echo "Domain     : $domain"
        echo "Port       : 443"
        echo "ID (UUID)  : $uuid"
        echo "Encryption : none"
        echo "Network    : ws"
        echo "Path       : /vless"
        echo "TLS        : tls"
        echo "Expired    : $exp"
        echo "================================================="
        ;;
    3)
        exit 0
        ;;
    *)
        echo "Pilihan tidak valid!"
        ;;
esac
EOF
    chmod +x /usr/local/sbin/menu
    print_success "Local Menu System"
}

function ins_restart(){
    print_install "Restarting All Packet"
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart haproxy
    systemctl restart ws
    systemctl restart nginx
    systemctl restart xray
    history -c
    echo "unset HISTFILE" >> /etc/profile
    print_success "All Packet"
}

function profile(){
    cat >/root/.profile <<EOF
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF
    chmod 644 /root/.profile
}

function enable_services(){
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now haproxy
    systemctl enable --now ws
}

function instal(){
    clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain_otomatis
    pasang_ssl
    install_xray
    ssh
    ins_SSHD
    ins_dropbear
    ins_epro
    build_menu
    ins_restart
    profile
    enable_services
}

instal
echo ""
history -c
rm -rf /root/*.zip
rm -rf /root/*.sh
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "${green} Script Successfull Installed"
echo -e "${YELLOW} Silakan ketik 'reboot' secara manual di terminal untuk menerapkan semua perubahan.${NC}"
