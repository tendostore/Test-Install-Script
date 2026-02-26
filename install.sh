#!/bin/bash
# ==========================================================
# Auto Script Install SSH & WebSocket (Unattended) + Menu
# ==========================================================

# Mematikan prompt interaktif saat instalasi paket
export DEBIAN_FRONTEND=noninteractive

echo "Memulai proses instalasi otomatis..."
apt-get update -y
apt-get upgrade -y
apt-get install -y wget curl jq iptables build-essential dirmngr libxml-parser-perl neofetch ufw stunnel4 python3 socat cron

# ==========================================================
# 1. SETUP CLOUDFLARE RANDOM DOMAIN
# ==========================================================
echo "Mengatur Random Domain Cloudflare..."
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

# Membuat random subdomain (5 karakter huruf/angka)
SUB_DOMAIN="$(tr -dc a-z0-9 </dev/urandom | head -c 5)"
DOMAIN="${SUB_DOMAIN}.vip2-tendo.my.id" 
IP=$(curl -sS ipv4.icanhazip.com)

# Dikembalikan ke Awan Abu-abu (proxied: false) sesuai permintaan Anda
curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}'

echo "Domain berhasil dibuat: ${DOMAIN}"

# Menyimpan Full Domain agar bisa dibaca oleh script menu
mkdir -p /etc/vps
echo "${DOMAIN}" > /etc/vps/domain

# ==========================================================
# 2. SETUP OPENSSH (Port 444)
# ==========================================================
echo "Konfigurasi OpenSSH..."
sed -i 's/#Port 22/Port 22\nPort 444/g' /etc/ssh/sshd_config
systemctl restart ssh
systemctl restart sshd

# ==========================================================
# 3. INSTALL DROPBEAR 2019 (Port 90)
# ==========================================================
echo "Menginstal Dropbear versi 2019.78 dari source..."
apt-get remove dropbear -y
apt-get purge dropbear -y
cd /usr/local/src
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
tar -xjf dropbear-2019.78.tar.bz2
cd dropbear-2019.78
./configure --disable-zlib
make
make install

# Konfigurasi Dropbear
mkdir -p /etc/dropbear
/usr/local/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/local/bin/dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key

# Membuat service systemd untuk Dropbear manual
cat > /etc/systemd/system/dropbear.service << END
[Unit]
Description=Dropbear SSH Daemon 2019
After=network.target

[Service]
ExecStart=/usr/local/sbin/dropbear -F -R -p 90 -W 65536
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable dropbear
systemctl start dropbear

# ==========================================================
# 4. SETUP WEBSOCKET PYTHON PROXY (Fix Payload Bypass)
# ==========================================================
echo "Mengatur Python WebSocket Proxy..."
# Menggunakan WS Proxy yang paling stabil untuk payload HTTP Injector/Custom
cat > /usr/local/bin/ws-proxy.py << 'END'
import socket, threading, sys

def handle_client(client_socket):
    try:
        request = client_socket.recv(8192)
        if not request:
            client_socket.close()
            return
        
        # Kirim HTTP 101 Response agar HTTP Custom terkoneksi
        client_socket.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        
        # Hubungkan ke Dropbear (90)
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect(('127.0.0.1', 90))
        
        # Deteksi sisa data payload SSH yang terbawa di belakang header
        if b'\r\n\r\n' in request:
            data = request.split(b'\r\n\r\n', 1)[1]
            if data:
                target_socket.sendall(data)
        else:
            target_socket.sendall(request)

        threading.Thread(target=forward, args=(client_socket, target_socket)).start()
        threading.Thread(target=forward, args=(target_socket, client_socket)).start()
    except:
        client_socket.close()

def forward(source, destination):
    try:
        while True:
            data = source.recv(8192)
            if not data: break
            destination.sendall(data)
    except:
        pass
    finally:
        try: source.close()
        except: pass
        try: destination.close()
        except: pass

def main(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(500)
    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == '__main__':
    main(int(sys.argv[1]))
END

chmod +x /usr/local/bin/ws-proxy.py

# Membuat Systemd untuk WS HTTP (Port 80, 8080) dan Any (2082, 2083, 8880)
PORTS=(80 8080 2082 2083 8880)
for PORT in "${PORTS[@]}"; do
cat > /etc/systemd/system/ws-$PORT.service << END
[Unit]
Description=WebSocket Proxy Port $PORT
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/ws-proxy.py $PORT
Restart=always

[Install]
WantedBy=multi-user.target
END
systemctl daemon-reload
systemctl enable ws-$PORT
systemctl start ws-$PORT
done

# ==========================================================
# 5. SETUP STUNNEL (TLS Port 443, 8443)
# ==========================================================
echo "Mengatur Stunnel untuk TLS..."
# Membuat sertifikat dummy untuk stunnel
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=ID/ST=JawaTengah/L=Tahunan/O=Server/OU=Websocket/CN=${DOMAIN}" \
    -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem

# Konfigurasi Stunnel mem-forward ke WS Proxy (Port 80)
cat > /etc/stunnel/stunnel.conf << END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ws-stunnel-443]
accept = 443
connect = 127.0.0.1:80

[ws-stunnel-8443]
accept = 8443
connect = 127.0.0.1:80
END

sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# ==========================================================
# 6. SETUP MENU & USER MANAGEMENT
# ==========================================================
echo "Mengatur Menu Manager & Create Akun..."

# Script Create Akun (usernew)
cat > /usr/local/bin/usernew << 'END'
#!/bin/bash
clear
DOMAIN_SERVER=$(cat /etc/vps/domain)
echo -e "======================================"
echo -e "         BUAT AKUN SSH & WS           "
echo -e "======================================"
read -p "Username          : " Login
read -p "Password          : " Pass
read -p "Masa Aktif (Hari) : " masaaktif
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
echo -e "$Pass\n$Pass\n" | passwd $Login &> /dev/null
echo -e ""
echo -e "======================================"
echo -e "Detail Akun Baru:"
echo -e "======================================"
echo -e "Username   : $Login"
echo -e "Password   : $Pass"
echo -e "Domain     : $DOMAIN_SERVER"
echo -e "Expired    : $masaaktif Hari"
echo -e "======================================"
echo -e "Port TLS   : 443, 8443"
echo -e "Port NTLS  : 80, 8080"
echo -e "Port Any   : 2082, 2083, 8880"
echo -e "Port OSSH  : 22, 444"
echo -e "Port DB    : 90"
echo -e "======================================"
END
chmod +x /usr/local/bin/usernew

# Script Menu Utama
cat > /usr/local/bin/menu << 'END'
#!/bin/bash
clear
echo -e "======================================"
echo -e "             MENU UTAMA               "
echo -e "======================================"
echo -e "1. Buat Akun SSH & WS (usernew)"
echo -e "2. Keluar"
echo -e "======================================"
read -p "Pilih menu (1/2) : " menu
case $menu in
1) usernew ;;
2) exit ;;
*) echo "Pilihan tidak valid!" ;;
esac
END
chmod +x /usr/local/bin/menu

# ==========================================================
# 7. PENUTUP & RESTART SERVICES
# ==========================================================
echo "Membersihkan dan merestart layanan..."
systemctl daemon-reload
systemctl restart ssh
systemctl restart dropbear
systemctl restart stunnel4
for PORT in "${PORTS[@]}"; do systemctl restart ws-$PORT; done

echo "=========================================================="
echo "                 INSTALASI SELESAI                        "
echo "=========================================================="
echo "Domain Baru       : ${DOMAIN}"
echo "IP Server         : ${IP}"
echo "TLS               : 443, 8443"
echo "None TLS          : 80, 8080"
echo "Any Port          : 2082, 2083, 8880"
echo "OpenSSH           : 22, 444"
echo "Dropbear (2019)   : 90"
echo "=========================================================="
echo "Ketik 'menu' di terminal untuk membuat akun SSH/WS."
echo "=========================================================="
