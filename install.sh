#!/bin/bash
# Script Auto Install SSH WebSocket & Menu
# Dibuat sesuai dengan spesifikasi port dan versi

# Pastikan dijalankan sebagai root
if [ "${EUID}" -ne 0 ]; then
    echo "Harap jalankan script ini sebagai root (sudo su)."
    exit 1
fi

# ==========================================
# 1. VARIABEL & AUTO POINTING CLOUDFLARE
# ==========================================
DOMAIN="free-tendo.store" 
SUB_DOMAIN="vpn.${DOMAIN}"
IP=$(curl -sS ifconfig.me)

# Menyimpan domain untuk dipanggil di menu
echo "${SUB_DOMAIN}" > /etc/vps_domain

CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

echo "Memulai Auto Pointing Domain ke Cloudflare..."
RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${SUB_DOMAIN}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)

if [ "${RECORD_ID}" = "" ]; then
    # Create record
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
         -H "X-Auth-Email: ${CF_ID}" \
         -H "X-Auth-Key: ${CF_KEY}" \
         -H "Content-Type: application/json" \
         --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' > /dev/null
else
    # Update record
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
         -H "X-Auth-Email: ${CF_ID}" \
         -H "X-Auth-Key: ${CF_KEY}" \
         -H "Content-Type: application/json" \
         --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' > /dev/null
fi
echo "Host Anda: ${SUB_DOMAIN} -> ${IP}"

# ==========================================
# 2. INSTALASI DEPENDENSI
# ==========================================
echo "Menginstal paket-paket yang dibutuhkan..."
apt-get update -y
apt-get install -y wget curl python3 stunnel4 gcc make bzip2 zlib1g-dev cron net-tools

# ==========================================
# 3. KONFIGURASI OPENSSH (PORT 444)
# ==========================================
echo "Mengonfigurasi OpenSSH di Port 444..."
sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 444' /etc/ssh/sshd_config
systemctl restart ssh

# ==========================================
# 4. INSTALASI DROPBEAR 2019 (PORT 90)
# ==========================================
echo "Kompilasi dan instalasi Dropbear versi 2019..."
cd /usr/local/src
wget -O dropbear-2019.78.tar.bz2 https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
tar xjf dropbear-2019.78.tar.bz2
cd dropbear-2019.78
./configure
make
make install

# Buat konfigurasi init untuk Dropbear
cat <<EOF > /etc/systemd/system/dropbear.service
[Unit]
Description=Dropbear SSH Daemon
After=network.target

[Service]
ExecStart=/usr/local/sbin/dropbear -F -R -p 90
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dropbear
systemctl start dropbear

# ==========================================
# 5. SCRIPT WEBSOCKET PROXY (PYTHON)
# ==========================================
# Membuat Script Proxy untuk menangani lalu lintas WS None TLS dan Any Port
echo "Mengonfigurasi proxy WebSocket..."
cat <<'EOF' > /usr/local/bin/ws-proxy.py
import socket
import threading
import sys

def handle_client(client_socket):
    target_host = '127.0.0.1'
    target_port = 90 # Arahkan trafik WS ke Dropbear
    
    try:
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_host, target_port))
        
        request = client_socket.recv(4096)
        if b"HTTP/1.1 101 Switching Protocols" not in request and b"GET / HTTP/1.1" in request:
            response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            client_socket.send(response.encode())
            
        target_socket.sendall(request)
        
        threading.Thread(target=forward, args=(client_socket, target_socket)).start()
        threading.Thread(target=forward, args=(target_socket, client_socket)).start()
    except Exception as e:
        client_socket.close()

def forward(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except:
        pass
    finally:
        source.close()
        destination.close()

def main(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(100)
    print(f"WS Listening on port {port}")
    
    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == '__main__':
    port = int(sys.argv[1])
    main(port)
EOF

chmod +x /usr/local/bin/ws-proxy.py

# Buat service untuk port WS (None TLS & Any)
PORTS=(80 8080 2082 2083 8880)
for p in "${PORTS[@]}"; do
cat <<EOF > /etc/systemd/system/ws-$p.service
[Unit]
Description=WS Proxy on Port $p
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ws-proxy.py $p
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ws-$p
systemctl start ws-$p
done

# ==========================================
# 6. KONFIGURASI STUNNEL4 (TLS PORT 443 & 8443)
# ==========================================
echo "Mengonfigurasi Stunnel untuk TLS..."
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=ID/ST=Jawa Tengah/L=Tahunan/O=VPN Service/CN=${SUB_DOMAIN}" \
    -keyout /etc/stunnel/stunnel.pem \
    -out /etc/stunnel/stunnel.pem > /dev/null 2>&1

cat <<EOF > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[stunnel-ws-443]
accept = 443
connect = 127.0.0.1:80

[stunnel-ws-8443]
accept = 8443
connect = 127.0.0.1:80
EOF

sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
systemctl restart stunnel4
systemctl enable stunnel4

# ==========================================
# 7. PEMBUATAN MENU SSH
# ==========================================
echo "Membuat executable menu..."
cat <<'EOF' > /usr/local/bin/menu
#!/bin/bash
clear
domain=$(cat /etc/vps_domain)

echo "======================================"
echo "          MENU VPN ACCOUNT            "
echo "======================================"
echo "1. Buat Akun SSH & WebSocket Baru"
echo "2. Hapus Akun"
echo "3. Perbarui Password Akun"
echo "4. Keluar"
echo "======================================"
read -p "Pilih menu (1-4): " opt

case $opt in
    1)
        clear
        read -p "Username: " user
        read -p "Password: " pass
        read -p "Expired (Hari): " exp
        
        # Penambahan user
        useradd -e `date -d "$exp days" +"%Y-%m-%d"` -s /bin/false -M $user
        echo -e "$pass\n$pass" | passwd $user > /dev/null 2>&1
        
        clear
        echo "======================================"
        echo "Informasi Akun SSH & WebSocket Anda:"
        echo "======================================"
        echo "Domain     : $domain"
        echo "Username   : $user"
        echo "Password   : $pass"
        echo "Expired    : $exp Hari"
        echo "--------------------------------------"
        echo "OpenSSH    : 444"
        echo "Dropbear   : 90"
        echo "WS TLS     : 443, 8443"
        echo "WS None TLS: 80, 8080"
        echo "WS Any     : 2082, 2083, 8880"
        echo "======================================"
        ;;
    2)
        clear
        read -p "Username yang akan dihapus: " user
        userdel $user
        echo "Akun $user berhasil dihapus!"
        ;;
    3)
        clear
        read -p "Username: " user
        read -p "Password Baru: " pass
        echo -e "$pass\n$pass" | passwd $user > /dev/null 2>&1
        echo "Password akun $user berhasil diperbarui!"
        ;;
    4)
        exit 0
        ;;
    *)
        echo "Pilihan tidak valid!"
        ;;
esac
EOF
chmod +x /usr/local/bin/menu

echo "=========================================================="
echo "Instalasi Selesai!"
echo "Untuk membuka menu manajemen akun, ketikkan perintah: menu"
echo "=========================================================="
