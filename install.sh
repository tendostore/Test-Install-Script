#!/bin/bash
# ============================================================
# Auto Installer for Xray + SSH WebSocket + Dropbear 2019
# Multi-port support with random domain using Cloudflare API
# Includes account management menu
# ============================================================

set -e
trap 'echo "Error on line $LINENO"' ERR

# Configuration from user
CF_ID="mbuntoncity@gmail.com"
CF_KEY="96bee4f14ef23e42c4509efc125c0eac5c02e"
CF_ZONE_ID="14f2e85e62d1d73bf0ce1579f1c3300c"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me)
if [[ -z "$PUBLIC_IP" ]]; then
    error "Failed to get public IP"
fi
log "Public IP: $PUBLIC_IP"

# Get domain name from Cloudflare zone
log "Fetching domain name from Cloudflare..."
ZONE_INFO=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID" \
    -H "X-Auth-Email: $CF_ID" \
    -H "X-Auth-Key: $CF_KEY" \
    -H "Content-Type: application/json")

if ! echo "$ZONE_INFO" | grep -q '"success":true'; then
    error "Failed to get zone info. Check CF_ID, CF_KEY, CF_ZONE_ID"
fi

DOMAIN=$(echo "$ZONE_INFO" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
if [[ -z "$DOMAIN" ]]; then
    error "Could not extract domain from zone"
fi
log "Base domain: $DOMAIN"

# Generate random subdomain
RAND_STR=$(tr -dc 'a-z0-9' < /dev/urandom | head -c8)
FULL_DOMAIN="${RAND_STR}.${DOMAIN}"
log "Random domain: $FULL_DOMAIN"

# Create DNS A record
log "Creating A record for $FULL_DOMAIN pointing to $PUBLIC_IP..."
CREATE_DNS=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
    -H "X-Auth-Email: $CF_ID" \
    -H "X-Auth-Key: $CF_KEY" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"A\",\"name\":\"$RAND_STR\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":false}")

if ! echo "$CREATE_DNS" | grep -q '"success":true'; then
    error "Failed to create DNS record. Response: $CREATE_DNS"
fi
log "DNS record created successfully"

# ============================================================
# Install dependencies
# ============================================================
log "Updating system and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl wget git build-essential libz-dev jq python3 python3-pip unzip

# ============================================================
# Install Certbot with Cloudflare plugin
# ============================================================
log "Installing Certbot and Cloudflare plugin..."
apt-get install -y certbot python3-certbot-dns-cloudflare

# Create Cloudflare credentials file for certbot
mkdir -p /etc/letsencrypt
cat > /etc/letsencrypt/cloudflare.ini <<EOF
dns_cloudflare_email = $CF_ID
dns_cloudflare_api_key = $CF_KEY
EOF
chmod 600 /etc/letsencrypt/cloudflare.ini

# Obtain SSL certificate
log "Obtaining SSL certificate for $FULL_DOMAIN using DNS challenge..."
certbot certonly --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d "$FULL_DOMAIN" --non-interactive --agree-tos --email "$CF_ID" || error "Certbot failed"

# ============================================================
# Install Dropbear 2019 from source
# ============================================================
log "Compiling Dropbear 2019.78 from source..."
cd /tmp
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
tar -xjf dropbear-2019.78.tar.bz2
cd dropbear-2019.78
./configure --prefix=/usr --sysconfdir=/etc/dropbear
make PROGRAMS="dropbear dbclient dropbearkey dropbearconvert" -j$(nproc)
make PROGRAMS="dropbear dbclient dropbearkey dropbearconvert" install

# Create necessary directories and keys
mkdir -p /etc/dropbear
/usr/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/bin/dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
/usr/bin/dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key

# Disable OpenSSH if running, move it to port 225
if systemctl is-active ssh &>/dev/null; then
    systemctl stop ssh
    systemctl disable ssh
    # Change OpenSSH port to 225 to avoid conflict
    sed -i 's/^#Port 22/Port 225/' /etc/ssh/sshd_config
    systemctl start ssh
    log "OpenSSH moved to port 225"
fi

# Create systemd service for Dropbear
cat > /etc/systemd/system/dropbear.service <<EOF
[Unit]
Description=Dropbear SSH Server
After=network.target

[Service]
ExecStart=/usr/sbin/dropbear -F -E -p 22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dropbear
systemctl start dropbear
log "Dropbear started on port 22"

# ============================================================
# Install wstunnel (WebSocket to TCP proxy)
# ============================================================
log "Installing wstunnel..."
WSTUNNEL_VERSION="v8.0"
wget -q "https://github.com/erebe/wstunnel/releases/download/${WSTUNNEL_VERSION}/wstunnel-linux-amd64" -O /usr/local/bin/wstunnel
chmod +x /usr/local/bin/wstunnel

# Create systemd service for SSH WebSocket non-TLS (port 2095)
cat > /etc/systemd/system/wstunnel-ssh-2095.service <<EOF
[Unit]
Description=WebSocket to SSH (Non-TLS) on port 2095
After=network.target

[Service]
ExecStart=/usr/local/bin/wstunnel server --restrict-to localhost:22 --listen ws://0.0.0.0:2095
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for SSH WebSocket TLS (port 2096)
cat > /etc/systemd/system/wstunnel-ssh-2096.service <<EOF
[Unit]
Description=WebSocket to SSH (TLS) on port 2096
After=network.target

[Service]
ExecStart=/usr/local/bin/wstunnel server --restrict-to localhost:22 --cert /etc/letsencrypt/live/${FULL_DOMAIN}/fullchain.pem --key /etc/letsencrypt/live/${FULL_DOMAIN}/privkey.pem --listen wss://0.0.0.0:2096
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wstunnel-ssh-2095 wstunnel-ssh-2096
systemctl start wstunnel-ssh-2095 wstunnel-ssh-2096
log "SSH WebSocket proxies started on ports 2095 (non-TLS) and 2096 (TLS)"

# ============================================================
# Install Xray
# ============================================================
log "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate random UUIDs and paths
UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)
PATH_VLESS="/vless"
PATH_VMESS="/vmess"
PATH_TROJAN="/trojan"

# Create Xray config with multiple inbounds (single user each for now)
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VLESS",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none",
        "fallbacks": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${FULL_DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${FULL_DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "$PATH_VLESS"
        }
      }
    },
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VMESS"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${FULL_DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${FULL_DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "$PATH_VMESS"
        }
      }
    },
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$UUID_TROJAN"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${FULL_DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${FULL_DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "$PATH_TROJAN"
        }
      }
    },
    {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VLESS"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "$PATH_VLESS"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF

systemctl restart xray
systemctl enable xray
log "Xray configured and started"

# ============================================================
# Save configuration to /etc/vps-config
# ============================================================
cat > /etc/vps-config <<EOF
# VPS Configuration File
DOMAIN="$FULL_DOMAIN"
PUBLIC_IP="$PUBLIC_IP"
UUID_VLESS="$UUID_VLESS"
UUID_VMESS="$UUID_VMESS"
UUID_TROJAN="$UUID_TROJAN"
PATH_VLESS="$PATH_VLESS"
PATH_VMESS="$PATH_VMESS"
PATH_TROJAN="$PATH_TROJAN"
EOF

chmod 600 /etc/vps-config

# ============================================================
# Create menu script /usr/local/bin/vpsmenu
# ============================================================
log "Creating account management menu..."

cat > /usr/local/bin/vpsmenu <<'EOF'
#!/bin/bash
# VPS Management Menu

source /etc/vps-config

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_header() {
    clear
    echo -e "${BLUE}============================================${NC}"
    echo -e "${GREEN}      VPS Account Management Menu${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo "Server Domain : $DOMAIN"
    echo "Public IP     : $PUBLIC_IP"
    echo -e "${BLUE}============================================${NC}"
}

show_server_info() {
    echo -e "\n${YELLOW}Server Information:${NC}"
    echo "Domain         : $DOMAIN"
    echo "Public IP      : $PUBLIC_IP"
    echo ""
    echo "Dropbear SSH   : port 22 (direct)"
    echo "SSH WebSocket  :"
    echo "  - Non-TLS    : ws://$DOMAIN:2095"
    echo "  - TLS        : wss://$DOMAIN:2096"
    echo ""
    echo "Xray Default Accounts:"
    echo "  Protocol/Path          | Port | UUID/Password"
    echo "  -----------------------|------|----------------------------------"
    echo "  VLess + TLS + WebSocket | 443  | $UUID_VLESS  (path: $PATH_VLESS)"
    echo "  VMess + TLS + WebSocket | 443  | $UUID_VMESS  (path: $PATH_VMESS)"
    echo "  Trojan + TLS + WebSocket| 443  | $UUID_TROJAN (path: $PATH_TROJAN)"
    echo "  VLess + WebSocket (noTLS)| 80   | $UUID_VLESS  (path: $PATH_VLESS)"
    echo ""
}

create_ssh_account() {
    echo -e "\n${YELLOW}Create SSH Account${NC}"
    read -p "Username: " username
    if id "$username" &>/dev/null; then
        echo -e "${RED}User $username already exists!${NC}"
        return
    fi
    read -s -p "Password: " password
    echo
    read -p "Expiry date (YYYY-MM-DD, leave empty for no expiry): " expiry
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    if [[ -n "$expiry" ]]; then
        chage -E "$(date -d "$expiry" +%Y-%m-%d)" "$username"
    fi
    echo -e "${GREEN}SSH account created successfully!${NC}"
    echo "Username: $username"
    echo "Password: $password"
    echo "Dropbear: $DOMAIN:22"
    echo "WS non-TLS: ws://$DOMAIN:2095"
    echo "WS TLS: wss://$DOMAIN:2096"
    echo ""
}

list_ssh_accounts() {
    echo -e "\n${YELLOW}List of SSH Accounts:${NC}"
    printf "%-20s %-15s %-15s\n" "Username" "Expiry Date" "Status"
    echo "------------------------------------------------"
    for user in $(getent passwd | awk -F: '$3>=1000 && $3!=65534 {print $1}'); do
        expiry=$(chage -l "$user" | grep "Account expires" | cut -d: -f2 | xargs)
        if [[ "$expiry" == "never" ]]; then
            expiry_date="Never"
            status="Active"
        else
            expiry_date="$expiry"
            if [[ $(date -d "$expiry" +%s) -lt $(date +%s) ]]; then
                status="${RED}Expired${NC}"
            else
                status="${GREEN}Active${NC}"
            fi
        fi
        printf "%-20s %-15s %-15b\n" "$user" "$expiry_date" "$status"
    done
}

add_xray_user() {
    echo -e "\n${YELLOW}Add Xray User${NC}"
    echo "Select protocol:"
    echo "1) VLESS"
    echo "2) VMESS"
    echo "3) Trojan"
    read -p "Choice [1-3]: " proto
    case $proto in
        1) proto_name="vless" ;;
        2) proto_name="vmess" ;;
        3) proto_name="trojan" ;;
        *) echo "Invalid choice"; return ;;
    esac

    # Generate new UUID/password
    new_uuid=$(cat /proc/sys/kernel/random/uuid)
    # Path same as existing (you could allow custom path)
    path_var="PATH_${proto_name^^}"
    path="${!path_var}"

    # Backup config
    cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.bak

    # Add client to the appropriate inbound using jq
    # For simplicity, we assume the first inbound of each protocol on port 443
    # Find the inbound index with matching protocol and port 443
    index=$(jq --arg proto "$proto_name" '[.inbounds[] | select(.protocol == $proto and .port == 443)] | map(.port) | length' /usr/local/etc/xray/config.json)
    if [[ $index -eq 0 ]]; then
        echo "No inbound found for $proto_name on port 443"
        return
    fi

    # For VLESS and VMESS, clients array contains objects with "id"
    # For Trojan, clients array contains objects with "password"
    if [[ "$proto_name" == "trojan" ]]; then
        jq --arg uuid "$new_uuid" '(.inbounds[] | select(.protocol == "trojan" and .port == 443) | .settings.clients) += [{"password": $uuid}]' /usr/local/etc/xray/config.json > /tmp/xray_config.json
    else
        jq --arg uuid "$new_uuid" '(.inbounds[] | select(.protocol == "'$proto_name'" and .port == 443) | .settings.clients) += [{"id": $uuid}]' /usr/local/etc/xray/config.json > /tmp/xray_config.json
    fi

    mv /tmp/xray_config.json /usr/local/etc/xray/config.json
    systemctl restart xray

    echo -e "${GREEN}Xray user added successfully!${NC}"
    echo "Protocol: $proto_name"
    echo "UUID/Password: $new_uuid"
    echo "Domain: $DOMAIN"
    echo "Port: 443 (TLS)"
    echo "Path: $path"
    echo "Network: ws"
    echo "Security: tls"
    echo ""
}

show_xray_users() {
    echo -e "\n${YELLOW}Xray Users:${NC}"
    echo "Protocol: VLESS (port 443 TLS)"
    jq -r '.inbounds[] | select(.protocol=="vless" and .port==443) | .settings.clients[] | "  UUID: " + .id' /usr/local/etc/xray/config.json
    echo "Protocol: VMESS (port 443 TLS)"
    jq -r '.inbounds[] | select(.protocol=="vmess" and .port==443) | .settings.clients[] | "  UUID: " + .id' /usr/local/etc/xray/config.json
    echo "Protocol: Trojan (port 443 TLS)"
    jq -r '.inbounds[] | select(.protocol=="trojan" and .port==443) | .settings.clients[] | "  Password: " + .password' /usr/local/etc/xray/config.json
    echo "Protocol: VLESS (port 80 no TLS)"
    jq -r '.inbounds[] | select(.protocol=="vless" and .port==80) | .settings.clients[] | "  UUID: " + .id' /usr/local/etc/xray/config.json
}

delete_xray_user() {
    echo -e "\n${YELLOW}Delete Xray User${NC}"
    echo "Select protocol:"
    echo "1) VLESS"
    echo "2) VMESS"
    echo "3) Trojan"
    read -p "Choice [1-3]: " proto
    case $proto in
        1) proto_name="vless" ;;
        2) proto_name="vmess" ;;
        3) proto_name="trojan" ;;
        *) echo "Invalid choice"; return ;;
    esac

    # Show current users
    echo "Current $proto_name users on port 443:"
    if [[ "$proto_name" == "trojan" ]]; then
        jq -r '.inbounds[] | select(.protocol=="trojan" and .port==443) | .settings.clients[] | .password' /usr/local/etc/xray/config.json
    else
        jq -r '.inbounds[] | select(.protocol=="'$proto_name'" and .port==443) | .settings.clients[] | .id' /usr/local/etc/xray/config.json
    fi

    read -p "Enter the UUID/Password to delete: " target

    # Backup config
    cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.bak

    if [[ "$proto_name" == "trojan" ]]; then
        jq '(.inbounds[] | select(.protocol=="trojan" and .port==443) | .settings.clients) |= map(select(.password != $target))' --arg target "$target" /usr/local/etc/xray/config.json > /tmp/xray_config.json
    else
        jq '(.inbounds[] | select(.protocol=="'$proto_name'" and .port==443) | .settings.clients) |= map(select(.id != $target))' --arg target "$target" /usr/local/etc/xray/config.json > /tmp/xray_config.json
    fi

    mv /tmp/xray_config.json /usr/local/etc/xray/config.json
    systemctl restart xray
    echo -e "${GREEN}User deleted if existed.${NC}"
}

while true; do
    show_header
    echo "1) Show Server Information"
    echo "2) Create SSH Account"
    echo "3) List SSH Accounts"
    echo "4) Add Xray User"
    echo "5) Show Xray Users"
    echo "6) Delete Xray User"
    echo "7) Exit"
    read -p "Select option [1-7]: " opt
    case $opt in
        1) show_server_info; read -p "Press enter to continue" ;;
        2) create_ssh_account; read -p "Press enter to continue" ;;
        3) list_ssh_accounts; read -p "Press enter to continue" ;;
        4) add_xray_user; read -p "Press enter to continue" ;;
        5) show_xray_users; read -p "Press enter to continue" ;;
        6) delete_xray_user; read -p "Press enter to continue" ;;
        7) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option"; read -p "Press enter to continue" ;;
    esac
done
EOF

chmod +x /usr/local/bin/vpsmenu

# ============================================================
# Create a sample SSH account
# ============================================================
log "Creating a sample SSH account (username: test, password: random)..."
SSH_PASS=$(tr -dc 'A-Za-z0-9!@#$%' < /dev/urandom | head -c12)
useradd -m -s /bin/bash test
echo "test:$SSH_PASS" | chpasswd
log "SSH account created: test / $SSH_PASS"

# ============================================================
# Final output
# ============================================================
clear
echo "============================================================"
echo -e "${GREEN}Installation completed successfully!${NC}"
echo "============================================================"
echo "Domain         : $FULL_DOMAIN"
echo "Public IP      : $PUBLIC_IP"
echo ""
echo "Dropbear SSH   : port 22 (direct)"
echo "SSH WebSocket  :"
echo "  - Non-TLS    : ws://$FULL_DOMAIN:2095"
echo "  - TLS        : wss://$FULL_DOMAIN:2096"
echo ""
echo "Xray Default Config:"
echo "  Protocol/Path          | Port | UUID/Password"
echo "  -----------------------|------|----------------------------------"
echo "  VLess + TLS + WebSocket | 443  | $UUID_VLESS  (path: $PATH_VLESS)"
echo "  VMess + TLS + WebSocket | 443  | $UUID_VMESS  (path: $PATH_VMESS)"
echo "  Trojan + TLS + WebSocket| 443  | $UUID_TROJAN (path: $PATH_TROJAN)"
echo "  VLess + WebSocket (noTLS)| 80   | $UUID_VLESS  (path: $PATH_VLESS)"
echo ""
echo "Sample SSH account:"
echo "  Username: test"
echo "  Password: $SSH_PASS"
echo ""
echo "Certificate path: /etc/letsencrypt/live/$FULL_DOMAIN/"
echo "============================================================"
echo "Management menu installed. Run 'vpsmenu' to manage accounts."
echo "============================================================"
