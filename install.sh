#!/bin/bash

# ==========================================
# Script Name: GoPay VPS System Manager
# Version: 7.2 (Bot Menu Updated)
# Description: Terminal Menu interaktif untuk setup VPS
# ==========================================

# Definisi Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==========================================
# FUNGSI: SETUP DOMAIN & SSL
# ==========================================
setup_domain_ssl() {
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${GREEN}      SETUP DOMAIN & HTTPS (SSL)          ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    
    read -p "Masukkan nama domain Anda (contoh: api.domain.com): " DOMAIN_NAME
    
    if [[ -z "$DOMAIN_NAME" ]]; then
        echo -e "${RED}Error: Domain tidak boleh kosong!${NC}"
        sleep 2
        return
    fi

    echo -e "\n${YELLOW}[+] Memperbarui sistem dan menginstal Nginx & Certbot...${NC}"
    sudo apt update -y
    sudo apt install nginx certbot python3-certbot-nginx -y

    echo -e "\n${YELLOW}[+] Menyiapkan konfigurasi Nginx untuk Reverse Proxy...${NC}"
    cat << EOF | sudo tee /etc/nginx/sites-available/gopay-proxy
server {
    listen 80;
    server_name $DOMAIN_NAME;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

    # Mengaktifkan konfigurasi Nginx
    sudo ln -sf /etc/nginx/sites-available/gopay-proxy /etc/nginx/sites-enabled/
    sudo nginx -t
    sudo systemctl restart nginx

    echo -e "\n${YELLOW}[+] Menjalankan Certbot untuk instalasi SSL...${NC}"
    sudo certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos -m admin@$DOMAIN_NAME || echo -e "${RED}Gagal mendapatkan SSL. Pastikan DNS sudah diarahkan ke IP VPS ini.${NC}"

    echo -e "\n${GREEN}Setup Domain dan SSL Selesai!${NC}"
    echo -e "Website / API Anda sekarang dapat diakses di: https://$DOMAIN_NAME"
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}

SELESAI
# ==========================================
# FUNGSI: SETUP BOT TELEGRAM
# ==========================================
setup_telegram_bot() {
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${GREEN}          SETUP BOT TELEGRAM              ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    
    read -p "Masukkan Telegram Bot Token Anda: " BOT_TOKEN
    read -p "Masukkan Admin Chat ID Anda: " CHAT_ID
    
    if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
        echo -e "${RED}Error: Token dan Chat ID tidak boleh kosong!${NC}"
        sleep 2
        return
    fi

    APP_DIR="/var/www/gopay-bot-button"
    sudo mkdir -p $APP_DIR
    sudo chown -R $USER:$USER $APP_DIR
    cd $APP_DIR

    echo -e "\n${YELLOW}[+] Menginstal Node.js dan PM2...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt install -y nodejs
    sudo npm install -g pm2

    echo -e "\n${YELLOW}[+] Inisialisasi Project Node.js...${NC}"
    npm init -y > /dev/null 2>&1
    npm install node-telegram-bot-api axios > /dev/null 2>&1

    echo -e "\n${YELLOW}[+] Menulis konfigurasi bot...${NC}"
    
    cat << EOF > bot.js
const TelegramBot = require('node-telegram-bot-api');
const bot = new TelegramBot('${BOT_TOKEN}', {polling: true});
const ADMIN_CHAT_ID = '${CHAT_ID}';

// Variabel untuk menyimpan sesi API secara internal
let SESSION_TOKEN = "Belum Login";
let DEVICE_ID = "Belum Diatur";

const mainKeyboard = {
    reply_markup: {
        keyboard: [
            ['🔑 Minta OTP', '📊 Cek Saldo'],
            ['🌐 GoPay API', '⚙️ Settings']
        ],
        resize_keyboard: true
    }
};

bot.onText(/\/start/, (msg) => {
    if (msg.chat.id.toString() !== ADMIN_CHAT_ID) return;
    bot.sendMessage(msg.chat.id, "👋 *Halo Admin! Panel Bot Terintegrasi Aktif.*", { 
        parse_mode: "Markdown", 
        ...mainKeyboard 
    });
});

bot.on('message', (msg) => {
    if (msg.chat.id.toString() !== ADMIN_CHAT_ID) return;
    
    const text = msg.text;

    if (text === '🔑 Minta OTP') {
        bot.sendMessage(msg.chat.id, "📲 *Request OTP*\nSilakan kirim nomor HP Anda (format: 085xxx).", {parse_mode: "Markdown"});
    }
    
    else if (text === '📊 Cek Saldo') {
        bot.sendMessage(msg.chat.id, "🔍 Sedang mengambil data saldo terbaru...");
        // Tambahkan logika axios.get saldo di sini
    }

    else if (text === '🌐 GoPay API') {
        const apiInfo = "🌐 *Status GoPay API*\n\n" +
                        "▪️ *Session:* " + SESSION_TOKEN.substring(0, 10) + "...\n" +
                        "▪️ *Device:* " + DEVICE_ID + "\n" +
                        "▪️ *Status:* Standby\n\n" +
                        "Klik tombol 'Minta OTP' jika sesi kedaluwarsa.";
        bot.sendMessage(msg.chat.id, apiInfo, {parse_mode: "Markdown"});
    }
});
EOF

    echo -e "\n${YELLOW}[+] Menjalankan Bot di background dengan PM2...${NC}"
    pm2 stop gopay-telegram-bot > /dev/null 2>&1 || true
    pm2 start bot.js --name "gopay-telegram-bot"
    pm2 save
    
    echo -e "\n${GREEN}Setup Bot Telegram Selesai!${NC}"
    echo -e "Sekarang tombol 'GoPay API' sudah tersedia di menu bot."
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}

# ==========================================
# MAIN MENU LOOP
# ==========================================
while true; do
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${GREEN}       GOPAY VPS TERMINAL MANAGER         ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo -e "1. Setup Domain & HTTPS (SSL)"
    echo -e "2. Setup Bot Telegram"
    echo -e "3. Keluar"
    echo -e "${CYAN}==========================================${NC}"
    read -p "Pilih menu (1-3): " OPTION
    
    case $OPTION in
        1) setup_domain_ssl ;;
        2) setup_telegram_bot ;;
        3) 
            echo -e "${GREEN}Keluar dari Terminal Manager. Terima kasih!${NC}"
            exit 0 
            ;;
        *) 
            echo -e "${RED}Pilihan tidak valid! Masukkan angka 1-3.${NC}"
            sleep 1 
            ;;
    esac
done

SELESAI
