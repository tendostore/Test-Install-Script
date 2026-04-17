#!/bin/bash

# ==========================================
# Script Name: GoPay VPS System Manager (Fixed Version)
# Version: 8.0
# Description: Terminal Menu + Fixed Telegram Bot Logic
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
    echo -e "API Anda sekarang aktif di: https://$DOMAIN_NAME"
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}

# ==========================================
# FUNGSI: SETUP BOT TELEGRAM (FIXED LOGIC)
# ==========================================
setup_telegram_bot() {
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${GREEN}          SETUP BOT TELEGRAM              ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    
    read -p "Masukkan Telegram Bot Token Anda: " BOT_TOKEN
    read -p "Masukkan Admin Chat ID Anda: " CHAT_ID
    
    if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
        echo -e "${RED}Error: Data tidak lengkap!${NC}"
        sleep 2
        return
    fi

    APP_DIR="/var/www/gopay-bot-button"
    sudo mkdir -p $APP_DIR
    sudo chown -R $USER:$USER $APP_DIR
    cd $APP_DIR

    echo -e "\n${YELLOW}[+] Menginstal Dependensi Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt install -y nodejs
    sudo npm install -g pm2
    npm init -y > /dev/null 2>&1
    npm install node-telegram-bot-api axios > /dev/null 2>&1

    echo -e "\n${YELLOW}[+] Menulis file bot.js dengan logika Fixed OTP...${NC}"
    
    cat << 'EOF' > bot.js
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');

// GANTI MANUAL BAGIAN INI JIKA PERLU
const TELEGRAM_TOKEN = 'TOKEN_BOT_PLACEHOLDER';
const ADMIN_CHAT_ID = 'CHAT_ID_PLACEHOLDER';
const GOJEK_API_URL = "https://api.gojekapi.com";

let GOJEK_HEADERS = {
    'Content-Type': 'application/json',
    'X-AppVersion': '4.80.1', 
    'X-UniqueId': 'android_c1a2b3c4d5e6f7g8', 
    'User-Agent': 'Gojek/4.80.1 (com.gojek.app; build:12345; Android 11)'
};

const bot = new TelegramBot(TELEGRAM_TOKEN, {polling: true});

let SESSION_TOKEN = ""; 
let TEMP_OTP_TOKEN = ""; 
let userState = ""; 

const mainKeyboard = {
    reply_markup: {
        keyboard: [['🔑 Minta OTP', '📊 Cek Saldo'], ['🌐 GoPay API', '⚙️ Settings']],
        resize_keyboard: true
    }
};

bot.onText(/\/start/, (msg) => {
    if (msg.chat.id.toString() !== ADMIN_CHAT_ID) return;
    userState = ""; 
    bot.sendMessage(msg.chat.id, "👋 *Halo Admin! Panel Bot Terintegrasi Aktif.*", { parse_mode: "Markdown", ...mainKeyboard });
});

bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const text = msg.text;
    if (chatId.toString() !== ADMIN_CHAT_ID) return;

    if (text === '🔑 Minta OTP') {
        userState = "WAITING_PHONE";
        return bot.sendMessage(chatId, "📲 *Request OTP*\nSilakan kirim nomor HP Anda (format: 085xxx).", {parse_mode: "Markdown"});
    }

    if (userState === "WAITING_PHONE") {
        userState = "SENDING_OTP";
        bot.sendMessage(chatId, `⏳ Sedang meminta OTP untuk ${text}...`);
        try {
            const res = await axios.post(`${GOJEK_API_URL}/v3/customers/login_with_phone`, { phone: text }, { headers: GOJEK_HEADERS });
            TEMP_OTP_TOKEN = res.data.data.otp_token; 
            userState = "WAITING_OTP";
            bot.sendMessage(chatId, `✅ *OTP Terkirim!*\n\nMasukkan 4 digit kode OTP dari SMS.`, {parse_mode: "Markdown"});
        } catch (e) {
            userState = "";
            bot.sendMessage(chatId, "❌ Gagal request OTP. Cek header/nomor.");
        }
        return;
    }

    if (userState === "WAITING_OTP") {
        bot.sendMessage(chatId, "⏳ Memverifikasi...");
        try {
            const res = await axios.post(`${GOJEK_API_URL}/v3/customers/login_with_otp`, { otp: text, otp_token: TEMP_OTP_TOKEN }, { headers: GOJEK_HEADERS });
            SESSION_TOKEN = res.data.data.access_token;
            userState = "";
            bot.sendMessage(chatId, "🎊 *Login Berhasil!*", {parse_mode: "Markdown", ...mainKeyboard});
        } catch (e) {
            bot.sendMessage(chatId, "❌ OTP Salah.");
        }
        return;
    }
    
    if (text === '📊 Cek Saldo') {
        bot.sendMessage(chatId, "🔍 Fitur saldo sedang diproses...");
    }
    
    if (text === '🌐 GoPay API') {
        bot.sendMessage(chatId, `🌐 *Status API*\nToken: \`${SESSION_TOKEN || 'Belum Ada'}\``, {parse_mode: "Markdown"});
    }
});
EOF

    # Mengganti placeholder dengan input user
    sed -i "s/TOKEN_BOT_PLACEHOLDER/${BOT_TOKEN}/g" bot.js
    sed -i "s/CHAT_ID_PLACEHOLDER/${CHAT_ID}/g" bot.js

    # Lanjutan Part 2...
    # Melanjutkan fungsi setup_telegram_bot...
    echo -e "\n${YELLOW}[+] Menjalankan Bot di background dengan PM2...${NC}"
    pm2 stop gopay-telegram-bot > /dev/null 2>&1 || true
    pm2 start bot.js --name "gopay-telegram-bot"
    pm2 save
    
    echo -e "\n${GREEN}Setup Bot Telegram Selesai!${NC}"
    echo -e "Sekarang tombol 'GoPay API' sudah tersedia di menu bot."
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}

# ==========================================
# MAIN MENU LOOP (INTERAKTIF)
# ==========================================
while true; do
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${GREEN}       GOPAY VPS TERMINAL MANAGER         ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo -e "1. Setup Domain & HTTPS (SSL)"
    echo -e "2. Setup Bot Telegram (Full Fixed OTP)"
    echo -e "3. Keluar"
    echo -e "${CYAN}==========================================${NC}"
    read -p "Pilih menu (1-3): " OPTION
    
    case $OPTION in
        1) 
            setup_domain_ssl 
            ;;
        2) 
            setup_telegram_bot 
            ;;
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
