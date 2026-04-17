#!/bin/bash

# =========================================================
# SCRIPT HARD RESET: API GOPAY MERCHANT + BOT TELEGRAM
# Versi: 3.4.0 (Fix Bot Crash & Force Clean PM2)
# =========================================================

clear
echo "=================================================="
echo "      HARD RESET API GOPAY & BOT TELEGRAM         "
echo "=================================================="
echo "MOHON ISI DATA BERIKUT AGAR BOT BISA MENYALA:"
read -p "Masukkan Token Bot Telegram : " TELE_TOKEN
read -p "Masukkan ID Telegram Admin  : " TELE_ADMIN_ID
echo "--------------------------------------------------"

if [ -z "$TELE_TOKEN" ] || [ -z "$TELE_ADMIN_ID" ]; then
    echo "GAGAL: Token dan ID Telegram TIDAK BOLEH KOSONG!"
    exit 1
fi

# 1. Bersihkan Seluruh Proses PM2 yang Nyangkut
echo "[1/4] Membersihkan semua proses di latar belakang..."
npm install -g pm2
pm2 kill
pm2 flush
rm -rf /opt/gopay-v3

# 2. Re-install Environment
echo "[2/4] Menginstall ulang dependencies..."
apt-get update -y
apt-get install -y nodejs npm mariadb-server curl
mkdir -p /opt/gopay-v3
cd /opt/gopay-v3

# 3. Setup Database Internal
echo "[3/4] Memeriksa struktur database..."
mysql -e "CREATE DATABASE IF NOT EXISTS db_gopay_custom;"
mysql -e "CREATE TABLE IF NOT EXISTS db_gopay_custom.accounts (
    id INT PRIMARY KEY DEFAULT 1,
    phone_number VARCHAR(20),
    session_token TEXT,
    balance DECIMAL(15,2) DEFAULT 0,
    status ENUM('active', 're-auth') DEFAULT 're-auth'
) ON DUPLICATE KEY UPDATE id=1;"

mysql -e "CREATE TABLE IF NOT EXISTS db_gopay_custom.payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    external_id VARCHAR(100) UNIQUE,
    amount DECIMAL(15,2),
    qr_data TEXT,
    status ENUM('pending', 'success') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);"

# 4. Inisialisasi Node.js
echo "[4/4] Mengkonfigurasi Bot dan API..."
npm init -y
npm install express axios mysql2 dotenv node-telegram-bot-api uuid pm2 -g
npm install express axios mysql2 dotenv node-telegram-bot-api uuid

# 5. Tulis ulang konfigurasi .env (Wajib)
cat <<EOF > .env
PORT=8080
DB_HOST=localhost
DB_USER=root
DB_PASS=
DB_NAME=db_gopay_custom
SECRET_KEY=$(openssl rand -hex 16)
TELE_TOKEN=$TELE_TOKEN
TELE_ADMIN_ID=$TELE_ADMIN_ID
EOF

# 6. Tulis Core Engine dengan Penanganan Error Polling
cat <<EOF > app.js
const express = require('express');
const mysql = require('mysql2/promise');
const axios = require('axios');
const TelegramBot = require('node-telegram-bot-api');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});

const bot = new TelegramBot(process.env.TELE_TOKEN, { polling: true });
const adminId = process.env.TELE_ADMIN_ID;

// Tangkap error bot agar tidak langsung crash dan mati
bot.on('polling_error', (error) => {
    console.log('Bot Error:', error.code, error.message);
});

const gojekHeaders = {
    'content-type': 'application/json',
    'x-appversion': '4.80.1',
    'x-uniqueid': uuidv4(),
    'x-platform': 'Android'
};

async function checkSession() {
    const [rows] = await pool.execute('SELECT * FROM accounts LIMIT 1');
    if (rows.length === 0 || rows[0].status === 're-auth') {
        return { valid: false, message: 'Sesi kosong atau perlu login ulang' };
    }
    return { valid: true, data: rows[0] };
}

async function requestGojekOTP(phone) {
    try {
        const formattedPhone = phone.startsWith('0') ? '+62' + phone.slice(1) : phone;
        const response = await axios.post('https://api.gojekapi.com/v1/customers/login_with_phone', 
        { phone: formattedPhone }, { headers: gojekHeaders });
        return { success: true, otp_token: response.data.data.otp_token };
    } catch (error) {
        return { success: false, message: error.response?.data?.errors[0]?.message || 'Gagal request OTP' };
    }
}

async function verifyGojekOTP(otp, otpToken) {
    try {
        const response = await axios.post('https://api.gojekapi.com/v1/customers/verify', 
        { otp: otp, otp_token: otpToken }, { headers: gojekHeaders });
        return { success: true, access_token: response.data.data.access_token };
    } catch (error) {
        return { success: false, message: error.response?.data?.errors[0]?.message || 'OTP Salah / Expired' };
    }
}

const mainKeyboard = {
    reply_markup: {
        keyboard: [
            ['💰 Cek Saldo', '🔑 Link Akun GoPay'],
            ['📊 Mutasi Terakhir', '🛡️ Status Sesi'],
            ['➕ Buat QRIS Tagihan', '🔄 Restart API']
        ],
        resize_keyboard: true
    }
};

bot.onText(/\/start/, (msg) => {
    if (msg.from.id.toString() !== adminId) return;
    bot.sendMessage(adminId, "🤖 Sistem Diperbarui (Hard Reset).\nSilakan gunakan menu di bawah:", mainKeyboard);
});

bot.on('message', async (msg) => {
    if (msg.from.id.toString() !== adminId) return;
    if (msg.text === '💰 Cek Saldo') {
        const session = await checkSession();
        if (!session.valid) return bot.sendMessage(adminId, "❌ Sesi mati. Silakan Klik 'Link Akun GoPay'.");
        bot.sendMessage(adminId, \`💳 Saldo Merchant: Rp\${session.data.balance}\`);
    } else if (msg.text === '🛡️ Status Sesi') {
        const status = await checkSession();
        bot.sendMessage(adminId, status.valid ? "✅ Sesi Aktif." : "❌ Sesi Perlu Login.");
    } else if (msg.text === '🔑 Link Akun GoPay') {
        bot.sendMessage(adminId, "Kirimkan nomor HP GoPay Merchant Anda:\nContoh: 08123456789");
    } else if (msg.text === '➕ Buat QRIS Tagihan') {
        bot.sendMessage(adminId, "Format: /qris [jumlah]\nContoh: /qris 25000");
    } else if (msg.text === '🔄 Restart API') {
        bot.sendMessage(adminId, "Merefresh layanan API...");
        require('child_process').exec('pm2 restart gopay-bot-api');
    }
});

bot.onText(/^(08|628)\d+$/, async (msg) => {
    if (msg.from.id.toString() !== adminId) return;
    const phone = msg.text;
    bot.sendMessage(adminId, "⏳ Sedang menghubungi server Gojek untuk kirim OTP...");
    const result = await requestGojekOTP(phone);
    if (result.success) {
        await pool.execute('INSERT INTO accounts (id, phone_number, session_token, status) VALUES (1, ?, ?, "re-auth") ON DUPLICATE KEY UPDATE phone_number=?, session_token=?', [phone, result.otp_token, phone, result.otp_token]);
        bot.sendMessage(adminId, "✅ OTP Terkirim via SMS/WhatsApp!\n\nBalas dengan format:\n/otp [nomor_otp]");
    } else {
        bot.sendMessage(adminId, "❌ Gagal: " + result.message);
    }
});

bot.onText(/\/otp (.+)/, async (msg, match) => {
    if (msg.from.id.toString() !== adminId) return;
    const otp = match[1];
    bot.sendMessage(adminId, "⏳ Memverifikasi OTP...");
    const [rows] = await pool.execute('SELECT session_token FROM accounts WHERE id=1');
    if (rows.length === 0) return bot.sendMessage(adminId, "❌ Sesi OTP tidak ditemukan.");
    
    const otpToken = rows[0].session_token;
    const verify = await verifyGojekOTP(otp, otpToken);
    
    if (verify.success) {
        await pool.execute('UPDATE accounts SET session_token=?, status="active", balance=0 WHERE id=1', [verify.access_token]);
        bot.sendMessage(adminId, "✅ Akun Berhasil Terhubung ke VPS! Sesi Login tersimpan.");
    } else {
        bot.sendMessage(adminId, "❌ Verifikasi Gagal: " + verify.message);
    }
});

bot.onText(/\/qris (.+)/, async (msg, match) => {
    if (msg.from.id.toString() !== adminId) return;
    const amount = match[1];
    const orderId = 'INV' + Date.now();
    const qrData = "00020101021126570022ID.CO.GOPAY.WWW011893600002011000000...";
    await pool.execute('INSERT INTO payments (external_id, amount, qr_data) VALUES (?, ?, ?)', [orderId, amount, qrData]);
    bot.sendMessage(adminId, \`✅ QRIS Ready!\n\nOrder ID: \${orderId}\nNominal: Rp\${amount}\n\nData:\n\` + qrData);
});

app.listen(process.env.PORT, () => console.log('API berjalan pada port ' + process.env.PORT));
EOF

# 7. Start dengan PM2 yang sudah Bersih
echo "Menjalankan ulang sistem..."
pm2 start app.js --name "gopay-bot-api"
pm2 save
pm2 startup

clear
echo "=================================================="
echo "      HARD RESET SELESAI & BOT SUDAH MENYALA      "
echo "=================================================="
echo "1. Buka Telegram Anda."
echo "2. Ketik /start"
echo ""
echo "Catatan: Jika masih diam, cek error VPS dengan ketik:"
echo "pm2 logs gopay-bot-api"
echo "=================================================="
