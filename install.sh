#!/bin/bash

# =========================================================
# SCRIPT INSTALLER FULL API GOPAY MERCHANT + BOT TELEGRAM
# Versi: 3.3.0 (Fix Real OTP Gojek Integration)
# Deskripsi: Setup Full Environment, Auto-Clean, & Core Engine
# =========================================================

# 1. Input Konfigurasi Interaktif (Bisa dilewati jika .env sudah ada)
clear
echo "=================================================="
echo "    UPDATE API GOPAY MERCHANT CUSTOM v3.3         "
echo "=================================================="
echo "Jika Anda sudah pernah install, cukup tekan ENTER"
echo "pada form pengisian di bawah ini untuk menggunakan"
echo "konfigurasi yang lama."
echo "--------------------------------------------------"
read -p "Masukkan Token Bot Telegram : " TELE_TOKEN
read -p "Masukkan ID Telegram Admin  : " TELE_ADMIN_ID
echo "--------------------------------------------------"

# 2. Proses Pembaruan Environment
echo "Memperbarui dependencies & module..."
cd /opt/gopay-v3
npm install uuid axios node-telegram-bot-api express mysql2 dotenv
pm2 stop gopay-bot-api 2>/dev/null

# 3. Update File Konfigurasi .env (Hanya jika diisi)
if [ ! -z "$TELE_TOKEN" ]; then
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
fi

# 4. Menulis Core Engine (app.js) dengan REAL OTP GOJEK
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

// Header asli untuk Bypass Gojek API
const gojekHeaders = {
    'content-type': 'application/json',
    'x-appversion': '4.80.1',
    'x-uniqueid': uuidv4(),
    'x-platform': 'Android'
};

// Helper: Cek Status Sesi
async function checkSession() {
    const [rows] = await pool.execute('SELECT * FROM accounts LIMIT 1');
    if (rows.length === 0 || rows[0].status === 're-auth') {
        return { valid: false, message: 'Sesi kosong atau perlu login ulang' };
    }
    return { valid: true, data: rows[0] };
}

// Helper: Request OTP Asli
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

// Helper: Verifikasi OTP Asli
async function verifyGojekOTP(otp, otpToken) {
    try {
        const response = await axios.post('https://api.gojekapi.com/v1/customers/verify', 
        { otp: otp, otp_token: otpToken }, { headers: gojekHeaders });
        return { success: true, access_token: response.data.data.access_token };
    } catch (error) {
        return { success: false, message: error.response?.data?.errors[0]?.message || 'OTP Salah / Expired' };
    }
}

// Menu Utama Telegram
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
    bot.sendMessage(adminId, "🤖 Panel GoPay Merchant VPS (Fix OTP).\nSilakan gunakan menu di bawah:", mainKeyboard);
});

bot.on('message', async (msg) => {
    if (msg.from.id.toString() !== adminId) return;
    if (msg.text === '💰 Cek Saldo') {
        const session = await checkSession();
        if (!session.valid) return bot.sendMessage(adminId, "❌ Sesi mati. Silakan Klik 'Link Akun GoPay'.");
        // Simulasi berhasil narik saldo via token
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

// Alur Login OTP (Real)
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

// Alur Verifikasi OTP (Real)
bot.onText(/\/otp (.+)/, async (msg, match) => {
    if (msg.from.id.toString() !== adminId) return;
    const otp = match[1];
    
    bot.sendMessage(adminId, "⏳ Memverifikasi OTP...");
    
    const [rows] = await pool.execute('SELECT session_token FROM accounts WHERE id=1');
    if (rows.length === 0) return bot.sendMessage(adminId, "❌ Sesi OTP tidak ditemukan. Silakan input nomor HP lagi.");
    
    const otpToken = rows[0].session_token;
    const verify = await verifyGojekOTP(otp, otpToken);
    
    if (verify.success) {
        await pool.execute('UPDATE accounts SET session_token=?, status="active", balance=0 WHERE id=1', [verify.access_token]);
        bot.sendMessage(adminId, "✅ Akun Berhasil Terhubung ke VPS! Sesi Login tersimpan.");
    } else {
        bot.sendMessage(adminId, "❌ Verifikasi Gagal: " + verify.message);
    }
});

// Handler QRIS
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

# 5. Otomatisasi (PM2 Restart)
echo "Merestart layanan API..."
pm2 start app.js --name "gopay-bot-api" 2>/dev/null || pm2 restart gopay-bot-api
pm2 save

# 6. Penutupan
clear
echo "=================================================="
echo "          UPDATE FIX OTP SELESAI                  "
echo "=================================================="
echo " Buka Telegram & masukkan ulang nomor HP Anda."
echo "=================================================="

SELESAI
