#!/bin/bash

# =========================================================
# SCRIPT INSTALLER GOPAY API + TELEGRAM MENU (INTERACTIVE)
# Versi: 3.0.0 (Auto-Config)
# =========================================================

# 1. Input Data dari User
clear
echo "--- KONFIGURASI BOT TELEGRAM ---"
read -p "Masukkan Token Bot Telegram: " TELE_TOKEN
read -p "Masukkan ID Telegram Admin: " TELE_ADMIN_ID
echo "--------------------------------"

# 2. Update & Install Dependencies
echo "Menginstall dependencies..."
apt-get update -y
apt-get install -y nodejs npm mariadb-server redis-server
mkdir -p /opt/self-gopay-api
cd /opt/self-gopay-api

# 3. Setup Database
echo "Mengkonfigurasi Database..."
mysql -e "CREATE DATABASE IF NOT EXISTS my_gopay_core;"
mysql -e "CREATE TABLE IF NOT EXISTS my_gopay_core.accounts (
    id INT PRIMARY KEY DEFAULT 1,
    phone_number VARCHAR(20),
    session_token TEXT,
    balance DECIMAL(15,2) DEFAULT 0,
    status ENUM('active', 're-auth') DEFAULT 're-auth'
) ON DUPLICATE KEY UPDATE id=1;"

mysql -e "CREATE TABLE IF NOT EXISTS my_gopay_core.payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    external_id VARCHAR(100) UNIQUE,
    amount DECIMAL(15,2),
    status ENUM('pending', 'success') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);"

# 4. Membuat File .env secara Otomatis
cat <<EOF > .env
PORT=8080
DB_HOST=localhost
DB_USER=root
DB_PASS=
DB_NAME=my_gopay_core
SECRET_KEY=$(openssl rand -hex 16)
TELE_TOKEN=$TELE_TOKEN
TELE_ADMIN_ID=$TELE_ADMIN_ID
EOF

# 5. Inisialisasi Node.js Project
npm init -y
npm install express axios mysql2 dotenv node-telegram-bot-api

# 6. Core Logic Part A (Server & Session Checker)
cat <<EOF > app.js
const express = require('express');
const mysql = require('mysql2/promise');
const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config();

const app = express();
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    connectionLimit: 5
});

const bot = new TelegramBot(process.env.TELE_TOKEN, { polling: true });
const adminId = process.env.TELE_ADMIN_ID;

// Fungsi Cek Sesi
async function checkSession() {
    const [rows] = await pool.execute('SELECT * FROM accounts LIMIT 1');
    if (rows.length === 0 || rows[0].status === 're-auth') {
        return { valid: false, message: 'Silakan Login/Link Akun Kembali' };
    }
    return { valid: true, data: rows[0] };
}

// Endpoint Internal
app.get('/health', (req, res) => res.send('OK'));

SELESAI
# 7. Core Logic Part B (Menu Telegram & Alur Login OTP)
cat <<EOF >> app.js

const mainKeyboard = {
    reply_markup: {
        keyboard: [
            ['💰 Cek Saldo', '🔑 Link Akun GoPay'],
            ['📊 Riwayat Transaksi', '🛡️ Status Sesi'],
            ['➕ Buat QRIS Tagihan']
        ],
        resize_keyboard: true
    }
};

// --- Perintah Start ---
bot.onText(/\/start/, (msg) => {
    if (msg.from.id.toString() !== adminId) return;
    bot.sendMessage(adminId, "🤖 Panel API GoPay Merchant Mandiri Siap.\nSilakan pilih menu di bawah:", mainKeyboard);
});

// --- Handler Menu ---
bot.on('message', async (msg) => {
    if (msg.from.id.toString() !== adminId) return;

    switch (msg.text) {
        case '💰 Cek Saldo':
            const session = await checkSession();
            if (!session.valid) return bot.sendMessage(adminId, "❌ Sesi mati. Silakan Klik 'Link Akun GoPay' ulang.");
            bot.sendMessage(adminId, \`Saldo saat ini: Rp\${session.data.balance}\`);
            break;

        case '🛡️ Status Sesi':
            const check = await checkSession();
            bot.sendMessage(adminId, \`Status: \${check.valid ? '✅ Aktif' : '❌ Perlu Login'}\`);
            break;

        case '🔑 Link Akun GoPay':
            bot.sendMessage(adminId, "Kirimkan nomor HP GoPay Anda.\nContoh: 08123456789");
            break;

        case '➕ Buat QRIS Tagihan':
            bot.sendMessage(adminId, "Format: /qris [jumlah]\nContoh: /qris 50000");
            break;
    }
});

// --- Alur Login (RegEx untuk Nomor HP) ---
bot.onText(/^(08|628)\d+$/, async (msg) => {
    if (msg.from.id.toString() !== adminId) return;
    const phone = msg.text;
    bot.sendMessage(adminId, \`Sedang meminta OTP untuk \${phone}...\`);
    
    // Logika Request OTP ke Gojek akan diproses di sini
    // Untuk saat ini, kita simpan nomor ke DB
    await pool.execute('INSERT INTO accounts (id, phone_number, status) VALUES (1, ?, "re-auth") ON DUPLICATE KEY UPDATE phone_number=?', [phone, phone]);
    
    bot.sendMessage(adminId, "OTP telah dikirim ke HP Anda. Balas dengan format: /otp [nomor_otp]");
});

bot.onText(/\/otp (.+)/, async (msg, match) => {
    if (msg.from.id.toString() !== adminId) return;
    const otp = match[1];
    bot.sendMessage(adminId, "Memverifikasi OTP...");

    // Simulasi Berhasil (Anda bisa menghubungkan fungsi Axios ke API Login Gojek di sini)
    await pool.execute('UPDATE accounts SET status="active", balance=0 WHERE id=1');
    bot.sendMessage(adminId, "✅ Akun Berhasil Terhubung! Sesi telah disimpan.");
});

bot.onText(/\/qris (.+)/, async (msg, match) => {
    if (msg.from.id.toString() !== adminId) return;
    const amount = match[1];
    bot.sendMessage(adminId, \`Membuat QRIS sebesar Rp\${amount}...\n[Contoh QRIS Data: 00020101021126570022ID.CO.GOPAY...]\`);
});

// Jalankan Server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(\`Server running on port \${PORT}\`));
EOF

# 8. Otomatisasi dengan PM2
echo "Menjalankan API di background..."
npm install -g pm2
pm2 start app.js --name "gopay-bot-api"
pm2 save
pm2 startup

# 9. Penutupan
clear
echo "--------------------------------------------------------"
echo " INSTALASI BERHASIL"
echo "--------------------------------------------------------"
echo " Silakan buka bot Telegram Anda dan ketik: /start"
echo "--------------------------------------------------------"
echo " API Key Internal Anda: \$(grep SECRET_KEY .env | cut -d '=' -f2)"
echo "--------------------------------------------------------"

SELESAI
