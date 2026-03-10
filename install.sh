#!/bin/bash

# ==========================================
# WARNA UNTUK UI TERMINAL
# ==========================================
C_RED="\e[31m"
C_GREEN="\e[32m"
C_YELLOW="\e[33m"
C_BLUE="\e[34m"
C_CYAN="\e[36m"
C_MAG="\e[35m"
C_RST="\e[0m"
C_BOLD="\e[1m"

# Buka Port 3000
sudo ufw allow 3000/tcp > /dev/null 2>&1 || true
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT > /dev/null 2>&1 || true

# ==========================================
# 1. BIKIN SHORTCUT 'BOT' OTOMATIS DI VPS
# ==========================================
if [ ! -f "/usr/bin/bot" ]; then
    if [ -f "/usr/bin/menu" ]; then sudo rm -f /usr/bin/menu; fi
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/bot > /dev/null
    sudo chmod +x /usr/bin/bot
fi

# ==========================================
# 2. FUNGSI MEMBUAT TAMPILAN WEB APLIKASI
# ==========================================
generate_web_app() {
    echo -e "${C_CYAN}⏳ Meracik Tampilan Web App (Fitur Login & OTP)...${C_RST}"
    mkdir -p public

    cat << 'EOF' > public/manifest.json
{
  "name": "Tendo Store App",
  "short_name": "Tendo Store",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#f0f2f5",
  "theme_color": "#0088cc",
  "orientation": "portrait",
  "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/3144/3144456.png", "sizes": "512x512", "type": "image/png"}]
}
EOF

    cat << 'EOF' > public/sw.js
self.addEventListener('install', (e) => { console.log('SW Install'); });
self.addEventListener('fetch', (e) => { });
EOF

    cat << 'EOF' > public/index.html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Tendo Store</title>
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#0088cc">
    <link rel="apple-touch-icon" href="https://cdn-icons-png.flaticon.com/512/3144/3144456.png">
    
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 0; display: flex; justify-content: center; }
        #app { width: 100%; max-width: 480px; background: #fafafa; min-height: 100vh; box-shadow: 0 0 20px rgba(0,0,0,0.05); position: relative; padding-bottom: 50px;}
        .header { background: linear-gradient(135deg, #0088cc, #005580); color: white; padding: 20px; text-align: center; font-size: 22px; font-weight: bold; border-bottom-left-radius: 20px; border-bottom-right-radius: 20px; box-shadow: 0 4px 15px rgba(0,136,204,0.2); display: flex; justify-content: space-between; align-items: center;}
        .container { padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.03); margin-bottom: 20px; border: 1px solid #f0f0f0;}
        .card-saldo { background: linear-gradient(135deg, #11998e, #38ef7d); color: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 15px rgba(17,153,142,0.3); margin-bottom: 25px; position: relative;}
        
        .btn { background: #0088cc; color: white; border: none; padding: 15px; width: 100%; border-radius: 10px; font-size: 16px; font-weight: bold; cursor: pointer; transition: 0.2s;}
        .btn-outline { background: white; color: #0088cc; border: 2px solid #0088cc; padding: 15px; width: 100%; border-radius: 10px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        .btn-topup { background: #fff; color: #11998e; border: none; padding: 8px 15px; border-radius: 20px; font-size: 13px; font-weight: bold; cursor: pointer; position: absolute; right: 20px; top: 50%; transform: translateY(-50%); box-shadow: 0 2px 5px rgba(0,0,0,0.1);}
        .btn-buy { background: #ff9800; color: white; border: none; padding: 8px 15px; border-radius: 8px; font-size: 14px; font-weight: bold; cursor: pointer;}
        
        .btn:active, .btn-buy:active, .btn-topup:active { transform: scale(0.95); }
        .btn-install { background: #ff9800; font-size: 12px; padding: 8px 12px; border-radius: 8px; border: none; color: white; font-weight: bold; cursor: pointer; display: none;}
        
        input { width: 100%; padding: 15px; margin-bottom: 15px; border: 1.5px solid #ddd; border-radius: 10px; box-sizing: border-box; font-size: 16px; outline: none;}
        input:focus { border-color: #0088cc; }
        .hidden { display: none !important; }
        
        .product-item { background: white; padding: 15px; border-radius: 12px; margin-bottom: 12px; border: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.02);}
        .product-info { flex: 1; padding-right: 10px;}
        .product-name { font-weight: bold; font-size: 14px; color: #333; margin-bottom: 5px; line-height: 1.4;}
        .product-cat { font-size: 10px; font-weight: bold; color: #fff; background: #888; padding: 3px 6px; border-radius: 5px; display: inline-block;}
        .cat-pulsa { background: #ff9800; } .cat-data { background: #2196f3; } .cat-game { background: #9c27b0; }
        .product-price-box { text-align: right;}
        .product-price { color: #0088cc; font-weight: bold; font-size: 15px; white-space: nowrap; margin-bottom: 8px;}
        
        .section-title { font-size: 18px; color: #444; margin-bottom: 15px; font-weight: 800; }
        .cat-buttons { display: flex; overflow-x: auto; gap: 10px; margin-bottom: 20px; padding-bottom: 5px;}
        .cat-btn { background: white; border: 1px solid #ddd; padding: 8px 15px; border-radius: 20px; font-size: 13px; white-space: nowrap; cursor: pointer; font-weight: bold; color: #555;}
        .cat-btn.active { background: #0088cc; color: white; border-color: #0088cc;}
        
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000; padding: 20px;}
        .modal-box { background: white; width: 100%; max-width: 400px; border-radius: 20px; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.2);}
        .modal-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #333;}
        .modal-detail { font-size: 14px; color: #666; margin-bottom: 20px; background: #f9f9f9; padding: 10px; border-radius: 10px;}
        .modal-btns { display: flex; gap: 10px; margin-top: 10px;}
        .btn-cancel { background: #eee; color: #555; }
    </style>
</head>
<body>
    <div id="app">
        <div class="header">
            <span>📱 Tendo Store</span>
            <button id="install-btn" class="btn-install">📥 INSTALL</button>
        </div>
        <div class="container">
            
            <div id="login-screen">
                <div class="card" style="margin-top: 20px;">
                    <h2 style="margin-top:0; color: #333; text-align: center;">Masuk Akun</h2>
                    <input type="email" id="log-email" placeholder="Alamat Email">
                    <input type="password" id="log-pass" placeholder="Password">
                    <button class="btn" onclick="login()">Login</button>
                    <button class="btn-outline" onclick="showScreen('register-screen')">Belum Punya Akun? Daftar</button>
                </div>
            </div>

            <div id="register-screen" class="hidden">
                <div class="card" style="margin-top: 20px;">
                    <h2 style="margin-top:0; color: #333; text-align: center;">Daftar Akun Baru</h2>
                    <p style="font-size:13px; color:#666; text-align:center;">Gunakan Nomor WhatsApp yang aktif untuk menerima kode OTP.</p>
                    <input type="email" id="reg-email" placeholder="Alamat Email">
                    <input type="number" id="reg-phone" placeholder="Nomor WhatsApp (Contoh: 62812...)">
                    <input type="password" id="reg-pass" placeholder="Buat Password">
                    <button class="btn" onclick="requestOTP()">Kirim Kode OTP</button>
                    <button class="btn-outline" onclick="showScreen('login-screen')">Sudah Punya Akun? Login</button>
                </div>
            </div>

            <div id="otp-screen" class="hidden">
                <div class="card" style="margin-top: 20px;">
                    <h2 style="margin-top:0; color: #333; text-align: center;">Verifikasi OTP</h2>
                    <p style="font-size:13px; color:#666; text-align:center;">Kode 4 digit telah dikirim ke WhatsApp Anda.</p>
                    <input type="number" id="otp-code" placeholder="Masukkan 4 Digit Kode" style="text-align:center; font-size:24px; letter-spacing: 5px;">
                    <button class="btn" onclick="verifyOTP()">Verifikasi & Daftar</button>
                    <button class="btn-outline" onclick="showScreen('register-screen')">Kembali</button>
                </div>
            </div>

            <div id="dashboard-screen" class="hidden">
                <div class="card-saldo">
                    <div style="font-size:14px; opacity: 0.9; margin-bottom: 5px;">Total Saldo Anda</div>
                    <h1 style="margin: 0; font-size: 32px;" id="user-saldo">Rp 0</h1>
                    <div style="font-size:13px; opacity: 0.8; margin-top: 10px;" id="user-email">Email: -</div>
                    
                    <button class="btn-topup" onclick="reqTopup()">➕ TOPUP</button>
                </div>
                
                <div class="section-title">🛒 Katalog Produk</div>
                
                <div class="cat-buttons" id="cat-filters">
                    <div class="cat-btn active" onclick="filterCat('Semua', this)">Semua</div>
                    <div class="cat-btn" onclick="filterCat('Pulsa', this)">Pulsa</div>
                    <div class="cat-btn" onclick="filterCat('Paket Data', this)">Data</div>
                    <div class="cat-btn" onclick="filterCat('Topup Game', this)">Game</div>
                    <div class="cat-btn" onclick="filterCat('Topup E-Wallet', this)">E-Wallet</div>
                    <div class="cat-btn" onclick="filterCat('Token Listrik', this)">PLN</div>
                </div>

                <div id="product-list">
                    <div style="text-align:center; padding: 20px; color: #888;">Memuat data...</div>
                </div>
            </div>
            
            <div id="order-modal" class="modal-overlay hidden">
                <div class="modal-box">
                    <div class="modal-title">Konfirmasi Pesanan</div>
                    <div class="modal-detail">
                        <strong id="m-name">Nama Produk</strong><br>
                        <span style="color:#0088cc; font-weight:bold; font-size: 16px;" id="m-price">Rp 0</span>
                    </div>
                    <label style="font-size:14px; font-weight:bold; color:#555; display:block; margin-bottom:5px;">Masukkan Nomor / ID Tujuan:</label>
                    <input type="text" id="m-target" placeholder="Contoh: 08123456789">
                    
                    <div class="modal-btns">
                        <button class="btn btn-cancel" onclick="closeModal()">Batal</button>
                        <button class="btn" id="m-submit" onclick="processOrder()">Beli Sekarang</button>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        // PWA SETUP
        let deferredPrompt;
        const installBtn = document.getElementById('install-btn');
        window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferredPrompt = e; installBtn.style.display = 'block'; });
        installBtn.addEventListener('click', async () => { if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; installBtn.style.display = 'none';} });
        if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

        let allProducts = {};
        let currentUser = ""; // Phone number
        let currentEmail = "";
        let selectedSKU = "";
        let tempRegPhone = "";

        function showScreen(id) {
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('register-screen').classList.add('hidden');
            document.getElementById('otp-screen').classList.add('hidden');
            document.getElementById('dashboard-screen').classList.add('hidden');
            document.getElementById(id).classList.remove('hidden');
        }

        // SISTEM LOGIN
        async function login() {
            let email = document.getElementById('log-email').value.trim();
            let pass = document.getElementById('log-pass').value.trim();
            if(!email || !pass) return alert('Masukkan Email dan Password!');
            
            try {
                let res = await fetch('/api/login', {
                    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email, password: pass})
                });
                let data = await res.json();
                if(data.success) {
                    currentUser = data.phone;
                    currentEmail = email;
                    document.getElementById('user-saldo').innerText = 'Rp ' + data.data.saldo.toLocaleString('id-ID');
                    document.getElementById('user-email').innerText = email;
                    showScreen('dashboard-screen');
                    loadProducts(); 
                } else { alert(data.message); }
            } catch(e) { alert('Gagal terhubung ke server.'); }
        }

        // SISTEM DAFTAR & OTP
        async function requestOTP() {
            let email = document.getElementById('reg-email').value.trim();
            let phone = document.getElementById('reg-phone').value.trim();
            let pass = document.getElementById('reg-pass').value.trim();
            if(!email || !phone || !pass) return alert('Lengkapi semua data!');
            
            try {
                let res = await fetch('/api/register', {
                    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email, phone, password: pass})
                });
                let data = await res.json();
                if(data.success) {
                    tempRegPhone = phone;
                    alert('Kode OTP berhasil dikirim ke WhatsApp Anda!');
                    showScreen('otp-screen');
                } else { alert(data.message); }
            } catch(e) { alert('Server error.'); }
        }

        async function verifyOTP() {
            let otp = document.getElementById('otp-code').value.trim();
            if(!otp) return alert('Masukkan OTP!');
            try {
                let res = await fetch('/api/verify-otp', {
                    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({phone: tempRegPhone, otp})
                });
                let data = await res.json();
                if(data.success) {
                    alert('Registrasi Berhasil! Silakan Login.');
                    document.getElementById('log-email').value = document.getElementById('reg-email').value;
                    document.getElementById('log-pass').value = document.getElementById('reg-pass').value;
                    showScreen('login-screen');
                } else { alert(data.message); }
            } catch(e) { alert('Server error.'); }
        }

        // FITUR TOPUP VIA WA
        function reqTopup() {
            let pesan = `Halo Admin, saya ingin mengajukan Topup Saldo akun Tendo Store.%0A%0A📧 Email: *${currentEmail}*%0A📱 No WA Akun: *${currentUser}*%0A💰 Nominal Topup: `;
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }

        // PRODUK & ORDER
        async function loadProducts() {
            try {
                let res = await fetch('/api/produk');
                allProducts = await res.json();
                renderProducts('Semua');
            } catch(e) { document.getElementById('product-list').innerHTML = '<div style="color:red;">Gagal memuat produk.</div>'; }
        }

        function filterCat(cat, el) {
            document.querySelectorAll('.cat-btn').forEach(btn => btn.classList.remove('active'));
            el.classList.add('active');
            renderProducts(cat);
        }

        function renderProducts(filterCategory) {
            let listHTML = '';
            for(let key in allProducts) {
                let p = allProducts[key];
                if (filterCategory !== 'Semua' && p.kategori !== filterCategory) continue;
                let badgeClass = 'cat-pulsa';
                if(p.kategori === 'Paket Data') badgeClass = 'cat-data';
                if(p.kategori === 'Topup Game') badgeClass = 'cat-game';
                let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                listHTML += `
                    <div class="product-item">
                        <div class="product-info">
                            <div class="product-name">${p.nama}</div>
                            <div class="product-cat ${badgeClass}">${p.kategori} - ${p.brand || 'Lainnya'}</div>
                        </div>
                        <div class="product-price-box">
                            <div class="product-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                            <button class="btn-buy" onclick="openModal('${key}', '${safeName}', ${p.harga})">Beli</button>
                        </div>
                    </div>`;
            }
            if(!listHTML) listHTML = '<div style="text-align:center; color:#888;">Produk kosong.</div>';
            document.getElementById('product-list').innerHTML = listHTML;
        }

        function openModal(sku, nama, harga) {
            selectedSKU = sku;
            document.getElementById('m-name').innerText = nama;
            document.getElementById('m-price').innerText = 'Rp ' + harga.toLocaleString('id-ID');
            document.getElementById('m-target').value = '';
            document.getElementById('order-modal').classList.remove('hidden');
        }
        function closeModal() { document.getElementById('order-modal').classList.add('hidden'); selectedSKU = ""; }

        async function processOrder() {
            let target = document.getElementById('m-target').value.trim();
            if(!target || target.length < 4) return alert("Masukkan Nomor/ID Tujuan yang benar!");
            let btn = document.getElementById('m-submit');
            let originalText = btn.innerText; btn.innerText = 'Memproses...'; btn.disabled = true;

            try {
                let res = await fetch('/api/order', {
                    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({phone: currentUser, sku: selectedSKU, tujuan: target})
                });
                let data = await res.json();
                if(data.success) {
                    alert('✅ Pesanan Diproses!\nStruk akan dikirim ke WhatsApp Anda.');
                    document.getElementById('user-saldo').innerText = 'Rp ' + data.saldo.toLocaleString('id-ID');
                    closeModal();
                } else { alert('❌ Gagal: ' + data.message); }
            } catch(e) { alert('Kesalahan jaringan.'); }
            btn.innerText = originalText; btn.disabled = false;
        }
    </script>
</body>
</html>
EOF
}

# ==========================================
# 3. FUNGSI UNTUK MEMBUAT FILE INDEX.JS (BOT + API SERVER)
# ==========================================
generate_bot_script() {
    cat << 'EOF' > index.js
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, Browsers, jidNormalizedUser, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const fs = require('fs');
const pino = require('pino');
const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const axios = require('axios'); 
const crypto = require('crypto'); 

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); 

const configFile = './config.json';
const dbFile = './database.json';
const produkFile = './produk.json';
const trxFile = './trx.json';

const loadJSON = (file) => fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
const saveJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

let configAwal = loadJSON(configFile);
configAwal.botName = configAwal.botName || "Tendo Store";
configAwal.botNumber = configAwal.botNumber || "";
configAwal.teleToken = configAwal.teleToken || "";
configAwal.teleChatId = configAwal.teleChatId || "";
configAwal.autoBackup = configAwal.autoBackup || false;
configAwal.backupInterval = configAwal.backupInterval || 720; 
saveJSON(configFile, configAwal);

if (!fs.existsSync(dbFile)) saveJSON(dbFile, {});
if (!fs.existsSync(produkFile)) saveJSON(produkFile, {});
if (!fs.existsSync(trxFile)) saveJSON(trxFile, {});

let globalSock = null;
let tempOtpDB = {}; // Menyimpan OTP sementara

// ==========================================
// 🚀 API ENDPOINT WEB
// ==========================================

app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });

// SISTEM LOGIN
app.post('/api/login', (req, res) => {
    let { email, password } = req.body;
    let db = loadJSON(dbFile);
    let userPhone = Object.keys(db).find(k => db[k].email === email && db[k].password === password);

    if (userPhone) res.json({success: true, data: db[userPhone], phone: userPhone});
    else res.json({success: false, message: 'Email atau Password salah!'});
});

// REQUEST OTP DAFTAR
app.post('/api/register', (req, res) => {
    let { email, phone, password } = req.body;
    phone = phone.replace(/[^0-9]/g, '');
    
    let db = loadJSON(dbFile);
    let emailExists = Object.keys(db).find(k => db[k].email === email);
    if (emailExists) return res.json({success: false, message: 'Email sudah terdaftar!'});

    let otp = Math.floor(1000 + Math.random() * 9000).toString();
    tempOtpDB[phone] = { email, password, otp };

    if (globalSock) {
        let msg = `*🛡️ TENDO STORE SECURITY 🛡️*\n\n`;
        msg += `Permintaan pembuatan akun Web App.\n\n`;
        msg += `Email: ${email}\n`;
        msg += `Kode OTP Anda: *${otp}*\n\n`;
        msg += `_⚠️ Jangan bagikan kode ini kepada siapapun!_`;
        globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>console.log("Gagal kirim OTP"));
    }

    res.json({success: true, message: 'OTP dikirim ke WA'});
});

// VERIFIKASI OTP
app.post('/api/verify-otp', (req, res) => {
    let { phone, otp } = req.body;
    phone = phone.replace(/[^0-9]/g, '');
    
    if(tempOtpDB[phone] && tempOtpDB[phone].otp === otp) {
        let db = loadJSON(dbFile);
        
        // Jika user sdh pernah daftar via WA, kita tambahkan email/pass ke akun lamanya
        if(db[phone]) {
            db[phone].email = tempOtpDB[phone].email;
            db[phone].password = tempOtpDB[phone].password;
        } else {
            // Member benar-benar baru
            db[phone] = {
                saldo: 0,
                tanggal_daftar: new Date().toLocaleDateString('id-ID'),
                jid: phone + '@s.whatsapp.net',
                step: 'idle',
                email: tempOtpDB[phone].email,
                password: tempOtpDB[phone].password
            };
        }
        
        saveJSON(dbFile, db);
        delete tempOtpDB[phone];
        res.json({success: true});
    } else {
        res.json({success: false, message: 'Kode OTP Salah!'});
    }
});

// ORDER
app.post('/api/order', async (req, res) => {
    let { phone, sku, tujuan } = req.body;
    let db = loadJSON(dbFile);
    let produkDB = loadJSON(produkFile);
    let config = loadJSON(configFile);

    if (!db[phone]) return res.json({success: false, message: 'ID Member tidak valid.'});
    if (!produkDB[sku]) return res.json({success: false, message: 'Produk tidak valid.'});

    let p = produkDB[sku];
    if (db[phone].saldo < p.harga) return res.json({success: false, message: 'Saldo tidak mencukupi. Silakan Topup.'});

    let username = (config.digiflazzUsername || '').trim();
    let apiKey = (config.digiflazzApiKey || '').trim();
    let refId = 'WEB-' + Date.now();
    let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

    try {
        const response = await axios.post('https://api.digiflazz.com/v1/transaction', {
            username: username, buyer_sku_code: sku, customer_no: tujuan, ref_id: refId, sign: sign
        });
        const resData = response.data.data;
        const statusOrder = resData.status; 
        
        if (statusOrder === 'Gagal') {
            return res.json({success: false, message: resData.message});
        } else {
            db[phone].saldo -= p.harga;
            saveJSON(dbFile, db);

            let trxs = loadJSON(trxFile);
            let targetJid = db[phone].jid || phone + '@s.whatsapp.net';
            trxs[refId] = { jid: targetJid, sku: sku, tujuan: tujuan, harga: p.harga, nama: p.nama, tanggal: Date.now() };
            saveJSON(trxFile, trxs);

            if (globalSock) {
                let msgWa = `🌐 *STRUK PEMBELIAN APLIKASI*\n\n📦 Produk: ${p.nama}\n📱 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status: *${statusOrder}*\n💰 Sisa Saldo: Rp ${db[phone].saldo.toLocaleString('id-ID')}`;
                globalSock.sendMessage(targetJid, { text: msgWa }).catch(e=>{});
            }
            return res.json({success: true, saldo: db[phone].saldo});
        }
    } catch (error) { return res.json({success: false, message: 'Server API Down'}); }
});

// ==========================================
// MESIN BOT WHATSAPP
// ==========================================
let pairingRequested = false; 

function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    
    console.log("\x1b[36m⏳ Memulai proses Auto-Backup ke Telegram...\x1b[0m");
    exec(`rm -f backup.zip && zip backup.zip config.json database.json trx.json index.js package-lock.json package.json produk.json 2>/dev/null`, (err) => {
        if (!err) {
            let caption = `📦 *Auto-Backup Tendo Store*\n⏰ Waktu: ${new Date().toLocaleString('id-ID')}`;
            exec(`curl -s -F chat_id="${cfg.teleChatId}" -F document=@"backup.zip" -F caption="${caption}" https://api.telegram.org/bot${cfg.teleToken}/sendDocument`, (err2) => {
                if (!err2) console.log("\x1b[32m✅ Auto-Backup berhasil dikirim ke Telegram!\x1b[0m");
                exec(`rm -f backup.zip`); 
            });
        }
    });
}

if (configAwal.autoBackup) {
    let intervalMs = (configAwal.backupInterval || 720) * 60 * 1000;
    setInterval(doBackupAndSend, intervalMs); 
}

async function startBot() {
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = loadJSON(configFile);
    const { version, isLatest } = await fetchLatestBaileysVersion();
    
    const sock = makeWASocket({
        version, auth: state, logger: pino({ level: 'silent' }), browser: Browsers.ubuntu('Chrome'), printQRInTerminal: false, syncFullHistory: false
    });
    
    globalSock = sock; 

    if (!sock.authState.creds.registered && !pairingRequested) {
        pairingRequested = true;
        setTimeout(async () => {
            try {
                let formattedNumber = config.botNumber.replace(/[^0-9]/g, '');
                const code = await sock.requestPairingCode(formattedNumber);
                console.log(`\x1b[33m🔑 KODE TAUTAN : ${code}\x1b[0m\n`);
            } catch (error) { pairingRequested = false; }
        }, 8000); 
    }

    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', (update) => {
        if (update.connection === 'close') setTimeout(startBot, 4000);
        else if (update.connection === 'open') console.log('\x1b[32m✅ BOT WA TERHUBUNG!\x1b[0m');
    });

    setInterval(async () => {
        let trxs = loadJSON(trxFile);
        let keys = Object.keys(trxs);
        if (keys.length === 0) return;

        let cfg = loadJSON(configFile);
        let userAPI = (cfg.digiflazzUsername || '').trim();
        let keyAPI = (cfg.digiflazzApiKey || '').trim();
        if (!userAPI || !keyAPI) return;

        for (let ref of keys) {
            let trx = trxs[ref];
            let signCheck = crypto.createHash('md5').update(userAPI + keyAPI + ref).digest('hex');

            try {
                const cekRes = await axios.post('https://api.digiflazz.com/v1/transaction', {
                    username: userAPI, buyer_sku_code: trx.sku, customer_no: trx.tujuan, ref_id: ref, sign: signCheck
                });

                const resData = cekRes.data.data;
                if (resData.status === 'Sukses' || resData.status === 'Gagal') {
                    let db = loadJSON(dbFile);
                    let senderNum = trx.jid.split('@')[0];
                    let msg = '';
                    
                    if(resData.status === 'Sukses') {
                        msg = `✅ *STATUS: SUKSES*\n\n📦 Produk: ${trx.nama}\n📱 Tujuan: ${trx.tujuan}\n🔑 SN: ${resData.sn || '-'}`;
                    } else {
                        if (db[senderNum]) { db[senderNum].saldo += trx.harga; saveJSON(dbFile, db); }
                        msg = `❌ *STATUS: GAGAL*\n\n📦 Produk: ${trx.nama}\nAlasan: ${resData.message}\n_💰 Saldo dikembalikan._`;
                    }
                    
                    await sock.sendMessage(trx.jid, { text: msg });
                    delete trxs[ref];
                    saveJSON(trxFile, trxs);
                } else if (Date.now() - trx.tanggal > 24 * 60 * 60 * 1000) {
                    delete trxs[ref]; saveJSON(trxFile, trxs);
                }
            } catch (err) {}
            await new Promise(r => setTimeout(r, 2000)); 
        }
    }, 15000); 

    sock.ev.on('messages.upsert', async m => {
        try {
            const msg = m.messages[0];
            if (!msg.message || msg.key.fromMe) return;

            const from = msg.key.remoteJid;
            const senderJid = jidNormalizedUser(msg.key.participant || msg.key.remoteJid);
            const sender = senderJid.split('@')[0]; 
            const body = msg.message.conversation || msg.message.extendedTextMessage?.text || "";
            if (!body) return;

            let db = loadJSON(dbFile);
            let config = loadJSON(configFile);
            if (!db[sender]) {
                db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle'};
                saveJSON(dbFile, db);
            }

            let rawCommand = body.trim().toLowerCase().split(' ')[0];
            if (['bot', 'menu', 'p', 'ping', 'halo'].includes(rawCommand)) {
                let menuText = `👋 *${config.botName || "Tendo Store"}*\n\nSilakan akses aplikasi kami untuk kemudahan berbelanja:\n🌐 http://${process.env.IP_ADDRESS || 'IP_VPS_ANDA'}:3000`;
                await sock.sendMessage(from, { text: menuText });
            }
        } catch (err) {}
    });
}

if (require.main === module) {
    app.listen(3000, '0.0.0.0', () => { console.log('\x1b[32m🌐 SERVER WEB AKTIF (PORT 3000).\x1b[0m'); });
    startBot().catch(err => {});
}
EOF
}

# ==========================================
# 4. FUNGSI INSTALASI DEPENDENSI
# ==========================================
install_dependencies() {
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}             🚀 MENGINSTALL SISTEM BOT 🚀             ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a

    echo -ne "${C_MAG}>> Meracik sistem utama bot (v28 FULL)...${C_RST}"
    generate_bot_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser > /dev/null 2>&1
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    read -p "Tekan Enter untuk kembali ke Panel Utama..."
}

# ==========================================
# 5. SUB-MENU TELEGRAM SETUP
# ==========================================
menu_telegram() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             ⚙️ BOT TELEGRAM SETUP ⚙️              ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Change BOT API & CHAT ID"
        echo -e "  ${C_GREEN}[2]${C_RST} Set Notifikasi Backup Otomatis"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read telechoice

        case $telechoice in
            1)
                echo -e "\n${C_MAG}--- PENGATURAN BOT TELEGRAM ---${C_RST}"
                read -p "Masukkan Token Bot Telegram: " token
                read -p "Masukkan Chat ID Anda: " chatid
                node -e "
                    const fs = require('fs');
                    let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                    config.teleToken = '$token';
                    config.teleChatId = '$chatid';
                    fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                    console.log('\x1b[32m\n✅ Data Telegram berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- SET AUTO BACKUP ---${C_RST}"
                read -p "Aktifkan Auto-Backup ke Telegram? (y/n): " set_auto
                if [ "$set_auto" == "y" ] || [ "$set_auto" == "Y" ]; then
                    status="true"
                    read -p "Berapa MENIT sekali bot harus backup? (Contoh: 60): " menit
                    if ! [[ "$menit" =~ ^[0-9]+$ ]]; then
                        menit=720
                    fi
                    echo -e "\n${C_GREEN}✅ Auto-Backup DIAKTIFKAN setiap $menit menit!${C_RST}"
                else
                    status="false"
                    menit=720
                    echo -e "\n${C_RED}❌ Auto-Backup DIMATIKAN!${C_RST}"
                fi
                node -e "
                    const fs = require('fs');
                    let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                    config.autoBackup = $status;
                    config.backupInterval = parseInt('$menit');
                    fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 6. SUB-MENU BACKUP & RESTORE
# ==========================================
menu_backup() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}               💾 BACKUP & RESTORE 💾               ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Backup Sekarang (Kirim ke Telegram)"
        echo -e "  ${C_GREEN}[2]${C_RST} Restore Database & Bot dari Link"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read backchoice

        case $backchoice in
            1)
                echo -e "\n${C_MAG}⏳ Sedang memproses arsip backup...${C_RST}"
                if ! command -v zip &> /dev/null; then sudo apt install zip -y > /dev/null 2>&1; fi
                rm -f backup.zip
                zip backup.zip config.json database.json trx.json index.js package-lock.json package.json produk.json 2>/dev/null
                echo -e "${C_GREEN}✅ File backup.zip berhasil dikompresi!${C_RST}"
                node -e "
                    const fs = require('fs');
                    const { exec } = require('child_process');
                    let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                    if(config.teleToken && config.teleChatId) {
                        console.log('\x1b[36m⏳ Sedang mengirim ke Telegram...\x1b[0m');
                        let cmd = \`curl -s -F chat_id=\"\${config.teleChatId}\" -F document=@\"backup.zip\" -F caption=\"📦 Manual Backup\" https://api.telegram.org/bot\${config.teleToken}/sendDocument\`;
                        exec(cmd, (err) => {
                            if(err) console.log('\x1b[31m❌ Gagal mengirim ke Telegram.\x1b[0m');
                            else console.log('\x1b[32m✅ File Backup berhasil mendarat di Telegram!\x1b[0m');
                        });
                    } else {
                        console.log('\x1b[33m⚠️ Token Telegram belum diisi.\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_RED}${C_BOLD}⚠️ PERHATIAN: Restore akan MENIMPA seluruh file bot Anda!${C_RST}"
                read -p "Apakah Anda yakin ingin melanjutkan? (y/n): " yakin
                if [ "$yakin" == "y" ] || [ "$yakin" == "Y" ]; then
                    read -p "🔗 Masukkan Direct Link file ZIP Backup Anda: " linkzip
                    if [ ! -z "$linkzip" ]; then
                        wget -qO restore.zip "$linkzip"
                        if [ -f "restore.zip" ]; then
                            if ! command -v unzip &> /dev/null; then sudo apt install unzip -y > /dev/null 2>&1; fi
                            unzip -o restore.zip > /dev/null 2>&1
                            rm restore.zip
                            npm install > /dev/null 2>&1
                            echo -e "\n${C_GREEN}${C_BOLD}✅ RESTORE BERHASIL SEPENUHNYA!${C_RST}"
                        else
                            echo -e "${C_RED}❌ Gagal mendownload file.${C_RST}"
                        fi
                    fi
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 7. SUB-MENU MANAJEMEN MEMBER
# ==========================================
menu_member() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             👥 MANAJEMEN MEMBER BOT 👥             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Saldo Member"
        echo -e "  ${C_GREEN}[2]${C_RST} Kurangi Saldo Member"
        echo -e "  ${C_GREEN}[3]${C_RST} Lihat Daftar Semua Member"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-3]: ${C_RST}"
        read subchoice

        case $subchoice in
            1)
                read -p "Masukkan ID Member (No WA): " nomor
                read -p "Masukkan Jumlah Saldo: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let target = '$nomor';
                    if(!db[target]) db[target] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: target + '@s.whatsapp.net' };
                    db[target].saldo += parseInt('$jumlah');
                    fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                    console.log('\x1b[32m\n✅ Saldo Rp $jumlah berhasil ditambahkan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                read -p "Masukkan ID Member (No WA): " nomor
                read -p "Masukkan Jumlah Saldo yg dikurangi: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let target = '$nomor';
                    if(!db[target]) { console.log('\x1b[31m\n❌ ID belum terdaftar.\x1b[0m'); } else {
                        db[target].saldo -= parseInt('$jumlah');
                        if(db[target].saldo < 0) db[target].saldo = 0;
                        fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                        console.log('\x1b[32m\n✅ Saldo berhasil dikurangi!\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let members = Object.keys(db);
                    if(members.length === 0) console.log('\x1b[33mBelum ada member.\x1b[0m');
                    else {
                        members.forEach((m, i) => console.log((i + 1) + '. ID: ' + m + ' | Email: ' + (db[m].email || '-') + ' | Saldo: Rp ' + db[m].saldo.toLocaleString('id-ID')));
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 8. MANAJEMEN PRODUK (DENGAN KATEGORI & BRAND)
# ==========================================
menu_produk() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             🛒 MANAJEMEN PRODUK BOT 🛒             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Produk Baru"
        echo -e "  ${C_GREEN}[2]${C_RST} Edit Produk"
        echo -e "  ${C_GREEN}[3]${C_RST} Hapus Produk"
        echo -e "  ${C_GREEN}[4]${C_RST} Lihat Daftar Produk"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-4]: ${C_RST}"
        read prodchoice

        case $prodchoice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH PRODUK BARU ---${C_RST}"
                echo -e "${C_CYAN}Pilih Kategori Utama:${C_RST}"
                echo "1. Pulsa         4. Topup E-Wallet"
                echo "2. Paket Data    5. Token Listrik"
                echo "3. Topup Game    6. Masa Aktif"
                read -p "👉 Masukkan Nomor Kategori [1-6]: " cat_idx
                
                brand_idx="1"
                if [ "$cat_idx" == "1" ] || [ "$cat_idx" == "2" ] || [ "$cat_idx" == "6" ]; then
                    echo -e "\n${C_CYAN}Pilih Provider:${C_RST}"
                    echo "1. Telkomsel | 2. XL | 3. Axis | 4. Indosat | 5. Tri"
                    read -p "👉 Masukkan Nomor Provider [1-5]: " brand_idx
                elif [ "$cat_idx" == "3" ]; then
                    echo -e "\n${C_CYAN}Pilih Game:${C_RST}"
                    echo "1. Mobile Legends | 2. Free Fire"
                    read -p "👉 Masukkan Nomor Game [1-2]: " brand_idx
                elif [ "$cat_idx" == "4" ]; then
                    echo -e "\n${C_CYAN}Pilih E-Wallet:${C_RST}"
                    echo "1. Gopay | 2. Dana | 3. Shopee Pay"
                    read -p "👉 Masukkan Nomor E-Wallet [1-3]: " brand_idx
                fi
                
                echo ""
                read -p "Kode Produk (Contoh: TSEL10): " kode
                read -p "Nama Produk (Contoh: Telkomsel 10K): " nama
                read -p "Harga Jual (Contoh: 12000): " harga
                read -p "Deskripsi Produk (Opsional): " deskripsi
                
                export TMP_CAT_IDX="$cat_idx"
                export TMP_BRAND_IDX="$brand_idx"
                export TMP_KODE="$kode"
                export TMP_NAMA="$nama"
                export TMP_HARGA="$harga"
                export TMP_DESC="$deskripsi"
                
                node -e "
                    const fs = require('fs');
                    const catMap = {'1':'Pulsa', '2':'Paket Data', '3':'Topup Game', '4':'Topup E-Wallet', '5':'Token Listrik', '6':'Masa Aktif'};
                    const brandMap = {
                        'Pulsa': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri'},
                        'Paket Data': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri'},
                        'Topup Game': {'1':'Mobile Legends', '2':'Free Fire'},
                        'Topup E-Wallet': {'1':'Gopay', '2':'Dana', '3':'Shopee Pay'},
                        'Token Listrik': {'1':'Token Listrik'},
                        'Masa Aktif': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri'}
                    };
                    
                    let catName = catMap[process.env.TMP_CAT_IDX] || 'Lainnya';
                    let brandName = (brandMap[catName] && brandMap[catName][process.env.TMP_BRAND_IDX]) ? brandMap[catName][process.env.TMP_BRAND_IDX] : (catName === 'Token Listrik' ? 'Token Listrik' : 'Lainnya');
                    
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let key = process.env.TMP_KODE.toUpperCase().replace(/\s+/g, '');
                    produk[key] = { 
                        nama: process.env.TMP_NAMA, 
                        harga: parseInt(process.env.TMP_HARGA),
                        deskripsi: process.env.TMP_DESC,
                        kategori: catName,
                        brand: brandName
                    };
                    fs.writeFileSync('produk.json', JSON.stringify(produk, null, 2));
                    console.log('\x1b[32m\n✅ Produk [' + key + '] berhasil ditambahkan ke ' + catName + ' - ' + brandName + '!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK UNTUK DIEDIT ---${C_RST}"
                node -e "
                    const fs = require('fs');
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let keys = Object.keys(produk);
                    if(keys.length === 0) { console.log('\x1b[33mBelum ada produk.\x1b[0m'); process.exit(1); }
                    keys.forEach((k, i) => {
                        let brand = produk[k].brand || 'Lainnya';
                        console.log((i + 1) + '. [' + brand + '] [' + k + '] ' + produk[k].nama);
                    });
                "
                if [ $? -eq 1 ]; then read -p "Tekan Enter untuk kembali..."; continue; fi
                
                echo ""
                read -p "👉 Masukkan NOMOR URUT produk yg ingin diedit: " no_edit
                export NO_EDIT="$no_edit"
                
                eval $(node -e "
                    const fs = require('fs');
                    let produk = JSON.parse(fs.readFileSync('produk.json'));
                    let keys = Object.keys(produk);
                    let idx = parseInt(process.env.NO_EDIT) - 1;
                    if(isNaN(idx) || idx < 0 || idx >= keys.length) {
                        console.log('export VALID=false');
                    } else {
                        let k = keys[idx];
                        let p = produk[k];
                        let kat = p.kategori || 'Belum Diatur';
                        let br = p.brand || 'Belum Diatur';
                        console.log('export VALID=true');
                        console.log('export OLD_KODE=\"' + k + '\"');
                        console.log('export OLD_NAMA=\"' + p.nama.replace(/[\"$\\\\]/g, '\\\\$&') + '\"');
                        console.log('export OLD_HARGA=\"' + p.harga + '\"');
                        console.log('export OLD_KAT=\"' + kat + '\"');
                        console.log('export OLD_BRAND=\"' + br + '\"');
                    }
                ")

                if [ "$VALID" != "true" ]; then
                    echo -e "${C_RED}\n❌ Nomor produk tidak valid!${C_RST}"
                    read -p "Tekan Enter untuk kembali..."
                    continue
                fi

                echo -e "\n${C_MAG}--- EDIT PRODUK : $OLD_NAMA ---${C_RST}"
                echo -e "${C_YELLOW}💡 Biarkan kosong (tekan Enter) jika Anda TIDAK INGIN mengubah datanya.${C_RST}"
                echo -e "${C_CYAN}Kategori saat ini: $OLD_KAT | Provider: $OLD_BRAND${C_RST}"
                echo "Pilihan Kategori: 1. Pulsa | 2. Paket Data | 3. Topup Game | 4. Topup E-Wallet | 5. Token Listrik | 6. Masa Aktif"
                
                read -p "Ubah Kategori? (Ketik angka 1-6) [Enter jika tidak]: " new_cat_idx
                
                new_brand_idx=""
                if [ ! -z "$new_cat_idx" ]; then
                    if [ "$new_cat_idx" == "1" ] || [ "$new_cat_idx" == "2" ] || [ "$new_cat_idx" == "6" ]; then
                        echo "1. Telkomsel | 2. XL | 3. Axis | 4. Indosat | 5. Tri"
                        read -p "Pilih Provider Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "3" ]; then
                        echo "1. Mobile Legends | 2. Free Fire"
                        read -p "Pilih Game Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "4" ]; then
                        echo "1. Gopay | 2. Dana | 3. Shopee Pay"
                        read -p "Pilih E-Wallet Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "5" ]; then
                        new_brand_idx="1"
                    fi
                fi

                read -p "Kode Baru [$OLD_KODE]: " new_kode
                read -p "Nama Baru [$OLD_NAMA]: " new_nama
                read -p "Harga Baru [$OLD_HARGA]: " new_harga
                read -p "Deskripsi Baru (Ketik - untuk menghapus): " new_desc
                
                export NEW_CAT_IDX="$new_cat_idx"
                export NEW_BRAND_IDX="$new_brand_idx"
                export NEW_KODE="${new_kode:-$OLD_KODE}"
                export NEW_NAMA="$new_nama"
                export NEW_HARGA="$new_harga"
                export NEW_DESC="$new_desc"
                
                node -e "
                    const fs = require('fs');
                    const catMap = {'1':'Pulsa', '2':'Paket Data', '3':'Topup Game', '4':'Topup E-Wallet', '5':'Token Listrik', '6':'Masa Aktif'};
                    const brandMap = {
                        'Pulsa': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri'},
                        'Paket Data': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri'},
                        'Topup Game': {'1':'Mobile Legends', '2':'Free Fire'},
                        'Topup E-Wallet': {'1':'Gopay', '2':'Dana', '3':'Shopee Pay'},
                        'Token Listrik': {'1':'Token Listrik'},
                        'Masa Aktif': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri'}
                    };

                    let produk = JSON.parse(fs.readFileSync('produk.json'));
                    let oldKey = process.env.OLD_KODE;
                    let newKey = process.env.NEW_KODE.toUpperCase().replace(/\s+/g, '');
                    
                    let item = produk[oldKey];
                    
                    if (process.env.NEW_NAMA && process.env.NEW_NAMA.trim() !== '') item.nama = process.env.NEW_NAMA;
                    if (process.env.NEW_HARGA && process.env.NEW_HARGA.trim() !== '') item.harga = parseInt(process.env.NEW_HARGA);
                    if (process.env.NEW_DESC && process.env.NEW_DESC.trim() !== '') {
                        if (process.env.NEW_DESC.trim() === '-') delete item.deskripsi;
                        else item.deskripsi = process.env.NEW_DESC;
                    }
                    
                    if (process.env.NEW_CAT_IDX && process.env.NEW_CAT_IDX.trim() !== '') {
                        let cName = catMap[process.env.NEW_CAT_IDX];
                        if(cName) {
                            item.kategori = cName;
                            item.brand = (brandMap[cName] && brandMap[cName][process.env.NEW_BRAND_IDX]) ? brandMap[cName][process.env.NEW_BRAND_IDX] : (cName === 'Token Listrik' ? 'Token Listrik' : 'Lainnya');
                        }
                    }
                    
                    if(!item.brand) item.brand = 'Lainnya';
                    
                    if (oldKey !== newKey) {
                        produk[newKey] = item;
                        delete produk[oldKey]; 
                    } else {
                        produk[oldKey] = item;
                    }
                    
                    fs.writeFileSync('produk.json', JSON.stringify(produk, null, 2));
                    console.log('\x1b[32m\n✅ Perubahan pada produk berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK UNTUK DIHAPUS ---${C_RST}"
                node -e "
                    const fs = require('fs');
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let keys = Object.keys(produk);
                    if(keys.length === 0) { console.log('\x1b[33mBelum ada produk.\x1b[0m'); process.exit(1); }
                    keys.forEach((k, i) => {
                        let brand = produk[k].brand || 'Lainnya';
                        console.log((i + 1) + '. [' + brand + '] [' + k + '] ' + produk[k].nama);
                    });
                "
                if [ $? -eq 1 ]; then read -p "Tekan Enter untuk kembali..."; continue; fi
                
                echo -e "\n${C_RED}⚠️ Hati-hati, produk yang dihapus tidak bisa dikembalikan!${C_RST}"
                read -p "👉 Masukkan NOMOR URUT produk yg ingin dihapus: " no_del
                export NO_DEL="$no_del"

                node -e "
                    const fs = require('fs');
                    let produk = JSON.parse(fs.readFileSync('produk.json'));
                    let keys = Object.keys(produk);
                    let idx = parseInt(process.env.NO_DEL) - 1;
                    
                    if(isNaN(idx) || idx < 0 || idx >= keys.length) {
                        console.log('\x1b[31m\n❌ Nomor urut produk tidak valid!\x1b[0m');
                    } else {
                        let key = keys[idx];
                        let nama = produk[key].nama;
                        delete produk[key];
                        fs.writeFileSync('produk.json', JSON.stringify(produk, null, 2));
                        console.log('\x1b[32m\n✅ Produk [' + key + '] ' + nama + ' berhasil dihapus dari database!\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK TOKO ---${C_RST}"
                node -e "
                    const fs = require('fs');
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let keys = Object.keys(produk);
                    if(keys.length === 0) {
                        console.log('\x1b[33mBelum ada produk.\x1b[0m');
                    } else {
                        let cats = ['Pulsa', 'Paket Data', 'Topup Game', 'Topup E-Wallet', 'Token Listrik', 'Masa Aktif', 'Lainnya'];
                        let count = 0;
                        cats.forEach(c => {
                            let catKeys = keys.filter(k => (produk[k].kategori || 'Lainnya') === c);
                            if(catKeys.length > 0) {
                                console.log('\n\x1b[33m=== KATEGORI: ' + c.toUpperCase() + ' ===\x1b[0m');
                                let brands = [...new Set(catKeys.map(k => produk[k].brand || 'Lainnya'))];
                                brands.forEach(b => {
                                    console.log('\x1b[35m>> Provider/Brand: ' + b.toUpperCase() + '\x1b[0m');
                                    let brandKeys = catKeys.filter(k => (produk[k].brand || 'Lainnya') === b);
                                    brandKeys.forEach(k => {
                                        count++;
                                        console.log(count + '. [' + k + '] ' + produk[k].nama + ' - Rp ' + produk[k].harga.toLocaleString('id-ID'));
                                        if (produk[k].deskripsi) console.log('   \x1b[36m↳ Info: ' + produk[k].deskripsi + '\x1b[0m');
                                    });
                                });
                            }
                        });
                        console.log('\n\x1b[32mTotal Produk Keseluruhan: ' + keys.length + '\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 9. MENU UTAMA (PANEL KONTROL)
# ==========================================
while true; do
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}             🤖 PANEL ADMIN TENDO STORE 🤖            ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_MAG}▶ MANAJEMEN BOT & WEB APP${C_RST}"
    echo -e "  ${C_GREEN}[1]${C_RST}  Install & Perbarui Sistem"
    echo -e "  ${C_GREEN}[2]${C_RST}  Mulai Bot (Terminal / Scan QR)"
    echo -e "  ${C_GREEN}[3]${C_RST}  Jalankan Bot & Web di Latar Belakang (PM2)"
    echo -e "  ${C_GREEN}[4]${C_RST}  Hentikan Bot & Web (PM2)"
    echo -e "  ${C_GREEN}[5]${C_RST}  Lihat Log / Error"
    echo ""
    echo -e "${C_MAG}▶ MANAJEMEN TOKO & SISTEM${C_RST}"
    echo -e "  ${C_GREEN}[6]${C_RST}  👥 Manajemen Saldo Member"
    echo -e "  ${C_GREEN}[7]${C_RST}  🛒 Manajemen Daftar Produk & Harga"
    echo -e "  ${C_GREEN}[8]${C_RST}  ⚙️ Pengaturan Bot Telegram (Auto-Backup)"
    echo -e "  ${C_GREEN}[9]${C_RST}  💾 Backup & Restore Data Database"
    echo -e "  ${C_GREEN}[10]${C_RST} 🔌 Ganti API Digiflazz"
    echo -e "  ${C_GREEN}[11]${C_RST} 🔄 Ganti Akun Bot WA (Reset Sesi)"
    echo -e "  ${C_GREEN}[12]${C_RST} 📢 Kirim Pesan Broadcast"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -e "  ${C_RED}[0]${C_RST}  Keluar dari Panel"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -ne "${C_YELLOW}Pilih menu [0-12]: ${C_RST}"
    read choice

    case $choice in
        1) install_dependencies ;;
        2) 
            if [ ! -f "index.js" ]; then echo -e "${C_RED}❌ Jalankan Menu 1 (Install) dulu!${C_RST}"; sleep 2; continue; fi
            if [ ! -d "sesi_bot" ] || [ -z "$(ls -A sesi_bot 2>/dev/null)" ]; then
                read -p "📲 Masukkan Nomor WA Bot (Awali 628...): " nomor_bot
                if [ ! -z "$nomor_bot" ]; then
                    node -e "
                        const fs = require('fs');
                        let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                        config.botNumber = '$nomor_bot';
                        config.botName = config.botName || 'Tendo Store';
                        fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                    "
                fi
            fi
            echo -e "\n${C_MAG}⏳ Menjalankan bot... (Tekan CTRL+C untuk mematikan dan kembali ke menu)${C_RST}"
            export IP_ADDRESS=$(curl -s ifconfig.me)
            node index.js
            echo -e "\n${C_YELLOW}⚠️ Proses bot terhenti.${C_RST}"
            read -p "Tekan Enter untuk kembali ke panel utama..."
            ;;
        3) 
            pm2 delete tendo-bot >/dev/null 2>&1
            export IP_ADDRESS=$(curl -s ifconfig.me)
            pm2 start index.js --name "tendo-bot" >/dev/null 2>&1
            pm2 save >/dev/null 2>&1
            pm2 startup >/dev/null 2>&1
            echo -e "\n${C_GREEN}✅ Sistem berhasil berjalan di latar belakang!${C_RST}"
            sleep 2 ;;
        4) 
            pm2 stop tendo-bot >/dev/null 2>&1
            pm2 delete tendo-bot >/dev/null 2>&1
            echo -e "\n${C_GREEN}✅ Bot dihentikan dan dibersihkan dari latar belakang.${C_RST}"
            sleep 2 ;;
        5) pm2 logs tendo-bot ;;
        6) menu_member ;;
        7) menu_produk ;;
        8) menu_telegram ;;
        9) menu_backup ;;
        10)
            echo -e "\n${C_MAG}--- GANTI API DIGIFLAZZ ---${C_RST}"
            read -p "Username Digiflazz Baru: " user_api
            read -p "API Key Digiflazz Baru: " key_api
            node -e "
                const fs = require('fs');
                let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                config.digiflazzUsername = '$user_api'.trim();
                config.digiflazzApiKey = '$key_api'.trim();
                fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                console.log('\x1b[32m\n✅ Konfigurasi API Digiflazz berhasil disimpan!\x1b[0m');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        11)
            echo -e "\n${C_RED}${C_BOLD}⚠️ Ini akan menghapus sesi login WhatsApp saat ini.${C_RST}"
            read -p "Lanjutkan? (y/n): " konfirmasi
            if [ "$konfirmasi" == "y" ] || [ "$konfirmasi" == "Y" ]; then
                pm2 stop tendo-bot >/dev/null 2>&1
                rm -rf sesi_bot
                echo -e "${C_GREEN}✅ Sesi dihapus! Silakan pilih menu 2 untuk Login Ulang.${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        12)
            echo -e "\n${C_MAG}--- BROADCAST PESAN ---${C_RST}"
            echo -e "Gunakan \n untuk baris baru."
            read -p "Ketik Pesan Broadcast: " pesan_bc
            if [ ! -z "$pesan_bc" ]; then
                echo -e "$pesan_bc" > broadcast.txt
                echo -e "\n${C_GREEN}✅ Pesan berhasil masuk antrean broadcast!${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        0) echo -e "${C_GREEN}Keluar dari panel. Sampai jumpa! 👋${C_RST}"; exit 0 ;;
        *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 2 ;;
    esac
done
