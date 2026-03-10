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

sudo ufw allow 3000/tcp > /dev/null 2>&1 || true
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT > /dev/null 2>&1 || true

if [ ! -f "/usr/bin/bot" ]; then
    if [ -f "/usr/bin/menu" ]; then sudo rm -f /usr/bin/menu; fi
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/bot > /dev/null
    sudo chmod +x /usr/bin/bot
fi

# ==========================================
# FUNGSI MEMBUAT TAMPILAN WEB APLIKASI (UI PRO)
# ==========================================
generate_web_app() {
    mkdir -p public

    cat << 'EOF' > public/manifest.json
{
  "name": "Tendo Store",
  "short_name": "Tendo Store",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#f5f5f5",
  "theme_color": "#000000",
  "orientation": "portrait",
  "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/3144/3144456.png", "sizes": "512x512", "type": "image/png"}]
}
EOF

    cat << 'EOF' > public/sw.js
self.addEventListener('install', (e) => { });
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
    <meta name="theme-color" content="#000000">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #eef2f5; margin: 0; display: flex; justify-content: center; }
        #app { width: 100%; max-width: 480px; background: #f8f9fa; min-height: 100vh; position: relative; overflow-x: hidden; padding-bottom: 70px;}
        
        .top-bar { background: #000; color: white; padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;}
        .menu-btn { font-size: 24px; cursor: pointer; background: none; border: none; color: white; padding: 0; margin-right: 15px;}
        .brand-title { font-size: 18px; font-weight: bold; flex: 1;}
        .trx-badge { font-size: 13px; color: #ccc;}

        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(0,0,0,0.6); z-index: 999; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:0; left:-300px; width: 280px; height: 100%; background: white; z-index: 1000; transition: left 0.3s ease; overflow-y: auto;}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 30px 20px; text-align: center; border-bottom: 1px solid #eee;}
        .sidebar-avatar { width: 80px; height: 80px; background: #0088cc; border-radius: 50%; margin: 0 auto 15px auto; display: flex; justify-content: center; align-items: center; color: white; font-size: 35px;}
        .sidebar-name { font-weight: bold; font-size: 18px; color: #333;}
        .sidebar-phone { font-size: 13px; color: #777; margin-top: 5px;}
        .sidebar-menu { padding: 10px 0; }
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: #333; text-decoration: none; font-size: 15px; border-bottom: 1px solid #f5f5f5;}
        .sidebar-item:active { background: #f0f0f0; }
        .sb-icon { width: 30px; font-size: 18px; color: #555;}

        .bottom-nav { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: white; display: flex; justify-content: space-around; padding: 10px 0; border-top: 1px solid #ddd; z-index: 90;}
        .nav-item { text-align: center; color: #666; font-size: 11px; flex: 1; cursor: pointer;}
        .nav-item.active { color: #000; font-weight: bold;}
        .nav-icon { font-size: 20px; margin-bottom: 3px; display: block;}

        .banner { background: linear-gradient(135deg, #11998e, #38ef7d); margin: 15px; border-radius: 15px; padding: 25px 20px; color: white; box-shadow: 0 4px 10px rgba(0,0,0,0.1); position: relative;}
        .saldo-title { font-size: 13px; opacity: 0.9;}
        .saldo-amount { font-size: 30px; font-weight: bold; margin: 5px 0;}
        .btn-topup { background: white; color: #11998e; border: none; padding: 6px 15px; border-radius: 20px; font-weight: bold; font-size: 12px; position: absolute; right: 20px; top: 50%; transform: translateY(-50%); box-shadow: 0 2px 5px rgba(0,0,0,0.1);}

        .grid-title { margin: 20px 15px 10px; font-weight: bold; color: #333;}
        .grid-container { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; padding: 0 15px;}
        .grid-box { background: white; border-radius: 15px; padding: 15px 5px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.04); cursor: pointer;}
        .grid-box:active { transform: scale(0.95); }
        .grid-icon { font-size: 28px; margin-bottom: 8px;}
        .grid-text { font-size: 11px; color: #444; line-height: 1.2;}

        .container { padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.03); margin-bottom: 20px;}
        input { width: 100%; padding: 15px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 10px; box-sizing: border-box; font-size: 15px; outline: none; background: #f9f9f9;}
        .btn { background: #000; color: white; border: none; padding: 15px; width: 100%; border-radius: 10px; font-size: 15px; font-weight: bold; cursor: pointer;}
        .btn-outline { background: white; color: #000; border: 1px solid #ccc; padding: 15px; width: 100%; border-radius: 10px; font-size: 15px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        
        .product-item { background: white; padding: 15px; border-radius: 12px; margin: 15px; border: 1px solid #eee; display: flex; justify-content: space-between; align-items: center;}
        .product-name { font-weight: bold; font-size: 14px; color: #333;}
        .product-price { color: #0088cc; font-weight: bold; font-size: 15px; margin-top: 5px;}
        .btn-buy { background: #000; color: white; border: none; padding: 8px 20px; border-radius: 20px; font-size: 13px; font-weight: bold;}

        .modal-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(0,0,0,0.6); display: flex; justify-content: center; align-items: center; z-index: 2000; padding: 20px;}
        .modal-box { background: white; width: 100%; max-width: 350px; border-radius: 20px; padding: 20px; text-align: center;}
        .modal-btns { display: flex; gap: 10px; margin-top: 15px;}
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div id="app">
        <div class="top-bar">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <div class="brand-title" id="top-title">Tendo Store</div>
            <div class="trx-badge">1 Trx</div>
        </div>

        <div class="sidebar-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-avatar">👤</div>
                <div class="sidebar-name" id="sb-name">Tendo Store</div>
                <div class="sidebar-phone" id="sb-phone">Belum Login</div>
            </div>
            <div class="sidebar-menu">
                <a href="#" class="sidebar-item" onclick="alert('Fitur Profil sedang dikembangkan')"><span class="sb-icon">👤</span> Akun</a>
                <a href="#" class="sidebar-item" onclick="alert('Fitur Riwayat segera hadir')"><span class="sb-icon">🔁</span> Transaksi</a>
                <a href="#" class="sidebar-item" onclick="alert('Tidak ada pemberitahuan')"><span class="sb-icon">🔔</span> Pemberitahuan</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showDashboard()"><span class="sb-icon">🏷️</span> Daftar Harga</a>
                <a href="#" class="sidebar-item" onclick="showContactModal()"><span class="sb-icon">📞</span> Hubungi Kami</a>
            </div>
        </div>

        <div id="login-screen" class="container">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0;">Masuk Akun</h2>
                <p style="font-size:13px; color:#666;">Masukkan Email & Password</p>
                <input type="email" id="log-email" placeholder="Alamat Email">
                <input type="password" id="log-pass" placeholder="Password">
                <button class="btn" onclick="login()">Login Sekarang</button>
                <button class="btn-outline" onclick="showScreen('register-screen')">Belum punya akun? Daftar</button>
            </div>
        </div>

        <div id="register-screen" class="container hidden">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0;">Daftar Akun</h2>
                <p style="font-size:13px; color:#666;">Bisa pakai awalan 08 atau 62</p>
                <input type="email" id="reg-email" placeholder="Alamat Email">
                <input type="number" id="reg-phone" placeholder="Nomor WA (Cth: 0812...)">
                <input type="password" id="reg-pass" placeholder="Buat Password">
                <button class="btn" onclick="requestOTP()">Kirim Kode OTP</button>
                <button class="btn-outline" onclick="showScreen('login-screen')">Kembali ke Login</button>
            </div>
        </div>

        <div id="otp-screen" class="container hidden">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0;">Verifikasi OTP</h2>
                <p style="font-size:13px; color:#666;">Kode 4 digit telah dikirim ke WA.</p>
                <input type="number" id="otp-code" placeholder="Kode OTP" style="text-align:center; font-size:24px; letter-spacing: 5px;">
                <button class="btn" onclick="verifyOTP()">Verifikasi</button>
            </div>
        </div>

        <div id="dashboard-screen" class="hidden">
            <div class="banner">
                <div class="saldo-title">Total Saldo Anda</div>
                <div class="saldo-amount" id="user-saldo">Rp 0</div>
                <button class="btn-topup" onclick="reqTopup()">➕ Topup</button>
            </div>

            <div class="grid-title">Sering Di Kunjungi 🥰</div>
            <div class="grid-container">
                <div class="grid-box" onclick="loadCategory('Pulsa')"><div class="grid-icon">📱</div><div class="grid-text">Pulsa Reguler</div></div>
                <div class="grid-box" onclick="loadCategory('Paket Data')"><div class="grid-icon">🌐</div><div class="grid-text">Paket Data</div></div>
                <div class="grid-box" onclick="loadCategory('Masa Aktif')"><div class="grid-icon">📆</div><div class="grid-text">Masa Aktif</div></div>
                <div class="grid-box" onclick="loadCategory('Topup Game')"><div class="grid-icon">🎮</div><div class="grid-text">Topup Game</div></div>
                <div class="grid-box" onclick="loadCategory('Token Listrik')"><div class="grid-icon">⚡</div><div class="grid-text">Token PLN</div></div>
                <div class="grid-box" onclick="loadCategory('Topup E-Wallet')"><div class="grid-icon">💳</div><div class="grid-text">E-Wallet</div></div>
                <div class="grid-box" onclick="loadCategory('Semua')"><div class="grid-icon">🛒</div><div class="grid-text">Semua Produk</div></div>
            </div>
            
            <div style="padding: 15px; margin: 20px 15px; background: white; border-radius: 15px; text-align: center; border: 1px solid #eee;" id="install-banner" class="hidden">
                <strong>Install Aplikasi Tendo Store</strong><br>
                <span style="font-size:12px; color:#666;">Akses lebih cepat langsung dari layar HP Anda!</span><br>
                <button class="btn" style="margin-top:10px; padding: 10px;" id="install-btn">Install Sekarang</button>
            </div>
        </div>

        <div id="produk-screen" class="hidden">
            <div style="padding: 10px 15px; font-weight: bold; display:flex; gap:10px; align-items:center;">
                <span style="cursor:pointer; font-size:20px;" onclick="showDashboard()">🔙</span>
                <span id="cat-title-text">Katalog Produk</span>
            </div>
            <div id="product-list"></div>
        </div>

        <div class="bottom-nav">
            <div class="nav-item active" onclick="showDashboard()"><span class="nav-icon">🏠</span>Home</div>
            <div class="nav-item" onclick="alert('Riwayat belum tersedia')"><span class="nav-icon">🧾</span>Riwayat</div>
            <div class="nav-item" onclick="alert('Rekapitulasi belum tersedia')"><span class="nav-icon">📊</span>Rekap</div>
            <div class="nav-item" onclick="alert('Informasi belum tersedia')"><span class="nav-icon">ℹ️</span>Informasi</div>
            <div class="nav-item" onclick="toggleSidebar()"><span class="nav-icon">👤</span>Profil</div>
        </div>

        <div id="contact-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0;">Hubungi Bantuan</h3>
                <p style="font-size:13px; color:#666;">Silakan pilih platform untuk menghubungi Admin:</p>
                <button class="btn" style="background:#25D366; margin-bottom:10px;" onclick="window.open('https://wa.me/6282224460678', '_blank'); closeContactModal()">💬 WhatsApp Admin</button>
                <button class="btn" style="background:#0088cc;" onclick="window.open('https://t.me/tendo_32', '_blank'); closeContactModal()">✈️ Telegram Admin</button>
                <div style="margin-top:15px;"><a href="#" style="color:#999; text-decoration:none;" onclick="closeContactModal()">Tutup</a></div>
            </div>
        </div>

        <div id="order-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0;">Beli Produk</h3>
                <div style="background:#f9f9f9; padding:10px; border-radius:10px; margin-bottom:15px;">
                    <strong id="m-name">Produk</strong><br>
                    <span style="color:#0088cc; font-weight:bold; font-size: 18px;" id="m-price">Rp 0</span>
                </div>
                <input type="text" id="m-target" placeholder="No HP/ID Tujuan (08/62...)">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeOrderModal()">Batal</button>
                    <button class="btn" id="m-submit" onclick="processOrder()">Beli Sekarang</button>
                </div>
            </div>
        </div>

    </div>

    <script>
        let deferredPrompt;
        const installBanner = document.getElementById('install-banner');
        const installBtn = document.getElementById('install-btn');
        window.addEventListener('beforeinstallprompt', (e) => { 
            e.preventDefault(); deferredPrompt = e; installBanner.classList.remove('hidden'); 
        });
        installBtn.addEventListener('click', async () => { 
            if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; installBanner.classList.add('hidden');} 
        });
        if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

        let currentUser = ""; let currentEmail = ""; let allProducts = {}; let selectedSKU = ""; let tempRegPhone = "";

        function toggleSidebar() {
            const sb = document.getElementById('sidebar');
            const ov = document.getElementById('sb-overlay');
            if(sb.classList.contains('open')) {
                sb.classList.remove('open');
                ov.style.opacity = '0';
                setTimeout(() => ov.style.display = 'none', 300);
            } else {
                ov.style.display = 'block';
                setTimeout(() => { ov.style.opacity = '1'; sb.classList.add('open'); }, 10);
            }
        }

        function showScreen(id) {
            ['login-screen', 'register-screen', 'otp-screen', 'dashboard-screen', 'produk-screen'].forEach(s => {
                document.getElementById(s).classList.add('hidden');
            });
            document.getElementById(id).classList.remove('hidden');
        }

        function showDashboard() { showScreen('dashboard-screen'); document.getElementById('top-title').innerText = "Hai, " + (currentEmail.split('@')[0] || "Tendo Store"); }

        function showContactModal() { toggleSidebar(); document.getElementById('contact-modal').classList.remove('hidden'); }
        function closeContactModal() { document.getElementById('contact-modal').classList.add('hidden'); }
        function reqTopup() { window.open(`https://wa.me/6282224460678?text=Halo Admin, mau topup saldo.%0AEmail: ${currentEmail}`, '_blank'); }

        async function login() {
            let email = document.getElementById('log-email').value.trim();
            let pass = document.getElementById('log-pass').value.trim();
            if(!email || !pass) return alert('Isi Email & Password!');
            try {
                let res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, password:pass}) });
                let data = await res.json();
                if(data.success) {
                    currentUser = data.phone; currentEmail = email;
                    document.getElementById('user-saldo').innerText = 'Rp ' + data.data.saldo.toLocaleString('id-ID');
                    document.getElementById('sb-phone').innerText = currentUser;
                    document.getElementById('sb-name').innerText = email;
                    fetchAllProducts(); showDashboard();
                } else alert(data.message);
            } catch(e) { alert('Gagal terhubung.'); }
        }

        async function requestOTP() {
            let email = document.getElementById('reg-email').value.trim();
            let phone = document.getElementById('reg-phone').value.trim();
            let pass = document.getElementById('reg-pass').value.trim();
            if(!email || !phone || !pass) return alert('Lengkapi data!');
            try {
                let res = await fetch('/api/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, phone, password:pass}) });
                let data = await res.json();
                if(data.success) { tempRegPhone = phone; showScreen('otp-screen'); } 
                else alert(data.message);
            } catch(e) { alert('Error server.'); }
        }

        async function verifyOTP() {
            let otp = document.getElementById('otp-code').value.trim();
            if(!otp) return alert('Masukkan OTP!');
            try {
                let res = await fetch('/api/verify-otp', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone: tempRegPhone, otp}) });
                let data = await res.json();
                if(data.success) {
                    alert('Berhasil! Silakan Login.');
                    document.getElementById('log-email').value = document.getElementById('reg-email').value;
                    document.getElementById('log-pass').value = document.getElementById('reg-pass').value;
                    showScreen('login-screen');
                } else alert(data.message);
            } catch(e) { alert('Error server.'); }
        }

        async function fetchAllProducts() {
            let res = await fetch('/api/produk');
            allProducts = await res.json();
        }

        function loadCategory(cat) {
            document.getElementById('cat-title-text').innerText = "Katalog " + cat;
            let listHTML = '';
            for(let key in allProducts) {
                let p = allProducts[key];
                if (cat !== 'Semua' && p.kategori !== cat) continue;
                let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                listHTML += `
                    <div class="product-item">
                        <div style="flex:1;">
                            <div class="product-name">${p.nama}</div>
                            <div style="font-size:11px; color:#888;">${p.brand || 'Lainnya'}</div>
                            <div class="product-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                        </div>
                        <button class="btn-buy" onclick="openOrderModal('${key}', '${safeName}', ${p.harga})">Beli</button>
                    </div>`;
            }
            document.getElementById('product-list').innerHTML = listHTML || '<p style="text-align:center; padding:20px; color:#888;">Produk kosong</p>';
            showScreen('produk-screen');
        }

        function openOrderModal(sku, nama, harga) {
            selectedSKU = sku;
            document.getElementById('m-name').innerText = nama;
            document.getElementById('m-price').innerText = 'Rp ' + harga.toLocaleString('id-ID');
            document.getElementById('m-target').value = '';
            document.getElementById('order-modal').classList.remove('hidden');
        }
        function closeOrderModal() { document.getElementById('order-modal').classList.add('hidden'); }

        async function processOrder() {
            let target = document.getElementById('m-target').value.trim();
            if(!target || target.length < 4) return alert("Nomor tujuan tidak valid!");
            let btn = document.getElementById('m-submit');
            let ori = btn.innerText; btn.innerText = 'Proses...'; btn.disabled = true;
            try {
                let res = await fetch('/api/order', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone: currentUser, sku: selectedSKU, tujuan: target}) });
                let data = await res.json();
                if(data.success) {
                    alert('Pesanan Diproses! Struk dikirim ke WA.');
                    document.getElementById('user-saldo').innerText = 'Rp ' + data.saldo.toLocaleString('id-ID');
                    closeOrderModal();
                } else alert('Gagal: ' + data.message);
            } catch(e) {}
            btn.innerText = ori; btn.disabled = false;
        }
    </script>
</body>
</html>
EOF
}

# ==========================================
# 3. FUNGSI UNTUK MEMBUAT FILE INDEX.JS (BACKEND CANGGIH v29)
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
saveJSON(configFile, configAwal);

if (!fs.existsSync(dbFile)) saveJSON(dbFile, {});
if (!fs.existsSync(produkFile)) saveJSON(produkFile, {});
if (!fs.existsSync(trxFile)) saveJSON(trxFile, {});

let globalSock = null;
let tempOtpDB = {}; 

function normalizePhone(phoneStr) {
    if(!phoneStr) return '';
    let num = phoneStr.replace(/[^0-9]/g, '');
    if(num.startsWith('0')) return '62' + num.substring(1);
    return num;
}

app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });

app.post('/api/login', (req, res) => {
    let { email, password } = req.body;
    let db = loadJSON(dbFile);
    let userPhone = Object.keys(db).find(k => db[k].email === email && db[k].password === password);
    if (userPhone) res.json({success: true, data: db[userPhone], phone: userPhone});
    else res.json({success: false, message: 'Email atau Password salah!'});
});

app.post('/api/register', (req, res) => {
    let { email, password } = req.body;
    let phone = normalizePhone(req.body.phone); 
    if(phone.length < 9) return res.json({success: false, message: 'Nomor WA tidak valid!'});
    
    let db = loadJSON(dbFile);
    if (Object.keys(db).find(k => db[k].email === email)) return res.json({success: false, message: 'Email terdaftar!'});

    let otp = Math.floor(1000 + Math.random() * 9000).toString();
    tempOtpDB[phone] = { email, password, otp };

    if (globalSock) {
        let msg = `*🛡️ TENDO STORE SECURITY 🛡️*\n\nKode OTP Anda: *${otp}*\n\n_⚠️ Jangan bagikan kode ini kepada siapapun!_`;
        globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>{});
    }
    res.json({success: true});
});

app.post('/api/verify-otp', (req, res) => {
    let otp = req.body.otp;
    let phone = normalizePhone(req.body.phone);
    
    if(tempOtpDB[phone] && tempOtpDB[phone].otp === otp) {
        let db = loadJSON(dbFile);
        if(db[phone]) {
            db[phone].email = tempOtpDB[phone].email;
            db[phone].password = tempOtpDB[phone].password;
        } else {
            db[phone] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: phone + '@s.whatsapp.net', step: 'idle', email: tempOtpDB[phone].email, password: tempOtpDB[phone].password };
        }
        saveJSON(dbFile, db);
        delete tempOtpDB[phone];
        res.json({success: true});
    } else res.json({success: false, message: 'Kode OTP Salah!'});
});

app.post('/api/order', async (req, res) => {
    let { phone, sku, tujuan } = req.body;
    
    let db = loadJSON(dbFile);
    let produkDB = loadJSON(produkFile);
    let config = loadJSON(configFile);

    if (!db[phone]) return res.json({success: false, message: 'ID Member tidak valid.'});
    let p = produkDB[sku];
    if (db[phone].saldo < p.harga) return res.json({success: false, message: 'Saldo tidak cukup. Hubungi Admin.'});

    let username = (config.digiflazzUsername || '').trim();
    let apiKey = (config.digiflazzApiKey || '').trim();
    let refId = 'WEB-' + Date.now();
    let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

    try {
        const response = await axios.post('https://api.digiflazz.com/v1/transaction', {
            username: username, buyer_sku_code: sku, customer_no: tujuan, ref_id: refId, sign: sign
        });
        const statusOrder = response.data.data.status; 
        if (statusOrder === 'Gagal') return res.json({success: false, message: response.data.data.message});
        
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
    } catch (error) { return res.json({success: false, message: 'Server Digiflazz Down'}); }
});

async function startBot() {
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = loadJSON(configFile);
    const { version } = await fetchLatestBaileysVersion();
    const sock = makeWASocket({ version, auth: state, logger: pino({ level: 'silent' }), browser: Browsers.ubuntu('Chrome'), printQRInTerminal: false, syncFullHistory: false });
    globalSock = sock; 

    if (!sock.authState.creds.registered) {
        setTimeout(async () => {
            try {
                let formattedNumber = config.botNumber.replace(/[^0-9]/g, '');
                const code = await sock.requestPairingCode(formattedNumber);
                console.log(`\x1b[33m🔑 KODE TAUTAN : ${code}\x1b[0m\n`);
            } catch (error) {}
        }, 8000); 
    }
    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', (u) => { if(u.connection === 'close') setTimeout(startBot, 4000); });

    setInterval(async () => {
        let trxs = loadJSON(trxFile); let keys = Object.keys(trxs); if (keys.length === 0) return;
        let cfg = loadJSON(configFile); let userAPI = (cfg.digiflazzUsername || '').trim(); let keyAPI = (cfg.digiflazzApiKey || '').trim();
        if (!userAPI || !keyAPI) return;

        for (let ref of keys) {
            let trx = trxs[ref];
            let signCheck = crypto.createHash('md5').update(userAPI + keyAPI + ref).digest('hex');
            try {
                const cekRes = await axios.post('https://api.digiflazz.com/v1/transaction', { username: userAPI, buyer_sku_code: trx.sku, customer_no: trx.tujuan, ref_id: ref, sign: signCheck });
                const resData = cekRes.data.data;
                if (resData.status === 'Sukses' || resData.status === 'Gagal') {
                    let db = loadJSON(dbFile); let senderNum = trx.jid.split('@')[0]; let msg = '';
                    if(resData.status === 'Sukses') {
                        msg = `✅ *STATUS: SUKSES*\n\n📦 Produk: ${trx.nama}\n📱 Tujuan: ${trx.tujuan}\n🔑 SN: ${resData.sn || '-'}`;
                    } else {
                        if (db[senderNum]) { db[senderNum].saldo += trx.harga; saveJSON(dbFile, db); }
                        msg = `❌ *STATUS: GAGAL*\n\n📦 Produk: ${trx.nama}\nAlasan: ${resData.message}\n_💰 Saldo dikembalikan._`;
                    }
                    await sock.sendMessage(trx.jid, { text: msg });
                    delete trxs[ref]; saveJSON(trxFile, trxs);
                } else if (Date.now() - trx.tanggal > 24 * 60 * 60 * 1000) { delete trxs[ref]; saveJSON(trxFile, trxs); }
            } catch (err) {}
            await new Promise(r => setTimeout(r, 2000)); 
        }
    }, 15000); 

    sock.ev.on('messages.upsert', async m => {
        try {
            const msg = m.messages[0]; if (!msg.message || msg.key.fromMe) return;
            const from = msg.key.remoteJid; const senderJid = jidNormalizedUser(msg.key.participant || msg.key.remoteJid);
            const sender = senderJid.split('@')[0]; const body = msg.message.conversation || msg.message.extendedTextMessage?.text || "";
            if (!body) return;

            let db = loadJSON(dbFile);
            if (!db[sender]) { db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle'}; saveJSON(dbFile, db); }

            let rawCommand = body.trim().toLowerCase().split(' ')[0];
            if (['bot', 'menu', 'p'].includes(rawCommand)) {
                await sock.sendMessage(from, { text: `👋 *Tendo Store*\n\nSilakan akses aplikasi kami untuk bertransaksi:\n🌐 http://${process.env.IP_ADDRESS || 'IP_VPS_ANDA'}:3000` });
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
# 4. INSTALASI DEPENDENSI (FULL LOADING)
# ==========================================
install_dependencies() {
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}             🚀 MENGINSTALL SISTEM BOT 🚀             ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a

    spin() {
        local pid=$1
        local delay=0.1
        local spinstr='|/-\'
        while kill -0 $pid 2>/dev/null; do
            local temp=${spinstr#?}
            printf " [%c] " "$spinstr"
            local spinstr=$temp${spinstr%"$temp"}
            sleep $delay
            printf "\b\b\b\b\b"
        done
        printf "      \b\b\b\b\b\b"
    }

    echo -ne "${C_MAG}>> Mengupdate repositori sistem...${C_RST}"
    (sudo -E apt-get update > /dev/null 2>&1 && sudo -E apt-get upgrade -y > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"

    echo -ne "${C_MAG}>> Meracik sistem utama & Web App (v29 UI PRO)...${C_RST}"
    generate_bot_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Mengunduh modul WhatsApp & Web API...${C_RST}"
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD}                 ✅ INSTALASI SELESAI!                ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    read -p "Tekan Enter untuk kembali..."
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
            echo -e "\n${C_GREEN}✅ Sistem berjalan di latar belakang!${C_RST}"
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
