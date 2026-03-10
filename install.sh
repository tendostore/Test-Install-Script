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
        
        /* TOP BAR */
        .top-bar { background: #000; color: white; padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;}
        .menu-btn { font-size: 24px; cursor: pointer; background: none; border: none; color: white; padding: 0; margin-right: 15px;}
        .brand-title { font-size: 18px; font-weight: bold; flex: 1;}
        .trx-badge { font-size: 13px; color: #ccc;}

        /* SIDEBAR / DRAWER */
        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(0,0,0,0.6); z-index: 999; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:0; left:-300px; width: 280px; height: 100%; background: white; z-index: 1000; transition: left 0.3s ease; overflow-y: auto; display: flex; flex-direction: column;}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 30px 20px; text-align: center; border-bottom: 1px solid #eee; background: #fafafa;}
        .sidebar-avatar { width: 80px; height: 80px; background: linear-gradient(135deg, #0088cc, #005580); border-radius: 50%; margin: 0 auto 15px auto; display: flex; justify-content: center; align-items: center; color: white; font-size: 35px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);}
        .sidebar-name { font-weight: bold; font-size: 18px; color: #333;}
        .sidebar-phone { font-size: 13px; color: #777; margin-top: 5px;}
        .sidebar-menu { padding: 10px 0; flex: 1;}
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: #333; text-decoration: none; font-size: 15px; border-bottom: 1px solid #f5f5f5;}
        .sidebar-item:active { background: #f0f0f0; }
        .sb-icon { width: 30px; font-size: 18px; color: #555;}

        /* BOTTOM NAVIGATION */
        .bottom-nav { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: white; display: flex; justify-content: space-around; padding: 10px 0; border-top: 1px solid #ddd; z-index: 90;}
        .nav-item { text-align: center; color: #666; font-size: 11px; flex: 1; cursor: pointer; display: flex; flex-direction: column; align-items: center;}
        .nav-item.active { color: #000; font-weight: bold;}
        .nav-icon { font-size: 20px; margin-bottom: 3px; display: block;}

        /* DASHBOARD CONTENT */
        .banner { background: linear-gradient(135deg, #11998e, #38ef7d); margin: 15px; border-radius: 15px; padding: 25px 20px; color: white; box-shadow: 0 4px 10px rgba(0,0,0,0.1); position: relative;}
        .saldo-title { font-size: 13px; opacity: 0.9;}
        .saldo-amount { font-size: 30px; font-weight: bold; margin: 5px 0;}
        .btn-topup { background: white; color: #11998e; border: none; padding: 6px 15px; border-radius: 20px; font-weight: bold; font-size: 12px; position: absolute; right: 20px; top: 50%; transform: translateY(-50%); box-shadow: 0 2px 5px rgba(0,0,0,0.1); cursor: pointer;}

        /* GRID MENU */
        .grid-title { margin: 20px 15px 10px; font-weight: bold; color: #333;}
        .grid-container { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; padding: 0 15px;}
        .grid-box { background: white; border-radius: 15px; padding: 15px 5px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.04); cursor: pointer;}
        .grid-box:active { transform: scale(0.95); }
        .grid-icon { font-size: 28px; margin-bottom: 8px;}
        .grid-text { font-size: 11px; color: #444; line-height: 1.2; font-weight: 500;}

        /* FORMS & LISTS */
        .container { padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.03); margin-bottom: 20px;}
        input { width: 100%; padding: 15px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 10px; box-sizing: border-box; font-size: 15px; outline: none; background: #f9f9f9;}
        .btn { background: #000; color: white; border: none; padding: 15px; width: 100%; border-radius: 10px; font-size: 15px; font-weight: bold; cursor: pointer;}
        .btn-outline { background: white; color: #000; border: 1px solid #ccc; padding: 15px; width: 100%; border-radius: 10px; font-size: 15px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        
        /* PRODUK ITEMS GROUPED */
        .brand-header { padding: 10px 15px; background: #e0e0e0; font-weight: bold; color: #555; font-size: 13px; text-transform: uppercase; margin-top: 10px; border-radius: 5px; margin-left: 15px; margin-right: 15px;}
        .product-item { background: white; padding: 15px; border-radius: 12px; margin: 10px 15px; border: 1px solid #eee; display: flex; justify-content: space-between; align-items: center;}
        .product-name { font-weight: bold; font-size: 14px; color: #333;}
        .product-price { color: #0088cc; font-weight: bold; font-size: 15px; margin-top: 5px;}
        .btn-buy { background: #000; color: white; border: none; padding: 8px 20px; border-radius: 20px; font-size: 13px; font-weight: bold; cursor: pointer;}

        /* HISTORY ITEMS */
        .history-item { background: white; padding: 15px; border-radius: 12px; margin-bottom: 15px; border: 1px solid #eee; box-shadow: 0 2px 5px rgba(0,0,0,0.02);}
        .hist-top { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 12px; color: #888;}
        .hist-name { font-weight: bold; font-size: 15px; color: #333; margin-bottom: 5px;}
        .hist-target { font-size: 13px; color: #555;}
        .hist-status { padding: 3px 8px; border-radius: 5px; font-size: 11px; font-weight: bold; color: white;}
        .stat-Pending { background: #ff9800; } .stat-Sukses { background: #4caf50; } .stat-Gagal { background: #f44336; }

        /* MODAL */
        .modal-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(0,0,0,0.6); display: flex; justify-content: center; align-items: center; z-index: 2000; padding: 20px;}
        .modal-box { background: white; width: 100%; max-width: 350px; border-radius: 20px; padding: 20px; text-align: center;}
        .modal-btns { display: flex; gap: 10px; margin-top: 15px;}
        .hidden { display: none !important; }
        
        .screen-header { padding: 15px; font-weight: bold; display: flex; gap: 10px; align-items: center; background: white; border-bottom: 1px solid #eee; position: sticky; top:0; z-index: 10;}
    </style>
</head>
<body>
    <div id="app">
        <div class="top-bar">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <div class="brand-title" id="top-title">Tendo Store</div>
            <div class="trx-badge" id="top-trx-badge">0 Trx</div>
        </div>

        <div class="sidebar-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-avatar">👤</div>
                <div class="sidebar-name" id="sb-name">Tendo Store</div>
                <div class="sidebar-phone" id="sb-phone">Belum Login</div>
            </div>
            <div class="sidebar-menu">
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showProfile()"><span class="sb-icon">👤</span> Profil Akun</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showHistory()"><span class="sb-icon">🔁</span> Transaksi</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showNotif()"><span class="sb-icon">🔔</span> Pemberitahuan</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showDashboard(); loadCategory('Semua');"><span class="sb-icon">🏷️</span> Daftar Harga</a>
                <a href="#" class="sidebar-item" onclick="showContactModal()"><span class="sb-icon">📞</span> Hubungi Kami</a>
            </div>
            <div style="padding: 20px;">
                <button class="btn-outline" style="color: red; border-color: red;" onclick="logout()">Keluar Akun</button>
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
                <p style="font-size:13px; color:#666;">Gunakan nomor aktif (awalan 08 atau 62)</p>
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
            <div class="screen-header">
                <span style="cursor:pointer; font-size:20px;" onclick="showDashboard()">🔙</span>
                <span id="cat-title-text">Katalog Produk</span>
            </div>
            <div id="product-list" style="padding-top: 10px;"></div>
        </div>

        <div id="history-screen" class="hidden">
            <div class="screen-header">
                <span style="cursor:pointer; font-size:20px;" onclick="showDashboard()">🔙</span>
                <span>Riwayat Transaksi</span>
            </div>
            <div id="history-list" class="container"></div>
        </div>

        <div id="profile-screen" class="hidden">
            <div class="screen-header">
                <span style="cursor:pointer; font-size:20px;" onclick="showDashboard()">🔙</span>
                <span>Profil Akun</span>
            </div>
            <div class="container">
                <div class="card" style="text-align: center;">
                    <div class="sidebar-avatar" style="margin-bottom: 20px; width: 100px; height: 100px; font-size: 45px;">👤</div>
                    <h2 id="prof-email" style="margin: 0 0 5px 0;">-</h2>
                    <p id="prof-phone" style="color: #666; margin: 0 0 20px 0;">-</p>
                    <div style="background: #f9f9f9; padding: 15px; border-radius: 10px; text-align: left;">
                        <div style="margin-bottom: 10px;"><strong>Tanggal Bergabung:</strong> <span id="prof-date" style="float: right;">-</span></div>
                        <div><strong>Total Transaksi:</strong> <span id="prof-trx" style="float: right; font-weight: bold; color: #0088cc;">0</span></div>
                    </div>
                </div>
            </div>
        </div>

        <div id="notif-screen" class="hidden">
            <div class="screen-header">
                <span style="cursor:pointer; font-size:20px;" onclick="showDashboard()">🔙</span>
                <span>Pemberitahuan</span>
            </div>
            <div class="container">
                <div class="card">
                    <h3 style="margin-top:0; color: #0088cc;">📢 Info Terbaru</h3>
                    <p id="notif-text" style="color: #444; line-height: 1.5; white-space: pre-wrap;">Tidak ada pemberitahuan saat ini.</p>
                </div>
            </div>
        </div>

        <div class="bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showDashboard()"><span class="nav-icon">🏠</span>Home</div>
            <div class="nav-item" id="nav-history" onclick="showHistory()"><span class="nav-icon">🧾</span>Riwayat</div>
            <div class="nav-item" id="nav-notif" onclick="showNotif()"><span class="nav-icon">🔔</span>Info</div>
            <div class="nav-item" id="nav-profile" onclick="showProfile()"><span class="nav-icon">👤</span>Profil</div>
        </div>

        <div id="contact-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0;">Hubungi Kami</h3>
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
                sb.classList.remove('open'); ov.style.opacity = '0'; setTimeout(() => ov.style.display = 'none', 300);
            } else {
                ov.style.display = 'block'; setTimeout(() => { ov.style.opacity = '1'; sb.classList.add('open'); }, 10);
            }
        }

        function updateNav(activeId) {
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            if(activeId) document.getElementById(activeId).classList.add('active');
        }

        function showScreen(id, navId) {
            ['login-screen', 'register-screen', 'otp-screen', 'dashboard-screen', 'produk-screen', 'history-screen', 'profile-screen', 'notif-screen'].forEach(s => {
                document.getElementById(s).classList.add('hidden');
            });
            document.getElementById(id).classList.remove('hidden');
            updateNav(navId);
        }

        function showDashboard() { 
            showScreen('dashboard-screen', 'nav-home'); 
            document.getElementById('top-title').innerText = "Hai, " + (currentEmail.split('@')[0] || "Tendo Store"); 
            syncUserData();
        }
        
        function showHistory() { showScreen('history-screen', 'nav-history'); syncUserData(); }
        function showProfile() { showScreen('profile-screen', 'nav-profile'); syncUserData(); }
        
        async function showNotif() { 
            showScreen('notif-screen', 'nav-notif'); 
            try {
                let res = await fetch('/api/notif');
                let data = await res.json();
                document.getElementById('notif-text').innerText = data.text || "Tidak ada pemberitahuan baru saat ini.";
            } catch(e) {}
        }

        function showContactModal() { toggleSidebar(); document.getElementById('contact-modal').classList.remove('hidden'); }
        function closeContactModal() { document.getElementById('contact-modal').classList.add('hidden'); }
        function reqTopup() { window.open(`https://wa.me/6282224460678?text=Halo Admin, saya ingin mengajukan Topup Saldo akun Tendo Store.%0A%0A📧 Email: *${currentEmail}*%0A📱 No WA: *${currentUser}*%0A💰 Nominal: `, '_blank'); }

        function logout() {
            currentUser = ""; currentEmail = ""; toggleSidebar(); showScreen('login-screen', null);
            document.getElementById('log-pass').value = '';
        }

        async function syncUserData() {
            if(!currentUser) return;
            try {
                let res = await fetch('/api/user/' + currentUser);
                let data = await res.json();
                if(data.success) {
                    let u = data.data;
                    document.getElementById('user-saldo').innerText = 'Rp ' + u.saldo.toLocaleString('id-ID');
                    document.getElementById('top-trx-badge').innerText = (u.trx_count || 0) + ' Trx';
                    
                    // Update Profile Data
                    document.getElementById('prof-email').innerText = u.email || '-';
                    document.getElementById('prof-phone').innerText = currentUser;
                    document.getElementById('prof-date').innerText = u.tanggal_daftar || '-';
                    document.getElementById('prof-trx').innerText = (u.trx_count || 0) + ' Kali';

                    // Update History List
                    let histHTML = '';
                    let historyList = u.history || [];
                    if(historyList.length === 0) histHTML = '<div style="text-align:center; color:#888; margin-top: 20px;">Belum ada transaksi.</div>';
                    else {
                        historyList.forEach(h => {
                            let statClass = 'stat-Pending';
                            if(h.status === 'Sukses') statClass = 'stat-Sukses';
                            if(h.status === 'Gagal') statClass = 'stat-Gagal';
                            histHTML += `
                                <div class="history-item">
                                    <div class="hist-top"><span>${h.tanggal}</span> <span class="hist-status ${statClass}">${h.status}</span></div>
                                    <div class="hist-name">${h.nama}</div>
                                    <div class="hist-target">Tujuan: ${h.tujuan}</div>
                                    ${h.sn && h.sn !== '-' ? `<div style="font-size:11px; color:#0088cc; margin-top:5px; background:#f0f8ff; padding:5px; border-radius:5px;">SN: ${h.sn}</div>` : ''}
                                </div>
                            `;
                        });
                    }
                    document.getElementById('history-list').innerHTML = histHTML;
                }
            } catch(e) {}
        }

        async function login() {
            let email = document.getElementById('log-email').value.trim();
            let pass = document.getElementById('log-pass').value.trim();
            if(!email || !pass) return alert('Isi Email & Password!');
            let btn = document.querySelector('#login-screen .btn');
            btn.innerText = "Memeriksa...";
            try {
                let res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, password:pass}) });
                let data = await res.json();
                if(data.success) {
                    currentUser = data.phone; currentEmail = email;
                    document.getElementById('sb-phone').innerText = currentUser;
                    document.getElementById('sb-name').innerText = email;
                    fetchAllProducts(); showDashboard();
                } else alert(data.message);
            } catch(e) { alert('Gagal terhubung.'); }
            btn.innerText = "Login Sekarang";
        }

        async function requestOTP() {
            let email = document.getElementById('reg-email').value.trim();
            let phone = document.getElementById('reg-phone').value.trim();
            let pass = document.getElementById('reg-pass').value.trim();
            if(!email || !phone || !pass) return alert('Lengkapi data!');
            let btn = document.querySelector('#register-screen .btn'); btn.innerText = "Mengirim...";
            try {
                let res = await fetch('/api/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, phone, password:pass}) });
                let data = await res.json();
                if(data.success) { tempRegPhone = phone; showScreen('otp-screen', null); } 
                else alert(data.message);
            } catch(e) { alert('Error server.'); }
            btn.innerText = "Kirim Kode OTP";
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
                    showScreen('login-screen', null);
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
            
            // GROUPING PRODUK BERDASARKAN BRAND
            let grouped = {};
            for(let key in allProducts) {
                let p = allProducts[key];
                if (cat !== 'Semua' && p.kategori !== cat) continue;
                let b = p.brand || 'Lainnya';
                if(!grouped[b]) grouped[b] = [];
                grouped[b].push({key, ...p});
            }

            for(let brand in grouped) {
                listHTML += `<div class="brand-header">${brand}</div>`;
                grouped[brand].forEach(p => {
                    let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                    listHTML += `
                        <div class="product-item">
                            <div style="flex:1; padding-right: 10px;">
                                <div class="product-name">${p.nama}</div>
                                <div class="product-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                            </div>
                            <button class="btn-buy" onclick="openOrderModal('${p.key}', '${safeName}', ${p.harga})">Beli</button>
                        </div>`;
                });
            }
            
            document.getElementById('product-list').innerHTML = listHTML || '<p style="text-align:center; padding:20px; color:#888;">Produk kosong</p>';
            showScreen('produk-screen', 'nav-home');
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
                    alert('Pesanan Diproses! Struk dikirim ke WA Anda.');
                    closeOrderModal();
                    syncUserData(); // Update saldo & riwayat
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
# 3. FUNGSI UNTUK MEMBUAT FILE INDEX.JS (BACKEND LENGKAP v30)
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
const notifFile = './web_notif.txt';

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

// API
app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });

app.get('/api/user/:phone', (req, res) => {
    let db = loadJSON(dbFile);
    let p = req.params.phone;
    if(db[p]) res.json({success: true, data: db[p]});
    else res.json({success: false});
});

app.get('/api/notif', (req, res) => {
    let txt = fs.existsSync(notifFile) ? fs.readFileSync(notifFile, 'utf8') : '';
    res.json({text: txt});
});

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
            db[phone] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: phone + '@s.whatsapp.net', step: 'idle', email: tempOtpDB[phone].email, password: tempOtpDB[phone].password, trx_count: 0, history: [] };
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
        db[phone].trx_count = (db[phone].trx_count || 0) + 1;
        db[phone].history = db[phone].history || [];
        db[phone].history.unshift({ tanggal: new Date().toLocaleString('id-ID'), nama: p.nama, tujuan: tujuan, status: statusOrder, sn: '-' });
        if(db[phone].history.length > 20) db[phone].history.pop();
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

function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    exec(`rm -f backup.zip && zip backup.zip config.json database.json trx.json index.js package-lock.json package.json produk.json 2>/dev/null`, (err) => {
        if (!err) {
            exec(`curl -s -F chat_id="${cfg.teleChatId}" -F document=@"backup.zip" -F caption="📦 Backup Tendo Store" https://api.telegram.org/bot${cfg.teleToken}/sendDocument`);
        }
    });
}

if (configAwal.autoBackup) setInterval(doBackupAndSend, (configAwal.backupInterval || 720) * 60 * 1000); 

const brandStructure = {
    'Pulsa': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri'],
    'Paket Data': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri'],
    'Topup Game': ['Mobile Legends', 'Free Fire'],
    'Topup E-Wallet': ['Gopay', 'Dana', 'Shopee Pay'],
    'Token Listrik': ['Token Listrik'],
    'Masa Aktif': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri']
};

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
                        if (db[senderNum]) {
                            if(db[senderNum].history && db[senderNum].history.length > 0) {
                                db[senderNum].history[0].status = 'Sukses';
                                db[senderNum].history[0].sn = resData.sn || '-';
                                saveJSON(dbFile, db);
                            }
                        }
                    } else {
                        if (db[senderNum]) { 
                            db[senderNum].saldo += trx.harga; 
                            if(db[senderNum].history && db[senderNum].history.length > 0) db[senderNum].history[0].status = 'Gagal';
                            saveJSON(dbFile, db); 
                        }
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
            let produkDB = loadJSON(produkFile);
            
            if (!db[sender]) { db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle', trx_count: 0, history: []}; saveJSON(dbFile, db); }
            if (!db[sender].step) db[sender].step = 'idle';

            let bodyLower = body.trim().toLowerCase();
            let rawCommand = bodyLower.split(' ')[0];
            let command = '';

            if (['batal', 'cancel', 'bot', 'menu', '.menu', 'p', 'ping'].includes(rawCommand)) {
                if (db[sender].step !== 'idle') {
                    db[sender].step = 'idle'; db[sender].temp_sku = ''; db[sender].temp_category = ''; db[sender].temp_brand = '';
                    saveJSON(dbFile, db);
                    if (['batal', 'cancel'].includes(rawCommand)) {
                        await sock.sendMessage(from, { text: `✅ Proses pesanan dibatalkan.\n\n_Ketik *bot* untuk kembali ke menu utama._` });
                        return;
                    }
                }
            }

            const catMap = { '3': 'Pulsa', '4': 'Paket Data', '5': 'Topup Game', '6': 'Topup E-Wallet', '7': 'Token Listrik', '8': 'Masa Aktif' };
            if (['bot', 'menu', '.menu', 'help', 'p', 'ping', 'halo'].includes(rawCommand)) command = 'bot';
            else if (['1', '1.', '1.saldo', 'saldo', '.saldo'].includes(rawCommand)) command = '.saldo';
            else if (['2', '2.', '2.harga', 'harga', '.harga', 'list'].includes(rawCommand)) command = '.harga';
            else if (catMap[rawCommand]) { command = '.show_cat'; db[sender].temp_category = catMap[rawCommand]; }

            if (command === 'bot') {
                let menuText = `👋 *${config.botName || "Tendo Store"}*\n\n📌 *ID Member:* ${sender}\n\n1. *Cek Saldo*\n2. *Cek Semua Harga*\n3. *Pulsa*\n4. *Paket Data*\n5. *Topup Game*\n6. *Topup E-Wallet*\n7. *Token Listrik*\n8. *Masa Aktif*\n\n_👉 Balas dengan angka pilihan._\n\n🌐 *Atau belanja lebih mudah di Aplikasi Web kami:* http://${process.env.IP_ADDRESS || 'IP_VPS_ANDA'}:3000`;
                await sock.sendMessage(from, { text: menuText });
                return;
            }

            if (command === '.saldo') return await sock.sendMessage(from, { text: `💰 Saldo Anda saat ini: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` });

            if (command === '.show_cat') {
                let cat = db[sender].temp_category;
                let brands = brandStructure[cat] || [];
                if (brands.length === 1) {
                    db[sender].temp_brand = brands[0]; db[sender].step = 'order_product'; saveJSON(dbFile, db);
                    let filteredKeys = Object.keys(produkDB).filter(k => (produkDB[k].kategori || 'Lainnya') === cat && (produkDB[k].brand || 'Lainnya') === db[sender].temp_brand);
                    if (filteredKeys.length === 0) { db[sender].step = 'idle'; saveJSON(dbFile, db); return await sock.sendMessage(from, { text: `🛒 Maaf, produk kosong.\n_Ketik *bot* untuk kembali._`}); }
                    let textCat = `🛒 *PILIH PRODUK: ${cat.toUpperCase()}*\n\n`;
                    filteredKeys.forEach((k, i) => { textCat += `*${i+1}.* ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`; });
                    textCat += `\n👉 *Silakan balas dengan NOMOR URUT produk.*\n\n_Ketik *batal* untuk membatalkan._`;
                    await sock.sendMessage(from, { text: textCat.trim() });
                } else {
                    db[sender].step = 'select_brand'; saveJSON(dbFile, db);
                    let textBrand = `🛒 *PILIH PROVIDER / GAME / E-WALLET*\n\nKategori: *${cat.toUpperCase()}*\n\n`;
                    brands.forEach((b, i) => { textBrand += `*${i+1}.* ${b}\n`; });
                    textBrand += `\n👉 *Balas pesan ini dengan ANGKA pilihannya.*\n\n_Ketik *batal* untuk membatalkan._`;
                    await sock.sendMessage(from, { text: textBrand });
                }
                return;
            }

            if (db[sender].step === 'select_brand') {
                let cat = db[sender].temp_category; let brands = brandStructure[cat]; let inputNum = parseInt(body.trim());
                if (!isNaN(inputNum) && inputNum > 0 && inputNum <= brands.length) {
                    db[sender].temp_brand = brands[inputNum - 1]; db[sender].step = 'order_product'; saveJSON(dbFile, db);
                    let filteredKeys = Object.keys(produkDB).filter(k => (produkDB[k].kategori || 'Lainnya') === cat && (produkDB[k].brand || 'Lainnya') === db[sender].temp_brand);
                    if (filteredKeys.length === 0) { db[sender].step = 'idle'; saveJSON(dbFile, db); return await sock.sendMessage(from, { text: `🛒 Maaf, produk kosong.`}); }
                    let textCat = `🛒 *PILIH PRODUK: ${cat.toUpperCase()} - ${db[sender].temp_brand.toUpperCase()}*\n\n`;
                    filteredKeys.forEach((k, i) => { textCat += `*${i+1}.* ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`; });
                    textCat += `\n👉 *Balas pesan ini dengan NOMOR URUT produknya.*\n\n_Ketik *batal* untuk membatalkan._`;
                    await sock.sendMessage(from, { text: textCat.trim() });
                    return;
                }
            }

            if (db[sender].step === 'order_product') {
                let cat = db[sender].temp_category; let brand = db[sender].temp_brand;
                let filteredKeys = Object.keys(produkDB).filter(k => (produkDB[k].kategori || 'Lainnya') === cat && (produkDB[k].brand || 'Lainnya') === brand);
                let inputKode = body.trim();
                if (!isNaN(inputKode) && Number(inputKode) > 0 && Number(inputKode) <= filteredKeys.length) {
                    db[sender].temp_sku = filteredKeys[Number(inputKode) - 1]; db[sender].step = 'order_target'; saveJSON(dbFile, db);
                    let p = produkDB[db[sender].temp_sku];
                    let msgBalasan = `📦 Produk dipilih: *${p.nama}*\n💰 Harga: Rp ${p.harga.toLocaleString('id-ID')}\n\n📱 *Silakan balas dengan NOMOR/ID TUJUAN pengisian!*\n\n_Ketik *batal* untuk membatalkan._`;
                    await sock.sendMessage(from, { text: msgBalasan });
                    return;
                }
            }

            if (db[sender].step === 'order_target') {
                let tujuan = body.trim(); let kodeProduk = db[sender].temp_sku;
                db[sender].step = 'idle'; db[sender].temp_sku = ''; db[sender].temp_category = ''; db[sender].temp_brand = ''; saveJSON(dbFile, db);
                if(!tujuan || tujuan.length < 4) return await sock.sendMessage(from, { text: `❌ Format nomor salah. Pesanan dibatalkan.` });
                
                const hargaProduk = produkDB[kodeProduk].harga;
                if (db[sender].saldo < hargaProduk) return await sock.sendMessage(from, { text: `❌ *Saldo tidak mencukupi!*\n\n💰 Saldo Anda: Rp ${db[sender].saldo.toLocaleString('id-ID')}\n🏷️ Harga: Rp ${hargaProduk.toLocaleString('id-ID')}` });
                
                let username = (config.digiflazzUsername || '').trim(); let apiKey = (config.digiflazzApiKey || '').trim();
                let refId = 'TENDO-' + Date.now(); let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');
                await sock.sendMessage(from, { text: `⏳ *Sedang memproses pesanan...*\n\n📦 Produk: ${produkDB[kodeProduk].nama}\n📱 Tujuan: ${tujuan}` });

                try {
                    const response = await axios.post('https://api.digiflazz.com/v1/transaction', {
                        username: username, buyer_sku_code: kodeProduk, customer_no: tujuan, ref_id: refId, sign: sign
                    });
                    const resData = response.data.data;
                    if (resData.status === 'Gagal') {
                        await sock.sendMessage(from, { text: `❌ *Transaksi Gagal!*\nAlasan: ${resData.message}\n\n_Saldo tidak dipotong._` });
                    } else if (resData.status === 'Pending' || resData.status === 'Sukses') {
                        db[sender].saldo -= hargaProduk;
                        db[sender].trx_count = (db[sender].trx_count || 0) + 1;
                        db[sender].history = db[sender].history || [];
                        db[sender].history.unshift({ tanggal: new Date().toLocaleString('id-ID'), nama: produkDB[kodeProduk].nama, tujuan: tujuan, status: resData.status, sn: '-' });
                        if(db[sender].history.length > 20) db[sender].history.pop();
                        saveJSON(dbFile, db);
                        
                        let trxs = loadJSON(trxFile);
                        trxs[refId] = { jid: from, sku: kodeProduk, tujuan: tujuan, harga: hargaProduk, nama: produkDB[kodeProduk].nama, tanggal: Date.now() };
                        saveJSON(trxFile, trxs);
                        
                        let pesanStatus = resData.status === 'Pending' ? `⏳ *PESANAN DIPROSES*` : `✅ *PESANAN SUKSES*`;
                        await sock.sendMessage(from, { text: `${pesanStatus}\n\n📦 Produk: ${produkDB[kodeProduk].nama}\n📱 Tujuan: ${tujuan}\n⚙️ Status: *${resData.status}*\n💰 Sisa Saldo: Rp ${db[sender].saldo.toLocaleString('id-ID')}` });
                    }
                } catch (error) { await sock.sendMessage(from, { text: `❌ *Transaksi Gagal!*\nAlasan: Server Error.\n_Saldo tidak dipotong._` }); }
                return;
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
# 4. INSTALASI DEPENDENSI LENGKAP BERSERTA LOADING
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

    echo -ne "${C_MAG}>> Menginstall dependensi (curl, zip, unzip)...${C_RST}"
    sudo -E apt-get install -y curl git wget nano zip unzip > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Menginstall Node.js...${C_RST}"
    (curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - > /dev/null 2>&1 && sudo -E apt-get install -y nodejs > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Menginstall PM2 untuk latar belakang...${C_RST}"
    (sudo npm install -g pm2 > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"

    echo -ne "${C_MAG}>> Meracik sistem utama & Web App (v31 ULTIMATE)...${C_RST}"
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
                echo -e "\n${C_MAG}--- TAMBAH SALDO ---${C_RST}"
                read -p "Masukkan ID Member (No WA awalan 08/62 atau Email): " nomor
                read -p "Masukkan Jumlah Saldo: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let input = '$nomor'.trim();
                    let normPhone = input.replace(/[^0-9]/g, '');
                    if(normPhone.startsWith('0')) normPhone = '62' + normPhone.substring(1);
                    
                    // Cari berdasarkan HP atau Email
                    let target = Object.keys(db).find(k => k === normPhone || db[k].email === input);
                    
                    if(!target) {
                        // Jika tidak ada, buat baru pakai nomor HP
                        target = normPhone || input;
                        db[target] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: target + '@s.whatsapp.net', trx_count: 0, history: [] };
                    }
                    db[target].saldo += parseInt('$jumlah');
                    fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                    console.log('\x1b[32m\n✅ Saldo Rp $jumlah berhasil ditambahkan ke ' + target + '!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- KURANGI SALDO ---${C_RST}"
                read -p "Masukkan ID Member (No WA awalan 08/62 atau Email): " nomor
                read -p "Masukkan Jumlah Saldo yg dikurangi: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let input = '$nomor'.trim();
                    let normPhone = input.replace(/[^0-9]/g, '');
                    if(normPhone.startsWith('0')) normPhone = '62' + normPhone.substring(1);
                    
                    let target = Object.keys(db).find(k => k === normPhone || db[k].email === input);
                    
                    if(!target) { 
                        console.log('\x1b[31m\n❌ Akun tidak ditemukan di database.\x1b[0m'); 
                    } else {
                        db[target].saldo -= parseInt('$jumlah');
                        if(db[target].saldo < 0) db[target].saldo = 0;
                        fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                        console.log('\x1b[32m\n✅ Saldo berhasil dikurangi!\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR MEMBER ---${C_RST}"
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let members = Object.keys(db);
                    if(members.length === 0) console.log('\x1b[33mBelum ada member.\x1b[0m');
                    else {
                        members.forEach((m, i) => console.log((i + 1) + '. WA: ' + m + ' | Email: ' + (db[m].email || '-') + ' | Saldo: Rp ' + db[m].saldo.toLocaleString('id-ID')));
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
    echo -e "  ${C_GREEN}[12]${C_RST} 📢 Kirim Pesan Broadcast WA"
    echo -e "  ${C_GREEN}[13]${C_RST} 🌐 Kirim Pemberitahuan ke Website"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -e "  ${C_RED}[0]${C_RST}  Keluar dari Panel"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -ne "${C_YELLOW}Pilih menu [0-13]: ${C_RST}"
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
            echo -e "\n${C_MAG}--- BROADCAST PESAN WA ---${C_RST}"
            echo -e "Gunakan \n untuk baris baru."
            read -p "Ketik Pesan Broadcast: " pesan_bc
            if [ ! -z "$pesan_bc" ]; then
                echo -e "$pesan_bc" > broadcast.txt
                echo -e "\n${C_GREEN}✅ Pesan berhasil masuk antrean broadcast WA!${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        13)
            echo -e "\n${C_MAG}--- PENGUMUMAN WEBSITE APLIKASI ---${C_RST}"
            echo -e "Pesan ini akan muncul di menu Notifikasi Aplikasi Pelanggan."
            read -p "Ketik Pengumuman Web: " web_notif
            if [ ! -z "$web_notif" ]; then
                echo -e "$web_notif" > web_notif.txt
                echo -e "\n${C_GREEN}✅ Pengumuman Aplikasi Web berhasil diupdate!${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        0) echo -e "${C_GREEN}Keluar dari panel. Sampai jumpa! 👋${C_RST}"; exit 0 ;;
        *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 2 ;;
    esac
done
