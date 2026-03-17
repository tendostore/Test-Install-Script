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
  "background_color": "#f8fafc",
  "theme_color": "#0b2136",
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
    <meta name="theme-color" content="#0b2136">
    <style>
        /* TEMA PREMIUM EKSKLUSIF */
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f4f7f6; color: #1e293b; margin: 0; display: flex; justify-content: center; }
        #app { width: 100%; max-width: 480px; background: #f8fafc; min-height: 100vh; position: relative; overflow-x: hidden; padding-bottom: 80px; box-sizing: border-box; box-shadow: 0 0 20px rgba(0,0,0,0.05);}
        
        /* TOP BAR */
        .top-bar { background: #0b2136; color: #ffffff; padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;}
        .menu-btn { font-size: 24px; cursor: pointer; background: none; border: none; color: #ffffff; padding: 0; margin-right: 15px;}
        .brand-title { font-size: 16px; font-weight: bold; flex: 1; text-align: center; margin-right: -10px;}
        .trx-badge { font-size: 11px; background: #e3f2fd; color: #0b2136; padding: 4px 10px; border-radius: 12px; font-weight: 800;}

        /* BANNER SALDO */
        .banner-container { background: #0b2136; border-radius: 0 0 25px 25px; padding: 0 20px 25px; box-shadow: 0 4px 15px rgba(11,33,54,0.1);}
        .banner { 
            background: linear-gradient(180deg, #0b2136 0%, #163756 100%); 
            border-radius: 16px; padding: 25px 20px; 
            color: #ffffff; text-align: center; position: relative; overflow: hidden;
            box-shadow: 0 8px 20px rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1);
        }
        .banner::before { content: ''; position: absolute; bottom: -40px; left: -20px; right: -20px; height: 120px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.05); pointer-events: none; }
        .banner::after { content: ''; position: absolute; top: -50px; right: -30px; width: 150px; height: 150px; border-radius: 50%; border: 1px solid rgba(255,255,255,0.05); pointer-events: none; }
        .saldo-title { font-size: 12px; font-weight: normal; opacity: 0.8; margin-bottom: 5px;}
        .saldo-amount { font-size: 34px; font-weight: 900; letter-spacing: -0.5px; margin-bottom: 15px;}
        .btn-topup-dash { 
            background: #ffffff; color: #0b2136; border: none; 
            padding: 8px 25px; border-radius: 20px; font-weight: 900; font-size: 12px; 
            cursor: pointer; display: inline-block; position: relative; z-index: 2;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1); transition: transform 0.2s;
        }
        .btn-topup-dash:active { transform: scale(0.95); }

        /* GRID MENU */
        .grid-title { margin: 25px 20px 15px; font-weight: 800; color: #1e293b; font-size: 16px;}
        .grid-container { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; padding: 0 20px;}
        .grid-box { 
            background: #ffffff; border-radius: 14px; padding: 15px 5px; 
            text-align: center; cursor: pointer; display: flex; flex-direction: column; align-items: center; 
            border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(226,232,240,0.5);
            transition: transform 0.2s, border-color 0.2s;
        }
        .grid-box:active { transform: scale(0.95); border-color: #0b2136; }
        .grid-icon-wrap { width: 45px; height: 45px; margin-bottom: 8px; display: flex; justify-content: center; align-items: center;}
        .grid-icon-wrap svg { width: 100%; height: 100%; }
        .grid-text { font-size: 10px; color: #0b2136; font-weight: 800; line-height: 1.2; text-transform: uppercase;}

        /* BOTTOM NAV */
        .bottom-nav { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: #ffffff; display: flex; justify-content: space-around; padding: 10px 0 8px; border-top: 1px solid #e2e8f0; box-shadow: 0 -2px 10px rgba(0,0,0,0.02); z-index: 90;}
        .nav-item { text-align: center; color: #94a3b8; font-size: 10px; flex: 1; cursor: pointer; display: flex; flex-direction: column; align-items: center; font-weight: 700; transition: color 0.3s;}
        .nav-icon { margin-bottom: 3px; display: flex; justify-content: center; align-items: center;}
        .nav-item.active { color: #0b2136;}

        /* TAB SYSTEM */
        .provider-tabs { display: flex; overflow-x: auto; gap: 10px; padding: 15px 20px; background: #ffffff; border-bottom: 1px solid #f1f5f9; position: sticky; top: 56px; z-index: 50;}
        .provider-tabs::-webkit-scrollbar { display: none; }
        .tab-btn { background: #ffffff; border: 1px solid #cbd5e1; padding: 8px 18px; border-radius: 20px; font-size: 12px; white-space: nowrap; cursor: pointer; font-weight: bold; color: #64748b; transition: 0.2s;}
        .tab-btn.active { background: #0b2136; color: #ffffff; border-color: #0b2136;}

        /* PRODUCT LIST STYLE */
        .brand-header { padding: 15px 20px 5px; font-weight: bold; color: #64748b; font-size: 12px; text-transform: uppercase;}
        .product-item { background: #ffffff; padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid #e2e8f0; display: flex; align-items: center; gap: 15px; box-shadow: 0 2px 6px rgba(0,0,0,0.02);}
        .prod-logo { width: 45px; height: 45px; background: #f8fafc; border-radius: 50%; display: flex; justify-content: center; align-items: center; font-weight: 900; color: #0b2136; font-size: 14px; border: 1px solid #e2e8f0;}
        .prod-info { flex: 1; }
        .prod-name { font-weight: 800; font-size: 13px; color: #0b2136; margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between;}
        .badge-open { background: #e0f2fe; color: #0284c7; font-size: 9px; padding: 2px 6px; border-radius: 4px; font-weight: 800; border: 1px solid #bae6fd;}
        .prod-desc { font-size: 10px; color: #64748b; font-weight: 600; margin-bottom: 4px;}
        .prod-price { color: #0b2136; font-weight: 900; font-size: 15px;}
        .badge-laris { background: #fff7ed; color: #ea580c; font-size: 9px; padding: 3px 8px; border-radius: 10px; font-weight: bold; float: right; margin-top: -15px; border: 1px solid #ffedd5;}
        .btn-buy { background: #0b2136; color: #ffffff; border: none; padding: 8px 22px; border-radius: 20px; font-size: 12px; font-weight: bold; cursor: pointer; transition: 0.2s;}
        .btn-buy:active { transform: scale(0.95); }

        /* SIDEBAR */
        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); z-index: 999; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:0; left:-300px; width: 280px; height: 100%; background: #ffffff; z-index: 1000; transition: left 0.3s ease; overflow-y: auto; display: flex; flex-direction: column; box-shadow: 5px 0 15px rgba(0,0,0,0.1);}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 30px 20px; text-align: center; border-bottom: 1px solid #f1f5f9; background: #0b2136; color: #ffffff;}
        .sidebar-avatar { width: 70px; height: 70px; background: #ffffff; border-radius: 50%; margin: 0 auto 10px auto; display: flex; justify-content: center; align-items: center; color: #0b2136; font-size: 30px; font-weight: bold;}
        .sidebar-name { font-weight: bold; font-size: 16px; color: #ffffff;}
        .sidebar-phone { font-size: 12px; color: #cbd5e1;}
        .sidebar-menu { padding: 10px 0; flex: 1;}
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: #334155; text-decoration: none; font-size: 14px; border-bottom: 1px solid #f8fafc; font-weight: 600;}
        .sidebar-item:active { background: #f1f5f9; }
        .sb-icon { width: 30px; font-size: 18px; color: inherit; }

        /* FORMS & COMPONENTS */
        .container { padding: 20px; }
        .card { background: #ffffff; padding: 25px 20px; border-radius: 16px; margin-bottom: 20px; border: 1px solid #e2e8f0; box-shadow: 0 4px 10px rgba(226,232,240,0.5);}
        input { width: 100%; padding: 15px; margin-bottom: 12px; border: 1px solid #cbd5e1; border-radius: 12px; box-sizing: border-box; font-size: 14px; outline: none; background: #f8fafc; color: #0b2136; font-weight: 600; transition: border-color 0.2s;}
        input:focus { border-color: #0b2136; background: #ffffff;}
        input::placeholder { color: #94a3b8; font-weight: normal; }
        .checkbox-container { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; font-size: 13px; font-weight: 600; color: #475569;}
        .checkbox-container input { width: 18px; height: 18px; margin: 0; cursor: pointer;}
        
        .btn { background: #0b2136; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer;}
        .btn-outline { background: #ffffff; color: #0b2136; border: 1.5px solid #0b2136; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        .btn:active, .btn-outline:active { transform: scale(0.98); }

        /* PROFILE SCREEN */
        .prof-header { background: #0b2136; color: #ffffff; padding: 30px 20px; text-align: center; border-bottom-left-radius: 25px; border-bottom-right-radius: 25px;}
        .prof-avatar { width: 80px; height: 80px; background: #ffffff; color: #0b2136; border-radius: 50%; font-size: 40px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-weight: bold;}
        .prof-box { background: #ffffff; margin: -20px 20px 20px; border-radius: 16px; padding: 20px; position: relative; z-index: 10; border: 1px solid #e2e8f0; box-shadow: 0 4px 15px rgba(226,232,240,0.5);}
        .prof-row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px dashed #e2e8f0; font-size: 13px;}
        .prof-row:last-child { border-bottom: none;}
        .prof-label { color: #64748b; font-weight: 600;}
        .prof-val { color: #0b2136; font-weight: 900; text-align: right;}
        .prof-action-btn { background: #f8fafc; color: #0b2136; border: 1px solid #e2e8f0; padding: 15px; width: 100%; border-radius: 12px; font-weight: bold; margin-bottom: 10px; cursor: pointer; font-size: 13px; display: flex; align-items: center; gap: 10px;}

        /* HISTORY ITEMS */
        .hist-item { background: #ffffff; padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(226,232,240,0.5);}
        .hist-top { display: flex; justify-content: space-between; font-size: 11px; color: #64748b; margin-bottom: 5px; font-weight: 700;}
        .hist-title { font-weight: 800; font-size: 14px; color: #0b2136; margin-bottom: 3px;}
        .hist-target { font-size: 12px; color: #475569; font-weight: 600;}
        .stat-badge { padding: 4px 10px; border-radius: 8px; font-weight: bold; font-size: 10px;}
        .stat-Sukses { background: #dcfce7; color: #166534; } 
        .stat-Pending { background: #ffedd5; color: #c2410c; } 
        .stat-Gagal { background: #fee2e2; color: #b91c1c; text-decoration: line-through; }

        /* MODAL */
        .modal-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); display: flex; justify-content: center; align-items: center; z-index: 2000; padding: 20px;}
        .modal-box { background: #ffffff; width: 100%; max-width: 340px; border-radius: 20px; padding: 25px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.2);}
        .modal-btns { display: flex; gap: 10px; margin-top: 15px;}
        
        .screen-header { padding: 15px 20px; font-weight: 800; font-size: 18px; display: flex; align-items: center; gap: 15px; background: #ffffff; border-bottom: 1px solid #e2e8f0; position: sticky; top:0; z-index: 10; color: #0b2136;}
        .hidden { display: none !important; }
        
        /* Ikon Back (Panah kiri) */
        .back-icon {
            cursor: pointer;
            fill: #0b2136;
        }
    </style>
</head>
<body>
    <div id="app">
        <div class="top-bar" id="home-topbar">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <div class="brand-title" id="top-title">Tendo Store</div>
            <div class="trx-badge" id="top-trx-badge">0 Trx</div>
        </div>

        <div class="sidebar-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-avatar" id="sb-avatar">T</div>
                <div class="sidebar-name" id="sb-name">Tendo Store</div>
                <div class="sidebar-phone" id="sb-phone">Belum Login</div>
            </div>
            <div class="sidebar-menu">
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showProfile()"><span class="sb-icon">👤</span> Profil Akun</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showHistory()"><span class="sb-icon">🔁</span> Transaksi Saya</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showNotif()"><span class="sb-icon">🔔</span> Pemberitahuan</a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showContactModal()"><span class="sb-icon">📞</span> Bantuan Admin</a>
            </div>
            <div style="padding: 20px;">
                <button class="btn-outline" style="color: #ef4444; border-color: #ef4444;" onclick="logout()">Keluar Akun</button>
            </div>
        </div>

        <div id="login-screen" class="container">
            <div style="text-align:center; margin: 40px 0;">
                <h1 style="color:#0b2136; margin:0; font-weight:900; font-size: 28px;">Tendo Store</h1>
                <p style="color:#64748b; font-size:13px; margin-top:5px; font-weight: 600;">Solusi Pembayaran Digital</p>
            </div>
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Masuk Akun</h2>
                <input type="email" id="log-email" placeholder="Alamat Email">
                <input type="password" id="log-pass" placeholder="Password">
                
                <label class="checkbox-container">
                    <input type="checkbox" id="rem-login"> Tetap masuk
                </label>

                <button class="btn" onclick="login()">Login Sekarang</button>
                <button class="btn-outline" onclick="showScreen('register-screen')">Buat Akun Baru</button>
            </div>
        </div>

        <div id="register-screen" class="container hidden">
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Daftar Akun</h2>
                <p style="font-size:12px; color:#64748b; text-align: center; margin-bottom: 20px; font-weight: 600;">Gunakan Nomor WhatsApp Aktif (08/62)</p>
                <input type="text" id="reg-user" placeholder="Username (Cth: BudiCell)">
                <input type="email" id="reg-email" placeholder="Alamat Email">
                <input type="number" id="reg-phone" placeholder="Nomor WhatsApp">
                <input type="password" id="reg-pass" placeholder="Buat Password">
                <button class="btn" onclick="requestOTP()">Kirim OTP WhatsApp</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('login-screen')">Kembali ke Login</button>
            </div>
        </div>

        <div id="otp-screen" class="container hidden">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0; font-size:18px;">Verifikasi WhatsApp</h2>
                <p style="font-size:13px; color:#64748b; margin-bottom: 20px; font-weight: 600;">Kode OTP 4 digit telah dikirim ke WA.</p>
                <input type="number" id="otp-code" placeholder="----" style="text-align:center; font-size:28px; letter-spacing: 12px; font-weight:bold; background:#f8fafc;">
                <button class="btn" onclick="verifyOTP()">Verifikasi & Daftar</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('register-screen')">Batal</button>
            </div>
        </div>

        <div id="dashboard-screen" class="hidden">
            <div class="banner-container">
                <div class="banner" id="home-banner">
                    <div class="saldo-title">Sisa Saldo Anda</div>
                    <div class="saldo-amount" id="user-saldo">Rp 0,00</div>
                    <button class="btn-topup-dash" onclick="openTopupModal()">[+] ISI SALDO</button>
                </div>
            </div>

            <div class="grid-title">Layanan Favorit</div>
            <div class="grid-container">
                <div class="grid-box" onclick="loadCategory('Pulsa')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <rect x="6" y="4" width="22" height="36" rx="4" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <rect x="13" y="34" width="8" height="2" rx="1" fill="#0b2136"/>
                            <circle cx="28" cy="32" r="8" fill="#FBBF24" stroke="#0b2136" stroke-width="2"/>
                            <text x="28" y="36" font-size="12" font-family="Arial" font-weight="bold" fill="#0b2136" text-anchor="middle">$</text>
                            <path d="M38 24 v-10 M44 24 v-16" stroke="#4ADE80" stroke-width="3" stroke-linecap="round"/>
                        </svg>
                    </div>
                    <div class="grid-text">PULSA</div>
                </div>
                <div class="grid-box" onclick="loadCategory('Data')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <rect x="6" y="6" width="20" height="32" rx="4" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="32" cy="24" r="10" fill="#4ADE80" stroke="#0b2136" stroke-width="2"/>
                            <path d="M22 24 h20 M32 14 v20 M27 15 c-4 5 -4 13 0 18 M37 15 c4 5 4 13 0 18" fill="none" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="16" cy="14" r="2" fill="#0b2136"/><circle cx="16" cy="22" r="2" fill="#0b2136"/><circle cx="16" cy="30" r="2" fill="#0b2136"/>
                        </svg>
                    </div>
                    <div class="grid-text">DATA</div>
                </div>
                <div class="grid-box" onclick="loadCategory('Masa Aktif')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <rect x="6" y="10" width="30" height="26" rx="3" fill="#ffffff" stroke="#0b2136" stroke-width="2"/>
                            <path d="M12 6 v8 M30 6 v8" stroke="#F87171" stroke-width="3" stroke-linecap="round"/>
                            <rect x="6" y="10" width="30" height="8" rx="3" fill="#F87171" stroke="#0b2136" stroke-width="2"/>
                            <path d="M6 18 h30" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="34" cy="34" r="10" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <path d="M34 28 v6 l4 4" fill="none" stroke="#0b2136" stroke-width="2" stroke-linecap="round"/>
                        </svg>
                    </div>
                    <div class="grid-text">MASA AKTIF</div>
                </div>
                <div class="grid-box" onclick="loadCategory('SMS & Telp')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <path d="M12 34 c-4-4 -6-10 -2-14 l4-4 c2-2 6-2 8 0 l2 2 c2 2 2 4 0 6 l-2 2 c0 4 4 8 8 8 l2-2 c2-2 4-2 6 0 l2 2 c2 2 2 6 0 8 l-4 4 c-4 4 -10 2 -14 -2 z" fill="#4ADE80" stroke="#0b2136" stroke-width="2"/>
                            <path d="M26 12 h14 a4 4 0 0 1 4 4 v8 a4 4 0 0 1 -4 4 h-4 l-6 4 v-4 h-4 a4 4 0 0 1 -4 -4 v-8 a4 4 0 0 1 4 -4 z" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="30" cy="20" r="1.5" fill="#0b2136"/><circle cx="35" cy="20" r="1.5" fill="#0b2136"/><circle cx="40" cy="20" r="1.5" fill="#0b2136"/>
                        </svg>
                    </div>
                    <div class="grid-text">SMS TELP</div>
                </div>
                <div class="grid-box" onclick="loadCategory('PLN')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <rect x="6" y="14" width="12" height="16" rx="2" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <path d="M10 8 v6 M14 8 v6" stroke="#0b2136" stroke-width="2" stroke-linecap="round"/>
                            <path d="M12 18 l-3 5 h6 l-3 5" fill="none" stroke="#0b2136" stroke-width="1.5" stroke-linejoin="round"/>
                            <path d="M12 30 v4 c0 4 6 4 10 4 c10 0 10 -14 10 -14" fill="none" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="32" cy="18" r="10" fill="#FBBF24" stroke="#0b2136" stroke-width="2"/>
                            <path d="M28 28 l4 4 l4-4" fill="none" stroke="#0b2136" stroke-width="2"/>
                            <path d="M30 14 l-2 6 h6 l-2 6" fill="none" stroke="#0b2136" stroke-width="2" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <div class="grid-text">PLN</div>
                </div>
                <div class="grid-box" onclick="loadCategory('E-Wallet')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <path d="M14 10 h16 l4 -4 h8 v10" fill="#4ADE80" stroke="#0b2136" stroke-width="2" stroke-linejoin="round"/>
                            <path d="M10 14 h12 l4 -4 h10 v10" fill="#34D399" stroke="#0b2136" stroke-width="2" stroke-linejoin="round"/>
                            <rect x="4" y="16" width="36" height="24" rx="4" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <path d="M40 24 h-6 a4 4 0 0 0 0 8 h6" fill="#ffffff" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="36" cy="28" r="2" fill="#0b2136"/>
                        </svg>
                    </div>
                    <div class="grid-text">E-WALLET</div>
                </div>
                <div class="grid-box" onclick="loadCategory('Tagihan')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <path d="M10 6 h16 l4 4 v26 l-3-2 l-3 2 l-3-2 l-3 2 l-3-2 l-3 2 l-3-2 l-3 2 v-32 z" fill="#ffffff" stroke="#0b2136" stroke-width="2"/>
                            <path d="M14 14 h10 M14 20 h14 M14 26 h6" stroke="#0b2136" stroke-width="2" stroke-linecap="round"/>
                            <rect x="22" y="24" width="22" height="14" rx="2" fill="#4ADE80" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="33" cy="31" r="3" fill="#ffffff" stroke="#0b2136" stroke-width="1.5"/>
                            <path d="M20 28 h2 M42 28 h2" stroke="#0b2136" stroke-width="2"/>
                        </svg>
                    </div>
                    <div class="grid-text">TAGIHAN</div>
                </div>
                <div class="grid-box" onclick="loadCategory('E-Toll')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <rect x="6" y="14" width="6" height="26" fill="#F97316" stroke="#0b2136" stroke-width="2"/>
                            <path d="M4 14 h10 M9 14 v-4 h24 v4" fill="none" stroke="#0b2136" stroke-width="2"/>
                            <rect x="15" y="6" width="12" height="4" fill="#ffffff" stroke="#0b2136" stroke-width="2"/>
                            <path d="M12 24 h28" stroke="#0b2136" stroke-width="2" stroke-dasharray="4 4"/>
                            <path d="M22 36 l-2 -8 h12 l-2 8 z" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <path d="M20 36 h12 v4 h-12 z" fill="#3B82F6" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="23" cy="38" r="1.5" fill="#ffffff"/><circle cx="29" cy="38" r="1.5" fill="#ffffff"/>
                        </svg>
                    </div>
                    <div class="grid-text">E-TOLL</div>
                </div>
                <div class="grid-box" onclick="loadCategory('Digital')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 48 48">
                            <path d="M8 26 c0-8 6-12 16-12 s16 4 16 12 c0 4-2 10-6 10 c-2 0-4-2-4-4 l-2-4 h-8 l-2 4 c0 2-2 4-4 4 c-4 0-6-6-6-10 z" fill="#60A5FA" stroke="#0b2136" stroke-width="2"/>
                            <circle cx="14" cy="24" r="3" fill="#ffffff" stroke="#0b2136" stroke-width="1.5"/>
                            <path d="M14 21 v6 M11 24 h6" stroke="#0b2136" stroke-width="1.5"/>
                            <circle cx="34" cy="22" r="1.5" fill="#0b2136"/><circle cx="32" cy="25" r="1.5" fill="#0b2136"/>
                            <circle cx="36" cy="25" r="1.5" fill="#0b2136"/><circle cx="34" cy="28" r="1.5" fill="#0b2136"/>
                            <rect x="10" y="4" width="8" height="6" rx="1" fill="#A78BFA" stroke="#0b2136" stroke-width="1.5"/>
                            <path d="M13 5 l3 2 l-3 2 z" fill="#ffffff"/>
                            <rect x="28" y="4" width="8" height="6" rx="1" fill="#F472B6" stroke="#0b2136" stroke-width="1.5"/>
                            <path d="M31 5 l3 2 l-3 2 z" fill="#ffffff"/>
                        </svg>
                    </div>
                    <div class="grid-text">DIGITAL</div>
                </div>
            </div>
            
            <div style="padding: 20px; margin: 30px 20px; background: #ffffff; border-radius: 16px; text-align: center; border: 1px dashed #cbd5e1;" id="install-banner" class="hidden">
                <strong style="color:#0b2136; font-size:14px;">Aplikasi Tendo Store</strong><br>
                <span style="font-size:12px; color:#64748b; font-weight: 600;">Pasang di layar utama HP Anda untuk akses cepat!</span><br>
                <button class="btn" style="margin-top:15px; padding: 10px 30px; font-size:12px; width:auto; border-radius:20px;" id="install-btn">Install Sekarang</button>
            </div>
        </div>

        <div id="produk-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="showDashboard()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <path d="M15.41 7.41L14 6l-6 6 6 6 1.41-1.41L10.83 12z"/>
                </svg>
                <span id="cat-title-text" style="text-transform: uppercase;">Katalog</span>
            </div>
            
            <div class="provider-tabs" id="provider-tabs"></div>
            <div id="product-list" style="padding-top: 5px;"></div>
        </div>

        <div id="history-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="showDashboard()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <path d="M15.41 7.41L14 6l-6 6 6 6 1.41-1.41L10.83 12z"/>
                </svg>
                <span style="text-transform: uppercase;">Riwayat Transaksi</span>
            </div>
            <div id="history-list" style="padding-top:10px;"></div>
        </div>

        <div id="profile-screen" class="hidden">
            <div class="prof-header">
                <div class="prof-avatar" id="p-avatar">T</div>
                <h2 style="margin:0 0 5px 0; font-size: 20px;" id="p-username">Username</h2>
                <div style="font-size:13px; font-weight: bold; color: rgba(255,255,255,0.8);" id="p-id">ID: TD-000000</div>
            </div>
            <div class="prof-box">
                <div class="prof-row"><span class="prof-label">Email</span><span class="prof-val" id="p-email">-</span></div>
                <div class="prof-row"><span class="prof-label">WhatsApp</span><span class="prof-val" id="p-phone">-</span></div>
                <div class="prof-row"><span class="prof-label">Tgl Daftar</span><span class="prof-val" id="p-date">-</span></div>
                <div class="prof-row"><span class="prof-label">Total Transaksi</span><span class="prof-val" id="p-trx">0 Kali</span></div>
            </div>
            
            <div style="padding: 0 20px;">
                <h3 style="font-size:14px; color:#888; margin-bottom:15px;">PENGATURAN</h3>
                <button class="prof-action-btn" onclick="openEditModal('email')"><span style="font-size: 18px;">✉️</span> Ubah Email</button>
                <button class="prof-action-btn" onclick="openEditModal('phone')"><span style="font-size: 18px;">📱</span> Ubah Nomor WA</button>
                <button class="prof-action-btn" onclick="openEditModal('password')"><span style="font-size: 18px;">🔐</span> Ubah Password</button>
            </div>
        </div>

        <div id="notif-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="showDashboard()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <path d="M15.41 7.41L14 6l-6 6 6 6 1.41-1.41L10.83 12z"/>
                </svg>
                <span>Pemberitahuan</span>
            </div>
            <div class="container">
                <div class="card" style="border-left: 4px solid #0b2136;">
                    <h3 style="margin-top:0; color: #0b2136; font-size:15px;">📢 Info Terbaru</h3>
                    <p id="notif-text" style="color: #555; line-height: 1.6; font-size:13px; white-space: pre-wrap; font-weight: 500;">Memuat...</p>
                </div>
            </div>
        </div>

        <div class="bottom-nav" id="main-bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showDashboard()">
                <span class="nav-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24">
                      <path d="M3 10 l9-7 9 7 v11 a2 2 0 0 1 -2 2 H5 a2 2 0 0 1 -2 -2 z" fill="#f8fafc" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                      <path d="M9 22 V12 h6 v10" fill="#e2e8f0" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                    </svg>
                </span>HOME
            </div>
            <div class="nav-item" id="nav-history" onclick="showHistory()">
                <span class="nav-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24">
                      <rect x="5" y="3" width="14" height="18" rx="2" fill="#f8fafc" stroke="currentColor" stroke-width="2"/>
                      <path d="M9 8h6 M9 12h6 M9 16h4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                </span>RIWAYAT
            </div>
            <div class="nav-item" id="nav-notif" onclick="showNotif()">
                <span class="nav-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24">
                      <path d="M18 8 A6 6 0 0 0 6 8 c0 7 -3 9 -3 9 h18 s-3 -2 -3 -9" fill="#f8fafc" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                      <path d="M13.73 21 a2 2 0 0 1 -3.46 0" fill="#e2e8f0" stroke="currentColor" stroke-width="2"/>
                    </svg>
                </span>INFO
            </div>
            <div class="nav-item" id="nav-profile" onclick="showProfile()">
                <span class="nav-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24">
                      <path d="M20 21 v-2 a4 4 0 0 0 -4 -4 H8 a4 4 0 0 0 -4 4 v2" fill="#f8fafc" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                      <circle cx="12" cy="7" r="4" fill="#e2e8f0" stroke="currentColor" stroke-width="2"/>
                    </svg>
                </span>PROFIL
            </div>
        </div>

        <div id="contact-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Pusat Bantuan</h3>
                <p style="font-size:13px; color:#666; margin-bottom: 20px;">Silakan pilih platform untuk menghubungi Admin:</p>
                <button class="btn" style="margin-bottom:10px; background:#25D366;" onclick="window.open('https://wa.me/6282224460678', '_blank'); closeContactModal()">WhatsApp Admin</button>
                <button class="btn" style="background:#2CA5E0;" onclick="window.open('https://t.me/tendo_32', '_blank'); closeContactModal()">Telegram Admin</button>
                <div style="margin-top:20px;"><a href="#" style="color:#aaa; text-decoration:none; font-size:14px; font-weight:bold;" onclick="closeContactModal()">Tutup</a></div>
            </div>
        </div>

        <div id="order-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Beli Produk</h3>
                <div style="background:#f9f9f9; padding:15px; border-radius:12px; margin-bottom:15px; border: 1px solid #eee;">
                    <strong id="m-name" style="font-size:14px; color:#2c3e50; line-height:1.4; display:block; margin-bottom:8px;">Produk</strong>
                    <span style="color:#2c3e50; font-weight:900; font-size: 22px;" id="m-price">Rp 0</span>
                </div>
                <input type="text" id="m-target" placeholder="Masukkan Nomor/ID Tujuan">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeOrderModal()">Batal</button>
                    <button class="btn" id="m-submit" onclick="processOrder()">Beli Sekarang</button>
                </div>
            </div>
        </div>

        <div id="topup-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Isi Saldo</h3>
                <p style="font-size:12px; color:#666; margin-bottom:20px;">Sistem akan mengarahkan Anda ke WhatsApp Admin untuk instruksi pembayaran.</p>
                <input type="text" id="topup-id" placeholder="Nomor HP atau Email Akun">
                <input type="number" id="topup-nominal" placeholder="Nominal (Cth: 50000)">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeTopupModal()">Batal</button>
                    <button class="btn" onclick="sendTopup()">Ajukan Topup</button>
                </div>
            </div>
        </div>

        <div id="edit-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;" id="edit-title">Ubah Data</h3>
                
                <div id="edit-step-1">
                    <input type="text" id="edit-input" placeholder="Masukkan data baru">
                    <div class="modal-btns">
                        <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeEditModal()">Batal</button>
                        <button class="btn" onclick="reqEditOTP()">Kirim OTP</button>
                    </div>
                </div>

                <div id="edit-step-2" class="hidden">
                    <p style="font-size:12px; color:#666; font-weight: bold;">OTP telah dikirim ke WA Anda.</p>
                    <input type="number" id="edit-otp-input" placeholder="----" style="letter-spacing:12px; text-align:center; font-size:24px; background:#f4f7f6;">
                    <div class="modal-btns">
                        <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeEditModal()">Batal</button>
                        <button class="btn" onclick="verifyEditOTP()">Simpan</button>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <script>
        // PWA SETUP
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

        // GLOBAL VARS
        let currentUser = ""; let userData = {}; let allProducts = {}; let selectedSKU = ""; let tempRegPhone = ""; let currentEditMode = "";

        // UI HELPERS
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
            
            if(id === 'login-screen' || id === 'register-screen' || id === 'otp-screen') {
                document.getElementById('home-topbar').classList.add('hidden');
                document.getElementById('main-bottom-nav').classList.add('hidden');
            } else {
                document.getElementById('home-topbar').classList.remove('hidden');
                document.getElementById('main-bottom-nav').classList.remove('hidden');
            }
            if(navId) updateNav(navId);
        }

        window.onload = async () => {
            let savedEmail = localStorage.getItem('tendo_email');
            let savedPass = localStorage.getItem('tendo_pass');
            if(savedEmail && savedPass) {
                try {
                    let res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:savedEmail, password:savedPass}) });
                    let data = await res.json();
                    if(data.success) {
                        currentUser = data.phone; userData = data.data;
                        fetchAllProducts(); showDashboard();
                    } else showScreen('login-screen', null);
                } catch(e) { showScreen('login-screen', null); }
            } else {
                showScreen('login-screen', null);
            }
        }

        function showDashboard() { 
            showScreen('dashboard-screen', 'nav-home'); 
            syncUserData();
        }
        function showHistory() { showScreen('history-screen', 'nav-history'); syncUserData(); }
        function showProfile() { showScreen('profile-screen', 'nav-profile'); syncUserData(); }
        
        async function showNotif() { 
            showScreen('notif-screen', 'nav-notif'); 
            try {
                let res = await fetch('/api/notif');
                let data = await res.json();
                document.getElementById('notif-text').innerText = data.text || "Tidak ada pemberitahuan sistem saat ini.";
            } catch(e) {}
        }

        function showContactModal() { document.getElementById('contact-modal').classList.remove('hidden'); }
        function closeContactModal() { document.getElementById('contact-modal').classList.add('hidden'); }
        
        function openTopupModal() {
            document.getElementById('topup-id').value = userData.email || currentUser;
            document.getElementById('topup-nominal').value = '';
            document.getElementById('topup-modal').classList.remove('hidden');
        }
        function closeTopupModal() { document.getElementById('topup-modal').classList.add('hidden'); }
        
        function sendTopup() {
            let id = document.getElementById('topup-id').value.trim();
            let nom = document.getElementById('topup-nominal').value.trim();
            if(!id || !nom) return alert("Lengkapi data!");
            let pesan = `Halo Admin Tendo Store,%0A%0ASaya ingin mengajukan Topup Saldo.%0A%0A👤 Identitas: *${id}*%0A💰 Nominal: *Rp ${nom}*%0A%0AMohon instruksi pembayaran selanjutnya.`;
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
            closeTopupModal();
        }

        function logout() {
            currentUser = ""; userData = {}; 
            localStorage.removeItem('tendo_email'); localStorage.removeItem('tendo_pass');
            toggleSidebar(); showScreen('login-screen', null);
            document.getElementById('log-pass').value = '';
        }

        async function syncUserData() {
            if(!currentUser) return;
            try {
                let res = await fetch('/api/user/' + currentUser);
                let data = await res.json();
                if(data.success) {
                    userData = data.data; let u = userData;
                    document.getElementById('user-saldo').innerText = 'Rp ' + u.saldo.toLocaleString('id-ID', {minimumFractionDigits: 2, maximumFractionDigits: 2});
                    document.getElementById('top-trx-badge').innerText = (u.trx_count || 0) + ' Trx';
                    
                    let firstLetter = (u.username || "T").charAt(0).toUpperCase();
                    document.getElementById('sb-avatar').innerText = firstLetter;
                    document.getElementById('sb-name').innerText = u.username || "Member";
                    document.getElementById('sb-phone').innerText = currentUser;

                    document.getElementById('p-avatar').innerText = firstLetter;
                    document.getElementById('p-username').innerText = u.username || "Member";
                    document.getElementById('p-id').innerText = "ID: " + (u.id_pelanggan || "TD-000");
                    document.getElementById('p-email').innerText = u.email || '-';
                    document.getElementById('p-phone').innerText = currentUser;
                    document.getElementById('p-date').innerText = u.tanggal_daftar || '-';
                    document.getElementById('p-trx').innerText = (u.trx_count || 0) + ' Kali';

                    let histHTML = '';
                    let historyList = u.history || [];
                    if(historyList.length === 0) histHTML = '<div style="text-align:center; color:#888; font-weight:bold; margin-top: 30px; font-size:13px;">Belum ada transaksi.</div>';
                    else {
                        historyList.forEach(h => {
                            let statClass = 'stat-Pending';
                            if(h.status === 'Sukses') statClass = 'stat-Sukses';
                            if(h.status === 'Gagal') statClass = 'stat-Gagal';
                            histHTML += `
                                <div class="hist-item">
                                    <div class="hist-top"><span>${h.tanggal}</span> <span class="stat-badge ${statClass}">${h.status}</span></div>
                                    <div class="hist-title">${h.nama}</div>
                                    <div class="hist-target">Tujuan: ${h.tujuan}</div>
                                    ${h.sn && h.sn !== '-' ? `<div style="font-size:11px; color:#0b2136; margin-top:6px; background:#f8fafc; padding:6px 10px; border-radius:6px; font-weight:bold; border: 1px solid #e2e8f0;">SN: ${h.sn}</div>` : ''}
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
            let rem = document.getElementById('rem-login').checked;
            if(!email || !pass) return alert('Isi Email & Password!');
            let btn = document.querySelector('#login-screen .btn'); btn.innerText = "Memeriksa...";
            try {
                let res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, password:pass}) });
                let data = await res.json();
                if(data.success) {
                    if(rem) { localStorage.setItem('tendo_email', email); localStorage.setItem('tendo_pass', pass); }
                    currentUser = data.phone; userData = data.data;
                    fetchAllProducts(); showDashboard();
                } else alert(data.message);
            } catch(e) { alert('Gagal terhubung.'); }
            btn.innerText = "Login Sekarang";
        }

        async function requestOTP() {
            let user = document.getElementById('reg-user').value.trim();
            let email = document.getElementById('reg-email').value.trim();
            let phone = document.getElementById('reg-phone').value.trim();
            let pass = document.getElementById('reg-pass').value.trim();
            if(!user || !email || !phone || !pass) return alert('Semua kolom wajib diisi!');
            let btn = document.querySelector('#register-screen .btn'); btn.innerText = "Mengirim...";
            try {
                let res = await fetch('/api/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:user, email, phone, password:pass}) });
                let data = await res.json();
                if(data.success) { tempRegPhone = phone; showScreen('otp-screen', null); } 
                else alert(data.message);
            } catch(e) { alert('Error server.'); }
            btn.innerText = "Kirim OTP WA";
        }

        async function verifyOTP() {
            let otp = document.getElementById('otp-code').value.trim();
            if(!otp) return alert('Masukkan OTP!');
            try {
                let res = await fetch('/api/verify-otp', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone: tempRegPhone, otp}) });
                let data = await res.json();
                if(data.success) {
                    alert('Pendaftaran Berhasil! Silakan Login.');
                    document.getElementById('log-email').value = document.getElementById('reg-email').value;
                    document.getElementById('log-pass').value = document.getElementById('reg-pass').value;
                    showScreen('login-screen', null);
                } else alert(data.message);
            } catch(e) { alert('Error server.'); }
        }

        function openEditModal(type) {
            currentEditMode = type;
            let inp = document.getElementById('edit-input');
            document.getElementById('edit-step-1').classList.remove('hidden');
            document.getElementById('edit-step-2').classList.add('hidden');
            
            if(type === 'email') { document.getElementById('edit-title').innerText = "Ganti Email"; inp.type="email"; inp.placeholder="Email baru"; inp.value = userData.email;}
            if(type === 'phone') { document.getElementById('edit-title').innerText = "Ganti Nomor WA"; inp.type="number"; inp.placeholder="Nomor WA baru (08/62)"; inp.value = currentUser;}
            if(type === 'password') { document.getElementById('edit-title').innerText = "Ganti Password"; inp.type="text"; inp.placeholder="Password baru"; inp.value = userData.password;}
            document.getElementById('edit-modal').classList.remove('hidden');
        }
        
        function closeEditModal() { document.getElementById('edit-modal').classList.add('hidden'); }
        
        async function reqEditOTP() {
            let val = document.getElementById('edit-input').value.trim();
            if(!val) return alert("Isi data baru!");
            let btn = document.querySelector('#edit-step-1 .btn'); btn.innerText = "Mengirim...";
            try {
                let res = await fetch('/api/req-edit-otp', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone: currentUser, type: currentEditMode, newValue: val}) });
                let data = await res.json();
                if(data.success) {
                    document.getElementById('edit-step-1').classList.add('hidden');
                    document.getElementById('edit-step-2').classList.remove('hidden');
                } else alert(data.message);
            } catch(e) { alert('Error server'); }
            btn.innerText = "Kirim OTP";
        }

        async function verifyEditOTP() {
            let otp = document.getElementById('edit-otp-input').value.trim();
            if(!otp) return alert("Masukkan OTP!");
            let btn = document.querySelector('#edit-step-2 .btn'); btn.innerText = "Memproses...";
            try {
                let res = await fetch('/api/verify-edit-otp', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone: currentUser, otp: otp}) });
                let data = await res.json();
                if(data.success) {
                    alert("Berhasil diubah!");
                    closeEditModal();
                    if(currentEditMode === 'phone' || currentEditMode === 'password') { logout(); } 
                    else { syncUserData(); }
                } else alert(data.message);
            } catch(e) { alert('Error server'); }
            btn.innerText = "Simpan";
        }

        async function fetchAllProducts() {
            let res = await fetch('/api/produk');
            allProducts = await res.json();
        }

        function loadCategory(cat) {
            document.getElementById('cat-title-text').innerText = cat;
            let tabsHTML = '';
            
            let brands = [];
            for(let key in allProducts) {
                if(allProducts[key].kategori !== cat) continue;
                let b = allProducts[key].brand || 'Lainnya';
                if(!brands.includes(b)) brands.push(b);
            }

            if(brands.length > 0) {
                brands.sort();
                brands.forEach((b, index) => {
                    let activeClass = index === 0 ? 'active' : '';
                    tabsHTML += `<div class="tab-btn ${activeClass}" onclick="filterBrand('${cat}', '${b}', this)">${b.toUpperCase()}</div>`;
                });
                document.getElementById('provider-tabs').innerHTML = tabsHTML;
                document.getElementById('provider-tabs').style.display = 'flex';
                filterBrand(cat, brands[0], document.querySelector('#provider-tabs .tab-btn'));
            } else {
                document.getElementById('provider-tabs').style.display = 'none';
                document.getElementById('product-list').innerHTML = '<div style="text-align:center; color:#888; padding:30px; font-weight:bold;">Produk belum tersedia.</div>';
            }
            showScreen('produk-screen', 'nav-home');
        }

        function filterBrand(cat, brand, el) {
            if(el) {
                document.querySelectorAll('#provider-tabs .tab-btn').forEach(btn => btn.classList.remove('active'));
                el.classList.add('active');
            }
            let listHTML = '';
            for(let key in allProducts) {
                let p = allProducts[key];
                if (p.kategori !== cat) continue;
                if ((p.brand || 'Lainnya') !== brand) continue;
                let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                let initial = p.brand ? p.brand.substring(0,2).toUpperCase() : 'PR';
                
                listHTML += `
                <div class="product-item">
                    <div class="prod-logo">${initial}</div>
                    <div class="prod-info">
                        <div class="prod-name">
                            ${p.nama}
                            <span class="badge-open">OPEN</span>
                        </div>
                        ${p.deskripsi ? `<div class="prod-desc">${p.deskripsi}</div>` : `<div class="prod-desc">Proses Otomatis</div>`}
                        <div class="prod-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                    </div>
                    <div>
                        <div class="badge-laris">TERLARIS</div>
                        <button class="btn-buy" onclick="openOrderModal('${key}', '${safeName}', ${p.harga})">Beli</button>
                    </div>
                </div>`;
            }
            document.getElementById('product-list').innerHTML = listHTML || '<div style="text-align:center; padding:30px; font-weight:bold; color:#94a3b8;">KOSONG</div>';
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
                    alert('Pesanan Sukses Diproses!\nCek tab Riwayat atau WhatsApp Anda.');
                    closeOrderModal();
                    syncUserData();
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
# 3. FUNGSI UNTUK MEMBUAT FILE INDEX.JS
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
const japriFile = './japri.txt';

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

// API ROUTER
app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });
app.get('/api/notif', (req, res) => { let txt = fs.existsSync(notifFile) ? fs.readFileSync(notifFile, 'utf8') : ''; res.json({text: txt}); });

app.get('/api/user/:phone', (req, res) => {
    let db = loadJSON(dbFile);
    let p = req.params.phone;
    if(db[p]) res.json({success: true, data: db[p]});
    else res.json({success: false});
});

app.post('/api/login', (req, res) => {
    let { email, password } = req.body;
    let db = loadJSON(dbFile);
    let userPhone = Object.keys(db).find(k => db[k].email === email && db[k].password === password);
    if (userPhone) res.json({success: true, data: db[userPhone], phone: userPhone});
    else res.json({success: false, message: 'Email atau Password salah!'});
});

app.post('/api/register', (req, res) => {
    let { username, email, password } = req.body;
    let phone = normalizePhone(req.body.phone); 
    if(phone.length < 9) return res.json({success: false, message: 'Nomor WA tidak valid!'});
    
    let db = loadJSON(dbFile);
    if (Object.keys(db).find(k => db[k].email === email)) return res.json({success: false, message: 'Email terdaftar!'});

    let otp = Math.floor(1000 + Math.random() * 9000).toString();
    tempOtpDB[phone] = { username, email, password, otp };

    if (globalSock) {
        let msg = `*🛡️ TENDO STORE SECURITY 🛡️*\n\nHai ${username},\nKode OTP Pendaftaran: *${otp}*\n\n_⚠️ Jangan bagikan kode ini!_`;
        globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>{});
    }
    res.json({success: true});
});

app.post('/api/verify-otp', (req, res) => {
    let otp = req.body.otp;
    let phone = normalizePhone(req.body.phone);
    
    if(tempOtpDB[phone] && tempOtpDB[phone].otp === otp) {
        let db = loadJSON(dbFile);
        let idPelanggan = 'TD-' + Math.floor(100000 + Math.random() * 900000); 
        
        if(db[phone]) {
            db[phone].username = tempOtpDB[phone].username;
            db[phone].email = tempOtpDB[phone].email;
            db[phone].password = tempOtpDB[phone].password;
            if(!db[phone].id_pelanggan) db[phone].id_pelanggan = idPelanggan;
        } else {
            db[phone] = { id_pelanggan: idPelanggan, username: tempOtpDB[phone].username, email: tempOtpDB[phone].email, password: tempOtpDB[phone].password, saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: phone + '@s.whatsapp.net', step: 'idle', trx_count: 0, history: [] };
        }
        saveJSON(dbFile, db);
        delete tempOtpDB[phone];
        res.json({success: true});
    } else res.json({success: false, message: 'Kode OTP Salah!'});
});

app.post('/api/req-edit-otp', (req, res) => {
    let { phone, type, newValue } = req.body;
    let db = loadJSON(dbFile);
    if(!db[phone]) return res.json({success: false, message: 'User tidak ditemukan.'});

    let otp = Math.floor(1000 + Math.random() * 9000).toString();
    tempOtpDB[phone + '_edit'] = { type, newValue, otp };

    if (globalSock) {
        let msg = `*🛡️ TENDO STORE SECURITY 🛡️*\n\nKode OTP untuk mengubah data Anda adalah: *${otp}*\n\n_⚠️ Jangan berikan ke siapapun!_`;
        globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>{});
    }
    res.json({success: true});
});

app.post('/api/verify-edit-otp', (req, res) => {
    let { phone, otp } = req.body;
    let db = loadJSON(dbFile);
    let session = tempOtpDB[phone + '_edit'];
    
    if(session && session.otp === otp) {
        if(session.type === 'email') db[phone].email = session.newValue;
        if(session.type === 'password') db[phone].password = session.newValue;
        if(session.type === 'phone') {
            let newPhone = normalizePhone(session.newValue);
            if(db[newPhone]) return res.json({success: false, message: 'Nomor sudah dipakai akun lain.'});
            db[newPhone] = db[phone];
            db[newPhone].jid = newPhone + '@s.whatsapp.net';
            delete db[phone];
        }
        saveJSON(dbFile, db);
        delete tempOtpDB[phone + '_edit'];
        res.json({success: true});
    } else res.json({success: false, message: 'OTP Salah!'});
});

app.post('/api/order', async (req, res) => {
    let { phone, sku, tujuan } = req.body;
    let db = loadJSON(dbFile);
    let produkDB = loadJSON(produkFile);
    let config = loadJSON(configFile);

    if (!db[phone]) return res.json({success: false, message: 'Sesi tidak valid.'});
    let p = produkDB[sku];
    if (db[phone].saldo < p.harga) return res.json({success: false, message: 'Saldo tidak cukup.'});

    let username = (config.digiflazzUsername || '').trim();
    let apiKey = (config.digiflazzApiKey || '').trim();
    let refId = 'WEB-' + Date.now();
    let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

    try {
        const response = await axios.post('https://api.digiflazz.com/v1/transaction', { username: username, buyer_sku_code: sku, customer_no: tujuan, ref_id: refId, sign: sign });
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
            let msgWa = `🌐 *NOTA PEMBELIAN APLIKASI*\n\n📦 Produk: ${p.nama}\n📱 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status: *${statusOrder}*\n💰 Sisa Saldo: Rp ${db[phone].saldo.toLocaleString('id-ID')}`;
            globalSock.sendMessage(targetJid, { text: msgWa }).catch(e=>{});
        }
        return res.json({success: true, saldo: db[phone].saldo});
    } catch (error) { return res.json({success: false, message: 'Server PPOB Down'}); }
});

function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    exec(`rm -f backup.zip && zip backup.zip config.json database.json trx.json produk.json 2>/dev/null`, (err) => {
        if (!err) exec(`curl -s -F chat_id="${cfg.teleChatId}" -F document=@"backup.zip" -F caption="📦 Backup Tendo Store" https://api.telegram.org/bot${cfg.teleToken}/sendDocument`);
    });
}

if (configAwal.autoBackup) setInterval(doBackupAndSend, (configAwal.backupInterval || 720) * 60 * 1000); 

const brandStructure = {
    'Pulsa': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri', 'Smartfren', 'By.U'],
    'Masa Aktif': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri', 'Smartfren', 'By.U'],
    'SMS & Telp': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri', 'Smartfren', 'By.U'],
    'Data': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri', 'Smartfren', 'By.U'],
    'PLN': ['Token PLN'],
    'E-Wallet': ['Gopay', 'Dana', 'Shopee Pay', 'OVO', 'LinkAja'],
    'Tagihan': ['PLN Pasca', 'BPJS', 'PDAM', 'Indihome'],
    'Saldo E-Toll': ['Mandiri E-Money', 'Brizzi', 'TapCash'],
    'Digital': ['Mobile Legends', 'Free Fire', 'PUBG', 'Vidio', 'Netflix']
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

    setInterval(() => {
        if(fs.existsSync(japriFile)) {
            let lines = fs.readFileSync(japriFile, 'utf8').split('\n');
            fs.unlinkSync(japriFile);
            for(let line of lines) {
                if(line.includes('|')) {
                    let parts = line.split('|'); let target = parts[0]; parts.shift(); let msg = parts.join('|');
                    let targetJid = normalizePhone(target) + '@s.whatsapp.net';
                    sock.sendMessage(targetJid, { text: msg }).catch(e=>{});
                }
            }
        }
    }, 3000);

    setInterval(async () => {
        let trxs = loadJSON(trxFile); let keys = Object.keys(trxs); if (keys.length === 0) return;
        let cfg = loadJSON(configFile); let userAPI = (cfg.digiflazzUsername || '').trim(); let keyAPI = (cfg.digiflazzApiKey || '').trim();
        if (!userAPI || !keyAPI) return;

        for (let ref of keys) {
            let trx = trxs[ref]; let signCheck = crypto.createHash('md5').update(userAPI + keyAPI + ref).digest('hex');
            try {
                const cekRes = await axios.post('https://api.digiflazz.com/v1/transaction', { username: userAPI, buyer_sku_code: trx.sku, customer_no: trx.tujuan, ref_id: ref, sign: signCheck });
                const resData = cekRes.data.data;
                if (resData.status === 'Sukses' || resData.status === 'Gagal') {
                    let db = loadJSON(dbFile); let senderNum = trx.jid.split('@')[0]; let msg = '';
                    if(resData.status === 'Sukses') {
                        msg = `✅ *STATUS: SUKSES*\n\n📦 Produk: ${trx.nama}\n📱 Tujuan: ${trx.tujuan}\n🔑 SN: ${resData.sn || '-'}`;
                        if (db[senderNum] && db[senderNum].history && db[senderNum].history.length > 0) {
                            db[senderNum].history[0].status = 'Sukses'; db[senderNum].history[0].sn = resData.sn || '-'; saveJSON(dbFile, db);
                        }
                    } else {
                        if (db[senderNum]) { db[senderNum].saldo += trx.harga; if(db[senderNum].history && db[senderNum].history.length > 0) db[senderNum].history[0].status = 'Gagal'; saveJSON(dbFile, db); }
                        msg = `❌ *STATUS: GAGAL*\n\n📦 Produk: ${trx.nama}\nAlasan: ${resData.message}\n_💰 Saldo dikembalikan._`;
                    }
                    
                    // PERBAIKAN: Hapus dari antrean file TERLEBIH DAHULU agar tidak terjadi looping refund
                    delete trxs[ref]; saveJSON(trxFile, trxs);
                    
                    // Gunakan catch untuk mencegah error memberhentikan proses berikutnya
                    sock.sendMessage(trx.jid, { text: msg }).catch(e => {}); 
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

            let db = loadJSON(dbFile); let produkDB = loadJSON(produkFile);
            if (!db[sender]) { db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle', trx_count:0, history:[]}; saveJSON(dbFile, db); }
            if (!db[sender].step) db[sender].step = 'idle';

            let rawCommand = body.trim().toLowerCase().split(' ')[0];
            if (['batal', 'cancel'].includes(rawCommand) && db[sender].step !== 'idle') {
                db[sender].step = 'idle'; saveJSON(dbFile, db);
                return await sock.sendMessage(from, { text: `✅ Batal.\n\nKetik *bot* untuk menu.` });
            }

            if (['bot', 'menu', 'p'].includes(rawCommand)) {
                let menuText = `👋 *${config.botName || "Tendo Store"}*\n\nSilakan belanja lebih mudah di Aplikasi:\n🌐 http://${process.env.IP_ADDRESS || 'IP_VPS_ANDA'}:3000\n\n_(Atau balas 1 untuk Cek Saldo)_`;
                return await sock.sendMessage(from, { text: menuText });
            }
            if (['1', 'saldo'].includes(rawCommand)) return await sock.sendMessage(from, { text: `💰 Saldo Anda: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` });

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
# 4. INSTALASI DEPENDENSI
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

    echo -ne "${C_MAG}>> Meracik sistem utama & Web App (v40 PREMIUM FINAL)...${C_RST}"
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
        echo -e "  ${C_GREEN}[1]${C_RST} Backup 4 File Inti (Kirim ke Telegram)"
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
                zip backup.zip config.json database.json trx.json produk.json 2>/dev/null
                echo -e "${C_GREEN}✅ File backup.zip berhasil dikompresi!${C_RST}"
                node -e "
                    const fs = require('fs');
                    const { exec } = require('child_process');
                    let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                    if(config.teleToken && config.teleChatId) {
                        console.log('\x1b[36m⏳ Sedang mengirim ke Telegram...\x1b[0m');
                        let cmd = \`curl -s -F chat_id=\"\${config.teleChatId}\" -F document=@\"backup.zip\" -F caption=\"📦 Manual Backup 4 File Wajib\" https://api.telegram.org/bot\${config.teleToken}/sendDocument\`;
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
                    
                    let target = Object.keys(db).find(k => k === normPhone || db[k].email === input);
                    
                    if(!target) {
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
# 8. MANAJEMEN PRODUK (KATEGORI SESUAI GAMBAR)
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
                echo "1. Pulsa         6. E-Wallet"
                echo "2. Data          7. Tagihan"
                echo "3. Masa Aktif    8. E-Toll"
                echo "4. SMS Telp      9. Digital"
                echo "5. PLN"
                read -p "👉 Masukkan Nomor Kategori [1-9]: " cat_idx
                
                brand_idx="1"
                if [ "$cat_idx" == "1" ] || [ "$cat_idx" == "2" ] || [ "$cat_idx" == "3" ] || [ "$cat_idx" == "4" ]; then
                    echo -e "\n${C_CYAN}Pilih Provider:${C_RST}"
                    echo "1. Telkomsel | 2. XL | 3. Axis | 4. Indosat | 5. Tri | 6. Smartfren | 7. By.U"
                    read -p "👉 Masukkan Nomor Provider [1-7]: " brand_idx
                elif [ "$cat_idx" == "6" ]; then
                    echo -e "\n${C_CYAN}Pilih E-Wallet:${C_RST}"
                    echo "1. Gopay | 2. Dana | 3. Shopee Pay | 4. OVO | 5. LinkAja"
                    read -p "👉 Masukkan Nomor E-Wallet [1-5]: " brand_idx
                elif [ "$cat_idx" == "7" ]; then
                    echo -e "\n${C_CYAN}Pilih Tagihan:${C_RST}"
                    echo "1. PLN Pasca | 2. BPJS | 3. PDAM | 4. Indihome"
                    read -p "👉 Masukkan Nomor Tagihan [1-4]: " brand_idx
                elif [ "$cat_idx" == "8" ]; then
                    echo -e "\n${C_CYAN}Pilih E-Toll:${C_RST}"
                    echo "1. Mandiri E-Money | 2. Brizzi | 3. TapCash"
                    read -p "👉 Masukkan Nomor E-Toll [1-3]: " brand_idx
                elif [ "$cat_idx" == "9" ]; then
                    echo -e "\n${C_CYAN}Pilih Digital:${C_RST}"
                    echo "1. Mobile Legends | 2. Free Fire | 3. PUBG | 4. Vidio | 5. Netflix"
                    read -p "👉 Masukkan Nomor Digital [1-5]: " brand_idx
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
                    const catMap = {'1':'Pulsa', '2':'Data', '3':'Masa Aktif', '4':'SMS Telp', '5':'PLN', '6':'E-Wallet', '7':'Tagihan', '8':'E-Toll', '9':'Digital'};
                    const brandMap = {
                        'Pulsa': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Data': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Masa Aktif': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'SMS Telp': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'E-Wallet': {'1':'Gopay', '2':'Dana', '3':'Shopee Pay', '4':'OVO', '5':'LinkAja'},
                        'Tagihan': {'1':'PLN Pasca', '2':'BPJS', '3':'PDAM', '4':'Indihome'},
                        'E-Toll': {'1':'Mandiri E-Money', '2':'Brizzi', '3':'TapCash'},
                        'Digital': {'1':'Mobile Legends', '2':'Free Fire', '3':'PUBG', '4':'Vidio', '5':'Netflix'},
                        'PLN': {'1':'Token PLN'}
                    };
                    
                    let catName = catMap[process.env.TMP_CAT_IDX] || 'Lainnya';
                    let brandName = (brandMap[catName] && brandMap[catName][process.env.TMP_BRAND_IDX]) ? brandMap[catName][process.env.TMP_BRAND_IDX] : (catName === 'PLN' ? 'Token PLN' : 'Lainnya');
                    
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
                echo "1. Pulsa | 2. Data | 3. Masa Aktif | 4. SMS Telp | 5. PLN | 6. E-Wallet | 7. Tagihan | 8. E-Toll | 9. Digital"
                
                read -p "Ubah Kategori? (Ketik angka 1-9) [Enter jika tidak]: " new_cat_idx
                
                new_brand_idx=""
                if [ ! -z "$new_cat_idx" ]; then
                    if [ "$new_cat_idx" == "1" ] || [ "$new_cat_idx" == "2" ] || [ "$new_cat_idx" == "3" ] || [ "$new_cat_idx" == "4" ]; then
                        echo "1. Telkomsel | 2. XL | 3. Axis | 4. Indosat | 5. Tri | 6. Smartfren | 7. By.U"
                        read -p "Pilih Provider Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "6" ]; then
                        echo "1. Gopay | 2. Dana | 3. Shopee Pay | 4. OVO | 5. LinkAja"
                        read -p "Pilih E-Wallet Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "7" ]; then
                        echo "1. PLN Pasca | 2. BPJS | 3. PDAM | 4. Indihome"
                        read -p "Pilih Tagihan Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "8" ]; then
                        echo "1. Mandiri E-Money | 2. Brizzi | 3. TapCash"
                        read -p "Pilih E-Toll Baru: " new_brand_idx
                    elif [ "$new_cat_idx" == "9" ]; then
                        echo "1. Mobile Legends | 2. Free Fire | 3. PUBG | 4. Vidio | 5. Netflix"
                        read -p "Pilih Digital Baru: " new_brand_idx
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
                    const catMap = {'1':'Pulsa', '2':'Data', '3':'Masa Aktif', '4':'SMS Telp', '5':'PLN', '6':'E-Wallet', '7':'Tagihan', '8':'E-Toll', '9':'Digital'};
                    const brandMap = {
                        'Pulsa': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Data': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Masa Aktif': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'SMS Telp': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'E-Wallet': {'1':'Gopay', '2':'Dana', '3':'Shopee Pay', '4':'OVO', '5':'LinkAja'},
                        'Tagihan': {'1':'PLN Pasca', '2':'BPJS', '3':'PDAM', '4':'Indihome'},
                        'E-Toll': {'1':'Mandiri E-Money', '2':'Brizzi', '3':'TapCash'},
                        'Digital': {'1':'Mobile Legends', '2':'Free Fire', '3':'PUBG', '4':'Vidio', '5':'Netflix'},
                        'PLN': {'1':'Token PLN'}
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
                            item.brand = (brandMap[cName] && brandMap[cName][process.env.NEW_BRAND_IDX]) ? brandMap[cName][process.env.NEW_BRAND_IDX] : (cName === 'PLN' ? 'Token PLN' : 'Lainnya');
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
                        let cats = ['Pulsa', 'Data', 'Masa Aktif', 'SMS Telp', 'PLN', 'E-Wallet', 'Tagihan', 'E-Toll', 'Digital', 'Lainnya'];
                        let count = 0;
                        cats.forEach(c => {
                            let catKeys = keys.filter(k => (produk[k].kategori || 'Lainnya') === c);
                            if(catKeys.length > 0) {
                                console.log('\n\x1b[33m=== KATEGORI: ' + c.toUpperCase() + ' ===\x1b[0m');
                                let brands = [...new Set(catKeys.map(k => produk[k].brand || 'Lainnya'))];
                                brands.forEach(b => {
                                    console.log('\x1b[35m>> Provider: ' + b.toUpperCase() + '\x1b[0m');
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
    echo -e "  ${C_GREEN}[12]${C_RST} 📢 Kirim Pesan Broadcast Kesemua Member (WA)"
    echo -e "  ${C_GREEN}[13]${C_RST} 🌐 Kirim Pemberitahuan ke Website Aplikasi"
    echo -e "  ${C_GREEN}[14]${C_RST} 💬 Kirim Pesan Langsung (Japri) ke Pelanggan"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -e "  ${C_RED}[0]${C_RST}  Keluar dari Panel"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -ne "${C_YELLOW}Pilih menu [0-14]: ${C_RST}"
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
        14)
            echo -e "\n${C_MAG}--- KIRIM PESAN JAPRI KE PELANGGAN ---${C_RST}"
            read -p "Masukkan Nomor WA Pelanggan (08/62): " no_japri
            read -p "Masukkan Pesan yang ingin dikirim: " pesan_japri
            if [ ! -z "$no_japri" ] && [ ! -z "$pesan_japri" ]; then
                echo "$no_japri|$pesan_japri" >> japri.txt
                echo -e "\n${C_GREEN}✅ Pesan masuk ke antrean dan akan segera dikirim oleh Bot!${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        0) echo -e "${C_GREEN}Keluar dari panel. Sampai jumpa! 👋${C_RST}"; exit 0 ;;
        *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 2 ;;
    esac
done
