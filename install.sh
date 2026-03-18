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

# Buka Port 3000, 80 (HTTP), dan 443 (HTTPS)
sudo ufw allow 3000/tcp > /dev/null 2>&1 || true
sudo ufw allow 80/tcp > /dev/null 2>&1 || true
sudo ufw allow 443/tcp > /dev/null 2>&1 || true
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT > /dev/null 2>&1 || true
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT > /dev/null 2>&1 || true
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT > /dev/null 2>&1 || true

# ==========================================
# 1. BIKIN SHORTCUT 'BOT' DI VPS
# ==========================================
# Hapus sisa-sisa Auto-Start panel yang bikin VPS macet sebelumnya
sed -i '/# Auto-start bot panel/d' ~/.bashrc
sed -i '/if \[ -f \/usr\/bin\/bot \] && \[ -t 1 \]; then/d' ~/.bashrc
sed -i '/\/usr\/bin\/bot/d' ~/.bashrc

if [ ! -f "/usr/bin/bot" ]; then
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/bot > /dev/null
    sudo chmod +x /usr/bin/bot
fi

if [ ! -f "/usr/bin/menu" ]; then
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/menu > /dev/null
    sudo chmod +x /usr/bin/menu
fi

# ==========================================
# 2. FUNGSI MEMBUAT TAMPILAN WEB APLIKASI
# ==========================================
generate_web_app() {
    # Buat folder public dan folder banner secara otomatis
    mkdir -p public/baner1 public/baner2 public/baner3 public/baner4 public/baner5

    cat << 'EOF' > public/manifest.json
{
  "name": "Digital Tendo Store",
  "short_name": "Digital Tendo Store",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#f1f5f9",
  "theme_color": "#f1f5f9",
  "orientation": "portrait",
  "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/3144/3144456.png", "sizes": "512x512", "type": "image/png"}]
}
EOF

    cat << 'EOF' > public/sw.js
self.addEventListener('install', (e) => { self.skipWaiting(); });
self.addEventListener('activate', (e) => { self.clients.claim(); });
self.addEventListener('fetch', (e) => { });
EOF

    cat << 'EOF' > public/index.html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Digital Tendo Store</title>
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#f1f5f9">
    <style>
        /* TEMA UI PERSIS REFERENSI GAMBAR 3 DENGAN NAVIGASI GELAP */
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #e2e8f0; color: #1e293b; margin: 0; display: flex; justify-content: center; }
        #app { width: 100%; max-width: 480px; background: #f1f5f9; min-height: 100vh; position: relative; overflow-x: hidden; padding-bottom: 80px; box-sizing: border-box; box-shadow: 0 0 20px rgba(0,0,0,0.05);}
        
        /* TOP BAR (MENYATU DENGAN BACKGROUND ABU-ABU) */
        .top-bar { background: transparent; padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; border-bottom: none;}
        .menu-btn { cursor: pointer; background: none; border: none; padding: 0; display: flex; align-items: center; justify-content: center;}
        .menu-btn svg { width: 26px; height: 26px; stroke: #0b1727; fill: none; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round;}
        
        /* LOGO 'TD' (Sesuai Gambar 2) & TITLE: BIRU GELAP */
        .brand-title-wrapper { display: flex; align-items: center; justify-content: center; gap: 8px; flex: 1; margin: 0 10px; }
        .brand-title { font-size: 15px; font-weight: 900; color: #0b1727; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap;}
        .brand-logo-svg { width: 26px; height: 26px; }
        
        /* TRX BADGE */
        .trx-badge { font-size: 11px; background: #cbd5e1; color: #0b1727; padding: 5px 10px; border-radius: 12px; font-weight: 800; cursor: pointer; border: none; transition: transform 0.2s; white-space: nowrap;}
        .trx-badge:active { transform: scale(0.95); }

        /* BANNER SALDO KOTAK (Gelap + Garis Grid seperti Gambar 3) */
        .banner-container { background: transparent; padding: 5px 20px 20px;}
        .banner { 
            background-color: #0f172a; 
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 400 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M-50,100 C100,-50 200,250 450,50' fill='none' stroke='rgba(255,255,255,0.05)' stroke-width='1.5'/%3E%3Cpath d='M-50,150 C150,0 250,300 450,100' fill='none' stroke='rgba(255,255,255,0.04)' stroke-width='1.5'/%3E%3C/svg%3E");
            background-size: cover;
            border-radius: 20px; padding: 30px 20px 25px; 
            color: #ffffff; text-align: center; position: relative; overflow: hidden;
            box-shadow: 0 10px 25px rgba(15,23,42,0.1);
        }
        /* Garis Grid Kotak-Kotak Faint */
        .banner::before { 
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%; 
            background: linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px); 
            background-size: 35px 35px; pointer-events: none; 
        }
        
        .saldo-title { font-size: 12px; font-weight: 500; opacity: 0.8; margin-bottom: 5px; position: relative; z-index: 2;}
        .saldo-amount { font-size: 36px; font-weight: 900; letter-spacing: -0.5px; margin-bottom: 20px; position: relative; z-index: 2;}
        
        .action-buttons { display: flex; justify-content: center; gap: 15px; position: relative; z-index: 2; }
        .btn-topup-dash, .btn-help-dash { 
            background: transparent; color: #ffffff; border: 1.5px solid rgba(255,255,255,0.8); 
            padding: 10px 20px; border-radius: 25px; font-weight: 800; font-size: 11px; 
            cursor: pointer; display: flex; align-items: center; justify-content: center; flex: 1; max-width: 140px;
            transition: background 0.2s, color 0.2s; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .btn-topup-dash:active, .btn-help-dash:active { background: rgba(255,255,255,0.2); }

        /* SLIDER BANNER (Di Bawah Saldo, Di Atas Menu) */
        .banner-slider-container { margin: 10px 20px 25px; border-radius: 16px; overflow: hidden; position: relative; background: #fff; box-shadow: 0 4px 10px rgba(0,0,0,0.03);}
        .banner-slider { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; -webkit-overflow-scrolling: touch; scrollbar-width: none; }
        .banner-slider::-webkit-scrollbar { display: none; }
        .banner-slide { flex: 0 0 100%; scroll-snap-align: center; display: flex; justify-content: center; align-items: center; }
        .banner-slide img { width: 100%; height: auto; object-fit: cover; aspect-ratio: 21/9; display: block;}

        /* GRID MENU (Layanan Produk) */
        .grid-title { margin: 0 20px 15px; font-weight: 800; color: #1e293b; font-size: 15px;}
        .grid-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; padding: 0 20px;}
        .grid-box { 
            background: #f8fafc; border-radius: 16px; padding: 18px 5px; 
            text-align: center; cursor: pointer; display: flex; flex-direction: column; align-items: center; justify-content: flex-start;
            border: 1px solid #e2e8f0; box-shadow: 0 4px 6px rgba(0,0,0,0.02);
            transition: transform 0.2s, background 0.2s;
        }
        .grid-box:active { transform: scale(0.95); background: #e2e8f0; }
        
        .grid-icon-wrap { width: 44px; height: 44px; margin-bottom: 12px; display: flex; justify-content: center; align-items: center;}
        
        .grid-text { font-size: 10px; color: #0f172a; font-weight: 800; line-height: 1.3; text-transform: uppercase; letter-spacing: -0.2px;}

        /* BRAND LIST (VERTICAL) */
        .brand-list { display: flex; flex-direction: column; padding: 15px 20px; gap: 12px; }
        .brand-row { background: #ffffff; padding: 15px; border-radius: 14px; border: 1px solid #e2e8f0; display: flex; align-items: center; gap: 15px; box-shadow: 0 2px 6px rgba(0,0,0,0.02); cursor: pointer; transition: transform 0.2s, border-color 0.2s;}
        .brand-row:active { transform: scale(0.98); border-color: #0b1727;}
        .b-logo { width: 45px; height: 45px; background: #f1f5f9; color: #0b1727; border-radius: 50%; font-weight: 900; font-size: 15px; display: flex; justify-content: center; align-items: center; border: 1px solid #e2e8f0; flex-shrink: 0;}
        .b-name { font-size: 14px; font-weight: 800; color: #1e293b; flex: 1;}

        /* BOTTOM NAV (GELAP) */
        .bottom-nav { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: #0b1727; display: flex; justify-content: space-around; padding: 12px 0 8px; border-top: 1px solid #1e293b; box-shadow: 0 -2px 10px rgba(0,0,0,0.1); z-index: 90;}
        .nav-item { text-align: center; color: #64748b; font-size: 10px; flex: 1; cursor: pointer; display: flex; flex-direction: column; align-items: center; font-weight: 700; transition: color 0.3s;}
        .nav-icon { margin-bottom: 4px; display: flex; justify-content: center; align-items: center;}
        .nav-icon svg { width: 24px; height: 24px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}
        .nav-item.active { color: #ffffff;}

        /* PRODUCT LIST STYLE */
        .product-item { background: #ffffff; padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid #e2e8f0; display: flex; align-items: center; gap: 15px; box-shadow: 0 2px 6px rgba(0,0,0,0.02); cursor: pointer; transition: 0.2s;}
        .product-item:active { transform: scale(0.98); border-color: #0b1727;}
        .prod-logo { width: 45px; height: 45px; background: #f8fafc; border-radius: 50%; display: flex; justify-content: center; align-items: center; font-weight: 900; color: #0b1727; font-size: 14px; border: 1px solid #e2e8f0; flex-shrink: 0;}
        .prod-info { flex: 1; min-width: 0; }
        .prod-name { font-weight: 800; font-size: 13px; color: #0b1727; margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between; word-wrap: break-word;}
        .badge-open { background: #e0f2fe; color: #0284c7; font-size: 9px; padding: 2px 6px; border-radius: 4px; font-weight: 800; border: 1px solid #bae6fd; flex-shrink: 0; margin-left: 8px;}
        .prod-desc { font-size: 10px; color: #64748b; font-weight: 600; margin-bottom: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; text-overflow: ellipsis;}
        .prod-price { color: #0b1727; font-weight: 900; font-size: 15px;}

        /* SEARCH BAR */
        .search-box { padding: 15px 20px 5px; position: sticky; top: 58px; z-index: 50; background: #f1f5f9; }
        .search-box input { margin-bottom: 0; box-shadow: 0 2px 5px rgba(0,0,0,0.02); border-radius: 12px; padding: 12px 15px; border: 1px solid #cbd5e1; outline: none; width: 100%; box-sizing: border-box; font-weight: bold; color: #0b1727;}

        /* SIDEBAR */
        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); z-index: 999; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:0; left:-300px; width: 280px; height: 100%; background: #ffffff; z-index: 1000; transition: left 0.3s ease; overflow-y: auto; display: flex; flex-direction: column; box-shadow: 5px 0 15px rgba(0,0,0,0.1);}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 30px 20px; text-align: center; border-bottom: 1px solid #f1f5f9; background: #0b1727; color: #ffffff;}
        .sidebar-avatar { width: 70px; height: 70px; background: #ffffff; border-radius: 50%; margin: 0 auto 10px auto; display: flex; justify-content: center; align-items: center; color: #0b1727; font-size: 30px; font-weight: bold;}
        .sidebar-name { font-weight: bold; font-size: 16px; color: #ffffff;}
        .sidebar-phone { font-size: 12px; color: #cbd5e1;}
        .sidebar-menu { padding: 10px 0; flex: 1;}
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: #334155; text-decoration: none; font-size: 14px; border-bottom: 1px solid #f8fafc; font-weight: 600; gap: 15px;}
        .sidebar-item:active { background: #f1f5f9; }
        .sidebar-item svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }

        /* FORMS & COMPONENTS */
        .container { padding: 20px; }
        .card { background: #ffffff; padding: 25px 20px; border-radius: 16px; margin-bottom: 20px; border: 1px solid #e2e8f0; box-shadow: 0 4px 10px rgba(0,0,0,0.02);}
        input { width: 100%; padding: 15px; margin-bottom: 12px; border: 1px solid #cbd5e1; border-radius: 12px; box-sizing: border-box; font-size: 14px; outline: none; background: #f8fafc; color: #0b1727; font-weight: 600; transition: border-color 0.2s;}
        input:focus { border-color: #0b1727; background: #ffffff;}
        
        .checkbox-container { display: flex; align-items: center; justify-content: flex-start; gap: 8px; margin-bottom: 20px; font-size: 13px; font-weight: 600; color: #475569; cursor: pointer;}
        .checkbox-container input { width: 16px; height: 16px; margin: 0; padding: 0; cursor: pointer;}
        
        .btn { background: #0b1727; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; transition: opacity 0.2s;}
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-outline { background: #ffffff; color: #0b1727; border: 1.5px solid #0b1727; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        .btn-danger { background: #ef4444; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}

        /* PROFILE & MODAL */
        .prof-header { background: #0b1727; color: #ffffff; padding: 30px 20px; text-align: center; border-bottom-left-radius: 25px; border-bottom-right-radius: 25px;}
        .prof-avatar { width: 80px; height: 80px; background: #ffffff; color: #0b1727; border-radius: 50%; font-size: 40px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-weight: bold;}
        .prof-box { background: #ffffff; margin: -20px 20px 20px; border-radius: 16px; padding: 20px; position: relative; z-index: 10; border: 1px solid #e2e8f0; box-shadow: 0 4px 15px rgba(0,0,0,0.03);}
        .prof-row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px dashed #e2e8f0; font-size: 13px;}
        .prof-label { color: #64748b; font-weight: 600;}
        .prof-val { color: #0b1727; font-weight: 900; text-align: right;}
        .prof-action-btn { background: #f8fafc; color: #0b1727; border: 1px solid #e2e8f0; padding: 15px; width: 100%; border-radius: 12px; font-weight: bold; margin-bottom: 10px; cursor: pointer; font-size: 13px; display: flex; align-items: center; gap: 10px;}
        .prof-action-btn svg { fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}

        .hist-item { background: #ffffff; padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.02); cursor: pointer;}
        .hist-item:active { transform: scale(0.98); }
        .hist-top { display: flex; justify-content: space-between; font-size: 11px; color: #64748b; margin-bottom: 5px; font-weight: 700;}
        .hist-title { font-weight: 800; font-size: 14px; color: #0b1727; margin-bottom: 3px;}
        .hist-target { font-size: 12px; color: #475569; font-weight: 600;}
        .stat-badge { padding: 4px 10px; border-radius: 8px; font-weight: bold; font-size: 10px;}
        .stat-Sukses { background: #dcfce7; color: #166534; } 
        .stat-Pending { background: #ffedd5; color: #c2410c; } 
        .stat-Gagal { background: #fee2e2; color: #b91c1c; text-decoration: line-through; }

        .modal-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); display: flex; justify-content: center; align-items: center; z-index: 2000; padding: 20px;}
        .modal-box { background: #ffffff; width: 100%; max-width: 340px; border-radius: 20px; padding: 25px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto;}
        .modal-btns { display: flex; gap: 10px; margin-top: 15px;}
        
        .screen-header { padding: 15px 20px; font-weight: 800; font-size: 18px; display: flex; align-items: center; gap: 15px; background: #f1f5f9; border-bottom: 1px solid #cbd5e1; position: sticky; top:0; z-index: 10; color: #0b1727;}
        .hidden { display: none !important; }
        .back-icon { cursor: pointer; fill: none; stroke: #0b1727; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round;}
    </style>
</head>
<body>
    <div id="app">
        <div class="top-bar" id="home-topbar">
            <button class="menu-btn" onclick="toggleSidebar()">
                <svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
            <div class="brand-title-wrapper">
                <svg class="brand-logo-svg" viewBox="0 0 24 24" fill="none">
                    <path d="M3 6h10" stroke="#0b1727" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M8 6v12" stroke="#0b1727" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M12 6h3a6 6 0 0 1 0 12h-3" stroke="#0b1727" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <div class="brand-title">DIGITAL TENDO STORE</div>
            </div>
            <div class="trx-badge" id="top-trx-badge" onclick="showHistory()">0 Trx</div>
        </div>

        <div class="sidebar-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-avatar" id="sb-avatar">T</div>
                <div class="sidebar-name" id="sb-name">Digital Tendo Store</div>
                <div class="sidebar-phone" id="sb-phone">Belum Login</div>
            </div>
            <div class="sidebar-menu">
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showProfile()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> Profil Akun
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showHistory()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Transaksi Saya
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showNotif()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg> Pemberitahuan
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); contactAdmin()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Hubungi Admin
                </a>
            </div>
            <div style="padding: 20px;">
                <button class="btn-outline" style="color: #ef4444; border-color: #ef4444;" onclick="logout()">Keluar Akun</button>
            </div>
        </div>

        <div id="login-screen" class="container">
            <div style="text-align:center; margin: 40px 0;">
                <h1 style="color:#0b1727; margin:0; font-weight:900; font-size: 28px;">Digital Tendo Store</h1>
                <p style="color:#64748b; font-size:13px; margin-top:5px; font-weight: 600;">Solusi Pembayaran Digital</p>
            </div>
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Masuk Akun</h2>
                <input type="email" id="log-email" placeholder="Alamat Email">
                <input type="password" id="log-pass" placeholder="Password">
                <label class="checkbox-container">
                    <input type="checkbox" id="rem-login"> Tetap masuk
                </label>
                <button class="btn" id="btn-login" onclick="login()">Login Sekarang</button>
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
                <button class="btn" id="btn-register" onclick="requestOTP()">Kirim OTP WhatsApp</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('login-screen')">Kembali ke Login</button>
            </div>
        </div>

        <div id="otp-screen" class="container hidden">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0; font-size:18px;">Verifikasi WhatsApp</h2>
                <p style="font-size:13px; color:#64748b; margin-bottom: 20px; font-weight: 600;">Kode OTP 4 digit telah dikirim ke WA.</p>
                <input type="number" id="otp-code" placeholder="----" style="text-align:center; font-size:28px; letter-spacing: 12px; font-weight:bold; background:#f8fafc;">
                <button class="btn" id="btn-verify" onclick="verifyOTP()">Verifikasi & Daftar</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('register-screen')">Batal</button>
            </div>
        </div>

        <div id="dashboard-screen" class="hidden">
            <div class="banner-container">
                <div class="banner" id="home-banner">
                    <div class="saldo-title">Sisa Saldo Anda</div>
                    <div class="saldo-amount" id="user-saldo">Rp 0</div>
                    <div class="action-buttons">
                        <button class="btn-topup-dash" onclick="openTopupModal()">ISI SALDO</button>
                        <button class="btn-help-dash" onclick="contactAdmin()">BANTUAN</button>
                    </div>
                </div>
            </div>

            <div id="banner-slider-container" class="banner-slider-container hidden">
                <div id="banner-slider" class="banner-slider"></div>
            </div>

            <div class="grid-title">Layanan Produk</div>
            <div class="grid-container">
                
                <div class="grid-box" onclick="loadCategory('Pulsa')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="6" y="3" width="12" height="18" rx="2" ry="2" fill="#bfdbfe" stroke-width="2.5"></rect>
                            <path d="M12 17v.01" stroke="#1e293b" stroke-width="3"></path>
                        </svg>
                    </div>
                    <div class="grid-text">PULSA</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Data')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="9" fill="#bbf7d0" stroke-width="2.5"></circle>
                            <ellipse cx="12" cy="12" rx="4" ry="9" fill="none" stroke-width="2.5"></ellipse>
                            <line x1="3" y1="12" x2="21" y2="12" stroke-width="2.5"></line>
                        </svg>
                    </div>
                    <div class="grid-text">DATA</div>
                </div>

                <div class="grid-box" onclick="loadCategory('Game')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="2" y="6" width="20" height="12" rx="5" fill="#fecaca" stroke-width="2.5"></rect>
                            <circle cx="16" cy="10" r="1.5" fill="#1e293b" stroke="none"></circle>
                            <circle cx="18" cy="14" r="1.5" fill="#1e293b" stroke="none"></circle>
                            <path d="M6 12h4M8 10v4" stroke-width="2.5"></path>
                        </svg>
                    </div>
                    <div class="grid-text">GAME</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Voucher')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M4 7h16a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4V9a2 2 0 0 1 2-2z" fill="#fef08a" stroke-width="2.5"></path>
                            <circle cx="12" cy="12" r="2" fill="#1e293b" stroke="none"></circle>
                        </svg>
                    </div>
                    <div class="grid-text">VOUCHER</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('E-Money')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="5" width="18" height="14" rx="2" fill="#ddd6fe" stroke-width="2.5"></rect>
                            <path d="M16 10h5v4h-5z" fill="#fef08a" stroke-width="2.5"></path>
                            <circle cx="18" cy="12" r="1" fill="#1e293b" stroke="none"></circle>
                        </svg>
                    </div>
                    <div class="grid-text">E-WALLET</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('PLN')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#fef08a" stroke-width="2.5"></path>
                        </svg>
                    </div>
                    <div class="grid-text">PLN</div>
                </div>

                <div class="grid-box" onclick="loadCategory('Paket SMS & Telpon')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" fill="#fbcfe8" stroke-width="2.5"></path>
                        </svg>
                    </div>
                    <div class="grid-text">SMS TELP</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Masa Aktif')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2" fill="#fed7aa" stroke-width="2.5"></rect>
                            <line x1="16" y1="2" x2="16" y2="6" stroke-width="2.5"></line>
                            <line x1="8" y1="2" x2="8" y2="6" stroke-width="2.5"></line>
                            <line x1="3" y1="10" x2="21" y2="10" stroke-width="2.5"></line>
                            <circle cx="9" cy="15" r="1.5" fill="#1e293b" stroke="none"></circle>
                            <circle cx="15" cy="15" r="1.5" fill="#1e293b" stroke="none"></circle>
                        </svg>
                    </div>
                    <div class="grid-text">MASA AKTIF</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Aktivasi Perdana')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" stroke="#1e293b" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M5 4h10l4 4v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" fill="#ccfbf1" stroke-width="2.5"></path>
                            <rect x="9" y="12" width="6" height="6" rx="1" fill="#fef08a" stroke-width="2.5"></rect>
                            <line x1="9" y1="15" x2="15" y2="15" stroke-width="2.5"></line>
                        </svg>
                    </div>
                    <div class="grid-text">PERDANA</div>
                </div>

            </div>
            
            <div style="padding: 20px; margin: 30px 20px; background: #ffffff; border-radius: 16px; text-align: center; border: 1px dashed #cbd5e1;" id="install-banner" class="hidden">
                <strong style="color:#0b1727; font-size:14px;">Aplikasi Digital Tendo Store</strong><br>
                <span style="font-size:12px; color:#64748b; font-weight: 600;">Pasang di layar utama HP Anda untuk akses cepat!</span><br>
                <button class="btn" style="margin-top:15px; padding: 10px 30px; font-size:12px; width:auto; border-radius:20px;" id="install-btn">Install Sekarang</button>
            </div>
        </div>

        <div id="brand-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackFromBrandScreen()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span id="brand-cat-title" style="text-transform: uppercase;">Kategori</span>
            </div>
            <div class="brand-list" id="brand-list"></div>
        </div>

        <div id="produk-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackFromProducts()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span id="cat-title-text" style="text-transform: uppercase;">Katalog</span>
            </div>
            <div class="search-box">
                <input type="text" id="search-product" placeholder="🔍 Cari nama produk..." onkeyup="filterProducts()">
            </div>
            <div id="product-list" style="padding-top: 10px;"></div>
        </div>

        <div id="history-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="showDashboard()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
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
                <button class="prof-action-btn" onclick="openEditModal('email')"><svg viewBox="0 0 24 24" width="20" stroke="#64748b"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg> Ubah Email</button>
                <button class="prof-action-btn" onclick="openEditModal('phone')"><svg viewBox="0 0 24 24" width="20" stroke="#64748b"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Ubah Nomor WA</button>
                <button class="prof-action-btn" onclick="openEditModal('password')"><svg viewBox="0 0 24 24" width="20" stroke="#64748b"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Ubah Password</button>
                
                <button class="prof-action-btn" onclick="contactAdmin()" style="border-color: #bae6fd; color: #0284c7; background: #f0f9ff; margin-top: 15px;">
                    <svg viewBox="0 0 24 24" width="20" stroke="#0284c7"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Hubungi Admin
                </button>
            </div>
        </div>

        <div id="notif-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="showDashboard()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span>Pemberitahuan</span>
            </div>
            <div class="container">
                <div class="card" style="border-left: 4px solid #0b1727;">
                    <h3 style="margin-top:0; color: #0b1727; font-size:15px;">📢 Info Terbaru</h3>
                    <p id="notif-text" style="color: #555; line-height: 1.6; font-size:13px; white-space: pre-wrap; font-weight: 500;">Memuat...</p>
                </div>
            </div>
        </div>

        <div class="bottom-nav" id="main-bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showDashboard()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg></span>HOME
            </div>
            <div class="nav-item" id="nav-history" onclick="showHistory()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></span>RIWAYAT
            </div>
            <div class="nav-item" id="nav-notif" onclick="showNotif()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg></span>INFO
            </div>
            <div class="nav-item" id="nav-profile" onclick="showProfile()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg></span>PROFIL
            </div>
        </div>

        <div id="order-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Formulir Pesanan</h3>
                <div style="background:#f9f9f9; padding:15px; border-radius:12px; margin-bottom:15px; border: 1px solid #eee; text-align: left;">
                    <strong id="m-name" style="font-size:14px; color:#2c3e50; line-height:1.4; display:block; margin-bottom:5px;">Produk</strong>
                    <div id="m-desc" style="font-size:11px; color:#64748b; margin-bottom:10px; line-height: 1.4;">Deskripsi Produk</div>
                    <span style="color:#0b1727; font-weight:900; font-size: 20px;" id="m-price">Rp 0</span>
                </div>
                <input type="text" id="m-target" placeholder="Masukkan Nomor/ID Tujuan" style="text-align:center; font-size: 16px; font-weight: bold;">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeOrderModal()">Batal</button>
                    <button class="btn" id="m-submit" onclick="processOrder()">Beli Sekarang</button>
                </div>
            </div>
        </div>

        <div id="topup-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Isi Saldo Otomatis</h3>
                <p style="font-size:12px; color:#666; margin-bottom:20px;">Mendukung QRIS, E-Wallet, dan Virtual Account.</p>
                <input type="number" id="topup-nominal" placeholder="Nominal (Min. 10000)" style="text-align:center; font-size:18px; font-weight:bold;">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeTopupModal()">Batal</button>
                    <button class="btn" id="btn-topup-submit" onclick="sendTopup()">Lanjut Bayar</button>
                </div>
            </div>
        </div>
        
        <div id="history-detail-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Detail Transaksi</h3>
                <div style="background:#f8fafc; padding:15px; border-radius:12px; margin-bottom:15px; border: 1px solid #e2e8f0; text-align: left; font-size:13px; line-height: 1.6;">
                    <div style="display:flex; justify-content:space-between;"><span>Waktu</span><strong id="hd-time"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span>Status</span><strong id="hd-status"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span>Produk</span><strong id="hd-name"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span>Tujuan</span><strong id="hd-target"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span>SN/Ref</span><strong id="hd-sn" style="word-break:break-all;"></strong></div>
                </div>
                <button class="btn-danger" id="hd-complain-btn" onclick="complainAdmin()" style="margin-bottom: 15px;">Hubungi Admin</button>
                <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeHistoryModal()">Tutup</button>
            </div>
        </div>

        <div id="edit-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;" id="edit-title">Ubah Data</h3>
                <div id="edit-step-1">
                    <input type="text" id="edit-input" placeholder="Masukkan data baru">
                    <div class="modal-btns">
                        <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeEditModal()">Batal</button>
                        <button class="btn" id="btn-req-edit" onclick="reqEditOTP()">Kirim OTP</button>
                    </div>
                </div>
                <div id="edit-step-2" class="hidden">
                    <p style="font-size:12px; color:#666; font-weight: bold;">OTP telah dikirim ke WA Anda.</p>
                    <input type="number" id="edit-otp-input" placeholder="----" style="letter-spacing:12px; text-align:center; font-size:24px; background:#f4f7f6;">
                    <div class="modal-btns">
                        <button class="btn-outline" style="margin-top:0; border-color:#ddd; color:#888;" onclick="closeEditModal()">Batal</button>
                        <button class="btn" id="btn-verify-edit" onclick="verifyEditOTP()">Simpan</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://app.sandbox.midtrans.com/snap/snap.js" data-client-key="YOUR_CLIENT_KEY_HERE"></script>
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
        let currentUser = ""; let userData = {}; let allProducts = {}; let selectedSKU = ""; let tempRegPhone = ""; let currentEditMode = ""; let currentHistoryItem = null;
        let currentCategory = ""; let currentBrand = "";
        let bannerInterval;

        // === API CALL KLASIK (ANTI-ERROR) ===
        async function apiCall(url, bodyData) {
            let options = {};
            if(bodyData) {
                options.method = 'POST';
                options.headers = {'Content-Type': 'application/json'};
                options.body = JSON.stringify(bodyData);
            }
            let res = await fetch(url, options);
            return await res.json();
        }

        // FUNGSI LOAD BANNER (SLIDER OTOMATIS)
        async function loadBanners() {
            try {
                let data = await apiCall('/api/banners');
                let container = document.getElementById('banner-slider-container');
                let slider = document.getElementById('banner-slider');
                
                if (data && data.success && data.data.length > 0) {
                    let html = '';
                    data.data.forEach(img => {
                        html += `<div class="banner-slide"><img src="${img}" alt="Banner"></div>`;
                    });
                    slider.innerHTML = html;
                    container.classList.remove('hidden');
                    
                    // Auto Scroll Logic (Bergeser otomatis setiap 3 detik)
                    clearInterval(bannerInterval);
                    if(data.data.length > 1) {
                        bannerInterval = setInterval(() => {
                            if(slider.scrollLeft + slider.clientWidth >= slider.scrollWidth - 10) {
                                slider.scrollTo({ left: 0, behavior: 'smooth' });
                            } else {
                                slider.scrollBy({ left: slider.clientWidth, behavior: 'smooth' });
                            }
                        }, 3000);
                    }
                } else {
                    container.classList.add('hidden');
                    clearInterval(bannerInterval);
                }
            } catch(e) {}
        }

        // FITUR PENCARIAN PRODUK
        function filterProducts() {
            let input = document.getElementById('search-product').value.toLowerCase();
            let items = document.querySelectorAll('#product-list .product-item');
            items.forEach(item => {
                let name = item.querySelector('.prod-name').innerText.toLowerCase();
                if (name.includes(input)) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        }

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
            ['login-screen', 'register-screen', 'otp-screen', 'dashboard-screen', 'brand-screen', 'produk-screen', 'history-screen', 'profile-screen', 'notif-screen'].forEach(s => {
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
                    let data = await apiCall('/api/login', {email:savedEmail, password:savedPass});
                    if(data && data.success) {
                        currentUser = data.phone; userData = data.data;
                        fetchAllProducts(); showDashboard();
                    } else { showScreen('login-screen', null); }
                } catch(e) { showScreen('login-screen', null); }
            } else {
                showScreen('login-screen', null);
            }
        }

        function showDashboard() { 
            showScreen('dashboard-screen', 'nav-home'); 
            syncUserData(); 
            fetchAllProducts(); 
            loadBanners(); // Memanggil fungsi banner otomatis
        }
        function showHistory() { showScreen('history-screen', 'nav-history'); syncUserData(); }
        function showProfile() { showScreen('profile-screen', 'nav-profile'); syncUserData(); }
        
        async function showNotif() { 
            showScreen('notif-screen', 'nav-notif'); 
            try {
                let data = await apiCall('/api/notif');
                if(data && data.text) document.getElementById('notif-text').innerText = data.text;
                else document.getElementById('notif-text').innerText = "Tidak ada pemberitahuan sistem saat ini.";
            } catch(e){}
        }

        function openTopupModal() { document.getElementById('topup-nominal').value = ''; document.getElementById('topup-modal').classList.remove('hidden'); }
        function closeTopupModal() { document.getElementById('topup-modal').classList.add('hidden'); }
        
        async function sendTopup() {
            let nom = parseInt(document.getElementById('topup-nominal').value);
            if(!nom || nom < 10000) return alert("Minimal Topup Rp 10.000");
            let btn = document.getElementById('btn-topup-submit');
            btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/topup', {phone: currentUser, nominal: nom});
                if(data && data.success) { window.location.href = data.url; } 
                else { alert(data.message || "Gagal membuka pembayaran."); }
            } catch(e) { alert("Kesalahan server."); }
            
            btn.innerText = "Lanjut Bayar"; btn.disabled = false;
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
                let data = await apiCall('/api/user/' + currentUser);
                if(data && data.success) {
                    userData = data.data; let u = userData;
                    document.getElementById('user-saldo').innerText = 'Rp ' + u.saldo.toLocaleString('id-ID');
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
                        historyList.forEach((h, idx) => {
                            let statClass = 'stat-Pending';
                            if(h.status === 'Sukses') statClass = 'stat-Sukses';
                            if(h.status === 'Gagal') statClass = 'stat-Gagal';
                            let safeH = JSON.stringify(h).replace(/"/g, '&quot;');
                            histHTML += `
                                <div class="hist-item" onclick="openHistoryDetail(${safeH})">
                                    <div class="hist-top"><span>${h.tanggal}</span> <span class="stat-badge ${statClass}">${h.status}</span></div>
                                    <div class="hist-title">${h.nama}</div>
                                    <div class="hist-target">Tujuan: ${h.tujuan}</div>
                                </div>
                            `;
                        });
                    }
                    document.getElementById('history-list').innerHTML = histHTML;
                }
            } catch(e) {}
        }

        function openHistoryDetail(h) {
            currentHistoryItem = h;
            document.getElementById('hd-time').innerText = h.tanggal;
            document.getElementById('hd-status').innerText = h.status;
            document.getElementById('hd-name').innerText = h.nama;
            document.getElementById('hd-target').innerText = h.tujuan;
            document.getElementById('hd-sn').innerText = h.sn || '-';
            
            document.getElementById('history-detail-modal').classList.remove('hidden');
        }
        function closeHistoryModal() { document.getElementById('history-detail-modal').classList.add('hidden'); }
        
        function contactAdmin() {
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya butuh bantuan terkait akun / layanan.`;
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }
        
        function complainAdmin() {
            let h = currentHistoryItem;
            if(!h) { contactAdmin(); return; }
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya ingin komplain/tanya transaksi ini:%0A%0A📦 Produk: *${h.nama}*%0A📱 Tujuan: *${h.tujuan}*%0A🕒 Waktu: *${h.tanggal}*%0A⚙️ Status: *${h.status}*%0A🔑 SN/Ref: *${h.sn || '-'}*%0A%0AMohon bantuannya dicek. Terima kasih.`;
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }

        async function login() {
            let email = document.getElementById('log-email').value.trim();
            let pass = document.getElementById('log-pass').value.trim();
            let rem = document.getElementById('rem-login').checked;
            if(!email || !pass) return alert('Isi Email & Password!');
            
            let btn = document.getElementById('btn-login');
            let ori = btn.innerText;
            btn.innerText = "Memeriksa..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/login', {email, password:pass});
                if(data && data.success) {
                    if(rem) { localStorage.setItem('tendo_email', email); localStorage.setItem('tendo_pass', pass); }
                    currentUser = data.phone; userData = data.data;
                    fetchAllProducts(); showDashboard();
                } else {
                    alert(data && data.message ? data.message : "Gagal terhubung.");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function requestOTP() {
            let user = document.getElementById('reg-user').value.trim();
            let email = document.getElementById('reg-email').value.trim();
            let phone = document.getElementById('reg-phone').value.trim();
            let pass = document.getElementById('reg-pass').value.trim();
            if(!user || !email || !phone || !pass) return alert('Semua kolom wajib diisi!');
            
            let btn = document.getElementById('btn-register');
            let ori = btn.innerText;
            btn.innerText = "Mengirim..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/register', {username:user, email, phone, password:pass});
                if(data && data.success) { 
                    tempRegPhone = phone; showScreen('otp-screen', null); 
                } else {
                    alert(data && data.message ? data.message : "Pendaftaran Gagal.");
                }
            } catch(e) { alert('Kesalahan jaringan. Pastikan internet lancar.'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyOTP() {
            let otp = document.getElementById('otp-code').value.trim();
            if(!otp) return alert('Masukkan OTP!');
            
            let btn = document.getElementById('btn-verify');
            let ori = btn.innerText;
            btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/verify-otp', {phone: tempRegPhone, otp});
                if(data && data.success) {
                    alert('Pendaftaran Berhasil! Silakan Login.');
                    document.getElementById('log-email').value = document.getElementById('reg-email').value;
                    document.getElementById('log-pass').value = document.getElementById('reg-pass').value;
                    showScreen('login-screen', null);
                } else {
                    alert(data && data.message ? data.message : "Sistem sibuk, coba sesaat lagi.");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
            btn.innerText = ori; btn.disabled = false;
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
            
            let btn = document.getElementById('btn-req-edit');
            let ori = btn.innerText;
            btn.innerText = "Mengirim..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/req-edit-otp', {phone: currentUser, type: currentEditMode, newValue: val});
                if(data && data.success) {
                    document.getElementById('edit-step-1').classList.add('hidden');
                    document.getElementById('edit-step-2').classList.remove('hidden');
                } else {
                    alert(data && data.message ? data.message : "Error server");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyEditOTP() {
            let otp = document.getElementById('edit-otp-input').value.trim();
            if(!otp) return alert("Masukkan OTP!");
            
            let btn = document.getElementById('btn-verify-edit');
            let ori = btn.innerText;
            btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/verify-edit-otp', {phone: currentUser, otp: otp});
                if(data && data.success) {
                    alert("Berhasil diubah!");
                    closeEditModal();
                    if(currentEditMode === 'phone' || currentEditMode === 'password') { logout(); } 
                    else { syncUserData(); }
                } else {
                    alert(data && data.message ? data.message : "Error server");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function fetchAllProducts() {
            try {
                let data = await apiCall('/api/produk');
                if(data) allProducts = data;
            } catch(e){}
        }

        async function loadCategory(cat) {
            currentCategory = cat; 
            currentBrand = "";
            await fetchAllProducts(); 
            document.getElementById('brand-cat-title').innerText = cat;
            
            let brands = [];

            // MEMBUAT BRAND MUNCUL PERMANEN
            if(cat === 'Game') brands = ['Free Fire', 'Mobile Legends', 'PUBG'];
            if(cat === 'E-Money') brands = ['Dana', 'Go Pay', 'LinkAja', 'OVO', 'ShopeePay'];
            if(cat === 'Pulsa' || cat === 'Data' || cat === 'Masa Aktif' || cat === 'Paket SMS & Telpon') {
                brands = ['Axis', 'By.U', 'Indosat', 'Smartfren', 'Telkomsel', 'Tri', 'XL'];
            }

            for(let key in allProducts) {
                if(allProducts[key].kategori !== cat) continue;
                let b = allProducts[key].brand || 'Lainnya';
                
                // Jangan tampilkan 'Lainnya' di kategori Data, Game, dan Pulsa
                if ((cat === 'Game' || cat === 'Data' || cat === 'Pulsa') && b === 'Lainnya') continue;

                if(!brands.includes(b)) brands.push(b);
            }

            if(brands.length > 0) {
                brands.sort();
                let gridHTML = '';
                brands.forEach(b => {
                    let initial = b.substring(0,2).toUpperCase();
                    // Jika kategori DATA, maka klik Brand akan memuat Sub-Kategori.
                    let clickAction = (cat === 'Data') ? `loadSubCategory('${cat}', '${b}')` : `loadProducts('${cat}', '${b}')`;
                    
                    gridHTML += `
                    <div class="brand-row" onclick="${clickAction}">
                        <div class="b-logo">${initial}</div>
                        <div class="b-name">${b}</div>
                        <div style="margin-left:auto">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                        </div>
                    </div>`;
                });
                document.getElementById('brand-list').innerHTML = gridHTML;
                showScreen('brand-screen', 'nav-home');
            } else {
                alert('Belum ada produk di kategori ini.');
            }
        }

        function loadSubCategory(cat, brand) {
            currentCategory = cat;
            currentBrand = brand;
            document.getElementById('brand-cat-title').innerText = brand + " (Paket)";
            
            let subs = [];
            for(let key in allProducts) {
                let p = allProducts[key];
                if(p.kategori === cat && (p.brand || 'Lainnya') === brand) {
                    let s = p.sub_kategori || 'Umum';
                    if(!subs.includes(s)) subs.push(s);
                }
            }
            
            if(subs.length > 0) {
                let sortedSubs = subs.filter(s => s !== 'Umum' && s !== 'Akrab').sort();
                
                // Khusus XL
                if(subs.includes('Akrab') || (brand === 'XL' && subs.includes('Umum'))) {
                    sortedSubs.unshift('Akrab');
                } else if(subs.includes('Umum')) {
                    sortedSubs.unshift('Umum');
                }
                
                let gridHTML = '';
                sortedSubs.forEach(s => {
                    let initial = s.substring(0,2).toUpperCase();
                    gridHTML += `
                    <div class="brand-row" onclick="loadProducts('${cat}', '${brand}', '${s}')">
                        <div class="b-logo">${initial}</div>
                        <div class="b-name">${s}</div>
                        <div style="margin-left:auto">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                        </div>
                    </div>`;
                });
                document.getElementById('brand-list').innerHTML = gridHTML;
                showScreen('brand-screen', 'nav-home');
            } else {
                alert('Belum ada paket untuk provider ini.');
            }
        }

        function loadProducts(cat, brand, subCat = null) {
            currentCategory = cat;
            currentBrand = brand;
            document.getElementById('cat-title-text').innerText = subCat ? subCat : brand;
            document.getElementById('search-product').value = ''; // Reset pencarian saat buka
            
            let listHTML = '';
            for(let key in allProducts) {
                let p = allProducts[key];
                if (p.kategori !== cat || (p.brand || 'Lainnya') !== brand) continue;
                
                if (subCat) {
                    let pSub = p.sub_kategori || 'Umum';
                    if (brand === 'XL' && pSub === 'Umum') pSub = 'Akrab';
                    if (pSub !== subCat) continue;
                }
                
                let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                let safeDesc = p.deskripsi ? p.deskripsi.replace(/'/g, "\\'").replace(/"/g, '&quot;') : 'Proses Otomatis 24 Jam';
                let initial = brand.substring(0,2).toUpperCase();
                
                listHTML += `
                <div class="product-item" onclick="openOrderModal('${key}', '${safeName}', ${p.harga}, '${safeDesc}')">
                    <div class="prod-logo">${initial}</div>
                    <div class="prod-info">
                        <div class="prod-name">${p.nama} <span class="badge-open">OPEN</span></div>
                        <div class="prod-desc">${p.deskripsi ? p.deskripsi.substring(0,40)+'...' : 'Proses Cepat'}</div>
                        <div class="prod-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                    </div>
                </div>`;
            }
            document.getElementById('product-list').innerHTML = listHTML || '<div style="text-align:center; padding:30px; font-weight:bold; color:#94a3b8;">KOSONG</div>';
            showScreen('produk-screen', 'nav-home');
        }

        function goBackFromBrandScreen() {
            let title = document.getElementById('brand-cat-title').innerText;
            if(currentCategory === 'Data' && title.includes('(Paket)')) {
                loadCategory(currentCategory); // Kembali ke list Brand
            } else {
                showDashboard(); // Kembali ke Dashboard utama
            }
        }

        function goBackFromProducts() {
            if(currentCategory === 'Data') {
                loadSubCategory(currentCategory, currentBrand); // Kembali ke Sub-kategori Data
            } else {
                loadCategory(currentCategory); // Kembali ke list Brand biasa
            }
        }

        function openOrderModal(sku, nama, harga, desc) {
            selectedSKU = sku;
            document.getElementById('m-name').innerText = nama;
            document.getElementById('m-price').innerText = 'Rp ' + harga.toLocaleString('id-ID');
            document.getElementById('m-desc').innerText = desc || 'Proses Otomatis';
            document.getElementById('m-target').value = '';
            document.getElementById('order-modal').classList.remove('hidden');
        }
        function closeOrderModal() { document.getElementById('order-modal').classList.add('hidden'); }

        async function processOrder() {
            if(!currentUser) {
                alert('Sesi Anda habis. Silakan login ulang.');
                logout(); return;
            }
            let target = document.getElementById('m-target').value.trim();
            if(!target || target.length < 4) return alert("Nomor tujuan tidak valid!");
            
            let btn = document.getElementById('m-submit');
            let ori = btn.innerText; 
            btn.innerText = 'Proses...'; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/order', {phone: currentUser, sku: selectedSKU, tujuan: target});
                if(data && data.success) {
                    alert('Pesanan Sukses Diproses!\nCek tab Riwayat Anda.');
                    closeOrderModal();
                    syncUserData();
                    showHistory();
                } else {
                    alert(data && data.message ? 'Gagal: ' + data.message : "Kesalahan server saat memproses order.");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
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
const fs = require('fs');
const pino = require('pino');
const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const axios = require('axios'); 
const crypto = require('crypto'); 
const midtransClient = require('midtrans-client');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); 

const configFile = './config.json';
const dbFile = './database.json';
const produkFile = './produk.json';
const trxFile = './trx.json';
const notifFile = './web_notif.txt';
const japriFile = './japri.txt';

const loadJSON = (file) => {
    try {
        return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
    } catch(e) {
        console.error(`Error loading ${file}:`, e);
        return {};
    }
};
const saveJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

let configAwal = loadJSON(configFile);
configAwal.botName = configAwal.botName || "Digital Tendo Store";
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

// BANNERS API
app.get('/api/banners', (req, res) => {
    let banners = [];
    try {
        for (let i = 1; i <= 5; i++) {
            let folderPath = `./public/baner${i}`;
            if (fs.existsSync(folderPath)) {
                let files = fs.readdirSync(folderPath);
                // Cek gambar saja
                let imgFiles = files.filter(f => f.match(/\.(jpg|jpeg|png|gif|webp)$/i));
                if (imgFiles.length > 0) {
                    banners.push(`/baner${i}/${imgFiles[0]}`);
                }
            }
        }
    } catch(e) { console.error(e); }
    res.json({ success: true, data: banners });
});

// MIDTRANS WEBHOOK
app.post('/api/webhook/midtrans', (req, res) => {
    try {
        let config = loadJSON(configFile);
        let { order_id, status_code, gross_amount, signature_key, transaction_status } = req.body;
        let serverKey = config.midtransServerKey || '';
        
        let hash = crypto.createHash('sha512').update(order_id + status_code + gross_amount + serverKey).digest('hex');
        if(hash !== signature_key) return res.status(403).send("Invalid Signature");
        
        if(transaction_status === 'capture' || transaction_status === 'settlement') {
            let phone = order_id.split('-')[1]; 
            let db = loadJSON(dbFile);
            if(db[phone]) {
                let amount = parseInt(gross_amount);
                db[phone].saldo += amount;
                saveJSON(dbFile, db);
                if(globalSock) {
                    globalSock.sendMessage(db[phone].jid, {text: `✅ *TOPUP OTOMATIS BERHASIL*\n\nNominal: Rp ${amount.toLocaleString('id-ID')}\nSaldo Sekarang: Rp ${db[phone].saldo.toLocaleString('id-ID')}`}).catch(()=>{});
                }
            }
        }
        res.status(200).send("OK");
    } catch(e) { res.status(500).send("Error"); }
});

// API ROUTER
app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });
app.get('/api/notif', (req, res) => { let txt = fs.existsSync(notifFile) ? fs.readFileSync(notifFile, 'utf8') : ''; res.json({text: txt}); });

app.get('/api/user/:phone', (req, res) => {
    try {
        let db = loadJSON(dbFile); let p = req.params.phone;
        if(db[p]) res.json({success: true, data: db[p]});
        else res.json({success: false});
    } catch(e) { res.json({success: false}); }
});

app.post('/api/login', (req, res) => {
    try {
        let { email, password } = req.body; let db = loadJSON(dbFile);
        let userPhone = Object.keys(db).find(k => db[k] && db[k].email === email && db[k].password === password);
        if (userPhone) res.json({success: true, data: db[userPhone], phone: userPhone});
        else res.json({success: false, message: 'Email atau Password salah!'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/register', (req, res) => {
    try {
        let { username, email, password } = req.body;
        let phone = normalizePhone(req.body.phone); 
        if(!phone || phone.length < 9) return res.json({success: false, message: 'Nomor WA tidak valid!'});
        
        let db = loadJSON(dbFile);
        let isEmailExist = Object.keys(db).some(k => db[k] && db[k].email === email);
        if (isEmailExist) return res.json({success: false, message: 'Email terdaftar!'});

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone] = { username, email, password, otp };

        res.json({success: true});

        setTimeout(() => {
            try {
                if (globalSock) {
                    let msg = `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nHai ${username},\nKode OTP Pendaftaran: *${otp}*\n\n_⚠️ Jangan bagikan kode ini!_`;
                    globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>{});
                }
            } catch(err) { console.error(err); }
        }, 100);

    } catch(e) { 
        if (!res.headersSent) res.json({success: false, message: 'Gagal memproses pendaftaran.'}); 
    }
});

app.post('/api/verify-otp', (req, res) => {
    try {
        let otp = req.body.otp; let phone = normalizePhone(req.body.phone);
        if(tempOtpDB[phone] && tempOtpDB[phone].otp === otp) {
            let db = loadJSON(dbFile); let idPelanggan = 'TD-' + Math.floor(100000 + Math.random() * 900000); 
            if(db[phone]) {
                db[phone].username = tempOtpDB[phone].username; db[phone].email = tempOtpDB[phone].email; db[phone].password = tempOtpDB[phone].password;
                if(!db[phone].id_pelanggan) db[phone].id_pelanggan = idPelanggan;
            } else {
                db[phone] = { id_pelanggan: idPelanggan, username: tempOtpDB[phone].username, email: tempOtpDB[phone].email, password: tempOtpDB[phone].password, saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: phone + '@s.whatsapp.net', step: 'idle', trx_count: 0, history: [] };
            }
            saveJSON(dbFile, db); delete tempOtpDB[phone]; res.json({success: true});
        } else res.json({success: false, message: 'Kode OTP Salah!'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/req-edit-otp', (req, res) => {
    try {
        let { phone, type, newValue } = req.body; let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: 'User tidak ditemukan.'});
        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone + '_edit'] = { type, newValue, otp };
        
        res.json({success: true});

        setTimeout(() => {
            try {
                if (globalSock) {
                    globalSock.sendMessage(phone + '@s.whatsapp.net', { text: `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nKode OTP untuk mengubah data Anda adalah: *${otp}*\n\n_⚠️ Jangan berikan ke siapapun!_` }).catch(e=>{});
                }
            } catch(e) {}
        }, 100);

    } catch(e) { 
        if (!res.headersSent) res.json({success: false, message: 'Gagal memproses OTP.'}); 
    }
});

app.post('/api/verify-edit-otp', (req, res) => {
    try {
        let { phone, otp } = req.body; let db = loadJSON(dbFile); let session = tempOtpDB[phone + '_edit'];
        if(session && session.otp === otp) {
            if(session.type === 'email') db[phone].email = session.newValue;
            if(session.type === 'password') db[phone].password = session.newValue;
            if(session.type === 'phone') {
                let newPhone = normalizePhone(session.newValue);
                if(db[newPhone]) return res.json({success: false, message: 'Nomor sudah dipakai akun lain.'});
                db[newPhone] = db[phone]; db[newPhone].jid = newPhone + '@s.whatsapp.net'; delete db[phone];
            }
            saveJSON(dbFile, db); delete tempOtpDB[phone + '_edit']; res.json({success: true});
        } else res.json({success: false, message: 'OTP Salah!'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/topup', async (req, res) => {
    try {
        let config = loadJSON(configFile);
        if(!config.midtransServerKey) return res.json({success: false, message: "Fitur Topup belum diatur oleh Admin."});
        
        let { phone, nominal } = req.body;
        let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: "User tidak ditemukan."});
        
        let snap = new midtransClient.Snap({
            isProduction : config.midtransProd || false,
            serverKey : config.midtransServerKey,
            clientKey : config.midtransClientKey
        });

        let parameter = {
            "transaction_details": {
                "order_id": "TOPUP-" + phone + "-" + Date.now(),
                "gross_amount": nominal
            },
            "customer_details": {
                "first_name": db[phone].username,
                "email": db[phone].email || "user@email.com",
                "phone": phone
            }
        };

        let transaction = await snap.createTransaction(parameter);
        res.json({success: true, url: transaction.redirect_url});
    } catch(e) {
        res.json({success: false, message: "Gagal membuat pembayaran."});
    }
});

app.post('/api/order', async (req, res) => {
    try {
        let { phone, sku, tujuan } = req.body;
        let pNorm = normalizePhone(phone);
        let db = loadJSON(dbFile); let produkDB = loadJSON(produkFile); let config = loadJSON(configFile);
        
        let targetKey = db[pNorm] ? pNorm : (db[phone] ? phone : null);
        if (!targetKey) return res.json({success: false, message: 'Sesi Anda tidak valid. Silakan Logout dan Login kembali.'});
        
        let p = produkDB[sku];
        if (!p) return res.json({success: false, message: 'Produk tidak ditemukan.'});
        if (db[targetKey].saldo < p.harga) return res.json({success: false, message: 'Saldo tidak cukup.'});

        let username = (config.digiflazzUsername || '').trim();
        let apiKey = (config.digiflazzApiKey || '').trim();
        let refId = 'WEB-' + Date.now();
        let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');
        let maxPrice = parseInt(p.harga);

        const response = await axios.post('https://api.digiflazz.com/v1/transaction', { 
            username: username, buyer_sku_code: sku, customer_no: tujuan, ref_id: refId, sign: sign, max_price: maxPrice
        });
        
        const statusOrder = response.data.data.status; 
        if (statusOrder === 'Gagal') return res.json({success: false, message: response.data.data.message});
        
        db[targetKey].saldo -= p.harga; db[targetKey].trx_count = (db[targetKey].trx_count || 0) + 1;
        db[targetKey].history = db[targetKey].history || [];
        db[targetKey].history.unshift({ tanggal: new Date().toLocaleString('id-ID'), nama: p.nama, tujuan: tujuan, status: statusOrder, sn: response.data.data.sn || '-' });
        if(db[targetKey].history.length > 20) db[targetKey].history.pop();
        saveJSON(dbFile, db);
        
        let trxs = loadJSON(trxFile);
        let targetJid = db[targetKey].jid || targetKey + '@s.whatsapp.net';
        trxs[refId] = { jid: targetJid, sku: sku, tujuan: tujuan, harga: p.harga, nama: p.nama, tanggal: Date.now() };
        saveJSON(trxFile, trxs);

        res.json({success: true, saldo: db[targetKey].saldo});

        setTimeout(() => {
            try {
                if (globalSock) {
                    let msgWa = `🌐 *NOTA PEMBELIAN APLIKASI*\n\n📦 Produk: ${p.nama}\n📱 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status: *${statusOrder}*\n💰 Sisa Saldo: Rp ${db[targetKey].saldo.toLocaleString('id-ID')}`;
                    globalSock.sendMessage(targetJid, { text: msgWa }).catch(e=>{});
                }
            } catch(e){}
        }, 100);

    } catch (error) { 
        if (!res.headersSent) return res.json({success: false, message: 'Gagal diproses Digiflazz (Nomor Tujuan Salah/Harga Berubah)'}); 
    }
});

function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    exec(`rm -f backup.zip && zip backup.zip config.json database.json trx.json produk.json 2>/dev/null`, (err) => {
        if (!err) exec(`curl -s -F chat_id="${cfg.teleChatId}" -F document=@"backup.zip" -F caption="📦 Backup Digital Tendo Store" https://api.telegram.org/bot${cfg.teleToken}/sendDocument`);
    });
}
if (configAwal.autoBackup) setInterval(doBackupAndSend, (configAwal.backupInterval || 720) * 60 * 1000); 

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
            let lines = fs.readFileSync(japriFile, 'utf8').split('\n'); fs.unlinkSync(japriFile);
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
                    delete trxs[ref]; saveJSON(trxFile, trxs);
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

            let db = loadJSON(dbFile); 
            if (!db[sender]) { db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle', trx_count:0, history:[]}; saveJSON(dbFile, db); }
            let rawCommand = body.trim().toLowerCase().split(' ')[0];
            if (['bot', 'menu', 'p'].includes(rawCommand)) {
                let menuText = `👋 *${config.botName || "Digital Tendo Store"}*\n\nSilakan belanja lebih mudah di Aplikasi:\n🌐 http://${process.env.IP_ADDRESS || 'IP_VPS_ANDA'}:3000\n\n_(Atau balas 1 untuk Cek Saldo)_`;
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
    
    echo -ne "${C_MAG}>> Menginstall PM2...${C_RST}"
    (sudo npm install -g pm2 > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"

    echo -ne "${C_MAG}>> Meracik sistem utama & Web App...${C_RST}"
    generate_bot_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Mengunduh modul (Baileys, Midtrans, XLSX, dll)...${C_RST}"
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser midtrans-client xlsx > /dev/null 2>&1 &
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
# 8. MANAJEMEN PRODUK & HARGA (DENGAN IMPORT)
# ==========================================
menu_produk() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             🛒 MANAJEMEN PRODUK BOT 🛒             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Produk Baru Manual"
        echo -e "  ${C_GREEN}[2]${C_RST} Edit Produk"
        echo -e "  ${C_GREEN}[3]${C_RST} Hapus Produk"
        echo -e "  ${C_GREEN}[4]${C_RST} Lihat Daftar Produk"
        echo -e "  ${C_GREEN}[5]${C_RST} 🚀 Import Massal via File Digiflazz (.xlsx / .csv)"
        echo -e "  ${C_GREEN}[6]${C_RST} ⚙️ Atur Margin Keuntungan Import (Auto-Pricing)"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-6]: ${C_RST}"
        read prodchoice

        case $prodchoice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH PRODUK BARU MANUAL ---${C_RST}"
                echo -e "${C_CYAN}Pilih Kategori Utama:${C_RST}"
                echo "1. Pulsa         6. PLN"
                echo "2. Data          7. Paket SMS & Telpon"
                echo "3. Game          8. Masa Aktif"
                echo "4. Voucher       9. Aktivasi Perdana"
                echo "5. E-Money"
                read -p "👉 Masukkan Nomor Kategori [1-9]: " cat_idx
                
                brand_idx="1"
                if [ "$cat_idx" == "1" ] || [ "$cat_idx" == "2" ] || [ "$cat_idx" == "7" ] || [ "$cat_idx" == "8" ]; then
                    echo -e "\n${C_CYAN}Pilih Provider:${C_RST}"
                    echo "1. Telkomsel | 2. XL | 3. Axis | 4. Indosat | 5. Tri | 6. Smartfren | 7. By.U"
                    read -p "👉 Masukkan Nomor Provider [1-7]: " brand_idx
                elif [ "$cat_idx" == "5" ]; then
                    echo -e "\n${C_CYAN}Pilih E-Wallet:${C_RST}"
                    echo "1. Gopay | 2. Dana | 3. Shopee Pay | 4. OVO | 5. LinkAja"
                    read -p "👉 Masukkan Nomor E-Wallet [1-5]: " brand_idx
                elif [ "$cat_idx" == "3" ]; then
                    echo -e "\n${C_CYAN}Pilih Game:${C_RST}"
                    echo "1. Mobile Legends | 2. Free Fire | 3. PUBG"
                    read -p "👉 Masukkan Nomor Game [1-3]: " brand_idx
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
                    const catMap = {'1':'Pulsa', '2':'Data', '3':'Game', '4':'Voucher', '5':'E-Money', '6':'PLN', '7':'Paket SMS & Telpon', '8':'Masa Aktif', '9':'Aktivasi Perdana'};
                    const brandMap = {
                        'Pulsa': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Data': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Paket SMS & Telpon': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Masa Aktif': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'E-Money': {'1':'Go Pay', '2':'Dana', '3':'Shopee Pay', '4':'OVO', '5':'LinkAja'},
                        'Game': {'1':'Mobile Legends', '2':'Free Fire', '3':'PUBG'}
                    };
                    
                    let catName = catMap[process.env.TMP_CAT_IDX] || 'Lainnya';
                    let brandName = (brandMap[catName] && brandMap[catName][process.env.TMP_BRAND_IDX]) ? brandMap[catName][process.env.TMP_BRAND_IDX] : 'Lainnya';
                    
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
                echo -e "${C_CYAN}Kategori saat ini: $OLD_KAT
