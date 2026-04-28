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
# Membersihkan script startup lama jika ada
sed -i '/# Auto-start bot panel/d' ~/.bashrc
sed -i '/if \[ -t 1 \] && \[ -x \/usr\/bin\/menu \]; then/d' ~/.bashrc
sed -i '/\/usr\/bin\/bot/d' ~/.bashrc
sed -i '/\/usr\/bin\/menu/d' ~/.bashrc

if [ ! -f "/usr/bin/bot" ]; then
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/bot > /dev/null
    sudo chmod +x /usr/bin/bot
fi

if [ ! -f "/usr/bin/menu" ]; then
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/menu > /dev/null
    sudo chmod +x /usr/bin/menu
fi

# Fitur Auto-Start Panel saat buka VPS
if ! grep -q "/usr/bin/menu" ~/.bashrc; then
    echo '# Auto-start bot panel' >> ~/.bashrc
    echo 'if [ -t 1 ] && [ -x /usr/bin/menu ] && [ -z "$TMUX" ]; then /usr/bin/menu; fi' >> ~/.bashrc
fi

# ==========================================
# 2. FUNGSI MEMBUAT TAMPILAN WEB APLIKASI
# ==========================================
generate_web_app() {
    mkdir -p public/baner1 public/baner2 public/baner3 public/baner4 public/baner5 public/info_images public/maint_images public/tutorials

    cat << 'EOF' > public/manifest.json
{
  "name": "Digital Tendo Store",
  "short_name": "Digital Tendo Store",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0f172a",
  "theme_color": "#0f172a",
  "orientation": "portrait",
  "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/3144/3144456.png", "sizes": "512x512", "type": "image/png"}]
}
EOF

    cat << 'EOF' > public/sw.js
const CACHE_NAME = 'tendo-v5';
self.addEventListener('install', (e) => { 
    self.skipWaiting(); 
});
self.addEventListener('activate', (e) => { 
    e.waitUntil(caches.keys().then((keyList) => {
        return Promise.all(keyList.map((key) => {
            if (key !== CACHE_NAME) {
                return caches.delete(key);
            }
        }));
    }));
    self.clients.claim(); 
});
self.addEventListener('fetch', (e) => { 
    e.respondWith(
        fetch(e.request).catch(() => caches.match(e.request))
    );
});
EOF

    cat << 'EOF' > public/index.html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Digital Tendo Store</title>
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#e2e8f0" id="meta-theme">
    <style>
        /* VARIABEL TEMA NEUMORPHISM BARU */
        :root {
            --bg-main: #e2e8f0; 
            --grid-bg: #e2e8f0; 
            --bg-card: #e2e8f0;
            --topbar-bg: #e2e8f0;
            --bg-icon: #e2e8f0; 
            --text-main: #0f172a;
            --text-muted: #475569;
            --border-color: transparent;
            --nav-bg: #e2e8f0;
            --nav-text: #64748b;
            --nav-active: #0ea5e9;
            --toast-bg: rgba(15, 23, 42, 0.85);
            --toast-text: #f8fafc;
            --shadow-outer: 8px 8px 16px #a3b4ce, -8px -8px 16px #ffffff;
            --shadow-inner: inset 6px 6px 12px #a3b4ce, inset -6px -6px 12px #ffffff;
            --shadow-icon: 8px 8px 16px #a3b4ce, -8px -8px 16px #ffffff;
            --shadow-icon-inner: inset 5px 5px 10px #a3b4ce, inset -5px -5px 10px #ffffff;
        }

        .dark-mode {
            --bg-main: #171717; 
            --grid-bg: #171717;
            --bg-card: #171717; 
            --topbar-bg: #171717;
            --bg-icon: #171717; 
            --text-main: #f5f5f5;
            --text-muted: #a3a3a3;
            --border-color: transparent;
            --nav-bg: #171717;
            --nav-text: #737373;
            --nav-active: #0ea5e9;
            --toast-bg: rgba(23, 23, 23, 0.9);
            --toast-text: #f5f5f5;
            --shadow-outer: 8px 8px 16px #0c0c0c, -8px -8px 16px #222222;
            --shadow-inner: inset 6px 6px 12px #0c0c0c, inset -6px -6px 12px #222222;
            --shadow-icon: 8px 8px 16px #0c0c0c, -8px -8px 16px #222222;
            --shadow-icon-inner: inset 5px 5px 10px #0c0c0c, inset -5px -5px 10px #222222;
        }

        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-main); color: var(--text-main); margin: 0; display: flex; justify-content: center; transition: background-color 0.3s;}
        
        #app { width: 100%; max-width: 480px; background: var(--bg-main); min-height: 100vh; position: relative; overflow-x: hidden; padding-bottom: 140px; box-sizing: border-box; box-shadow: 0 0 20px rgba(0,0,0,0.1); transition: background 0.3s;}
        
        .top-bar { background: var(--topbar-bg); color: var(--text-main); padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; transition: background 0.3s;}
        
        .menu-btn { cursor: pointer; background: var(--bg-card); border: none; padding: 6px 10px; border-radius: 12px; margin-right: 15px; display: flex; align-items: center; justify-content: center; z-index: 2; box-shadow: var(--shadow-outer); transition: transform 0.2s, box-shadow 0.2s;}
        .menu-btn:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .menu-btn svg { width: 24px; height: 24px; stroke: var(--text-main); fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}
        
        .brand-title { position: absolute; left: 50%; transform: translateX(-50%); font-size: 18px; font-weight: 800; background: transparent; color: var(--text-main); padding: 8px 0; border-radius: 0; box-shadow: none; z-index: 2; overflow: visible; width: auto; display: flex; align-items: center; white-space: nowrap; text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer;}
        
        .trx-badge { font-size: 11px; background: var(--bg-card); color: var(--text-main); padding: 6px 14px; border-radius: 20px; font-weight: 800; cursor: pointer; border: none; box-shadow: var(--shadow-outer); transition: transform 0.2s, box-shadow 0.2s; z-index: 2;}
        .trx-badge:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }

        .banner-container { 
            background: var(--topbar-bg); 
            padding: 5px 20px 25px; 
            border-bottom-left-radius: 30px; 
            border-bottom-right-radius: 30px; 
            position: relative;
            z-index: 10;
            transition: background 0.3s;
        }

        .saldo-card-modern {
            background: var(--bg-card);
            border-radius: 20px;
            padding: 18px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-outer);
            border: none;
            position: relative;
            z-index: 2;
            flex-wrap: wrap;
            gap: 10px;
        }
        .sc-left { display: flex; align-items: center; gap: 14px; }
        .sc-icon { 
            width: 44px; height: 44px; background: var(--bg-icon); 
            border-radius: 50%; display: flex; justify-content: center; align-items: center; color: var(--nav-active);
            box-shadow: var(--shadow-icon); transition: all 0.3s ease, transform 0.2s;
        }
        .sc-info { display: flex; flex-direction: column; justify-content: center;}
        .sc-title { font-size: 11px; color: var(--text-muted); font-weight: 700; text-transform: uppercase; margin-bottom: 2px;}
        .sc-amount { font-size: 20px; font-weight: 900; color: var(--text-main); letter-spacing: 0.5px;}

        .sc-actions { display: flex; gap: 8px; align-items: center; }
        .sc-btn-action {
            background: var(--bg-card);
            color: var(--text-main);
            border: none;
            width: 38px; height: 38px;
            border-radius: 12px; display: flex; justify-content: center; align-items: center;
            cursor: pointer; box-shadow: var(--shadow-outer); transition: transform 0.2s, box-shadow 0.2s;
        }
        .sc-btn-action:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .sc-btn-action svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }

        .sc-btn-topup { 
            background: var(--nav-active); color: #ffffff; border: none; 
            padding: 0 16px; height: 38px; border-radius: 12px; font-weight: 800; font-size: 13px; cursor: pointer;
            box-shadow: var(--shadow-outer); transition: transform 0.2s, box-shadow 0.2s;
        }
        .sc-btn-topup:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }

        .banner-slider-container { margin: 20px 20px 0px; border-radius: 20px; overflow: hidden; position: relative; background: var(--bg-card); box-shadow: var(--shadow-outer);}
        .banner-slider { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; -webkit-overflow-scrolling: touch; scrollbar-width: none; }
        .banner-slider::-webkit-scrollbar { display: none; }
        .banner-slide { flex: 0 0 100%; scroll-snap-align: center; display: flex; justify-content: center; align-items: center; }
        .banner-slide img { width: 100%; height: auto; object-fit: cover; aspect-ratio: 21/9; display: block;}

        .grid-title { margin: 25px 20px 15px; font-weight: 800; color: var(--text-main); font-size: 15px;}
        .grid-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 0 20px;}
        .grid-box { 
            background: var(--grid-bg); border-radius: 20px; padding: 18px 5px; 
            text-align: center; cursor: pointer; display: flex; flex-direction: column; align-items: center; justify-content: flex-start;
            box-shadow: var(--shadow-outer); border: none;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .grid-icon-wrap { 
            width: 50px; height: 50px; margin-bottom: 12px; display: flex; justify-content: center; align-items: center; 
            border-radius: 50%; box-shadow: var(--shadow-icon); transition: all 0.3s ease, transform 0.2s; background: var(--bg-icon);
        }
        
        /* Neumorphism Active States */
        .sc-icon:active, .grid-icon-wrap:active, .b-logo:active, .prod-logo:active, .prof-avatar:active, .sidebar-avatar:active { 
            box-shadow: var(--shadow-icon-inner) !important; 
            transform: scale(0.95); 
        }
        .grid-box:active { box-shadow: var(--shadow-inner) !important; transform: scale(0.95); }

        .ic-pulsa { color: #0ea5e9; }
        .ic-data { color: #10b981; }
        .ic-game { color: #ef4444; }
        .ic-voucher { color: #f59e0b; }
        .ic-ewallet { color: #8b5cf6; }
        .ic-pln { color: #f59e0b; }
        .ic-sms { color: #ec4899; }
        .ic-masa { color: #f97316; }
        .ic-perdana { color: #14b8a6; }
        .ic-vpn { color: #6366f1; }

        .grid-text { font-size: 11px; color: var(--text-main); font-weight: 700; line-height: 1.3; text-transform: uppercase; letter-spacing: -0.2px;}

        .stats-container { margin: 25px 20px; padding: 20px; background: var(--bg-card); border-radius: 20px; border: none; text-align: center; box-shadow: var(--shadow-outer);}
        .stats-title { font-size: 14px; font-weight: 800; color: var(--text-main); margin-bottom: 15px; text-transform: uppercase; letter-spacing: 0.5px;}
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;}
        .stat-box { flex: 1; padding: 12px 5px; background: var(--bg-card); border-radius: 12px; border: none; box-shadow: var(--shadow-outer);}
        .stat-val { font-size: 16px; font-weight: 900; color: var(--nav-active); margin-bottom: 5px;}
        .stat-lbl { font-size: 9px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;}

        .brand-list { display: flex; flex-direction: column; padding: 15px 20px; gap: 15px; }
        .brand-row { background: var(--bg-card); padding: 16px; border-radius: 16px; border: none; display: flex; align-items: center; gap: 15px; box-shadow: var(--shadow-outer); cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; color: var(--text-main);}
        .brand-row:active { transform: scale(0.98); box-shadow: var(--shadow-inner); }
        .b-logo { width: 45px; height: 45px; background: var(--bg-icon); color: var(--nav-active); border-radius: 50%; font-weight: 900; font-size: 15px; display: flex; justify-content: center; align-items: center; box-shadow: var(--shadow-icon); transition: all 0.3s ease, transform 0.2s; flex-shrink: 0; text-transform: uppercase;}
        .b-name { font-size: 14px; font-weight: 700; flex: 1;}

        .bottom-nav { 
            position: fixed; 
            bottom: 20px; 
            left: 50%;
            transform: translateX(-50%);
            width: calc(100% - 40px); 
            max-width: 400px; 
            background: var(--bg-card);
            display: flex; 
            justify-content: space-around; 
            padding: 12px 5px; 
            border-radius: 50px; 
            box-shadow: var(--shadow-outer); 
            z-index: 900; 
            transition: background 0.3s;
            border: none;
        }

        .nav-item { text-align: center; color: var(--nav-text); font-size: 10px; flex: 1; cursor: pointer; display: flex; flex-direction: column; align-items: center; font-weight: 700; transition: color 0.3s;}
        .nav-icon { margin-bottom: 4px; display: flex; justify-content: center; align-items: center;}
        .nav-icon svg { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}
        .nav-item.active { color: var(--nav-active);}

        .product-item { background: var(--bg-card); padding: 16px; border-radius: 16px; margin: 10px 20px 15px; border: none; display: flex; align-items: center; gap: 15px; box-shadow: var(--shadow-outer); cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;}
        .product-item:active { transform: scale(0.98); box-shadow: var(--shadow-inner); }
        .prod-logo { width: 45px; height: 45px; background: var(--bg-icon); color: var(--nav-active); border-radius: 50%; display: flex; justify-content: center; align-items: center; font-weight: 900; font-size: 14px; box-shadow: var(--shadow-icon); transition: all 0.3s ease, transform 0.2s; flex-shrink: 0; text-transform: uppercase;}
        .prod-info { flex: 1; min-width: 0; }
        .prod-name { font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between; word-wrap: break-word;}
        .badge-open { background: var(--bg-main); color: #0284c7; font-size: 9px; padding: 4px 8px; border-radius: 6px; font-weight: 800; box-shadow: var(--shadow-outer); flex-shrink: 0; margin-left: 8px;}
        .prod-desc { font-size: 11px; color: var(--text-muted); font-weight: 500; margin-bottom: 6px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; text-overflow: ellipsis;}
        .prod-price { color: var(--text-main); font-weight: 900; font-size: 15px;}

        .search-box { padding: 15px 20px 5px; position: sticky; top: 58px; z-index: 50; background: var(--bg-main); transition: background 0.3s; }
        .search-box input { margin-bottom: 0; box-shadow: var(--shadow-inner); border-radius: 14px; padding: 14px 18px; width: 100%; box-sizing: border-box; font-weight: 600; border: none; background: var(--bg-main); outline: none; color: var(--text-main);}

        /* ANIMASI SKELETON LOADING */
        .skeleton-box { 
            animation: skeleton-loading 1.2s infinite linear alternate; 
            border-radius: 16px; 
            background-color: var(--border-color); 
            height: 80px; 
            margin: 10px 20px 15px; 
            box-shadow: var(--shadow-outer);
        }
        @keyframes skeleton-loading { 
            0% { opacity: 0.4; } 
            100% { opacity: 0.8; } 
        }

        .history-tabs { display: flex; gap: 15px; padding: 10px 20px; background: var(--bg-main); position: sticky; top: 58px; z-index: 50; }
        .hist-tab { flex: 1; text-align: center; padding: 12px 0; font-size: 13px; font-weight: 700; cursor: pointer; color: var(--text-main); background: var(--bg-card); border-radius: 14px; border: none; box-shadow: var(--shadow-outer); transition: all 0.2s; text-transform: uppercase;}
        
        .history-status-filters { display: flex; gap: 10px; padding: 0 20px 10px; margin-top: 10px; position: sticky; top: 110px; z-index: 40; justify-content: space-between;}
        .status-btn { flex: 1; background: var(--bg-card); color: var(--text-main); border: none; padding: 8px 0; border-radius: 20px; font-size: 11.5px; font-weight: 700; cursor: pointer; transition: all 0.2s; box-shadow: var(--shadow-outer); text-align: center; white-space: nowrap;}
        
        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.85); z-index: 1001; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:0; left:-300px; width: 280px; height: 100vh; background: var(--bg-main); z-index: 1002; transition: left 0.3s ease; overflow-y: auto; display: flex; flex-direction: column; box-shadow: 5px 0 25px rgba(0,0,0,0.1);}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 40px 20px 30px; text-align: center; background: var(--bg-card); color: var(--text-main); box-shadow: var(--shadow-outer); border-bottom-left-radius: 20px; border-bottom-right-radius: 20px;}
        .sidebar-avatar { width: 70px; height: 70px; background: var(--bg-icon); border-radius: 50%; margin: 0 auto 15px auto; display: flex; justify-content: center; align-items: center; color: var(--nav-active); font-size: 30px; font-weight: bold; text-transform: uppercase; box-shadow: var(--shadow-icon); transition: all 0.3s ease;}
        .sidebar-name { font-weight: 800; font-size: 16px; color: var(--text-main);}
        .sidebar-phone { font-size: 12px; color: var(--text-muted);}
        .sidebar-menu { padding: 20px 0; }
        
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: var(--text-main); text-decoration: none; font-size: 14px; border: none; font-weight: 600; gap: 15px; background: var(--bg-card); border-radius: 14px; margin: 10px 20px; box-shadow: var(--shadow-outer); transition: transform 0.2s, box-shadow 0.2s; }
        .sidebar-item:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .sidebar-item svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }

        .container { padding: 20px; }
        .card { background: var(--bg-card); padding: 25px 20px; border-radius: 20px; margin-bottom: 20px; border: none; box-shadow: var(--shadow-outer);}
        input, select { width: 100%; padding: 15px; margin-bottom: 12px; border: none; border-radius: 14px; box-sizing: border-box; font-size: 14px; outline: none; background: var(--bg-main); color: var(--text-main); font-weight: 600; transition: box-shadow 0.2s; box-shadow: var(--shadow-inner);}
        input:focus, select:focus { box-shadow: var(--shadow-outer);}
        input::placeholder { color: #94a3b8; font-weight: 600; }
        
        .checkbox-container { display: flex; align-items: center; justify-content: flex-start; gap: 8px; margin-bottom: 20px; font-size: 13px; font-weight: 600; color: var(--text-muted); cursor: pointer;}
        .checkbox-container input { width: 16px; height: 16px; margin: 0; padding: 0; cursor: pointer;}
        
        .btn { background: var(--bg-card); color: var(--nav-active); border: none; padding: 16px; width: 100%; border-radius: 14px; font-size: 14px; font-weight: 800; cursor: pointer; transition: transform 0.1s, box-shadow 0.2s; box-shadow: var(--shadow-outer);}
        .btn:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-outline { background: var(--bg-card); color: var(--text-main); border: none; padding: 16px; width: 100%; border-radius: 14px; font-size: 14px; font-weight: 700; cursor: pointer; margin-top: 10px; transition: transform 0.1s, box-shadow 0.2s; box-shadow: var(--shadow-outer);}
        .btn-outline:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .btn-danger { background: var(--bg-card); color: #ef4444; border: none; padding: 16px; width: 100%; border-radius: 14px; font-size: 14px; font-weight: 800; cursor: pointer; margin-top: 10px; box-shadow: var(--shadow-outer); transition: transform 0.1s, box-shadow 0.2s;}
        .btn-danger:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        
        /* WARNA BACKGROUND PENUH UNTUK TOMBOL AKTIF */
        .btn-saldo.active, .btn-qris.active, .pay-btn-vpn.active, .hist-tab.active, .status-btn.active { 
            background: var(--nav-active) !important; 
            color: #ffffff !important; 
            box-shadow: var(--shadow-inner) !important; 
            transform: scale(0.98); 
        }
        .btn-saldo.active svg, .btn-qris.active svg, .pay-btn-vpn.active svg, .hist-tab.active svg, .status-btn.active svg {
            stroke: #ffffff;
            fill: #ffffff;
        }

        .prof-header { background: var(--bg-card); color: var(--text-main); padding: 30px 20px; text-align: center; border-bottom-left-radius: 30px; border-bottom-right-radius: 30px; box-shadow: var(--shadow-outer);}
        
        .prof-avatar-wrap {
            width: 86px; height: 86px;
            background: transparent;
            border-radius: 50%;
            padding: 0;
            margin: 0 auto 20px auto;
            box-shadow: none;
        }
        .prof-avatar {
            width: 100%; height: 100%;
            background: var(--bg-icon); color: var(--nav-active);
            border-radius: 50%; font-size: 38px; display: flex; justify-content: center; align-items: center; font-weight: 900; text-transform: uppercase;
            box-shadow: var(--shadow-icon); transition: all 0.3s ease;
        }

        .prof-box { background: var(--bg-card); color: var(--text-main); margin: -20px 20px 20px; border-radius: 20px; padding: 20px; position: relative; z-index: 10; border: none; box-shadow: var(--shadow-outer);}
        .prof-row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px dashed var(--border-color); font-size: 13px;}
        .prof-label { color: var(--text-muted); font-weight: 600;}
        .prof-val { font-weight: 800; text-align: right;}
        
        .prof-actions-container {
            padding: 0 20px;
            margin-bottom: 150px; 
            display: flex;
            flex-direction: column;
            gap: 15px;
            position: relative;
            z-index: 10;
        }
        
        .prof-action-btn { background: var(--bg-card); color: var(--text-main); border: none; padding: 16px; width: 100%; border-radius: 14px; font-weight: 700; cursor: pointer; font-size: 14px; display: flex; align-items: center; gap: 12px; transition: transform 0.2s, box-shadow 0.2s; box-shadow: var(--shadow-outer); }
        .prof-action-btn:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .prof-action-btn svg { fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}

        .hist-item { background: var(--bg-card); color: var(--text-main); padding: 16px; border-radius: 16px; margin: 10px 20px 15px; border: none; box-shadow: var(--shadow-outer); cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;}
        .hist-item:active { transform: scale(0.98); box-shadow: var(--shadow-inner); }
        .hist-top { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-bottom: 8px; font-weight: 700;}
        .hist-title { font-weight: 800; font-size: 14px; margin-bottom: 4px;}
        .hist-target { font-size: 12px; font-weight: 600; color: var(--text-muted);}
        .stat-badge { padding: 4px 10px; border-radius: 8px; font-weight: bold; font-size: 10px; box-shadow: none;}
        .stat-Sukses { background: #dcfce7; color: #059669; } 
        .stat-Pending { background: #fef3c7; color: #d97706; } 
        .stat-Gagal { background: #fee2e2; color: #dc2626; text-decoration: line-through; }
        .stat-Refund { background: #e0e7ff; color: #4f46e5; }

        .modal-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15, 23, 42, 0.85); display: flex; justify-content: center; align-items: center; z-index: 2000; padding: 20px;}
        .modal-box { background: var(--bg-card); color: var(--text-main); width: 100%; max-width: 360px; border-radius: 24px; padding: 25px; text-align: center; box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2); max-height: 90vh; overflow-y: auto;}
        .modal-btns { display: flex; gap: 15px; margin-top: 20px;}
        
        .screen-header { padding: 15px 20px; font-weight: 800; font-size: 18px; display: flex; align-items: center; gap: 15px; background: var(--bg-card); color: var(--text-main); border-bottom: none; box-shadow: var(--shadow-outer); position: sticky; top:0; z-index: 10; transition: background 0.3s;}
        .hidden { display: none !important; }
        .back-icon { cursor: pointer; fill: none; stroke: var(--text-main); stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round;}

        .custom-toast {
            position: fixed;
            top: -100px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(15, 23, 42, 0.85);
            color: #f8fafc;
            padding: 14px 28px;
            border-radius: 50px;
            font-size: 13px;
            font-weight: 700;
            z-index: 9999;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: top 0.5s cubic-bezier(0.68, -0.55, 0.27, 1.55), opacity 0.3s;
            opacity: 0;
            display: flex;
            align-items: center;
            gap: 12px;
            width: max-content;
            max-width: 90%;
            text-align: center;
        }
        .custom-toast.show { top: 40px; opacity: 1; }
        .custom-toast.error { 
            background: rgba(220, 38, 38, 0.85); 
            border: 1px solid rgba(248, 113, 113, 0.4); 
            box-shadow: 0 10px 30px rgba(220, 38, 38, 0.2);
        }
        .custom-toast.success { 
            background: rgba(16, 185, 129, 0.85); 
            border: 1px solid rgba(52, 211, 153, 0.4); 
            box-shadow: 0 10px 30px rgba(16, 185, 129, 0.2);
        }

        .provider-toast {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(15, 23, 42, 0.85);
            color: #ffffff;
            padding: 10px 22px;
            border-radius: 50px;
            font-size: 12px;
            font-weight: 800;
            z-index: 3000;
            opacity: 0;
            transition: opacity 0.4s, top 0.4s;
            pointer-events: none;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .provider-toast.show { opacity: 1; top: 50px; }

        /* FLOATING WHATSAPP BUTTON (NEUMORPHISM) */
        .floating-wa {
            position: fixed;
            bottom: 95px;
            right: 20px;
            width: 55px;
            height: 55px;
            background-color: #25D366;
            color: #ffffff;
            border-radius: 50px;
            display: flex;
            justify-content: center;
            align-items: center;
            cursor: pointer;
            box-shadow: var(--shadow-outer);
            z-index: 950;
            transition: transform 0.2s, box-shadow 0.2s;
            animation: pulse-wa 2s infinite;
        }
        .floating-wa:active { transform: scale(0.95); box-shadow: var(--shadow-inner) !important; }
        
        @keyframes pulse-wa {
            0% { box-shadow: 0 0 0 0 rgba(37, 211, 102, 0.7); }
            70% { box-shadow: 0 0 0 15px rgba(37, 211, 102, 0); }
            100% { box-shadow: 0 0 0 0 rgba(37, 211, 102, 0); }
        }

        .vpn-server-list { display: flex; flex-direction: column; gap: 15px; text-align: left; margin-top: 15px; }
        .vpn-server-item { background: var(--bg-card); padding: 15px; border-radius: 14px; border: none; display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; box-shadow: var(--shadow-outer);}
        .vpn-server-item:active { transform: scale(0.95); box-shadow: var(--shadow-inner); }
        .vpn-server-info { flex: 1; }
        .vpn-server-name { font-weight: 800; font-size: 14px; display: flex; align-items: center; gap: 8px;}
        .vpn-server-price { font-size: 13px; color: var(--nav-active); font-weight: 800; margin-top: 5px;}

        @media screen and (min-width: 768px) {
            body { padding: 30px 0; background-color: var(--bg-main); }
            #app { max-width: 800px; border-radius: 36px; min-height: calc(100vh - 60px); box-shadow: 0 25px 60px rgba(0,0,0,0.15); padding-bottom: 130px; }
            .top-bar { border-top-left-radius: 36px; border-top-right-radius: 36px; padding: 20px 30px; }
            .banner-container { padding: 10px 30px 30px; }
            .bottom-nav { max-width: 740px; bottom: 40px; padding: 15px 10px; border-radius: 60px; }
            .floating-wa { right: max(20px, calc(50% - 380px)); bottom: 45px; }
            .nav-item .nav-icon svg { width: 26px; height: 26px; }
            .grid-container { grid-template-columns: repeat(4, 1fr); padding: 0 30px; gap: 20px; }
            .stats-container { margin: 30px; }
            .banner-slider-container { margin: 20px 30px 0px; }
            #product-list, #brand-list, #history-list, #tutorial-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; padding: 10px 30px 30px !important; }
            .product-item, .brand-row, .hist-item { margin: 0 !important; }
            #notif-list, #global-trx-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; padding: 30px !important; }
            #notif-list .card, #global-trx-list .card, #tutorial-list .card { margin-bottom: 0 !important; }
            #login-screen .card, #register-screen .card, #otp-screen .card, #forgot-screen .card, #login-otp-screen .card { max-width: 450px; margin: 0 auto; padding: 40px; }
            .sidebar { width: 340px; }
        }

        @media screen and (min-width: 1024px) {
            #app { max-width: 1024px; }
            .bottom-nav { max-width: 964px; }
            .floating-wa { right: max(30px, calc(50% - 480px)); bottom: 45px; }
            .grid-container { grid-template-columns: repeat(5, 1fr); }
            #product-list, #brand-list, #history-list, #notif-list, #global-trx-list, #tutorial-list { grid-template-columns: repeat(3, 1fr); }
        }
    </style>
</head>
<body class="dark-mode"> <div id="app">
        <div id="initial-loader" style="display:flex; justify-content:center; align-items:center; height:100vh; flex-direction:column; background: var(--bg-main); position: fixed; top:0; left:0; width:100%; z-index:9999; transition: opacity 0.3s;">
            <div style="width: 50px; height: 50px; border: 4px solid var(--border-color); border-top-color: #0ea5e9; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 20px;"></div>
            <div style="font-size:20px; font-weight:900; color:var(--text-main); letter-spacing: 1px;">DIGITAL TENDO</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:5px; font-weight: bold;">Memuat sistem...</div>
            <style>@keyframes spin { 100% { transform: rotate(360deg); } }</style>
        </div>

        <div id="provider-toast" class="provider-toast">Telkomsel</div>

        <div class="floating-wa hidden" id="floating-wa-btn" onclick="contactAdmin()" title="Hubungi Admin">
            <svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>
        </div>

        <div class="top-bar hidden" id="home-topbar">
            <button class="menu-btn" onclick="toggleSidebar()">
                <svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
            <div class="brand-title" style="justify-content: center; padding: 8px 20px;" onclick="secretPanelClick()">
                <span id="top-title">Digital Tendo Store</span>
            </div>
            <div class="trx-badge" id="top-trx-badge" onclick="showHistory('Order')">0 Trx</div>
        </div>

        <div class="banner-container hidden" id="banner-container-wrap">
            <div class="saldo-card-modern">
                <div class="sc-left">
                    <div class="sc-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="24" height="24"><rect x="2" y="5" width="20" height="14" rx="2"></rect><line x1="2" y1="10" x2="22" y2="10"></line></svg>
                    </div>
                    <div class="sc-info">
                        <div class="sc-title">Saldo Aktif</div>
                        <div class="sc-amount" id="user-saldo" data-saldo="0">Rp 0</div>
                    </div>
                </div>
                <div class="sc-actions">
                    <button class="sc-btn-action" onclick="showHistory('Topup')" title="Riwayat Topup">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                    </button>
                    <button class="sc-btn-action" onclick="contactAdmin()" title="Bantuan Admin">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>
                    </button>
                    <button class="sc-btn-topup" onclick="openTopupModal()">Topup</button>
                </div>
            </div>
        </div>

        <div class="sidebar-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-avatar" id="sb-avatar"></div>
                <div class="sidebar-name" id="sb-name">Digital Tendo Store</div>
                <div class="sidebar-phone" id="sb-phone">Belum Login</div>
            </div>
            <div class="sidebar-menu">
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showProfile()">
                    <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> Profil Akun
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showHistory('Order')">
                    <svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg> Transaksi Saya
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showNotif()">
                    <svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg> Pemberitahuan
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); contactAdmin()">
                    <svg viewBox="0 0 24 24"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg> Hubungi Admin
                </a>
                <a href="#" class="sidebar-item" onclick="toggleTheme()" id="sidebar-theme-toggle">
                    <svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg> <span id="theme-text">Mode Terang</span>
                </a>
                <a href="#" class="sidebar-item" onclick="logout()" style="color: #ef4444;" id="sidebar-logout-btn">
                    <svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg> Keluar Akun
                </a>
            </div>
        </div>

        <div id="login-screen" class="container hidden">
            <div style="text-align:center; margin: 40px 0;">
                <h1 style="color:var(--text-main); margin:0; font-weight:900; font-size: 28px;">Digital Tendo Store</h1>
                <p style="color:var(--text-muted); font-size:13px; margin-top:5px; font-weight: 600;">Solusi Pembayaran Digital</p>
            </div>
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Masuk Akun</h2>
                <input type="text" id="log-id" placeholder="Email / WA / Username">
                <input type="password" id="log-pass" placeholder="Password">
                <label class="checkbox-container">
                    <input type="checkbox" id="rem-login" checked> Tetap masuk
                </label>
                <button class="btn" id="btn-login" onclick="login()">Login Sekarang</button>
                <a href="#" onclick="showScreen('forgot-screen')" style="display:block; text-align:center; font-size:13px; font-weight:600; color:var(--text-muted); margin-top:15px; text-decoration:none;">Lupa Password?</a>
                <button class="btn-outline" onclick="showScreen('register-screen')">Buat Akun Baru</button>
                <a href="#" onclick="contactAdmin()" style="display:block; text-align:center; font-size:13px; font-weight:bold; color:#0ea5e9; margin-top:20px; text-decoration:none;">Butuh Bantuan? Hubungi Admin</a>
            </div>
        </div>

        <div id="login-otp-screen" class="container hidden">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0; font-size:18px;">Verifikasi Login</h2>
                <p style="font-size:13px; color:var(--text-muted); margin-bottom: 20px; font-weight: 600;">OTP telah dikirim ke WA Anda.</p>
                <input type="number" id="login-otp-code" placeholder="----" style="text-align:center; font-size:28px; letter-spacing: 12px; font-weight:bold; background:var(--bg-main);" oninput="if(this.value.length > 4) this.value = this.value.slice(0,4);">
                <button class="btn" id="btn-login-verify" onclick="verifyLoginOTP()">Masuk Ke Dashboard</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('login-screen')">Batal</button>
            </div>
        </div>

        <div id="register-screen" class="container hidden">
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Daftar Akun</h2>
                <p style="font-size:12px; color:var(--text-muted); text-align: center; margin-bottom: 20px; font-weight: 600;">Gunakan Nomor WhatsApp Aktif (08/62)</p>
                <input type="text" id="reg-user" placeholder="Username Unik (Cth: BudiCell)">
                <input type="email" id="reg-email" placeholder="Alamat Email">
                <input type="number" id="reg-phone" placeholder="Nomor WhatsApp">
                <input type="password" id="reg-pass" placeholder="Buat Password">
                <button class="btn" id="btn-register" onclick="requestOTP()">Kirim OTP WhatsApp</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('login-screen')">Kembali ke Login</button>
                <button class="btn-outline" style="border:none; margin-top:5px; color:#0ea5e9; font-weight:bold;" onclick="contactAdmin()">Butuh Bantuan? Hubungi Admin</button>
            </div>
        </div>

        <div id="otp-screen" class="container hidden">
            <div class="card" style="text-align:center;">
                <h2 style="margin-top:0; font-size:18px;">Verifikasi WhatsApp</h2>
                <p style="font-size:13px; color:var(--text-muted); margin-bottom: 20px; font-weight: 600;">Kode OTP 4 digit telah dikirim ke WA.</p>
                <input type="number" id="otp-code" placeholder="----" style="text-align:center; font-size:28px; letter-spacing: 12px; font-weight:bold; background:var(--bg-main);" oninput="if(this.value.length > 4) this.value = this.value.slice(0,4);">
                <button class="btn" id="btn-verify" onclick="verifyOTP()">Verifikasi & Daftar</button>
                <button class="btn-outline" style="border:none;" onclick="showScreen('register-screen')">Batal</button>
            </div>
        </div>
        
        <div id="forgot-screen" class="container hidden">
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Lupa Password</h2>
                <p style="font-size:12px; color:var(--text-muted); text-align: center; margin-bottom: 20px; font-weight: 600;">Reset password melalui OTP WhatsApp</p>
                
                <div id="forgot-step-1">
                    <input type="number" id="forgot-phone" placeholder="Nomor WhatsApp (08/62)">
                    <button class="btn" id="btn-req-forgot" onclick="reqForgotOTP()">Kirim OTP WhatsApp</button>
                    <button class="btn-outline" style="border:none;" onclick="showScreen('login-screen')">Kembali ke Login</button>
                </div>
                
                <div id="forgot-step-2" class="hidden">
                    <p style="font-size:12px; color:var(--text-muted); text-align: center; font-weight: bold;">OTP dikirim ke WA Anda.</p>
                    <input type="number" id="forgot-otp" placeholder="----" style="text-align:center; font-size:28px; letter-spacing: 12px; font-weight:bold; background:var(--bg-main);" oninput="if(this.value.length > 4) this.value = this.value.slice(0,4);">
                    <input type="text" id="forgot-new-pass" placeholder="Buat Password Baru">
                    <button class="btn" id="btn-verify-forgot" onclick="verifyForgotOTP()">Simpan Password</button>
                    <button class="btn-outline" style="border:none;" onclick="showScreen('login-screen')">Batal</button>
                </div>
            </div>
        </div>

        <div id="dashboard-screen" class="hidden">
            <div id="banner-slider-container" class="banner-slider-container hidden">
                <div id="banner-slider" class="banner-slider"></div>
            </div>
            
            <div id="live-clock" style="text-align:center; font-size:11.5px; font-weight:800; color:var(--text-main); margin: 25px 20px 0; letter-spacing: 0.5px;">Memuat waktu...</div>

            <div class="search-box" id="global-search-container" style="top: 58px; z-index: 49; margin: 20px 20px 10px; border-radius: 14px; padding: 0;">
                <input type="text" id="global-search-db" placeholder="🔍 Cari layanan, produk, provider..." onkeyup="filterGlobalDashboard()">
            </div>

            <div id="custom-layout-container"></div>

            <div class="grid-title">Daftar Produk Prabayar</div>
            <div class="grid-container">
                <div class="grid-box" onclick="loadCategory('Pulsa')">
                    <div class="grid-icon-wrap ic-pulsa">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line>
                        </svg>
                    </div>
                    <div class="grid-text">PULSA</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Data')">
                    <div class="grid-icon-wrap ic-data">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">DATA</div>
                </div>

                <div class="grid-box" onclick="loadCategory('Game')">
                    <div class="grid-icon-wrap ic-game">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <rect x="2" y="6" width="20" height="12" rx="4"></rect><line x1="6" y1="12" x2="10" y2="12"></line><line x1="8" y1="10" x2="8" y2="14"></line><line x1="15" y1="13" x2="15.01" y2="13"></line><line x1="18" y1="11" x2="18.01" y2="11"></line>
                        </svg>
                    </div>
                    <div class="grid-text">GAME</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Voucher')">
                    <div class="grid-icon-wrap ic-voucher">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <path d="M15 5H9a2 2 0 0 0-2 2v3a1 1 0 0 1 0 2v3a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-3a1 1 0 0 1 0-2V7a2 2 0 0 0-2-2z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">VOUCHER</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('E-Money')">
                    <div class="grid-icon-wrap ic-ewallet">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <rect x="2" y="5" width="20" height="14" rx="2"></rect><line x1="2" y1="10" x2="22" y2="10"></line><path d="M16 14h.01"></path>
                        </svg>
                    </div>
                    <div class="grid-text">E-WALLET</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('PLN')">
                    <div class="grid-icon-wrap ic-pln">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                        </svg>
                    </div>
                    <div class="grid-text">PLN</div>
                </div>

                <div class="grid-box" onclick="loadCategory('Paket SMS & Telpon')">
                    <div class="grid-icon-wrap ic-sms">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path><path d="M9 10h.01"></path><path d="M12 10h.01"></path><path d="M15 10h.01"></path>
                        </svg>
                    </div>
                    <div class="grid-text">SMS TELP</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Masa Aktif')">
                    <div class="grid-icon-wrap ic-masa">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line><path d="M12 14v4"></path><path d="M10 16h4"></path>
                        </svg>
                    </div>
                    <div class="grid-text">MASA AKTIF</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Aktivasi Perdana')">
                    <div class="grid-icon-wrap ic-perdana">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" width="28" height="28">
                            <path d="M4 4h12l4 4v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"></path><rect x="8" y="12" width="8" height="6" rx="1"></rect><line x1="12" y1="12" x2="12" y2="18"></line>
                        </svg>
                    </div>
                    <div class="grid-text">PERDANA</div>
                </div>
            </div>

            <div class="grid-title">Daftar Produk Pascabayar</div>
            <div class="grid-container">
                <div class="grid-box" onclick="loadCategory('PLN Pasca')">
                    <div class="grid-icon-wrap" style="color: #f59e0b;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                        </svg>
                    </div>
                    <div class="grid-text">PLN</div>
                </div>
                <div class="grid-box" onclick="loadCategory('PDAM')">
                    <div class="grid-icon-wrap" style="color: #0ea5e9;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">PDAM</div>
                </div>
                <div class="grid-box" onclick="loadCategory('Internet & TV')">
                    <div class="grid-icon-wrap" style="color: #8b5cf6;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <rect x="2" y="7" width="20" height="15" rx="2" ry="2"></rect><polyline points="17 2 12 7 7 2"></polyline>
                        </svg>
                    </div>
                    <div class="grid-text">INTERNET</div>
                </div>
                <div class="grid-box" onclick="loadCategory('BPJS')">
                    <div class="grid-icon-wrap" style="color: #10b981;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                        </svg>
                    </div>
                    <div class="grid-text">BPJS</div>
                </div>
                <div class="grid-box" onclick="loadCategory('Gas Negara')">
                    <div class="grid-icon-wrap" style="color: #f97316;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <path d="M17.5 19c2.5 0 4.5-2 4.5-4.5a4.5 4.5 0 0 0-4-4.47V6a2 2 0 0 0-2-2h-3a2 2 0 0 0-2 2v4.03a4.5 4.5 0 0 0-4 4.47C7 17 9 19 11.5 19h6z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">GAS</div>
                </div>
                <div class="grid-box" onclick="loadCategory('E-Money Pasca')">
                    <div class="grid-icon-wrap" style="color: #ec4899;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            <rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line>
                        </svg>
                    </div>
                    <div class="grid-text">E-MONEY</div>
                </div>
            </div>

            <div class="grid-title">Produk VPN Premium</div>
            <div class="grid-container" id="vpn-grid-container">
                <div style="text-align:center; grid-column: 1 / -1; font-size:12px; color:var(--text-muted);">Memuat protokol VPN...</div>
            </div>

            <div style="margin: 25px 20px 0; padding: 20px; background: var(--bg-card); border-radius: 20px; box-shadow: var(--shadow-outer);">
                <div style="font-size:14px; font-weight:800; color:var(--text-main); margin-bottom:8px;">📢 Komunitas & Update</div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:15px; line-height:1.5; font-weight:500;">Dapatkan informasi terbaru seputar Digital Tendo Store melalui Channel Telegram dan Saluran WhatsApp kami.</div>
                <div style="display:flex; gap:10px;">
                    <button class="btn" style="background:#2481cc; color:#fff; flex:1; font-size:12px; padding:14px; border-radius:14px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="window.open('https://t.me/+CMUMhuJYnX44ZjNl', '_blank')">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg> Telegram
                    </button>
                    <button class="btn" style="background:#25D366; color:#fff; flex:1; font-size:12px; padding:14px; border-radius:14px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="window.open('https://whatsapp.com/channel/0029VbCZzAfHQbS4YeW03Z0m', '_blank')">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg> WhatsApp
                    </button>
                </div>
            </div>

            <div class="stats-container" id="stats-dashboard">
                <div class="stats-title">Statistik Transaksi Pelanggan</div>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-val" id="stat-daily">0</div>
                        <div class="stat-lbl">Hari Ini</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val" id="stat-weekly">0</div>
                        <div class="stat-lbl">Minggu Ini</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val" id="stat-monthly">0</div>
                        <div class="stat-lbl">Bulan Ini</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val" id="stat-total">0</div>
                        <div class="stat-lbl">Semua</div>
                    </div>
                </div>
            </div>
            
            <div class="container" id="leaderboard-container" style="padding: 0 20px 20px;"></div>
        </div>

        <div id="tutorial-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span>Tutorial / Panduan</span>
            </div>
            <div class="container" id="tutorial-list" style="margin-bottom: 120px;">
                <div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Memuat tutorial...</div>
            </div>
        </div>

        <div id="brand-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span id="brand-cat-title" style="text-transform: uppercase;">Kategori</span>
            </div>
            <div class="brand-list" id="brand-list"></div>
        </div>

        <div id="produk-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
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
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span style="text-transform: uppercase;" id="history-title-text">Riwayat Transaksi</span>
            </div>
            <div class="history-tabs">
                <div class="hist-tab active" id="tab-hist-order" onclick="showHistory('Order')">Produk</div>
                <div class="hist-tab" id="tab-hist-topup" onclick="showHistory('Topup')">Topup Saldo</div>
            </div>
            
            <div class="history-status-filters" id="status-filter-container">
                <button class="status-btn active" onclick="filterHistoryStatus('Semua', this)">Semua</button>
                <button class="status-btn" onclick="filterHistoryStatus('Sukses', this)">Sukses</button>
                <button class="status-btn" onclick="filterHistoryStatus('Pending', this)">Pending</button>
                <button class="status-btn" onclick="filterHistoryStatus('Gagal', this)">Gagal</button>
            </div>

            <div id="history-list" style="padding-top:0px;"></div>
        </div>

        <div id="global-trx-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span>Transaksi Semua Pelanggan</span>
            </div>
            <div class="container" id="global-trx-list" style="margin-bottom: 120px;">
                <div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Memuat transaksi...</div>
            </div>
        </div>

        <div id="profile-screen" class="hidden">
            <div class="prof-header">
                <div class="prof-avatar-wrap">
                    <div class="prof-avatar" id="p-avatar"></div>
                </div>
                <h2 style="margin:0 0 5px 0; font-size: 20px;" id="p-username">Username</h2>
                <div style="font-size:13px; font-weight: bold; color: var(--text-muted);" id="p-id">ID: TD-000000</div>
            </div>
            <div class="prof-box">
                <div class="prof-row">
                    <span class="prof-label">Email</span>
                    <span class="prof-val" style="display:flex; align-items:center; gap:8px;">
                        <span id="p-email">-</span>
                        <svg onclick="copyData('p-email', 'Email')" viewBox="0 0 24 24" width="16" height="16" stroke="#0ea5e9" fill="none" stroke-width="2" style="cursor:pointer;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </span>
                </div>
                <div class="prof-row">
                    <span class="prof-label">Username</span>
                    <span class="prof-val" style="display:flex; align-items:center; gap:8px;">
                        <span id="p-username-val">-</span>
                        <svg onclick="copyData('p-username-val', 'Username')" viewBox="0 0 24 24" width="16" height="16" stroke="#0ea5e9" fill="none" stroke-width="2" style="cursor:pointer;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </span>
                </div>
                <div class="prof-row">
                    <span class="prof-label">WhatsApp</span>
                    <span class="prof-val" style="display:flex; align-items:center; gap:8px;">
                        <span id="p-phone">-</span>
                        <svg onclick="copyData('p-phone', 'Nomor WA')" viewBox="0 0 24 24" width="16" height="16" stroke="#0ea5e9" fill="none" stroke-width="2" style="cursor:pointer;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </span>
                </div>
                <div class="prof-row"><span class="prof-label">Tgl Daftar</span><span class="prof-val" id="p-date">-</span></div>
                <div class="prof-row"><span class="prof-label">Total Transaksi</span><span class="prof-val" id="p-trx">0 Kali</span></div>
            </div>
            
            <div class="prof-actions-container">
                <h3 style="font-size:14px; color:var(--text-muted); margin-bottom:5px;">PENGATURAN</h3>
                <button class="prof-action-btn" onclick="window.openEditModal('email')"><svg viewBox="0 0 24 24" width="20" stroke="currentColor"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg> Ubah Email</button>
                <button class="prof-action-btn" onclick="window.openEditModal('phone')"><svg viewBox="0 0 24 24" width="20" stroke="currentColor"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Ubah Nomor WA</button>
                <button class="prof-action-btn" onclick="window.openEditModal('password')"><svg viewBox="0 0 24 24" width="20" stroke="currentColor"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Ubah Password</button>
                
                <button class="prof-action-btn" onclick="contactAdmin()" style="color: #0ea5e9; margin-top: 5px;">
                    <svg viewBox="0 0 24 24" width="20" stroke="currentColor"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg> Hubungi Admin
                </button>
            </div>
        </div>

        <div id="notif-screen" class="hidden">
            <div class="screen-header">
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span>Pemberitahuan</span>
            </div>
            <div class="container" id="notif-list" style="margin-bottom: 120px;">
                <div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Memuat info...</div>
            </div>
        </div>

        <div id="panel-vpn-screen" class="hidden container" style="margin-bottom:120px; margin-top:20px;">
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Generator VPN Manual</h2>
                <select id="mv-server" class="form-control" style="margin-bottom:12px;">
                    <option value="">Pilih Server...</option>
                </select>
                <select id="mv-mode" class="form-control" style="margin-bottom:12px;" onchange="toggleManualVpnFields()">
                    <option value="reguler">Reguler (Premium)</option>
                    <option value="trial">Trial (Uji Coba 30M)</option>
                </select>
                <select id="mv-type" class="form-control" style="margin-bottom:12px;" onchange="toggleManualVpnFields()">
                    <option value="vless">VLESS</option>
                    <option value="vmess">VMESS</option>
                    <option value="ssh">SSH/OpenVPN</option>
                    <option value="trojan">TROJAN</option>
                    <option value="zivpn">ZIVPN</option>
                </select>

                <div id="mv-trial-info" style="display:none; background:var(--bg-main); color:var(--nav-active); padding:12px; border-radius:14px; font-size:12px; font-weight:bold; margin-bottom:12px; border-left:4px solid var(--nav-active);">
                    Mode Trial: Otomatis 30 Menit, Kuota 2GB, 2 Device.
                </div>

                <div id="mv-reguler-group">
                    <input type="text" id="mv-user" placeholder="Username Pelanggan">
                    <input type="number" id="mv-exp" placeholder="Masa Aktif (Hari)" value="30">
                </div>
                <div id="mv-pass-group" style="display:none;">
                    <input type="text" id="mv-pass" placeholder="Password (SSH/ZIVPN)">
                </div>

                <button class="btn" id="btn-mv-submit" onclick="processManualVpn()">Eksekusi Sekarang</button>
                <button class="btn-outline" onclick="goBackGlobal()">Kembali</button>
            </div>
            
            <div id="mv-result" class="card hidden" style="border:1px solid #10b981; margin-top:10px;">
                <h3 style="color:#10b981; margin-top:0;">✅ Berhasil Dibuat</h3>
                <textarea id="mv-result-text" readonly style="width:100%; height:250px; font-size:11px; padding:12px; border-radius:14px; border:none; box-shadow:var(--shadow-inner); background:var(--bg-main); color:var(--text-main); resize:none; font-family:monospace;" onclick="this.select();"></textarea>
                <button class="btn-outline" style="margin-top:10px; color:var(--nav-active);" onclick="copyData('mv-result-text', 'Akun VPN Manual')">Salin Detail Akun</button>
            </div>
        </div>

        <div class="bottom-nav hidden" id="main-bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showDashboard()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg></span>HOME
            </div>
            <div class="nav-item" id="nav-history" onclick="showHistory('Order')">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg></span>RIWAYAT
            </div>
            <div class="nav-item" id="nav-notif" onclick="showNotif()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg></span>INFO
            </div>
            <div class="nav-item" id="nav-global-trx" onclick="showGlobalTrx()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg></span>TRANSAKSI
            </div>
            <div class="nav-item" id="nav-profile" onclick="showProfile()">
                <span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg></span>PROFIL
            </div>
        </div>

        <div id="order-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Formulir Pesanan</h3>
                <div style="background:var(--bg-main); padding:15px; border-radius:16px; margin-bottom:15px; box-shadow:var(--shadow-inner); text-align: left;">
                    <strong id="m-name" style="font-size:14px; line-height:1.4; display:block; margin-bottom:5px;">Produk</strong>
                    <div id="m-desc" style="font-size:11px; color:var(--text-muted); margin-bottom:10px; line-height: 1.4;">Deskripsi Produk</div>
                    <span style="font-weight:900; font-size: 20px;" id="m-price">Rp 0</span>
                </div>
                <input type="text" id="m-target" placeholder="Masukkan Nomor/ID Tujuan" style="text-align:center; font-size: 16px; font-weight: bold;" oninput="checkProvider(this.value)">
                
                <div style="margin-bottom:15px; text-align:left;">
                    <label style="font-size:12px; font-weight:800; color:var(--text-muted);">Metode Pembayaran:</label>
                    <div style="display:flex; gap:10px; margin-top:5px;">
                        <button class="btn-outline pay-btn btn-saldo active" id="btn-pay-saldo" onclick="selectPayment('saldo')" style="margin:0; flex:1;">💳 Saldo Akun</button>
                        <button class="btn-outline pay-btn btn-qris" id="btn-pay-qris" onclick="selectPayment('qris')" style="margin:0; flex:1;">📲 QRIS Auto</button>
                    </div>
                    <input type="hidden" id="m-payment-method" value="saldo">
                </div>

                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeOrderModal()">Batal</button>
                    <button class="btn" id="m-submit" onclick="processOrder()">Beli Sekarang</button>
                </div>
            </div>
        </div>

        <div id="vpn-server-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 id="vpn-modal-title" style="margin-top:0; font-size:18px;">Pilih Produk</h3>
                <div id="vpn-server-list" class="vpn-server-list">
                </div>
                <button class="btn-outline" style="margin-top:15px; width: 100%;" onclick="closeVPNServerModal()">Batal</button>
            </div>
        </div>

        <div id="vpn-order-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Beli Akun VPN Premium</h3>
                <div style="background:var(--bg-main); padding:15px; border-radius:16px; margin-bottom:15px; box-shadow:var(--shadow-inner); text-align: left;">
                    <strong id="m-vpn-name" style="font-size:14px; line-height:1.4; display:block; margin-bottom:5px;">Produk VPN</strong>
                    <div id="m-vpn-desc" style="font-size:11px; color:var(--text-muted); margin-bottom:10px; line-height: 1.4;">Deskripsi VPN</div>
                    <span style="font-weight:900; font-size: 20px; color:var(--nav-active);" id="m-vpn-price">Rp 0</span>
                </div>

                <div id="vpn-input-container">
                    <div style="font-size:10px; color:#ef4444; font-weight:bold; margin-bottom:5px; text-align:left;">⚠️ WAJIB: Huruf kecil tanpa spasi (4-17 Karakter)!</div>
                    <input type="text" id="m-vpn-username" placeholder="Buat Username VPN (4-17 Karakter)" maxlength="17" style="text-align:center; font-size: 14px; font-weight: bold; margin-bottom: 10px;" oninput="this.value = this.value.toLowerCase().replace(/\s/g, '');">
                    <input type="password" id="m-vpn-password" placeholder="Buat Password (4-17 Karakter)" maxlength="17" style="text-align:center; font-size: 14px; font-weight: bold; margin-bottom: 10px;" class="hidden" oninput="this.value = this.value.toLowerCase().replace(/\s/g, '');">
                </div>

                <div id="m-vpn-duration-wrap">
                    <label style="font-size:12px; font-weight:800; color:var(--text-muted); display:block; text-align:left; margin-bottom:5px;">Durasi Aktif (1 - 30 Hari):</label>
                    <input type="number" id="m-vpn-expired" placeholder="Masa Aktif (Hari)" value="30" min="1" max="30" style="text-align:center; font-size: 14px; font-weight: bold; margin-bottom: 10px;" oninput="updateVpnPrice()">
                </div>

                <div id="m-vpn-payment-wrap" style="margin-bottom:15px; text-align:left;">
                    <label style="font-size:12px; font-weight:800; color:var(--text-muted);">Metode Pembayaran:</label>
                    <div style="display:flex; gap:10px; margin-top:5px;">
                        <button class="btn-outline pay-btn-vpn btn-saldo active" id="btn-pay-vpn-saldo" onclick="selectPaymentVpn('saldo')" style="margin:0; flex:1;">💳 Saldo Akun</button>
                        <button class="btn-outline pay-btn-vpn btn-qris" id="btn-pay-vpn-qris" onclick="selectPaymentVpn('qris')" style="margin:0; flex:1;">📲 QRIS Auto</button>
                    </div>
                    <input type="hidden" id="m-vpn-payment" value="saldo">
                </div>

                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeVPNOrderModal()">Batal</button>
                    <button class="btn" id="m-vpn-submit" onclick="processVPNOrder()">Buat Akun</button>
                </div>
            </div>
        </div>

        <div id="vpn-trial-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Klaim Trial VPN Gratis</h3>
                <div style="background:var(--bg-main); padding:15px; border-radius:16px; margin-bottom:15px; box-shadow:var(--shadow-inner); text-align: left;">
                    <strong id="m-vpn-trial-name" style="font-size:14px; line-height:1.4; display:block; margin-bottom:5px;">Produk VPN</strong>
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px; line-height: 1.4;">Masa Aktif: 30 Menit<br>Limit Kuota: 1 GB<br>Cooldown: 2 Jam per Server</div>
                    <span style="font-weight:900; font-size: 20px; color:#10b981;">Gratis</span>
                </div>
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeVPNTrialModal()">Batal</button>
                    <button class="btn" id="m-vpn-trial-submit" style="color:#10b981;" onclick="processVPNTrial()">Klaim Trial</button>
                </div>
            </div>
        </div>

        <div id="order-success-modal" class="modal-overlay hidden">
            <div class="modal-box" style="text-align:center;">
                <div style="width:60px; height:60px; background:var(--bg-main); box-shadow:var(--shadow-inner); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 15px;">
                    <svg viewBox="0 0 24 24" width="35" height="35" stroke="#10b981" fill="none" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
                <h3 style="margin-top:0; font-size:20px; color:#10b981;">Pesanan Berhasil!</h3>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:20px;">Pesanan Anda sedang diproses oleh sistem.</p>
                <div style="background:var(--bg-main); padding:15px; border-radius:16px; margin-bottom:15px; box-shadow:var(--shadow-inner); text-align: left; font-size:13px; line-height: 1.6;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Produk</span><strong id="os-name" style="text-align:right; max-width:60%;"></strong></div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Tujuan</span><strong id="os-target" style="text-align:right;"></strong></div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Metode</span><strong id="os-metode" style="color:var(--nav-active);">Saldo Akun</strong></div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Harga</span><strong id="os-price" style="text-align:right;"></strong></div>
                </div>
                <button class="btn" style="width:100%;" onclick="cekRiwayatBaru()">Cek Riwayat Pembelian</button>
            </div>
        </div>

        <div id="topup-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Isi Saldo Otomatis</h3>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:15px;">Pilih atau masukkan nominal (Khusus QRIS Tanpa biaya admin). Saldo masuk utuh.</p>
                
                <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:15px; justify-items:center; margin-bottom:20px; width: 100%;">
                    <div class="trx-badge" style="padding:12px; width:100%; box-sizing:border-box; text-align:center; font-size:12px;" onclick="document.getElementById('topup-nominal').value='1000'">Rp.1000</div>
                    <div class="trx-badge" style="padding:12px; width:100%; box-sizing:border-box; text-align:center; font-size:12px;" onclick="document.getElementById('topup-nominal').value='5000'">Rp.5000</div>
                    <div class="trx-badge" style="padding:12px; width:100%; box-sizing:border-box; text-align:center; font-size:12px;" onclick="document.getElementById('topup-nominal').value='10000'">Rp.10.000</div>
                    <div class="trx-badge" style="padding:12px; width:100%; box-sizing:border-box; text-align:center; font-size:12px;" onclick="document.getElementById('topup-nominal').value='50000'">Rp.50.000</div>
                    <div class="trx-badge" style="padding:12px; width:100%; box-sizing:border-box; text-align:center; grid-column: span 2; font-size:12px;" onclick="document.getElementById('topup-nominal').value='100000'">Rp.100.000</div>
                </div>

                <input type="number" id="topup-nominal" placeholder="Nominal (Min. 1000)" style="text-align:center; font-size:18px; font-weight:bold;">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeTopupModal()">Batal</button>
                    <button class="btn" id="btn-topup-submit" onclick="generateQris()">Buat QRIS</button>
                </div>
                <button class="btn-outline" style="margin-top:15px; width:100%; color: var(--nav-active);" onclick="manualTopupWA()">Topup Manual (Hubungi Admin)</button>
            </div>
        </div>

        <div id="topup-success-modal" class="modal-overlay hidden">
            <div class="modal-box" style="text-align:center;">
                <div style="width:60px; height:60px; background:var(--bg-main); box-shadow:var(--shadow-inner); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 15px;">
                    <svg viewBox="0 0 24 24" width="35" height="35" stroke="#10b981" fill="none" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
                <h3 style="margin-top:0; font-size:20px; color:#10b981;">Berhasil Dibuat!</h3>
                <p style="font-size:13px; color:var(--text-muted); margin-bottom:20px;">Silakan bayar menggunakan barcode QRIS yang akan ditampilkan di Riwayat.</p>
                <button class="btn" style="width:100%;" onclick="closeTopupSuccessModal()">Oke, Lanjut Bayar</button>
            </div>
        </div>
        
        <div id="history-detail-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Detail Transaksi</h3>
                
                <div id="hd-qris-box" class="hidden" style="background:var(--bg-main); box-shadow:var(--shadow-inner); padding:15px; border-radius:16px; margin-bottom:15px; text-align: center;">
                    <p style="font-size:12px; color:var(--text-main); margin-top:0; margin-bottom:5px; font-weight:bold;">Sisa Waktu Pembayaran:</p>
                    <div id="qris-countdown" style="font-size:22px; font-weight:900; color:#ef4444; margin-bottom:10px; background:var(--bg-card); box-shadow:var(--shadow-outer); padding:5px; border-radius:12px;">-- : --</div>
                    
                    <p style="font-size:11px; color:var(--text-main); margin-top:0; margin-bottom:10px;">Segera bayar dengan QRIS ini:</p>
                    <img id="hd-qris-img" src="" style="width:100%; max-width:240px; padding:20px; border-radius:16px; margin-bottom:15px; background:#ffffff; box-sizing: border-box; box-shadow: var(--shadow-outer);">
                    
                    <div style="display:flex; gap:10px; justify-content:center; margin-bottom:15px;">
                        <button class="btn-outline" style="flex:1; margin:0; padding:10px 5px; font-size:12px; font-weight: bold; color:#10b981; border-radius:20px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="shareQRIS()">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
                            Bagikan
                        </button>
                        <button class="btn-outline" style="flex:1; margin:0; padding:10px 5px; font-size:12px; font-weight: bold; color:#10b981; border-radius:20px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="downloadQRIS()">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            Simpan
                        </button>
                    </div>

                    <div style="font-size:11px; color:var(--text-muted); font-weight:bold;">Transfer TEPAT SEBESAR:</div>
                    <div style="font-size:24px; font-weight:900; color:var(--nav-active); margin: 5px 0;" id="hd-qris-amount">Rp 0</div>
                    <div style="font-size:11px; color:#ef4444; font-weight:bold; line-height:1.4;">Harus persis agar otomatis masuk.</div>
                </div>

                <div id="hd-vpn-info-box" class="hidden" style="background:var(--bg-main); padding:15px; border-radius:16px; margin-bottom:15px; text-align: left; box-shadow:var(--shadow-inner); font-size: 13px;">
                    <div style="font-weight: 800; margin-bottom: 8px; color: var(--text-main);">Detail Akun VPN:</div>
                    <textarea id="hd-vpn-details" readonly style="width:100%; height:180px; font-size:10px; padding:10px; border-radius:12px; border:none; box-shadow:var(--shadow-inner); background:var(--bg-main); color:var(--text-main); resize:none; margin-bottom:10px; font-family: monospace;" onclick="this.focus(); this.select();"></textarea>
                    <button class="btn-outline" style="padding:10px; margin:0; width:100%; font-size: 12px; color:var(--nav-active);" onclick="copyData('hd-vpn-details', 'Detail Akun VPN')">Salin Akun VPN</button>
                </div>

                <div style="background:var(--bg-main); box-shadow:var(--shadow-inner); padding:15px; border-radius:16px; margin-bottom:15px; text-align: left; font-size:13px; line-height: 1.6;">
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Waktu</span><strong id="hd-time"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Status</span><strong id="hd-status"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Layanan</span><strong id="hd-name" style="text-align:right; max-width:60%;"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Nominal</span><strong id="hd-amount"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Tujuan</span><strong id="hd-target"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">SN/Ref</span><strong id="hd-sn" style="word-break:break-all;"></strong></div>
                    <div style="display:flex; justify-content:space-between;" class="hd-saldo-row hidden"><span style="color:var(--text-muted);">Saldo Sebelum</span><strong id="hd-saldo-sebelum"></strong></div>
                    <div style="display:flex; justify-content:space-between;" class="hd-saldo-row hidden"><span style="color:var(--text-muted);">Saldo Sesudah</span><strong id="hd-saldo-sesudah"></strong></div>
                </div>
                <button class="btn-danger hidden" id="hd-cancel-topup-btn" onclick="cancelTopup()" style="margin-bottom: 10px;">Batalkan Topup</button>
                <button class="btn-danger" id="hd-complain-btn" onclick="complainAdmin()" style="margin-bottom: 15px;">Hubungi Admin (Komplain)</button>
                <button class="btn-outline" style="margin-top:0;" onclick="closeHistoryModal()">Tutup</button>
            </div>
        </div>

        <div id="edit-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;" id="edit-title">Ubah Data</h3>
                <div id="edit-step-1">
                    <input type="text" id="edit-input" placeholder="Masukkan data baru">
                    <div class="modal-btns">
                        <button class="btn-outline" style="margin-top:0;" onclick="closeEditModal()">Batal</button>
                        <button class="btn" id="btn-req-edit" onclick="reqEditOTP()">Kirim OTP</button>
                    </div>
                </div>
                <div id="edit-step-2" class="hidden">
                    <p style="font-size:12px; color:var(--text-muted); font-weight: bold;">OTP telah dikirim ke WA Anda.</p>
                    <input type="number" id="edit-otp-input" placeholder="----" style="letter-spacing:12px; text-align:center; font-size:24px; background:var(--bg-main);" oninput="if(this.value.length > 4) this.value = this.value.slice(0,4);">
                    <div class="modal-btns">
                        <button class="btn-outline" style="margin-top:0;" onclick="closeEditModal()">Batal</button>
                        <button class="btn" id="btn-verify-edit" onclick="verifyEditOTP()">Simpan</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let sysMaintStart = "23:00";
        let sysMaintEnd = "00:30";
        let adminWaNumber = "6282224460678";

        // TEMA DAN NEUMORPHISM HANDLER
        function applyTheme(isDark) {
            if(isDark) {
                document.body.classList.add('dark-mode');
                let txt = document.getElementById('theme-text');
                if(txt) txt.innerText = 'Mode Terang';
            } else {
                document.body.classList.remove('dark-mode');
                let txt = document.getElementById('theme-text');
                if(txt) txt.innerText = 'Mode Gelap';
            }
        }
        function toggleTheme() {
            let isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('tendo_theme', !isDark ? 'dark' : 'light');
            applyTheme(!isDark);
        }

        setInterval(() => {
            let d = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Jakarta"}));
            let clockEl = document.getElementById('live-clock');
            if(clockEl) {
                let opts = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' };
                clockEl.innerText = d.toLocaleString('id-ID', opts).replace(/\./g, ':') + ' WIB';
            }

            let h = d.getHours();
            let m = d.getMinutes();
            let curMins = h * 60 + m;
            let sParts = sysMaintStart.split(':');
            let eParts = sysMaintEnd.split(':');
            let sMins = parseInt(sParts[0])*60 + parseInt(sParts[1]);
            let eMins = parseInt(eParts[0])*60 + parseInt(eParts[1]);
            
            let isMaint = false;
            if(sMins < eMins) isMaint = (curMins >= sMins && curMins < eMins);
            else isMaint = (curMins >= sMins || curMins < eMins);
            
            let mb = document.getElementById('maint-banner');
            let dbScreen = document.getElementById('dashboard-screen');
            if (isMaint && dbScreen) {
                if(!mb) {
                    mb = document.createElement('div');
                    mb.id = 'maint-banner';
                    mb.innerHTML = `🛠️ PEMELIHARAAN SISTEM (${sysMaintStart} - ${sysMaintEnd} WIB). TRANSAKSI SEMENTARA DITUTUP.`;
                    mb.style = 'background:#ef4444; color:#fff; font-size:11px; font-weight:bold; text-align:center; padding:14px; margin: 20px 20px 0; border-radius:14px; box-shadow: var(--shadow-outer);';
                    dbScreen.prepend(mb);
                }
            } else {
                if(mb) mb.remove();
            }
        }, 1000);

        let historyStack = [];
        let currentState = null;

        function pushState(newState) {
            if (currentState && JSON.stringify(currentState) !== JSON.stringify(newState)) {
                historyStack.push(currentState);
            }
            currentState = newState;
        }

        function goBackGlobal() {
            if (historyStack.length > 0) {
                let prevState = historyStack.pop();
                currentState = prevState; 
                restoreState(prevState);
            } else {
                currentState = {screen: 'dashboard-screen'};
                showDashboardInternal();
            }
        }

        function restoreState(s) {
            if(s.screen === 'dashboard-screen') showDashboardInternal();
            else if(s.screen === 'etalase-screen') loadEtalaseProductsInternal(s.idx);
            else if(s.screen === 'brand-screen') {
                if(s.subcat_mode) loadSubCategoryInternal(s.cat, s.brand);
                else loadCategoryInternal(s.cat);
            }
            else if(s.screen === 'brand-vpn') loadVpnCategoryInternal(s.proto);
            else if(s.screen === 'produk-vpn') loadVpnProductsListInternal(s.proto, s.serverId);
            else if(s.screen === 'produk-screen') loadProductsInternal(s.cat, s.brand, s.subcat);
            else if(s.screen === 'history-screen') showHistoryInternal(s.filter);
            else if(s.screen === 'profile-screen') showProfileInternal();
            else if(s.screen === 'notif-screen') showNotifInternal();
            else if(s.screen === 'global-trx-screen') showGlobalTrxInternal();
            else if(s.screen === 'tutorial-screen') showTutorialsInternal();
            else if(s.screen === 'panel-vpn-screen') showPanelVPNInternal();
        }

        function showToast(msg, type='info') {
            let t = document.getElementById('custom-toast-alert');
            if(!t) {
                t = document.createElement('div');
                t.id = 'custom-toast-alert';
                document.body.appendChild(t);
            }
            let icon = type === 'error' ? '⚠️ ' : (type === 'success' ? '✅ ' : 'ℹ️ ');
            t.className = 'custom-toast ' + (type === 'error' ? 'error' : (type === 'success' ? 'success' : '')) + ' show';
            t.innerHTML = icon + '<span>' + msg + '</span>';
            setTimeout(() => { t.classList.remove('show'); }, 3500);
        }

        function copyData(elementId, label) {
            let text = '';
            let el = document.getElementById(elementId);
            if(el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') text = el.value;
            else text = el.innerText;

            if(text && text !== '-') {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(text).then(() => {
                        showToast(label + ' disalin!', 'success');
                    }).catch(err => {
                        showToast('Gagal menyalin', 'error');
                    });
                } else {
                    let textArea = document.createElement("textarea");
                    textArea.value = text;
                    textArea.style.position = "fixed";
                    textArea.style.left = "-999999px";
                    textArea.style.top = "-999999px";
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    try {
                        document.execCommand('copy');
                        showToast(label + ' disalin!', 'success');
                    } catch (err) {
                        showToast('Gagal menyalin', 'error');
                    }
                    document.body.removeChild(textArea);
                }
            }
        }

        function filterGlobalDashboard() {
            let input = document.getElementById('global-search-db').value.toLowerCase();
            let boxes = document.querySelectorAll('.grid-box, #custom-layout-container .brand-row');
            boxes.forEach(box => {
                let text = box.innerText.toLowerCase();
                if (text.includes(input)) box.style.display = 'flex';
                else box.style.display = 'none';
            });
        }

        let deferredPrompt;
        window.addEventListener('beforeinstallprompt', (e) => { 
            e.preventDefault(); deferredPrompt = e;
        });
        if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

        let currentUser = ""; let userData = {}; let allProducts = {}; let selectedSKU = ""; let tempRegPhone = ""; let tempForgotPhone = ""; let tempLoginPhone = ""; let currentEditMode = ""; let currentHistoryItem = null;
        let currentCategory = ""; let currentBrand = ""; let currentHistoryFilter = 'Order'; let currentHistoryStatusFilter = 'Semua';
        let vpnConfigData = null; let selectedVPNProto = ""; let selectedVPNServer = "";
        let currentVpnBasePrice = 0; let currentVpnBaseDesc = "";
        let bannerInterval; let qrisInterval;
        let titleClicks = 0;

        function secretPanelClick() {
            titleClicks++;
            if(titleClicks >= 5) {
                titleClicks = 0;
                if(currentUser) window.showPanelVPN();
                else showToast('Silakan login dulu.', 'error');
            }
            setTimeout(() => { titleClicks = 0; }, 3000);
        }

        function selectPayment(method) {
            document.getElementById('m-payment-method').value = method;
            if(method === 'saldo') {
                document.getElementById('btn-pay-saldo').classList.add('active');
                document.getElementById('btn-pay-qris').classList.remove('active');
            } else {
                document.getElementById('btn-pay-qris').classList.add('active');
                document.getElementById('btn-pay-saldo').classList.remove('active');
            }
        }

        function selectPaymentVpn(method) {
            document.getElementById('m-vpn-payment').value = method;
            if(method === 'saldo') {
                document.getElementById('btn-pay-vpn-saldo').classList.add('active');
                document.getElementById('btn-pay-vpn-qris').classList.remove('active');
            } else {
                document.getElementById('btn-pay-vpn-qris').classList.add('active');
                document.getElementById('btn-pay-vpn-saldo').classList.remove('active');
            }
        }

        let lastDetected = "";
        let toastTimer;
        function checkProvider(val) {
            if(val.length < 4) { lastDetected = ""; return; }
            let prefix = val.substring(0, 4);
            if(val.startsWith('+62')) prefix = '0' + val.substring(3, 6);
            else if(val.startsWith('62')) prefix = '0' + val.substring(2, 5);

            let provider = "";
            if(['0811','0812','0813','0821','0822','0852','0853','0851'].includes(prefix)) provider = "Telkomsel / By.U";
            else if(['0814','0815','0816','0855','0856','0857','0858'].includes(prefix)) provider = "Indosat";
            else if(['0817','0818','0819','0859','0877','0878'].includes(prefix)) provider = "XL";
            else if(['0831','0832','0833','0838'].includes(prefix)) provider = "Axis";
            else if(['0895','0896','0897','0898','0899'].includes(prefix)) provider = "Tri";
            else if(['0881','0882','0883','0884','0885','0886','0887','0888','0889'].includes(prefix)) provider = "Smartfren";

            if(provider && provider !== lastDetected) {
                lastDetected = provider;
                let toast = document.getElementById('provider-toast');
                toast.innerText = "Terdeteksi: " + provider;
                toast.classList.add('show');
                clearTimeout(toastTimer);
                toastTimer = setTimeout(() => { toast.classList.remove('show'); lastDetected = ""; }, 3000);
            }
        }

        async function apiCall(url, bodyData) {
            let options = {};
            let headers = {};
            let token = localStorage.getItem('tendo_token');
            if (token) headers['Authorization'] = 'Bearer ' + token;
            
            if(bodyData) {
                options.method = 'POST';
                headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(bodyData);
            }
            options.headers = headers;
            let res = await fetch(url, options);
            if(res.status === 403) {
                let data = await res.json();
                if(data.message.includes('Token') || data.message.includes('token') || data.message.includes('Akses') || data.message.includes('Sesi')) {
                    logout();
                    showToast(data.message || 'Sesi kedaluwarsa, silakan login ulang.', 'error');
                    return {success: false, message: 'Sesi kedaluwarsa'};
                }
                return data;
            }
            return await res.json();
        }

        async function fetchGlobalStats() {
            try {
                let res = await apiCall('/api/stats');
                if(res && res.success) {
                    document.getElementById('stat-daily').innerText = res.daily;
                    document.getElementById('stat-weekly').innerText = res.weekly;
                    document.getElementById('stat-monthly').innerText = res.monthly;
                    if(document.getElementById('stat-total')) document.getElementById('stat-total').innerText = res.total;
                    if(res.maintStart) sysMaintStart = res.maintStart;
                    if(res.maintEnd) sysMaintEnd = res.maintEnd;
                    if(res.adminWa) adminWaNumber = res.adminWa.replace(/[^0-9]/g, '');
                }
            } catch(e){}
        }

        async function fetchLeaderboard() {
            try {
                let res = await apiCall('/api/leaderboard');
                if(res && res.success && res.data.length > 0) {
                    let html = '<div class="stats-title" style="margin-top:20px; margin-bottom:15px; font-size:14px; text-transform:uppercase;">🏆 Top Sultan 🏆</div><div style="display:flex; flex-direction:column; gap:15px;">';
                    res.data.forEach((u, i) => {
                        let badge = (i === 0) ? '👑' : (i === 1) ? '🥈' : (i === 2) ? '🥉' : `<span style="font-size:14px; font-weight:bold; color:var(--text-muted);">${i+1}</span>`;
                        html += `
                        <div class="brand-row" style="margin: 0; cursor:default;">
                            <div class="b-logo" style="width:40px; height:40px; font-size: 18px;">${badge}</div>
                            <div class="b-name">${u.name}</div>
                            <div style="font-weight:900; color:var(--nav-active); font-size:12px;">${u.trx} Trx</div>
                        </div>`;
                    });
                    html += '</div>';
                    document.getElementById('leaderboard-container').innerHTML = html;
                }
            } catch(e) {}
        }

        async function fetchVPNConfig() {
            try {
                let res = await apiCall('/api/vpn-config');
                if(res && res.success) {
                    vpnConfigData = res.data;
                    renderVpnGrid();
                }
            } catch(e) {}
        }
        
        async function fetchCustomLayout() {
            try {
                let res = await apiCall('/api/custom-layout');
                if(res && res.success && res.data && res.data.sections) {
                    window.etalaseData = res.data.sections;
                    let container = document.getElementById('custom-layout-container');
                    let html = '';
                    res.data.sections.forEach((sec, idx) => {
                        if(sec.skus && sec.skus.length > 0) {
                            html += `
                            <div class="brand-row" onclick="loadEtalaseProducts(${idx})" style="margin: 0 20px 15px;">
                                <div class="b-logo" style="width: 45px; height: 45px;">
                                    ${sec.title.substring(0,2).toUpperCase()}
                                </div>
                                <div class="b-name">${sec.title}</div>
                                <div style="margin-left:auto">
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                </div>
                            </div>`;
                        }
                    });
                    if (html !== '') {
                        container.innerHTML = '<div class="grid-title">Layanan Unggulan</div>' + html;
                    } else {
                        container.innerHTML = '';
                    }
                }
            } catch(e){}
        }

        function loadEtalaseProductsInternal(idx) {
            let sec = window.etalaseData[idx];
            if (!sec) return;
            document.getElementById('cat-title-text').innerText = sec.title;
            document.getElementById('search-product').value = '';
            
            let listHTML = '';
            sec.skus.forEach(sku => {
                let p = allProducts[sku];
                if (p) {
                    let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                    let safeDesc = p.deskripsi ? p.deskripsi.replace(/'/g, "\\'").replace(/"/g, '&quot;') : 'Proses Otomatis';
                    let initial = (p.brand || 'O').substring(0,2).toUpperCase();
                    let statusBadge = p.status_produk === false 
                        ? '<span style="background:var(--bg-main); color:#b91c1c; font-size:9px; padding:4px 8px; border-radius:6px; font-weight:800; box-shadow:var(--shadow-outer); flex-shrink:0; margin-left:8px;">GANGGUAN</span>' 
                        : '<span class="badge-open">OPEN</span>';
                    let onClickAction = p.status_produk === false
                        ? `showToast('Maaf, produk ini sedang gangguan.', 'error')`
                        : `openOrderModal('${sku}', '${safeName}', ${p.harga}, '${safeDesc}')`;
                    
                    listHTML += `
                    <div class="product-item" onclick="${onClickAction}">
                        <div class="prod-logo">${initial}</div>
                        <div class="prod-info">
                            <div class="prod-name">${p.nama} ${statusBadge}</div>
                            <div class="prod-desc">${p.deskripsi ? p.deskripsi.substring(0,40)+'...' : 'Proses Cepat'}</div>
                            <div class="prod-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                        </div>
                    </div>`;
                }
            });
            
            document.getElementById('product-list').innerHTML = '<div class="skeleton-box"></div><div class="skeleton-box"></div><div class="skeleton-box"></div>';
            setTimeout(() => {
                document.getElementById('product-list').innerHTML = listHTML || '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">KOSONG</div>';
            }, 600);
            showScreen('produk-screen', 'nav-home');
        }

        function loadEtalaseProducts(idx) { pushState({screen: 'etalase-screen', idx: idx}); loadEtalaseProductsInternal(idx); }

        function renderVpnGrid() {
            let container = document.getElementById('vpn-grid-container');
            if(!vpnConfigData || !vpnConfigData.products) return;

            let protocols = ['SSH', 'Vmess', 'Vless', 'Trojan', 'ZIVPN'];
            let html = '';
            protocols.forEach(proto => {
                let isAvailable = false;
                for(let pId in vpnConfigData.products) {
                    let prod = vpnConfigData.products[pId];
                    if(prod.protocol.toUpperCase() === proto.toUpperCase()) {
                        let sId = prod.server_id;
                        if(vpnConfigData.servers && vpnConfigData.servers[sId]) {
                            isAvailable = true;
                            break;
                        }
                    }
                }
                
                let statusBadge = isAvailable 
                    ? '<div style="font-size:9px; background:#16a34a; color:#ffffff; padding:4px 8px; border-radius:6px; margin-top:8px; font-weight:800; box-shadow:var(--shadow-outer);">Tersedia</div>' 
                    : '<div style="font-size:9px; background:#ef4444; color:#ffffff; padding:4px 8px; border-radius:6px; margin-top:8px; font-weight:800; box-shadow:var(--shadow-outer);">Kosong</div>';

                let iconSvg = '';
                if(proto.toUpperCase() === 'SSH') iconSvg = '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z"></path>';
                else if(proto.toUpperCase() === 'VMESS') iconSvg = '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>';
                else if(proto.toUpperCase() === 'VLESS') iconSvg = '<path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>';
                else if(proto.toUpperCase() === 'TROJAN') iconSvg = '<path d="M2 22l5-5M22 2l-5 5M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z"></path>';
                else if(proto.toUpperCase() === 'ZIVPN') iconSvg = '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>';
                else iconSvg = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>';

                html += `
                <div class="grid-box" onclick="loadVpnCategory('${proto}')">
                    <div class="grid-icon-wrap ic-vpn">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                            ${iconSvg}
                        </svg>
                    </div>
                    <div class="grid-text">${proto}</div>
                    ${statusBadge}
                </div>`;
            });
            
            html += `
            <div class="grid-box" onclick="showTutorials()">
                <div class="grid-icon-wrap" style="color: #ec4899;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="28" height="28">
                        <polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect>
                    </svg>
                </div>
                <div class="grid-text">TUTORIAL</div>
            </div>`;

            container.innerHTML = html;
        }

        function loadVpnCategoryInternal(proto) {
            document.getElementById('brand-cat-title').innerText = proto;
            localStorage.setItem('tendo_current_vpn_proto', proto);
            localStorage.setItem('tendo_current_vpn_server', '');
            localStorage.setItem('tendo_is_vpn', 'true');
            
            let serversMap = {};
            if(vpnConfigData && vpnConfigData.products && vpnConfigData.servers) {
                for(let pId in vpnConfigData.products) {
                    let prod = vpnConfigData.products[pId];
                    if(prod.protocol.toUpperCase() === proto.toUpperCase()) {
                        let sId = prod.server_id;
                        if(!serversMap[sId]) {
                            let srv = vpnConfigData.servers[sId];
                            if(srv && srv.host) {
                                let srvName = srv.server_name || sId;
                                let flag = (srv.city && srv.city.toLowerCase().includes('sg')) ? '🇸🇬' : ((srv.city && srv.city.toLowerCase().includes('id')) ? '🇮🇩' : '🌐');
                                serversMap[sId] = { name: srvName, flag: flag };
                            }
                        }
                    }
                }
            }

            let html = '';
            for(let sId in serversMap) {
                let s = serversMap[sId];
                html += `
                <div class="brand-row" onclick="loadVpnProductsList('${proto}', '${sId}')">
                    <div class="b-logo">${s.flag}</div>
                    <div class="b-name">Server ${s.name}</div>
                    <div style="margin-left:auto">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </div>
                </div>`;
            }

            if(html === '') html = '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">Belum ada server untuk protokol ini.</div>';
            document.getElementById('brand-list').innerHTML = html;
            showScreen('brand-screen', 'nav-home');
        }
        function loadVpnCategory(proto) { pushState({screen: 'brand-vpn', proto: proto}); loadVpnCategoryInternal(proto); }

        function loadVpnProductsListInternal(proto, serverId) {
            let srv = vpnConfigData.servers[serverId];
            let srvName = srv ? (srv.server_name || serverId) : serverId;
            document.getElementById('cat-title-text').innerText = "Server " + srvName;
            document.getElementById('search-product').value = '';
            localStorage.setItem('tendo_current_vpn_proto', proto);
            localStorage.setItem('tendo_current_vpn_server', serverId);
            localStorage.setItem('tendo_is_vpn', 'true');

            let html = '';
            if(vpnConfigData && vpnConfigData.products) {
                for(let pId in vpnConfigData.products) {
                    let prod = vpnConfigData.products[pId];
                    if(prod.protocol.toUpperCase() === proto.toUpperCase() && prod.server_id === serverId) {
                        let price = prod.price || 0;
                        let stok = prod.stok !== undefined ? parseInt(prod.stok) : 0;
                        let desc = prod.desc || 'Proses Otomatis';
                        let customName = prod.name || `${proto} Premium`;
                        let safeDesc = desc.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                        let safeName = customName.replace(/'/g, "\\'").replace(/"/g, '&quot;');

                        let statusBadge = stok > 0 
                            ? '<span class="badge-open" style="background:#16a34a; color:#ffffff; box-shadow:var(--shadow-outer);">STOK: '+stok+'</span>' 
                            : '<span style="background:#ef4444; color:#ffffff; font-size:9px; padding:4px 8px; border-radius:6px; font-weight:800; box-shadow:var(--shadow-outer); flex-shrink:0; margin-left:8px;">HABIS</span>';

                        let initial = proto.substring(0,2).toUpperCase();

                        html += `
                        <div class="product-item" style="cursor:default; display:flex; flex-direction:column; align-items:stretch;">
                            <div style="display:flex; align-items:center; gap:15px; width:100%;">
                                <div class="prod-logo">${initial}</div>
                                <div class="prod-info">
                                    <div class="prod-name">${customName} ${statusBadge}</div>
                                    <div class="prod-desc">${desc.substring(0,40)}...</div>
                                    <div class="prod-price" style="margin-bottom:8px;">Rp ${price.toLocaleString('id-ID')}</div>
                                </div>
                            </div>
                            <div style="display:flex; gap:10px; margin-top:12px; width:100%;">
                                <button class="btn" style="flex:1; padding:12px; font-size:12px; border-radius:12px;" onclick="openVPNOrderModal('${pId}', '${proto}', ${price}, '${safeDesc}', '${safeName}')" ${stok > 0 ? '' : 'disabled'}>Beli Premium</button>
                                <button class="btn-outline" style="flex:1; padding:12px; font-size:12px; border-radius:12px; color:#10b981; margin-top:0;" onclick="openVPNTrialModal('${pId}', '${proto}', '${safeName}')">Trial Gratis</button>
                            </div>
                        </div>`;
                    }
                }
            }

            document.getElementById('product-list').innerHTML = '<div class="skeleton-box"></div><div class="skeleton-box"></div><div class="skeleton-box"></div>';
            setTimeout(() => {
                document.getElementById('product-list').innerHTML = html || '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">KOSONG</div>';
            }, 600);
            showScreen('produk-screen', 'nav-home');
        }
        function loadVpnProductsList(proto, serverId) { pushState({screen: 'produk-vpn', proto: proto, serverId: serverId}); loadVpnProductsListInternal(proto, serverId); }

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

        function filterProducts() {
            let input = document.getElementById('search-product').value.toLowerCase();
            let items = document.querySelectorAll('#product-list .product-item');
            items.forEach(item => {
                let name = item.querySelector('.prod-name').innerText.toLowerCase();
                if (name.includes(input)) item.style.display = 'flex';
                else item.style.display = 'none';
            });
        }

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
            let loader = document.getElementById('initial-loader');
            if(loader) { loader.style.opacity = '0'; setTimeout(() => { if(loader) loader.style.display = 'none'; }, 300); }

            ['login-screen', 'login-otp-screen', 'register-screen', 'otp-screen', 'forgot-screen', 'dashboard-screen', 'brand-screen', 'produk-screen', 'history-screen', 'profile-screen', 'notif-screen', 'global-trx-screen', 'tutorial-screen', 'panel-vpn-screen'].forEach(s => {
                let el = document.getElementById(s);
                if(el) el.classList.add('hidden');
            });
            let targetEl = document.getElementById(id);
            if(targetEl) targetEl.classList.remove('hidden');
            
            if (['dashboard-screen', 'history-screen', 'notif-screen', 'profile-screen', 'brand-screen', 'produk-screen', 'global-trx-screen', 'tutorial-screen'].includes(id)) {
                localStorage.setItem('tendo_last_tab', id);
            }
            if (navId) {
                localStorage.setItem('tendo_last_nav', navId);
                updateNav(navId);
            }
            
            let btnWa = document.getElementById('floating-wa-btn');
            if(id === 'login-screen' || id === 'login-otp-screen' || id === 'register-screen' || id === 'otp-screen' || id === 'forgot-screen' || id === 'panel-vpn-screen') {
                document.getElementById('home-topbar').classList.add('hidden');
                document.getElementById('main-bottom-nav').classList.add('hidden');
                document.getElementById('banner-container-wrap').classList.add('hidden');
                if(btnWa) btnWa.classList.add('hidden');
            } else {
                document.getElementById('home-topbar').classList.remove('hidden');
                document.getElementById('main-bottom-nav').classList.remove('hidden');
                if(btnWa) btnWa.classList.remove('hidden');
                
                if(id === 'dashboard-screen') document.getElementById('banner-container-wrap').classList.remove('hidden');
                else document.getElementById('banner-container-wrap').classList.add('hidden');
            }
        }

        document.addEventListener('DOMContentLoaded', async () => {
            let savedTheme = localStorage.getItem('tendo_theme');
            if(savedTheme) {
                applyTheme(savedTheme === 'dark');
            } else {
                let hour = new Date().getHours();
                let isNight = hour >= 18 || hour < 6;
                let sysDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
                applyTheme(isNight || sysDark);
            }

            let savedId = localStorage.getItem('tendo_rem_id');
            let savedPass = localStorage.getItem('tendo_rem_pass');
            if(savedId && savedPass) {
                document.getElementById('log-id').value = savedId;
                document.getElementById('log-pass').value = savedPass;
                login(true);
            } else {
                showDashboardInternal(); 
            }
        });

        async function showDashboardInternal() { 
            showScreen('dashboard-screen', 'nav-home'); 
            if(currentUser) {
                syncUserData(); 
            } else {
                let sbAvatar = document.getElementById('sb-avatar');
                if(sbAvatar) sbAvatar.innerHTML = '<svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="var(--nav-active)" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>';
                document.getElementById('sb-name').innerText = "Guest (Belum Login)";
                document.getElementById('sb-phone').innerText = "Silakan login untuk transaksi";
                document.getElementById('user-saldo').innerText = "Rp 0";
                document.getElementById('top-trx-badge').innerText = "0 Trx";
                let btnSidebarLogout = document.getElementById('sidebar-logout-btn');
                if(btnSidebarLogout) btnSidebarLogout.innerHTML = '<svg viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path><polyline points="10 17 15 12 10 7"></polyline><line x1="15" y1="12" x2="3" y2="12"></line></svg> <span>Masuk / Daftar</span>';
            }
            await fetchAllProducts(); 
            fetchCustomLayout();
            fetchVPNConfig(); 
            fetchLeaderboard();
        }
        function showDashboard() { pushState({screen: 'dashboard-screen'}); showDashboardInternal(); }
        
        async function showTutorialsInternal() {
            showScreen('tutorial-screen', 'nav-home');
            try {
                let data = await apiCall('/api/tutorials');
                let html = '';
                if(data && Array.isArray(data) && data.length > 0) {
                    data.forEach(t => {
                        let videoHtml = '';
                        if(t.video && t.video !== '' && t.video !== '-') {
                            videoHtml = `<video width="100%" controls style="border-radius:10px; margin-bottom:10px; background:#000;">
                                <source src="/tutorials/${t.video}" type="video/mp4">
                            </video>`;
                        }
                        
                        html += `
                        <div class="card" style="margin-bottom:15px; padding:20px;">
                            <h3 style="margin-top:0; font-size:15px; color:var(--text-main);">${t.title}</h3>
                            ${videoHtml}
                            <div style="font-size:12px; color:var(--text-muted); line-height:1.6; white-space: pre-line;">${t.desc}</div>
                        </div>`;
                    });
                } else {
                    html = '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">Belum ada tutorial saat ini.</div>';
                }
                document.getElementById('tutorial-list').innerHTML = html;
            } catch(e){}
        }
        function showTutorials() { pushState({screen: 'tutorial-screen'}); showTutorialsInternal(); }

        window.showPanelVPNInternal = function() {
            showScreen('panel-vpn-screen');
            let sel = document.getElementById('mv-server');
            sel.innerHTML = '<option value="">Pilih Server...</option>';
            if(vpnConfigData && vpnConfigData.servers) {
                for(let id in vpnConfigData.servers) {
                    let opt = document.createElement('option');
                    opt.value = id; opt.innerText = id + ' - ' + vpnConfigData.servers[id].server_name;
                    sel.appendChild(opt);
                }
            }
        }
        window.showPanelVPN = function() { pushState({screen: 'panel-vpn-screen'}); showPanelVPNInternal(); }

        window.toggleManualVpnFields = function() {
            let mode = document.getElementById('mv-mode').value;
            let type = document.getElementById('mv-type').value;
            if(mode === 'trial') {
                document.getElementById('mv-reguler-group').style.display = 'none';
                document.getElementById('mv-pass-group').style.display = 'none';
                document.getElementById('mv-trial-info').style.display = 'block';
            } else {
                document.getElementById('mv-reguler-group').style.display = 'block';
                document.getElementById('mv-trial-info').style.display = 'none';
                if(type === 'ssh' || type === 'zivpn') document.getElementById('mv-pass-group').style.display = 'block';
                else document.getElementById('mv-pass-group').style.display = 'none';
            }
        }

        window.processManualVpn = async function() {
            let server_id = document.getElementById('mv-server').value;
            let mode = document.getElementById('mv-mode').value;
            let type = document.getElementById('mv-type').value;
            let username = document.getElementById('mv-user').value;
            let password = document.getElementById('mv-pass').value;
            let expired = document.getElementById('mv-exp').value;

            if(!server_id) return showToast('Pilih server terlebih dahulu!', 'error');
            if(mode === 'reguler' && (!username || username.trim() === '')) return showToast('Isi username pelanggan!', 'error');

            let btn = document.getElementById('btn-mv-submit');
            let ori = btn.innerText; btn.innerText = "Memproses Ke VPS..."; btn.disabled = true;
            document.getElementById('mv-result').classList.add('hidden');

            try {
                let res = await apiCall('/api/manual-vpn', {server_id, mode, type, username, password, expired});
                if(res.success) {
                    showToast('Akun berhasil dibuat di server!', 'success');
                    let d = res.data; let srv = res.server;
                    let expStr = mode === 'trial' ? '30 Menit' : expired + ' Hari';
                    
                    let text = `====================================\nAkun ${type.toUpperCase()} ${mode === 'trial'?'Trial':'Premium'}\n====================================\n`;
                    text += `Domain Host  : ${srv.host}\n`;
                    text += `City         : ${d.city || srv.city || '-'}\n`;
                    text += `ISP          : ${d.isp || srv.isp || '-'}\n`;
                    text += `Username     : ${d.username || username || 'TrialUser'}\n`;
                    
                    if(type === 'ssh' || type === 'zivpn') {
                        text += `Password     : ${d.password || password || '1'}\n`;
                    } else {
                        text += `ID / UUID    : ${d.uuid || d.id || '-'}\n`;
                    }
                    text += `Expired On   : ${d.expired || d.exp || d.to || expStr}\n`;
                    text += `Limit IP     : 2 Device\n`;
                    text += `====================================\n`;

                    if(d.port) {
                        text += `[ Informasi Port ]\nTLS: ${d.port.tls || '-'}\nNon-TLS: ${d.port.none || '-'}\nUDP Custom: ${d.port.udpcustom || '-'}\n====================================\n`;
                    }

                    if(d.link) {
                        if(d.link.tls) text += `[ Link TLS ]\n${d.link.tls}\n====================================\n`;
                        if(d.link.none) text += `[ Link Non-TLS ]\n${d.link.none}\n====================================\n`;
                        if(d.link.grpc) text += `[ Link gRPC ]\n${d.link.grpc}\n====================================\n`;
                    }

                    document.getElementById('mv-result-text').value = text;
                    document.getElementById('mv-result').classList.remove('hidden');
                } else {
                    showToast('Gagal: ' + res.message, 'error');
                }
            } catch(e) { showToast('Kesalahan Jaringan: ' + e.message, 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        function showHistoryInternal(filter) { 
            if(!currentUser) {
                showToast("Silakan masuk/daftar terlebih dahulu.", "error");
                showScreen("login-screen", null);
                return;
            }
            currentHistoryFilter = filter;
            localStorage.setItem('tendo_history_filter', filter);

            document.getElementById('tab-hist-order').classList.remove('active');
            document.getElementById('tab-hist-topup').classList.remove('active');
            
            if(filter === 'Topup') {
                document.getElementById('tab-hist-topup').classList.add('active');
                document.getElementById('history-title-text').innerText = 'Riwayat Topup';
            } else {
                document.getElementById('tab-hist-order').classList.add('active');
                document.getElementById('history-title-text').innerText = 'Riwayat Transaksi';
            }
            showScreen('history-screen', 'nav-history'); 
            syncUserData(); 
        }
        function showHistory(filter = 'Order') { pushState({screen: 'history-screen', filter: filter}); showHistoryInternal(filter); }
        
        function filterHistoryStatus(status, el) {
            currentHistoryStatusFilter = status;
            let btns = document.querySelectorAll('#status-filter-container .status-btn');
            btns.forEach(b => b.classList.remove('active'));
            el.classList.add('active');
            syncUserData();
        }

        function showProfileInternal() { 
            if(!currentUser) {
                showToast("Silakan masuk/daftar terlebih dahulu.", "error");
                showScreen("login-screen", null);
                return;
            }
            showScreen('profile-screen', 'nav-profile'); syncUserData(); 
        }
        function showProfile() { pushState({screen: 'profile-screen'}); showProfileInternal(); }

        async function showGlobalTrxInternal() {
            showScreen('global-trx-screen', 'nav-global-trx');
            try {
                let data = await apiCall('/api/global-trx');
                let html = '';
                if(data && Array.isArray(data) && data.length > 0) {
                    data.forEach(n => {
                        html += `
                        <div class="card" style="border-left: 4px solid #10b981; margin-bottom:15px; padding:18px;">
                            <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); margin-bottom:5px; font-weight:700;">
                                <span>🕒 ${n.time} WIB</span>
                                <span style="color:#10b981;">Berhasil</span>
                            </div>
                            <div style="font-weight:800; font-size:14px; margin-bottom:4px; color:var(--text-main);">${n.product}</div>
                            <div style="font-size:12px; font-weight:600; color:var(--text-muted);">Akun: ${n.user}</div>
                            <div style="font-size:12px; font-weight:600; color:var(--text-muted);">Tujuan: ${n.target}</div>
                            <div style="font-size:12px; font-weight:600; color:var(--text-muted);">Harga: Rp ${n.price ? n.price.toLocaleString('id-ID') : '0'}</div>
                            <div style="font-size:12px; font-weight:600; color:var(--text-muted);">Metode: ${n.method || 'Saldo Akun'}</div>
                        </div>`;
                    });
                } else {
                    html = '<div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Belum ada transaksi terbaru.</div>';
                }
                document.getElementById('global-trx-list').innerHTML = html;
            } catch(e){}
        }
        function showGlobalTrx() { pushState({screen: 'global-trx-screen'}); showGlobalTrxInternal(); }
        
        async function showNotifInternal() { 
            showScreen('notif-screen', 'nav-notif'); 
            try {
                let data = await apiCall('/api/notif');
                let html = '';
                if(data && Array.isArray(data) && data.length > 0) {
                    data.forEach(n => {
                        let imgTag = '';
                        if(n.image) {
                            let imgSrc = n.image.startsWith('maint_') ? `/maint_images/${n.image}` : `/info_images/${n.image}`;
                            imgTag = `<img src="${imgSrc}" style="width:100%; border-radius:12px; margin-bottom:12px; display:block;">`;
                        }
                        
                        html += `
                        <div class="card" style="border-left: 4px solid var(--nav-active); margin-bottom:15px; padding:18px;">
                            <div style="font-size:10px; color:var(--text-muted); margin-bottom:5px; font-weight:700;">${n.date}</div>
                            <h3 style="margin-top:0; color: var(--text-main); font-size:15px; margin-bottom:12px;">📢 Info Terbaru</h3>
                            ${imgTag}
                            <p style="color: var(--text-muted); line-height: 1.6; font-size:13px; white-space: pre-wrap; font-weight: 500; margin:0;">${n.text}</p>
                        </div>`;
                    });
                } else {
                    html = '<div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Tidak ada pemberitahuan sistem saat ini.</div>';
                }
                document.getElementById('notif-list').innerHTML = html;
            } catch(e){}
        }
        function showNotif() { pushState({screen: 'notif-screen'}); showNotifInternal(); }

        function openTopupModal() { 
            if(!currentUser) {
                showToast("Silakan masuk/daftar terlebih dahulu untuk isi saldo.", "error");
                showScreen("login-screen", null);
                return;
            }
            document.getElementById('topup-nominal').value = ''; document.getElementById('topup-modal').classList.remove('hidden'); 
        }
        function closeTopupModal() { document.getElementById('topup-modal').classList.add('hidden'); }
        
        async function generateQris() {
            let nom = parseInt(document.getElementById('topup-nominal').value);
            if(!nom || nom < 1000) return showToast("Minimal Topup Rp 1.000", "error");
            let btn = document.getElementById('btn-topup-submit');
            btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/topup', {phone: currentUser, nominal: nom});
                if(data && data.success) { 
                    closeTopupModal();
                    document.getElementById('topup-success-modal').classList.remove('hidden');
                } else { showToast(data.message || "Sistem QRIS Sedang Gangguan / Belum diatur admin.", "error"); }
            } catch(e) { showToast("Kesalahan server.", "error"); }
            
            btn.innerText = "Buat QRIS"; btn.disabled = false;
        }

        async function closeTopupSuccessModal() {
            document.getElementById('topup-success-modal').classList.add('hidden');
            await syncUserData(); 
            showHistory('Topup');
            if(userData.history && userData.history.length > 0) {
                let latest = userData.history.find(h => (h.type === 'Topup' || h.type === 'Order QRIS' || h.type === 'Order VPN QRIS') && h.status === 'Pending');
                if(latest) openHistoryDetail(latest);
            }
        }

        async function shareQRIS() {
            let imgUrl = document.getElementById('hd-qris-img').src;
            if(!imgUrl) return;
            try {
                let response = await fetch(imgUrl, { mode: 'cors' });
                let blob = await response.blob();
                let file = new File([blob], "QRIS_Digital_Tendo.jpg", { type: "image/jpeg" });
                
                if (navigator.canShare && navigator.canShare({ files: [file] })) {
                    await navigator.share({
                        title: 'QRIS Pembayaran',
                        text: 'Silakan scan QRIS berikut untuk melakukan pembayaran.',
                        files: [file]
                    });
                } else {
                    showToast("Browser tidak mendukung bagikan gambar. Gunakan tombol Simpan.", "error");
                }
            } catch(e) { showToast("Gagal membagikan gambar QRIS.", "error"); }
        }

        async function downloadQRIS() {
            let imgUrl = document.getElementById('hd-qris-img').src;
            if(!imgUrl) return;
            try {
                let response = await fetch(imgUrl, { mode: 'cors' });
                let blob = await response.blob();
                let url = window.URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = 'QRIS_Topup_' + Date.now() + '.jpg';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } catch(e) {
                let a = document.createElement('a');
                a.href = imgUrl;
                a.target = '_blank';
                a.download = 'QRIS_Topup.jpg';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }
        }

        function manualTopupWA() {
            let email = userData.email || "-";
            let phone = currentUser || "-";
            let nom = document.getElementById('topup-nominal').value || "[Sebutkan Nominal]";
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya ingin melakukan *Topup Saldo Manual*.%0A%0A📧 Email Akun: *${email}*%0A📱 Nomor WA: *${phone}*%0A💰 Nominal: *Rp ${nom}*%0A%0AMohon info panduan transfernya. Terima kasih.`;
            window.open(`https://wa.me/${adminWaNumber}?text=${pesan}`, '_blank');
        }

        async function logout() {
            try {
                await apiCall('/api/logout', {});
            } catch(e){}
            currentUser = ""; userData = {}; 
            localStorage.removeItem('tendo_rem_id'); localStorage.removeItem('tendo_rem_pass');
            localStorage.removeItem('tendo_last_tab'); localStorage.removeItem('tendo_last_nav');
            localStorage.removeItem('tendo_history_filter');
            localStorage.removeItem('tendo_current_cat'); localStorage.removeItem('tendo_current_brand');
            localStorage.removeItem('tendo_current_vpn_proto'); localStorage.removeItem('tendo_current_vpn_server');
            localStorage.removeItem('tendo_is_vpn');
            localStorage.removeItem('tendo_token');
            let btnSidebarLogout = document.getElementById('sidebar-logout-btn');
            if(btnSidebarLogout) btnSidebarLogout.innerHTML = '<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg> <span>Keluar Akun</span>';
            toggleSidebar(); showScreen('login-screen', null);
            document.getElementById('log-pass').value = '';
        }

        async function syncUserData() {
            if(!currentUser) return;
            try {
                let data = await apiCall('/api/user/' + currentUser);
                if(data && data.success) {
                    userData = data.data; let u = userData;
                    
                    let elSaldo = document.getElementById('user-saldo');
                    elSaldo.setAttribute('data-saldo', u.saldo);
                    elSaldo.innerText = 'Rp ' + u.saldo.toLocaleString('id-ID');

                    document.getElementById('top-trx-badge').innerText = (u.trx_count || 0) + ' Trx';
                    
                    let shanksGif = 'https://cdn-icons-png.flaticon.com/512/3135/3135715.png';
                    document.getElementById('sb-avatar').innerHTML = '<img src="' + shanksGif + '" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">';
                    document.getElementById('sb-name').innerText = u.username || "Member";
                    document.getElementById('sb-phone').innerText = currentUser;

                    let btnSidebarLogout = document.getElementById('sidebar-logout-btn');
                    if(btnSidebarLogout) btnSidebarLogout.innerHTML = '<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg> <span>Keluar Akun</span>';

                    document.getElementById('p-avatar').innerHTML = '<img src="' + shanksGif + '" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">';
                    document.getElementById('p-username').innerText = u.username || "Member";
                    document.getElementById('p-id').innerText = "ID: " + (u.id_pelanggan || "TD-000");
                    document.getElementById('p-email').innerText = u.email || '-';
                    document.getElementById('p-username-val').innerText = u.username || "Member";
                    document.getElementById('p-phone').innerText = currentUser;
                    document.getElementById('p-date').innerText = u.tanggal_daftar || '-';
                    document.getElementById('p-trx').innerText = (u.trx_count || 0) + ' Kali';

                    let histHTML = '';
                    let historyList = u.history || [];
                    
                    historyList = historyList.filter(h => {
                        let typeMatch = false;
                        let type = h.type || 'Order';
                        if (currentHistoryFilter === 'Topup') typeMatch = (type === 'Topup');
                        else typeMatch = (type === 'Order' || type === 'Order QRIS' || type === 'Refund' || type === 'Order VPN' || type === 'Order VPN QRIS');
                        
                        if(!typeMatch) return false;

                        if (currentHistoryStatusFilter === 'Semua') return true;
                        if (currentHistoryStatusFilter === 'Sukses' && (h.status === 'Sukses' || h.status === 'Sukses Bayar')) return true;
                        if (currentHistoryStatusFilter === 'Pending' && h.status === 'Pending') return true;
                        if (currentHistoryStatusFilter === 'Gagal' && (h.status === 'Gagal' || h.status === 'Gagal (Kedaluwarsa)' || h.status === 'Gagal (Dibatalkan)' || h.status === 'Refund')) return true;
                        
                        return false;
                    });

                    if(historyList.length === 0) histHTML = '<div style="text-align:center; color:var(--text-muted); font-weight:bold; margin-top: 30px; font-size:13px;">Belum ada transaksi di filter ini.</div>';
                    else {
                        historyList.forEach((h, idx) => {
                            let statClass = 'stat-Pending';
                            if(h.status === 'Sukses' || h.status === 'Sukses Bayar') statClass = 'stat-Sukses';
                            if(h.status === 'Gagal' || h.status === 'Gagal (Kedaluwarsa)' || h.status === 'Gagal (Dibatalkan)') statClass = 'stat-Gagal';
                            if(h.type === 'Refund' || h.status === 'Refund') statClass = 'stat-Refund';
                            
                            let displayTujuan = h.tujuan; 
                            
                            let safeH = JSON.stringify(h).replace(/"/g, '&quot;');
                            histHTML += `
                                <div class="hist-item" onclick='openHistoryDetail(${safeH})'>
                                    <div class="hist-top"><span>${h.tanggal}</span> <span class="stat-badge ${statClass}">${h.status}</span></div>
                                    <div class="hist-title" style="display:flex; justify-content:space-between; align-items:center;">
                                        <span style="max-width:65%;">${h.nama}</span>
                                        <span style="color:var(--nav-active); font-size:13px;">Rp ${h.amount ? h.amount.toLocaleString('id-ID') : '0'}</span>
                                    </div>
                                    <div class="hist-target">Tujuan: ${displayTujuan}</div>
                                </div>
                            `;
                        });
                    }
                    document.getElementById('history-list').innerHTML = histHTML;
                }
            } catch(e) {}
        }

        function startQrisCountdown(expiredAt) {
            clearInterval(qrisInterval);
            let el = document.getElementById('qris-countdown');
            
            function update() {
                let now = Date.now();
                let diff = expiredAt - now;
                if (diff <= 0) {
                    clearInterval(qrisInterval);
                    el.innerText = "KEDALUWARSA";
                    document.getElementById('hd-status').innerText = 'Gagal (Kedaluwarsa)';
                    document.getElementById('hd-qris-box').classList.add('hidden');
                    if(currentHistoryItem) currentHistoryItem.status = 'Gagal (Kedaluwarsa)';
                } else {
                    let m = Math.floor(diff / 60000);
                    let s = Math.floor((diff % 60000) / 1000);
                    el.innerText = (m < 10 ? "0" + m : m) + " : " + (s < 10 ? "0" + s : s);
                }
            }
            update();
            qrisInterval = setInterval(update, 1000);
        }

        function openHistoryDetail(h) {
            currentHistoryItem = h;
            document.getElementById('hd-time').innerText = h.tanggal;
            document.getElementById('hd-status').innerText = h.status;
            document.getElementById('hd-name').innerText = h.nama;
            document.getElementById('hd-amount').innerText = h.amount ? 'Rp ' + h.amount.toLocaleString('id-ID') : '-';
            
            let displayTujuan = h.tujuan; 
            document.getElementById('hd-target').innerText = displayTujuan;
            
            document.getElementById('hd-sn').innerText = h.sn || '-';
            
            let btnComplain = document.getElementById('hd-complain-btn');
            btnComplain.classList.remove('hidden'); 

            let btnCancel = document.getElementById('hd-cancel-topup-btn');
            if(h.type === 'Topup' && h.status === 'Pending') {
                btnCancel.classList.remove('hidden');
            } else {
                btnCancel.classList.add('hidden');
            }

            if(h.saldo_sebelumnya !== undefined) {
                document.querySelectorAll('.hd-saldo-row').forEach(el => el.classList.remove('hidden'));
                document.getElementById('hd-saldo-sebelum').innerText = 'Rp ' + h.saldo_sebelumnya.toLocaleString('id-ID');
                document.getElementById('hd-saldo-sesudah').innerText = 'Rp ' + h.saldo_sesudah.toLocaleString('id-ID');
            } else {
                document.querySelectorAll('.hd-saldo-row').forEach(el => el.classList.add('hidden'));
            }
            
            let qrisBox = document.getElementById('hd-qris-box');
            if((h.type === 'Topup' || h.type === 'Order QRIS' || h.type === 'Order VPN QRIS') && h.status === 'Pending') {
                if(Date.now() < h.expired_at) {
                    document.getElementById('hd-qris-img').src = h.qris_url;
                    document.getElementById('hd-qris-amount').innerText = 'Rp ' + h.amount.toLocaleString('id-ID');
                    qrisBox.classList.remove('hidden');
                    startQrisCountdown(h.expired_at);
                } else {
                    qrisBox.classList.add('hidden');
                    document.getElementById('hd-status').innerText = 'Gagal (Kedaluwarsa)';
                }
            } else {
                qrisBox.classList.add('hidden');
                clearInterval(qrisInterval);
            }

            let vpnInfoBox = document.getElementById('hd-vpn-info-box');
            if(h.vpn_details) {
                document.getElementById('hd-vpn-details').value = h.vpn_details;
                vpnInfoBox.classList.remove('hidden');
            } else {
                vpnInfoBox.classList.add('hidden');
            }
            
            document.getElementById('history-detail-modal').classList.remove('hidden');
        }
        
        function closeHistoryModal() { 
            clearInterval(qrisInterval);
            document.getElementById('history-detail-modal').classList.add('hidden'); 
        }

        async function cancelTopup() {
            if(!currentHistoryItem) return;
            if(confirm("Yakin ingin membatalkan topup ini?")) {
                let btn = document.getElementById('hd-cancel-topup-btn');
                let ori = btn.innerText; btn.innerText = "Membatalkan..."; btn.disabled = true;
                try {
                    let res = await apiCall('/api/cancel-topup', { sn: currentHistoryItem.sn, phone: currentUser });
                    if(res.success) {
                        showToast("Topup berhasil dibatalkan", "success");
                        closeHistoryModal();
                        syncUserData();
                    } else {
                        showToast(res.message || "Gagal membatalkan", "error");
                    }
                } catch(e) { showToast("Kesalahan jaringan", "error"); }
                btn.innerText = ori; btn.disabled = false;
            }
        }
        
        function contactAdmin() {
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya butuh bantuan terkait akun / layanan.`;
            window.open(`https://wa.me/${adminWaNumber}?text=${pesan}`, '_blank');
        }
        
        function complainAdmin() {
            let h = currentHistoryItem;
            if(!h) { contactAdmin(); return; }
            let email = userData.email || "-";
            let phone = currentUser || "-";
            let currentSaldo = userData.saldo || 0;
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya ingin komplain/tanya transaksi ini:%0A%0A📧 Email: *${email}*%0A📱 Nomor WA: *${phone}*%0A💰 Saldo Saat Ini: *Rp ${currentSaldo.toLocaleString('id-ID')}*%0A💸 Nominal Transaksi: *Rp ${h.amount ? h.amount.toLocaleString('id-ID') : '0'}*%0A📦 Layanan: *${h.nama}*%0A📱 Tujuan: *${h.tujuan}*%0A🕒 Waktu: *${h.tanggal}*%0A⚙️ Status: *${h.status}*%0A🔑 SN/Ref: *${h.sn || '-'}*%0A%0AMohon bantuannya dicek.%0A%0A_*(Note: Jika komplain topup/pembayaran belum masuk, mohon kirimkan juga foto/bukti transfernya)*_ Terima kasih.`;
            window.open(`https://wa.me/${adminWaNumber}?text=${pesan}`, '_blank');
        }

        async function login(isAuto = false) {
            let idLogin = document.getElementById('log-id').value.trim();
            let pass = document.getElementById('log-pass').value.trim();
            let rem = document.getElementById('rem-login').checked;
            if(!idLogin || !pass) {
                if(!isAuto) showToast('Isi Email/WA/Username & Password!', 'error');
                return;
            }
            
            let btn = document.getElementById('btn-login');
            let ori = btn.innerText;
            btn.innerText = "Memeriksa..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/login', {id: idLogin, password:pass});
                if(data && data.success) {
                    currentUser = data.phone; userData = data.data;
                    if(data.token) localStorage.setItem('tendo_token', data.token);
                    await fetchAllProducts(); 
                    await fetchVPNConfig();
                    fetchGlobalStats();
                    fetchLeaderboard();
                    loadBanners();
                    
                    let lastTab = localStorage.getItem('tendo_last_tab') || 'dashboard-screen';
                    currentState = { screen: lastTab };
                    let isVpn = localStorage.getItem('tendo_is_vpn') === 'true';
                    
                    if (lastTab === 'history-screen') {
                        let savedFilter = localStorage.getItem('tendo_history_filter') || 'Order';
                        showHistoryInternal(savedFilter);
                        currentState.filter = savedFilter;
                    }
                    else if (lastTab === 'profile-screen') showProfileInternal();
                    else if (lastTab === 'notif-screen') showNotifInternal();
                    else if (lastTab === 'global-trx-screen') showGlobalTrxInternal();
                    else if (lastTab === 'tutorial-screen') showTutorialsInternal();
                    else if (lastTab === 'panel-vpn-screen') showPanelVPNInternal();
                    else if (lastTab === 'brand-screen') {
                        if(isVpn) {
                            let cProto = localStorage.getItem('tendo_current_vpn_proto');
                            if(cProto) { loadVpnCategoryInternal(cProto); currentState = {screen: 'brand-vpn', proto: cProto}; }
                            else showDashboardInternal();
                        } else {
                            let cCat = localStorage.getItem('tendo_current_cat');
                            if(cCat) { loadCategoryInternal(cCat); currentState.cat = cCat; currentState.subcat_mode = false; }
                            else showDashboardInternal();
                        }
                    }
                    else if (lastTab === 'produk-screen') {
                        if(isVpn) {
                            let cProto = localStorage.getItem('tendo_current_vpn_proto');
                            let cServer = localStorage.getItem('tendo_current_vpn_server');
                            if(cProto && cServer) { loadVpnProductsListInternal(cProto, cServer); currentState = {screen: 'produk-vpn', proto: cProto, serverId: cServer}; }
                            else showDashboardInternal();
                        } else {
                            let cCat = localStorage.getItem('tendo_current_cat');
                            let cBrand = localStorage.getItem('tendo_current_brand');
                            let cSub = localStorage.getItem('tendo_current_subcat');
                            if(cCat && cBrand) { 
                                loadProductsInternal(cCat, cBrand, (cSub === 'null' ? null : cSub)); 
                                currentState.cat = cCat; currentState.brand = cBrand; currentState.subcat = (cSub === 'null' ? null : cSub);
                            } else showDashboardInternal();
                        }
                    }
                    else showDashboardInternal();
                    
                    if(rem) { localStorage.setItem('tendo_rem_id', idLogin); localStorage.setItem('tendo_rem_pass', pass); }
                    if(!isAuto) showToast('Berhasil Masuk!', 'success');
                } else {
                    if(!isAuto) showToast(data && data.message ? data.message : "Data tidak cocok atau Gagal terhubung.", 'error');
                    localStorage.removeItem('tendo_rem_id');
                    localStorage.removeItem('tendo_rem_pass');
                }
            } catch(e) { if(!isAuto) showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyLoginOTP() {}

        async function requestOTP() {
            let user = document.getElementById('reg-user').value.trim();
            let email = document.getElementById('reg-email').value.trim();
            let phone = document.getElementById('reg-phone').value.trim();
            let pass = document.getElementById('reg-pass').value.trim();
            if(!user || !email || !phone || !pass) return showToast('Semua kolom wajib diisi!', 'error');
            
            let btn = document.getElementById('btn-register');
            let ori = btn.innerText;
            btn.innerText = "Mengirim..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/register', {username:user, email, phone, password:pass});
                if(data && data.success) { 
                    tempRegPhone = phone; showScreen('otp-screen', null); 
                } else {
                    showToast(data && data.message ? data.message : "Pendaftaran Gagal.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan. Pastikan internet lancar.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyOTP() {
            let otp = document.getElementById('otp-code').value.trim();
            if(!otp) return showToast('Masukkan OTP!', 'error');
            
            let btn = document.getElementById('btn-verify');
            let ori = btn.innerText;
            btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/verify-otp', {phone: tempRegPhone, otp});
                if(data && data.success) {
                    showToast('Pendaftaran Berhasil! Silakan Login.', 'success');
                    document.getElementById('log-id').value = document.getElementById('reg-user').value;
                    document.getElementById('log-pass').value = document.getElementById('reg-pass').value;
                    showScreen('login-screen', null);
                } else {
                    showToast(data && data.message ? data.message : "Sistem sibuk, coba sesaat lagi.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function reqForgotOTP() {
            let phone = document.getElementById('forgot-phone').value.trim();
            if(!phone) return showToast('Masukkan Nomor WhatsApp!', 'error');
            
            let btn = document.getElementById('btn-req-forgot');
            let ori = btn.innerText; btn.innerText = "Mengirim..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/req-forgot-otp', {phone});
                if(data && data.success) {
                    tempForgotPhone = phone;
                    document.getElementById('forgot-step-1').classList.add('hidden');
                    document.getElementById('forgot-step-2').classList.remove('hidden');
                } else {
                    showToast(data && data.message ? data.message : "Nomor tidak terdaftar.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyForgotOTP() {
            let otp = document.getElementById('forgot-otp').value.trim();
            let newPass = document.getElementById('forgot-new-pass').value.trim();
            if(!otp || !newPass) return showToast('Isi OTP dan Password Baru!', 'error');
            
            let btn = document.getElementById('btn-verify-forgot');
            let ori = btn.innerText; btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/verify-forgot-otp', {phone: tempForgotPhone, otp, newPass});
                if(data && data.success) {
                    showToast('Password berhasil diubah! Silakan login.', 'success');
                    showScreen('login-screen', null);
                    document.getElementById('forgot-step-1').classList.remove('hidden');
                    document.getElementById('forgot-step-2').classList.add('hidden');
                    document.getElementById('forgot-phone').value = '';
                    document.getElementById('forgot-otp').value = '';
                    document.getElementById('forgot-new-pass').value = '';
                } else {
                    showToast(data && data.message ? data.message : "Sistem error.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        window.openEditModal = function(type) {
            currentEditMode = type;
            let inp = document.getElementById('edit-input');
            document.getElementById('edit-step-1').classList.remove('hidden');
            document.getElementById('edit-step-2').classList.add('hidden');
            
            if(type === 'email') { 
                document.getElementById('edit-title').innerText = "Ganti Email"; 
                inp.type="email"; inp.placeholder="Email baru"; inp.value = (userData && userData.email) ? userData.email : "";
            }
            if(type === 'phone') { 
                document.getElementById('edit-title').innerText = "Ganti Nomor WA"; 
                inp.type="number"; inp.placeholder="Nomor WA baru (08/62)"; inp.value = currentUser ? currentUser : "";
            }
            if(type === 'password') { 
                document.getElementById('edit-title').innerText = "Ganti Password"; 
                inp.type="text"; inp.placeholder="Password baru"; inp.value = "";
            }
            document.getElementById('edit-modal').classList.remove('hidden');
        };
        
        function closeEditModal() { document.getElementById('edit-modal').classList.add('hidden'); }
        
        async function reqEditOTP() {
            let val = document.getElementById('edit-input').value.trim();
            if(!val) return showToast("Isi data baru!", 'error');
            
            let btn = document.getElementById('btn-req-edit');
            let ori = btn.innerText; btn.innerText = "Mengirim..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/req-edit-otp', {phone: currentUser, type: currentEditMode, newValue: val});
                if(data && data.success) {
                    document.getElementById('edit-step-1').classList.add('hidden');
                    document.getElementById('edit-step-2').classList.remove('hidden');
                } else {
                    showToast(data && data.message ? data.message : "Error server", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyEditOTP() {
            let otp = document.getElementById('edit-otp-input').value.trim();
            if(!otp) return showToast("Masukkan OTP!", 'error');
            
            let btn = document.getElementById('btn-verify-edit');
            let ori = btn.innerText; btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/verify-edit-otp', {phone: currentUser, otp: otp});
                if(data && data.success) {
                    showToast("Berhasil diubah!", 'success');
                    closeEditModal();
                    if(currentEditMode === 'phone' || currentEditMode === 'password') { logout(); } 
                    else { syncUserData(); }
                } else {
                    showToast(data && data.message ? data.message : "Error server", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function fetchAllProducts() {
            try {
                let data = await apiCall('/api/produk');
                if(data) { allProducts = data; }
            } catch(e){}
        }

        function loadCategoryInternal(cat) {
            currentCategory = cat; currentBrand = "";
            localStorage.setItem('tendo_current_cat', cat);
            localStorage.setItem('tendo_current_brand', '');
            localStorage.setItem('tendo_current_subcat', '');
            localStorage.setItem('tendo_is_vpn', 'false');
            
            document.getElementById('brand-cat-title').innerText = cat;
            document.getElementById('brand-list').innerHTML = '';
            
            let brands = [];
            for(let key in allProducts) {
                if(allProducts[key].kategori !== cat) continue;
                let b = allProducts[key].brand || 'Lainnya';
                if ((cat === 'Game' || cat === 'Data' || cat === 'Pulsa') && b === 'Lainnya') continue;
                if(!brands.includes(b)) brands.push(b);
            }

            if(brands.length > 0) {
                brands.sort();
                let gridHTML = '';
                brands.forEach(b => {
                    let initial = b.substring(0,2).toUpperCase();
                    let clickAction = (cat === 'Data') ? `loadSubCategory('${cat}', '${b}')` : `loadProducts('${cat}', '${b}')`;
                    
                    gridHTML += `
                    <div class="brand-row" onclick="${clickAction}">
                        <div class="b-logo">${initial}</div>
                        <div class="b-name">${b}</div>
                        <div style="margin-left:auto">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                        </div>
                    </div>`;
                });
                document.getElementById('brand-list').innerHTML = gridHTML;
                showScreen('brand-screen', 'nav-home');
            } else { 
                showToast('Belum ada produk di kategori ini.', 'error');
                document.getElementById('brand-list').innerHTML = '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">Kategori ini sedang kosong</div>'; 
            }
        }
        function loadCategory(cat) { pushState({screen: 'brand-screen', cat: cat, subcat_mode: false}); loadCategoryInternal(cat); }

        function loadSubCategoryInternal(cat, brand) {
            currentCategory = cat; currentBrand = brand;
            localStorage.setItem('tendo_current_cat', cat);
            localStorage.setItem('tendo_current_brand', brand);
            localStorage.setItem('tendo_current_subcat', '');
            localStorage.setItem('tendo_is_vpn', 'false');

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
                let sortedSubs = subs.sort((a, b) => {
                    let aIsCustom = a.startsWith('\u200B');
                    let bIsCustom = b.startsWith('\u200B');
                    if (aIsCustom && !bIsCustom) return -1;
                    if (!aIsCustom && bIsCustom) return 1;
                    return a.localeCompare(b);
                });
                let gridHTML = '';
                sortedSubs.forEach(s => {
                    let displayS = s.replace('\u200B', '');
                    let initial = displayS.substring(0,2).toUpperCase();
                    gridHTML += `
                    <div class="brand-row" onclick="loadProducts('${cat}', '${brand}', '${s}')">
                        <div class="b-logo">${initial}</div>
                        <div class="b-name">${displayS}</div>
                        <div style="margin-left:auto">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                        </div>
                    </div>`;
                });
                document.getElementById('brand-list').innerHTML = gridHTML;
                showScreen('brand-screen', 'nav-home');
            } else { showToast('Belum ada paket untuk provider ini.', 'error'); }
        }
        function loadSubCategory(cat, brand) { pushState({screen: 'brand-screen', cat: cat, brand: brand, subcat_mode: true}); loadSubCategoryInternal(cat, brand); }

        function loadProductsInternal(cat, brand, subCat = null) {
            currentCategory = cat; currentBrand = brand;
            localStorage.setItem('tendo_current_cat', cat);
            localStorage.setItem('tendo_current_brand', brand);
            localStorage.setItem('tendo_current_subcat', subCat || 'null');
            localStorage.setItem('tendo_is_vpn', 'false');

            document.getElementById('cat-title-text').innerText = subCat ? subCat.replace('\u200B', '') : brand;
            document.getElementById('search-product').value = ''; 
            
            let listHTML = '';
            for(let key in allProducts) {
                let p = allProducts[key];
                if (p.kategori !== cat || (p.brand || 'Lainnya') !== brand) continue;
                if (subCat) {
                    let pSub = p.sub_kategori || 'Umum';
                    if (pSub !== subCat) continue;
                }
                
                let safeName = p.nama.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                let safeDesc = p.deskripsi ? p.deskripsi.replace(/'/g, "\\'").replace(/"/g, '&quot;') : 'Proses Otomatis 24 Jam';
                let initial = brand.substring(0,2).toUpperCase();
                
                let statusBadge = p.status_produk === false 
                    ? '<span style="background:var(--bg-main); color:#b91c1c; font-size:9px; padding:4px 8px; border-radius:6px; font-weight:800; box-shadow:var(--shadow-outer); flex-shrink:0; margin-left:8px;">GANGGUAN</span>' 
                    : '<span class="badge-open">OPEN</span>';
                
                let onClickAction = p.status_produk === false
                    ? `showToast('Maaf, produk ini sedang gangguan dari pusat.', 'error')`
                    : `openOrderModal('${key}', '${safeName}', ${p.harga}, '${safeDesc}')`;
                
                listHTML += `
                <div class="product-item" onclick="${onClickAction}">
                    <div class="prod-logo">${initial}</div>
                    <div class="prod-info">
                        <div class="prod-name">${p.nama} ${statusBadge}</div>
                        <div class="prod-desc">${p.deskripsi ? p.deskripsi.substring(0,40)+'...' : 'Proses Cepat'}</div>
                        <div class="prod-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                    </div>
                </div>`;
            }
            
            document.getElementById('product-list').innerHTML = '<div class="skeleton-box"></div><div class="skeleton-box"></div><div class="skeleton-box"></div>';
            setTimeout(() => {
                document.getElementById('product-list').innerHTML = listHTML || '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">KOSONG</div>';
            }, 600);
            showScreen('produk-screen', 'nav-home');
        }
        function loadProducts(cat, brand, subCat = null) { pushState({screen: 'produk-screen', cat: cat, brand: brand, subcat: subCat}); loadProductsInternal(cat, brand, subCat); }

        function openOrderModal(sku, nama, harga, desc) {
            if(!currentUser) {
                showToast("Silakan masuk/daftar terlebih dahulu untuk membeli produk.", "error");
                showScreen("login-screen", null);
                return;
            }
            selectedSKU = sku;
            document.getElementById('m-name').innerText = nama;
            document.getElementById('m-price').innerText = 'Rp ' + harga.toLocaleString('id-ID');
            document.getElementById('m-desc').innerText = desc || 'Proses Otomatis';
            document.getElementById('m-target').value = '';
            document.getElementById('m-payment-method').value = 'saldo';
            selectPayment('saldo'); // set default
            document.getElementById('order-modal').classList.remove('hidden');
        }
        function closeOrderModal() { document.getElementById('order-modal').classList.add('hidden'); }
        
        async function cekRiwayatBaru() {
            document.getElementById('order-success-modal').classList.add('hidden');
            await syncUserData();
            showHistory('Order');
            if(userData.history && userData.history.length > 0) {
                let latest = userData.history[0];
                openHistoryDetail(latest);
            }
        }

        async function processOrder() {
            if(!currentUser) { showToast('Sesi Anda habis. Silakan login ulang.', 'error'); logout(); return; }
            let target = document.getElementById('m-target').value.trim();
            let method = document.getElementById('m-payment-method').value;

            if(!target || target.length < 4) return showToast("Nomor tujuan tidak valid!", 'error');
            
            let btn = document.getElementById('m-submit');
            let ori = btn.innerText; btn.innerText = 'Proses...'; btn.disabled = true;
            
            try {
                let url = method === 'qris' ? '/api/order-qris' : '/api/order';
                let data = await apiCall(url, {phone: currentUser, sku: selectedSKU, tujuan: target});
                
                if(data && data.success) {
                    closeOrderModal();
                    await syncUserData();
                    
                    if (method === 'qris') {
                        document.getElementById('topup-success-modal').classList.remove('hidden');
                    } else {
                        document.getElementById('os-name').innerText = document.getElementById('m-name').innerText;
                        document.getElementById('os-target').innerText = target;
                        document.getElementById('os-metode').innerText = "Saldo Akun";
                        document.getElementById('os-price').innerText = document.getElementById('m-price').innerText;
                        document.getElementById('order-success-modal').classList.remove('hidden');
                    }
                } else {
                    showToast(data && data.message ? 'Gagal: ' + data.message : "Kesalahan server saat memproses order.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        /* -----------------------------------------
           FUNGSI ORDER VPN PREMIUM & TRIAL
        ------------------------------------------*/
        function updateVpnPrice() {
            let days = parseInt(document.getElementById('m-vpn-expired').value) || 30;
            if(days > 30) { days = 30; document.getElementById('m-vpn-expired').value = 30; }
            if(days < 1) { days = 1; document.getElementById('m-vpn-expired').value = 1; }
            
            let finalPrice = Math.ceil((currentVpnBasePrice / 30) * days);
            document.getElementById('m-vpn-price').innerText = 'Rp ' + finalPrice.toLocaleString('id-ID');
        }

        function openVPNServerSelection(protocol) {
            document.getElementById('vpn-modal-title').innerText = "Pilih Produk " + protocol;

            let html = '';
            if(vpnConfigData && vpnConfigData.products && vpnConfigData.servers) {
                for(let pId in vpnConfigData.products) {
                    let prod = vpnConfigData.products[pId];
                    if(prod.protocol.toUpperCase() === protocol.toUpperCase()) {
                        let srv = vpnConfigData.servers[prod.server_id];
                        if(srv && srv.host) {
                            let srvName = srv.server_name || prod.server_id;
                            let flag = (srv.city && srv.city.toLowerCase().includes('sg')) ? '🇸🇬 ' : ((srv.city && srv.city.toLowerCase().includes('id')) ? '🇮🇩 ' : '🌐 ');
                            let price = prod.price || 0;
                            let stok = prod.stok !== undefined ? parseInt(prod.stok) : 0;
                            let desc = prod.desc || 'Proses Otomatis';
                            let customName = prod.name || `${protocol} Premium`;
                            let safeDesc = desc.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                            let safeName = customName.replace(/'/g, "\\'").replace(/"/g, '&quot;');

                            let stokBadge = stok > 0 ? `<span style="background:#16a34a; color:#ffffff; padding:2px 6px; border-radius:4px; font-weight:bold; font-size:11px;">Stok: ${stok}</span>` : `<span style="background:#ef4444; color:#ffffff; padding:2px 6px; border-radius:4px; font-weight:bold; font-size:11px;">Stok Habis</span>`;
                            let onClick = stok > 0 ? `openVPNOrderModal('${pId}', '${protocol}', ${price}, '${safeDesc}', '${safeName}')` : `showToast('Maaf, stok produk ini sedang habis.', 'error')`;

                            html += `
                            <div class="vpn-server-item" onclick="${onClick}">
                                <div class="vpn-server-info">
                                    <div class="vpn-server-name">${flag} ${customName}</div>
                                    <div style="font-size:11.5px; color:var(--text-muted); margin-top:3px; font-weight:bold;">Server: ${srvName}</div>
                                    <div class="vpn-server-price" style="display:flex; justify-content:space-between; align-items:center; margin-top:5px;">
                                        <span>Rp ${price.toLocaleString('id-ID')} / 30 Hari</span>
                                        ${stokBadge}
                                    </div>
                                </div>
                                <div>
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--nav-active)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                </div>
                            </div>`;
                        }
                    }
                }
            }

            if(html === '') html = '<div style="text-align:center; font-size:12px; color:var(--text-muted); margin-top:10px;">Belum ada produk diatur untuk protokol ini.</div>';

            document.getElementById('vpn-server-list').innerHTML = html;
            document.getElementById('vpn-server-modal').classList.remove('hidden');
        }

        function closeVPNServerModal() {
            document.getElementById('vpn-server-modal').classList.add('hidden');
        }

        function openVPNTrialModal(productId, protocol, customName) {
            if(!currentUser) {
                showToast("Silakan masuk/daftar terlebih dahulu untuk klaim trial.", "error");
                showScreen("login-screen", null);
                return;
            }
            closeVPNServerModal();
            selectedVPNServer = productId; 
            selectedVPNProto = protocol;
            document.getElementById('m-vpn-trial-name').innerText = customName;
            document.getElementById('vpn-trial-modal').classList.remove('hidden');
        }

        function closeVPNTrialModal() {
            document.getElementById('vpn-trial-modal').classList.add('hidden');
        }

        async function processVPNTrial() {
            if(!currentUser) { showToast('Sesi Anda habis. Silakan login ulang.', 'error'); logout(); return; }
            let btn = document.getElementById('m-vpn-trial-submit');
            let ori = btn.innerText; btn.innerText = 'Mengklaim...'; btn.disabled = true;

            try {
                let data = await apiCall('/api/order-vpn', {
                    phone: currentUser, 
                    protocol: selectedVPNProto, 
                    product_id: selectedVPNServer, 
                    mode: 'trial',
                    username: '', 
                    password: '', 
                    expired: 1
                });
                
                if(data && data.success) {
                    closeVPNTrialModal();
                    await syncUserData();
                    
                    if(userData.history && userData.history.length > 0) {
                        let latest = userData.history[0];
                        openHistoryDetail(latest);
                    }
                } else {
                    showToast(data && data.message ? 'Gagal: ' + data.message : "Kesalahan server.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }

            btn.innerText = ori; btn.disabled = false;
        }

        function openVPNOrderModal(productId, protocol, price, desc, customName) {
            if(!currentUser) {
                showToast("Silakan masuk/daftar terlebih dahulu untuk membeli VPN.", "error");
                showScreen("login-screen", null);
                return;
            }
            closeVPNServerModal();
            selectedVPNServer = productId; 
            selectedVPNProto = protocol;
            currentVpnBasePrice = price;
            currentVpnBaseDesc = desc;
            
            document.getElementById('m-vpn-name').innerText = customName;
            document.getElementById('m-vpn-username').value = '';
            document.getElementById('m-vpn-password').value = '';
            document.getElementById('m-vpn-expired').value = '30';
            
            document.getElementById('m-vpn-payment').value = 'saldo';
            selectPaymentVpn('saldo'); // set default btn

            if(protocol.toUpperCase() === 'SSH' || protocol.toUpperCase() === 'ZIVPN') {
                document.getElementById('m-vpn-password').classList.remove('hidden');
            } else {
                document.getElementById('m-vpn-password').classList.add('hidden');
            }
            document.getElementById('m-vpn-desc').innerText = currentVpnBaseDesc;
            updateVpnPrice();

            document.getElementById('vpn-order-modal').classList.remove('hidden');
        }

        function closeVPNOrderModal() {
            document.getElementById('vpn-order-modal').classList.add('hidden');
        }

        async function processVPNOrder() {
            if(!currentUser) { showToast('Sesi Anda habis. Silakan login ulang.', 'error'); logout(); return; }
            
            let username = document.getElementById('m-vpn-username').value.trim();
            let password = document.getElementById('m-vpn-password').value.trim();
            let expired = document.getElementById('m-vpn-expired').value;
            let method = document.getElementById('m-vpn-payment').value;

            if(!username || username.length < 4 || username.length > 17) return showToast("Username VPN harus 4-17 Karakter!", 'error');
            if((selectedVPNProto.toUpperCase() === 'SSH' || selectedVPNProto.toUpperCase() === 'ZIVPN') && (!password || password.length < 4 || password.length > 17)) {
                return showToast("Password VPN harus 4-17 Karakter!", 'error');
            }
            if(!expired || parseInt(expired) < 1) return showToast("Masa aktif tidak valid!", 'error');

            let btn = document.getElementById('m-vpn-submit');
            let ori = btn.innerText; btn.innerText = 'Membuat Akun...'; btn.disabled = true;

            try {
                let url = method === 'qris' ? '/api/order-vpn-qris' : '/api/order-vpn';
                let payload = {
                    phone: currentUser, 
                    protocol: selectedVPNProto, 
                    product_id: selectedVPNServer, 
                    mode: 'reguler',
                    username: username, 
                    password: password, 
                    expired: parseInt(expired)
                };

                let data = await apiCall(url, payload);
                
                if(data && data.success) {
                    closeVPNOrderModal();
                    await syncUserData();
                    
                    if (method === 'qris') {
                        document.getElementById('topup-success-modal').classList.remove('hidden');
                    } else {
                        document.getElementById('os-name').innerText = document.getElementById('m-vpn-name').innerText;
                        document.getElementById('os-target').innerText = username;
                        document.getElementById('os-metode').innerText = 'Saldo Akun';
                        document.getElementById('os-price').innerText = document.getElementById('m-vpn-price').innerText;
                        document.getElementById('order-success-modal').classList.remove('hidden');
                    }
                } else {
                    showToast(data && data.message ? 'Gagal: ' + data.message : "Kesalahan server saat memproses order VPN.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }

            btn.innerText = ori; btn.disabled = false;
        }
    </script>
</body>
</html>
EOF
}
# === SELESAI ===
# ==========================================
# 3. FUNGSI UNTUK MEMBUAT FILE INDEX.JS (BACKEND)
# ==========================================
generate_bot_script() {
    cat << 'EOF' > index.js
process.env.TZ = 'Asia/Jakarta';
const fs = require('fs');
const pino = require('pino');
const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const axios = require('axios'); 
const crypto = require('crypto'); 
const TelegramBot = require('node-telegram-bot-api');
const { pipeline } = require('stream/promises');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');

const app = express();
app.disable('x-powered-by');

// SECURITY: Memblokir akses langsung file konfigurasi JSON/DB lewat URL
app.use((req, res, next) => {
    if ((req.path.endsWith('.json') && !req.path.endsWith('manifest.json')) || req.path.endsWith('.db') || req.path.endsWith('.bak')) {
        return res.status(403).json({success: false, message: 'Akses Ditolak (Sistem Keamanan Tendo)'});
    }
    next();
});

app.use(bodyParser.json());
app.use(express.static('public')); 

// ==============================================================
// INIT SQLITE DATABASE & OPTIMASI PRAGMA
// ==============================================================
const dbSqlite = new Database('tendo_database.db');

// Eksekusi PRAGMA untuk optimasi performa SQLite
dbSqlite.pragma('journal_mode = WAL');
dbSqlite.pragma('busy_timeout = 5000');
dbSqlite.pragma('synchronous = NORMAL');

dbSqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS config (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS produk (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS trx (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS topup (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS web_notif (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT);
    CREATE TABLE IF NOT EXISTS global_trx (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT);
    CREATE TABLE IF NOT EXISTS global_stats (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS tutorial (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS vpn_config (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS custom_layout (id TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS jwt_blacklist (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS used_mutations (id TEXT PRIMARY KEY, timestamp INTEGER);
`);

// ==============================================================
// SQLITE CRUD HELPERS
// ==============================================================
function getRecord(table, id) {
    const row = dbSqlite.prepare(`SELECT data FROM ${table} WHERE id = ?`).get(id);
    return row ? JSON.parse(row.data) : null;
}

function saveRecord(table, id, data) {
    dbSqlite.prepare(`INSERT OR REPLACE INTO ${table} (id, data) VALUES (?, ?)`).run(id, JSON.stringify(data));
}

function deleteRecord(table, id) {
    dbSqlite.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
}

function getAllRecords(table) {
    const rows = dbSqlite.prepare(`SELECT id, data FROM ${table}`).all();
    let res = {};
    for(let r of rows) res[r.id] = JSON.parse(r.data);
    return res;
}

function getAllRecordsArray(table, limit = 100) {
    if(table === 'tutorial') {
        const rows = dbSqlite.prepare(`SELECT data FROM ${table}`).all();
        return rows.map(r => JSON.parse(r.data));
    }
    const rows = dbSqlite.prepare(`SELECT data FROM ${table} ORDER BY id DESC LIMIT ?`).all(limit);
    return rows.map(r => JSON.parse(r.data));
}

function unshiftRecordArray(table, data, maxLen = 100) {
    dbSqlite.prepare(`INSERT INTO ${table} (data) VALUES (?)`).run(JSON.stringify(data));
    dbSqlite.prepare(`DELETE FROM ${table} WHERE id NOT IN (SELECT id FROM ${table} ORDER BY id DESC LIMIT ?)`).run(maxLen);
}

function normalizePhone(phoneStr) {
    if(!phoneStr) return '';
    let num = phoneStr.replace(/[^0-9]/g, '');
    if(num.startsWith('0')) return '62' + num.substring(1);
    return num;
}

function sanitizeInput(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ==============================================================
// DYNAMIC SECRET KEY (JWT)
// ==============================================================
let cfgJwt = getRecord('config', 'main') || {};
if (!cfgJwt.jwt_secret) {
    cfgJwt.jwt_secret = crypto.randomBytes(64).toString('hex');
    saveRecord('config', 'main', cfgJwt);
}
const SECRET_KEY = cfgJwt.jwt_secret;

// ==============================================================
// MIDDLEWARE JWT VERIFY
// ==============================================================
const verifyToken = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];
    if(typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const token = bearer[1];
        
        // Cek Blacklist Token
        const isBlacklisted = dbSqlite.prepare(`SELECT id FROM jwt_blacklist WHERE id = ?`).get(token);
        if (isBlacklisted) return res.status(403).json({success: false, message: 'Token telah di-logout (Blacklist). Silakan login ulang.'});

        jwt.verify(token, SECRET_KEY, (err, authData) => {
            if(err) return res.status(403).json({success: false, message: 'Token kedaluwarsa atau tidak valid. Silakan login ulang.'});
            
            // Validasi Nomor HP di req.body & req.params (Mencegah Bypass Sesi)
            if (req.body && req.body.phone) {
                if (normalizePhone(req.body.phone) !== authData.phone) {
                    return res.status(403).json({success: false, message: 'Akses Ditolak (Sesi Body tidak cocok).'});
                }
            }
            if (req.params && req.params.phone) {
                if (normalizePhone(req.params.phone) !== authData.phone) {
                    return res.status(403).json({success: false, message: 'Akses Ditolak (Sesi Parameter tidak cocok).'});
                }
            }
            
            req.authData = authData;
            req.token = token;
            next();
        });
    } else {
        res.status(403).json({success: false, message: 'Akses Ditolak. Token Otorisasi diperlukan.'});
    }
};

// ==============================================================
// SQLITE ATOMIC TRANSACTIONS (MENCEGAH RACE CONDITION)
// ==============================================================
const atomicDeductBalance = dbSqlite.transaction((phone, amount) => {
    const row = dbSqlite.prepare(`SELECT data FROM users WHERE id = ?`).get(phone);
    if (!row) throw new Error("User tidak valid.");
    
    let u = JSON.parse(row.data);
    let hargaFix = parseInt(amount);
    
    if (parseInt(u.saldo) < hargaFix) {
        throw new Error("Saldo tidak cukup.");
    }
    
    u.saldo = parseInt(u.saldo) - hargaFix;
    dbSqlite.prepare(`UPDATE users SET data = ? WHERE id = ?`).run(JSON.stringify(u), phone);
    
    return { saldoTerkini: u.saldo, uData: u };
});

const atomicRefundBalance = dbSqlite.transaction((phone, amount, historyObj = null) => {
    const row = dbSqlite.prepare(`SELECT data FROM users WHERE id = ?`).get(phone);
    if (!row) return null;
    
    let u = JSON.parse(row.data);
    let saldoSebelum = parseInt(u.saldo);
    u.saldo = saldoSebelum + parseInt(amount);
    
    if (historyObj) {
        historyObj.saldo_sebelumnya = saldoSebelum;
        historyObj.saldo_sesudah = u.saldo;
        u.history = u.history || [];
        u.history.unshift(historyObj);
        if (u.history.length > 50) u.history.pop();
    }
    
    dbSqlite.prepare(`UPDATE users SET data = ? WHERE id = ?`).run(JSON.stringify(u), phone);
    return u;
});

const atomicAddBalance = dbSqlite.transaction((phone, amount, historyObj = null) => {
    const row = dbSqlite.prepare(`SELECT data FROM users WHERE id = ?`).get(phone);
    if (!row) return null;
    
    let u = JSON.parse(row.data);
    let saldoSebelum = parseInt(u.saldo);
    u.saldo = saldoSebelum + parseInt(amount);
    
    if (historyObj) {
        historyObj.saldo_sebelumnya = saldoSebelum;
        historyObj.saldo_sesudah = u.saldo;
        u.history = u.history || [];
        u.history.unshift(historyObj);
        if (u.history.length > 50) u.history.pop();
    }
    
    dbSqlite.prepare(`UPDATE users SET data = ? WHERE id = ?`).run(JSON.stringify(u), phone);
    return u;
});

const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd).digest('hex');

function maskStringTarget(str) {
    if (!str) return '-';
    let s = str.toString().trim();
    if (s.length <= 3) return s;
    return '*'.repeat(s.length - 3) + s.substring(s.length - 3);
}

function cekPemeliharaan() {
    let cfg = getRecord('config', 'main') || {};
    let s = cfg.maintStart || "23:00";
    let e = cfg.maintEnd || "00:30";
    let d = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Jakarta"}));
    let h = d.getHours(); let m = d.getMinutes();
    let curMins = h * 60 + m;
    let sParts = s.split(':'); let eParts = e.split(':');
    let sMins = parseInt(sParts[0])*60 + parseInt(sParts[1]);
    let eMins = parseInt(eParts[0])*60 + parseInt(eParts[1]);
    
    if(sMins < eMins) return (curMins >= sMins && curMins < eMins);
    else return (curMins >= sMins || curMins < eMins);
}

function cleanupOldHistory() {
    try {
        let now = Date.now();
        let thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
        let updates = [];
        
        let stmt = dbSqlite.prepare('SELECT id, data FROM users');
        for (const row of stmt.iterate()) {
            let u = JSON.parse(row.data);
            if (u && u.history && u.history.length > 0) {
                let origLen = u.history.length;
                u.history = u.history.filter(h => (now - h.ts) < thirtyDaysMs);
                if (u.history.length !== origLen) {
                    updates.push({id: row.id, data: u});
                }
            }
        }
        
        if (updates.length > 0) {
            const updateStmt = dbSqlite.prepare('INSERT OR REPLACE INTO users (id, data) VALUES (?, ?)');
            dbSqlite.transaction(() => {
                for (let up of updates) {
                    updateStmt.run(up.id, JSON.stringify(up.data));
                }
            })();
        }
        
        // Membersihkan blacklist JWT lama (yg lebih dari 24 jam)
        dbSqlite.prepare(`DELETE FROM jwt_blacklist`).run();
        
        // Membersihkan mutasi usang (> 24 jam)
        dbSqlite.prepare(`DELETE FROM used_mutations WHERE timestamp < ?`).run(Date.now() - 86400000);
    } catch (e) {
        console.error("Error during cleanup:", e.message);
    }
}
setInterval(cleanupOldHistory, 6 * 60 * 60 * 1000); 

function sendTelegramAdmin(message) {
    try {
        let cfg = getRecord('config', 'main') || {};
        if (cfg.teleToken && cfg.teleChatId) {
            let chatIdStr = cfg.teleChatId.toString();
            axios.post(`https://api.telegram.org/bot${cfg.teleToken}/sendMessage`, {
                chat_id: chatIdStr,
                text: message,
                parse_mode: 'HTML'
            }).catch(e => {});
        }
    } catch(e) {}
}

function sendBroadcastSuccess(productName, rawUser, rawTarget, price, method) {
    try {
        let cfg = getRecord('config', 'main') || {};
        let maskTarget = maskStringTarget(rawTarget); 
        let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
        let priceStr = price ? `\n💰 Harga: Rp ${price.toLocaleString('id-ID')}` : '';
        let methodStr = method ? `\n💳 Metode: ${method}` : '';
        
        let msgTele = `✅ <b>PEMBELIAN BERHASIL</b>\n\n👤 Pelanggan: ${rawUser}\n📦 Layanan: ${productName}\n🎯 Tujuan: ${maskTarget}${priceStr}${methodStr}\n🕒 Waktu: ${timeStr} WIB\n\n<i>🌐 Transaksi diproses otomatis oleh sistem.</i>`;

        if (cfg.teleTokenInfo && cfg.teleChannelId) {
            let channelIdStr = cfg.teleChannelId.toString();
            if (!channelIdStr.startsWith('-100') && !channelIdStr.startsWith('@')) {
                channelIdStr = '-100' + channelIdStr;
            }
            axios.post(`https://api.telegram.org/bot${cfg.teleTokenInfo}/sendMessage`, {
                chat_id: channelIdStr,
                text: msgTele,
                parse_mode: 'HTML'
            }).catch(e => { console.error("Gagal kirim Telegram Channel:", e.message); });
        }

        if (globalSock && cfg.waBroadcastId) {
            let msgWa = `✅ *PEMBELIAN BERHASIL*\n\n👤 Pelanggan: ${rawUser}\n📦 Layanan: ${productName}\n🎯 Tujuan: ${maskTarget}${priceStr}${methodStr}\n🕒 Waktu: ${timeStr} WIB\n\n_🌐 Transaksi diproses otomatis oleh sistem._`;
            globalSock.sendMessage(cfg.waBroadcastId, { text: msgWa }).catch(e => {});
        }
    } catch(e) {}
}

function convertToDynamicQris(staticQris, amount) {
    try {
        if(!staticQris || staticQris.length < 30) return staticQris;
        let qris = staticQris.substring(0, staticQris.length - 8);
        qris = qris.replace("010211", "010212");
        let parsed = ""; let i = 0;
        while (i < qris.length) {
            let id = qris.substring(i, i+2);
            let lenStr = qris.substring(i+2, i+4);
            let len = parseInt(lenStr, 10);
            if (isNaN(len)) break;
            let val = qris.substring(i+4, i+4+len);
            if (id !== "54") parsed += id + lenStr + val;
            i += 4 + len;
        }
        let amtStr = amount.toString();
        let amtLen = amtStr.length.toString().padStart(2, '0');
        let tag54 = "54" + amtLen + amtStr;
        let finalQris = "";
        if (parsed.includes("5802ID")) finalQris = parsed.replace("5802ID", tag54 + "5802ID");
        else finalQris = parsed + tag54;
        finalQris += "6304";
        
        let crc = 0xFFFF;
        for(let j=0; j<finalQris.length; j++){
            crc ^= finalQris.charCodeAt(j) << 8;
            for(let k=0; k<8; k++){
                if(crc & 0x8000) crc = (crc << 1) ^ 0x1021;
                else crc = crc << 1;
            }
        }
        let crcStr = (crc & 0xFFFF).toString(16).toUpperCase().padStart(4, '0');
        return finalQris + crcStr;
    } catch(e) { return staticQris; }
}

let configAwal = getRecord('config', 'main') || {};
configAwal.botName = configAwal.botName || "Digital Tendo Store";
configAwal.botNumber = configAwal.botNumber || "";
configAwal.gopayToken = configAwal.gopayToken || "";
configAwal.gopayMerchantId = configAwal.gopayMerchantId || "";
configAwal.qrisUrl = configAwal.qrisUrl || "https://upload.wikimedia.org/wikipedia/commons/d/d0/QR_code_for_mobile_English_Wikipedia.svg";
configAwal.qrisText = configAwal.qrisText || "";
configAwal.teleTokenInfo = configAwal.teleTokenInfo || ""; 
configAwal.margin = configAwal.margin || { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
saveRecord('config', 'main', configAwal);

let vpnAwal = getRecord('vpn_config', 'main') || {};
if(!vpnAwal.servers) vpnAwal.servers = {};
if(!vpnAwal.products) vpnAwal.products = {};
saveRecord('vpn_config', 'main', vpnAwal);

let customLayoutAwal = getRecord('custom_layout', 'main') || {};
if(!customLayoutAwal.sections) customLayoutAwal.sections = [];
saveRecord('custom_layout', 'main', customLayoutAwal);

if(!fs.existsSync('./public/maint_images')) fs.mkdirSync('./public/maint_images', { recursive: true });

let globalSock = null;
let tempOtpDB = {}; 
let otpCooldown = {}; 
let loginAttempts = {}; // Menyimpan percobaan login rate limit
let isMaintenanceNow = cekPemeliharaan();

let teleBotInfo = null;
let teleState = {}; 

if (configAwal.teleTokenInfo) {
    try {
        teleBotInfo = new TelegramBot(configAwal.teleTokenInfo, {polling: true});
        teleBotInfo.on('polling_error', () => {});
        teleBotInfo.on('error', () => {});
        // ... (Kode callback bot telegram sama spt sblmnya, dipersingkat di view bash instalasinya)
    } catch(e) {}
}

app.get('/api/banners', (req, res) => {
    let banners = [];
    try {
        for (let i = 1; i <= 5; i++) {
            let folderPath = `./public/baner${i}`;
            if (fs.existsSync(folderPath)) {
                let files = fs.readdirSync(folderPath);
                let imgFiles = files.filter(f => f.match(/\.(jpg|jpeg|png|gif|webp)$/i));
                if (imgFiles.length > 0) banners.push(`/baner${i}/${imgFiles[0]}`);
            }
        }
    } catch(e) {}
    res.json({ success: true, data: banners });
});

app.get('/api/stats', (req, res) => {
    try {
        let gStats = getAllRecords('global_stats');
        let cfg = getRecord('config', 'main') || {};
        let daily = 0, weekly = 0, monthly = 0, total = 0;
        
        let now = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Jakarta"}));
        let nowYear = now.getFullYear();
        let nowMonth = now.getMonth();
        let nowString = now.toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
        
        let day = now.getDay() || 7; 
        let monday = new Date(now);
        monday.setDate(now.getDate() - day + 1);
        monday.setHours(0,0,0,0);

        for(let k in gStats) {
            let count = gStats[k];
            total += count;
            let recordDate = new Date(k + 'T00:00:00+07:00');
            if(k === nowString) daily += count;
            if(recordDate >= monday) weekly += count;
            if(recordDate.getFullYear() === nowYear && recordDate.getMonth() === nowMonth) monthly += count;
        }
        res.json({ 
            success: true, daily, weekly, monthly, total, 
            maintStart: cfg.maintStart || '23:00', maintEnd: cfg.maintEnd || '00:30',
            adminWa: cfg.botNumber || "6282224460678"
        });
    } catch(e) { res.json({ success: false, daily: 0, weekly: 0, monthly: 0, total: 0 }); }
});

app.get('/api/produk', (req, res) => { res.json(getAllRecords('produk')); });

app.get('/api/leaderboard', (req, res) => {
    try {
        let users = getAllRecords('users');
        let leaderboard = [];
        for (let id in users) {
            let u = users[id];
            let trx = u.trx_count || 0;
            if (trx > 0) {
                let nameStr = u.username || id;
                let maskedName = nameStr.length > 5 ? nameStr.substring(0, 4) + '***' + nameStr.substring(nameStr.length - 2) : nameStr.substring(0, 2) + '***';
                leaderboard.push({ name: maskedName, trx: trx });
            }
        }
        leaderboard.sort((a, b) => b.trx - a.trx);
        res.json({ success: true, data: leaderboard.slice(0, 5) }); 
    } catch(e) { 
        res.json({ success: false, data: [] }); 
    }
});

app.get('/api/notif', (req, res) => { res.json(getAllRecordsArray('web_notif')); });
app.get('/api/global-trx', (req, res) => { res.json(getAllRecordsArray('global_trx')); });
app.get('/api/custom-layout', (req, res) => { res.json({success: true, data: getRecord('custom_layout', 'main') || {sections:[]}}); }); 
app.get('/api/tutorials', (req, res) => { res.json(getAllRecordsArray('tutorial')); });

app.get('/api/vpn-config', (req, res) => {
    try {
        let vpn = getRecord('vpn_config', 'main') || {};
        let safeConfig = JSON.parse(JSON.stringify(vpn));
        if(safeConfig.servers) {
            for(let srv in safeConfig.servers) {
                delete safeConfig.servers[srv].pass;
                delete safeConfig.servers[srv].user;
                delete safeConfig.servers[srv].api_key;
                delete safeConfig.servers[srv].port;
            }
        }
        res.json({success: true, data: safeConfig});
    } catch(e) { res.json({success: false}); }
});

app.get('/api/user/:phone', verifyToken, (req, res) => {
    try {
        let p = req.params.phone;
        let u = getRecord('users', p);
        if(u) {
            let safeData = { ...u }; delete safeData.password; 
            res.json({success: true, data: safeData});
        } else res.json({success: false});
    } catch(e) { res.json({success: false}); }
});

app.post('/api/cancel-topup', verifyToken, (req, res) => {
    try {
        let { sn, phone } = req.body;
        let topup = getRecord('topup', sn);
        
        if(topup && topup.phone === phone) {
            topup.status = 'gagal';
            saveRecord('topup', sn, topup);
        }
        
        let u = getRecord('users', phone);
        if(u) {
            let hist = u.history.find(h => h.sn === sn);
            if(hist && hist.status === 'Pending') {
                hist.status = 'Gagal (Dibatalkan)';
                saveRecord('users', phone, u);
                return res.json({success: true});
            }
        }
        res.json({success: false, message: 'Topup tidak ditemukan atau sudah diproses.'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/logout', verifyToken, (req, res) => {
    try {
        dbSqlite.prepare(`INSERT OR IGNORE INTO jwt_blacklist (id) VALUES (?)`).run(req.token);
        res.json({success: true, message: 'Berhasil logout.'});
    } catch(e) { res.json({success: false}); }
});

app.post('/api/login', (req, res) => {
    try {
        let idRaw = (req.body.id || '').trim();
        let id = sanitizeInput(idRaw);
        let password = req.body.password;
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        let limitKey = ip + '_' + id;
        if (loginAttempts[limitKey] && loginAttempts[limitKey].count >= 5) {
            if (Date.now() - loginAttempts[limitKey].time < 300000) {
                return res.json({success: false, message: 'Terlalu banyak percobaan login gagal. Harap tunggu 5 menit.'});
            } else {
                loginAttempts[limitKey] = {count: 0, time: Date.now()};
            }
        }

        let hashedInput = hashPassword(password);
        let normInput = normalizePhone(id);
        
        // Optimasi Pencarian User: Cek via Key (Phone) Dulu
        let uDirect = getRecord('users', normInput) || getRecord('users', id);
        let userPhone = null;

        if (uDirect && (uDirect.password === password || uDirect.password === hashedInput)) {
            userPhone = uDirect.jid ? uDirect.jid.split('@')[0] : (getRecord('users', normInput) ? normInput : id);
            if(uDirect.password === password) { uDirect.password = hashedInput; saveRecord('users', userPhone, uDirect); }
        } else {
            // Pencarian via Email/Username jika Phone gagal
            let users = getAllRecords('users');
            userPhone = Object.keys(users).find(k => {
                let usr = users[k];
                if (!usr) return false;
                let matchId = (usr.email && usr.email.toLowerCase() === id.toLowerCase()) || 
                              (usr.username && usr.username.toLowerCase() === id.toLowerCase());
                if (!matchId) return false;
                if (usr.password === password || usr.password === hashedInput) {
                    if (usr.password === password) { usr.password = hashedInput; saveRecord('users', k, usr); }
                    return true;
                }
                return false;
            });
        }

        if (userPhone) {
            delete loginAttempts[limitKey]; // Reset rate limit on success
            let uFinal = getRecord('users', userPhone);
            let safeData = { ...uFinal }; delete safeData.password;
            const token = jwt.sign({ phone: userPhone }, SECRET_KEY, { expiresIn: '1d' });
            res.json({success: true, phone: userPhone, data: safeData, token: token});
        } else {
            loginAttempts[limitKey] = loginAttempts[limitKey] || {count: 0, time: Date.now()};
            loginAttempts[limitKey].count += 1;
            res.json({success: false, message: 'Data Akun (Email/WA/Username) atau Password salah!'});
        }
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/register', (req, res) => {
    try {
        let username = sanitizeInput(req.body.username);
        let email = sanitizeInput(req.body.email);
        let password = req.body.password;
        let phone = normalizePhone(req.body.phone); 
        
        if(!phone || phone.length < 9) return res.json({success: false, message: 'Nomor WA tidak valid!'});
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        otpCooldown[phone] = Date.now();
        
        let users = getAllRecords('users');
        let isEmailExist = Object.values(users).some(u => u && u.email && u.email.toLowerCase() === email.toLowerCase());
        if (isEmailExist) return res.json({success: false, message: 'Email terdaftar!'});
        
        let isUsernameExist = Object.values(users).some(u => u && u.username && u.username.toLowerCase() === username.toLowerCase());
        if (isUsernameExist) return res.json({success: false, message: 'Username sudah digunakan!'});

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone] = { username, email, password: hashPassword(password), otp, attempts: 0 };
        
        // Auto-delete OTP setelah 5 menit (Cegah Memory Leak)
        setTimeout(() => { if (tempOtpDB[phone]) delete tempOtpDB[phone]; }, 300000);

        res.json({success: true});
        setTimeout(() => {
            if (globalSock) globalSock.sendMessage(phone + '@s.whatsapp.net', { text: `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nHai ${username},\nKode OTP Pendaftaran: *${otp}*\n\n_⚠️ Jangan bagikan kode ini!_` }).catch(e=>{});
        }, 100);

    } catch(e) { if (!res.headersSent) res.json({success: false, message: 'Gagal memproses pendaftaran.'}); }
});

app.post('/api/verify-otp', (req, res) => {
    try {
        let otp = req.body.otp; let phone = normalizePhone(req.body.phone);
        let session = tempOtpDB[phone];
        if(!session) return res.json({success: false, message: 'Sesi pendaftaran kadaluwarsa. Silakan request OTP ulang.'});

        if(session.otp === otp) {
            let idPelanggan = 'TD-' + Math.floor(100000 + Math.random() * 900000); 
            let u = getRecord('users', phone) || { 
                id_pelanggan: idPelanggan, saldo: 0, 
                tanggal_daftar: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta' }), 
                jid: phone + '@s.whatsapp.net', step: 'idle', trx_count: 0, history: [] 
            };
            
            u.username = session.username; 
            u.email = session.email; 
            u.password = session.password;
            if(!u.id_pelanggan) u.id_pelanggan = idPelanggan;
            
            saveRecord('users', phone, u); 
            delete tempOtpDB[phone]; 
            res.json({success: true});
        } else {
            session.attempts = (session.attempts || 0) + 1;
            if(session.attempts >= 3) {
                delete tempOtpDB[phone];
                return res.json({success: false, message: 'Sesi diblokir, silakan request OTP ulang.'});
            }
            res.json({success: false, message: 'Kode OTP Salah!'});
        }
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/req-edit-otp', verifyToken, (req, res) => {
    try {
        let { phone, type, newValue } = req.body; 
        let u = getRecord('users', phone);
        if(!u) return res.json({success: false, message: 'User tidak ditemukan.'});
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        otpCooldown[phone] = Date.now();

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        if (type === 'password') newValue = hashPassword(newValue);
        tempOtpDB[phone + '_edit'] = { type, newValue, otp, attempts: 0 };
        
        // Auto-delete
        setTimeout(() => { if (tempOtpDB[phone + '_edit']) delete tempOtpDB[phone + '_edit']; }, 300000);
        res.json({success: true});

        setTimeout(() => {
            if (globalSock) globalSock.sendMessage(phone + '@s.whatsapp.net', { text: `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nKode OTP perubahan data: *${otp}*\n\n_⚠️ Jangan berikan ke siapapun!_` }).catch(e=>{});
        }, 100);
    } catch(e) { if (!res.headersSent) res.json({success: false, message: 'Gagal memproses OTP.'}); }
});

app.post('/api/verify-edit-otp', verifyToken, (req, res) => {
    try {
        let { phone, otp } = req.body; let session = tempOtpDB[phone + '_edit'];
        if(!session) return res.json({success: false, message: 'Sesi kadaluwarsa, silakan request ulang.'});

        if(session.otp === otp) {
            let u = getRecord('users', phone);
            if(session.type === 'email') u.email = session.newValue;
            if(session.type === 'password') u.password = session.newValue;
            if(session.type === 'phone') {
                let newPhone = normalizePhone(session.newValue);
                let existU = getRecord('users', newPhone);
                if(existU) return res.json({success: false, message: 'Nomor sudah dipakai akun lain.'});
                u.jid = newPhone + '@s.whatsapp.net';
                saveRecord('users', newPhone, u);
                deleteRecord('users', phone);
            } else {
                saveRecord('users', phone, u);
            }
            delete tempOtpDB[phone + '_edit']; res.json({success: true});
        } else {
            session.attempts = (session.attempts || 0) + 1;
            if(session.attempts >= 3) {
                delete tempOtpDB[phone + '_edit'];
                return res.json({success: false, message: 'Sesi diblokir, silakan request OTP ulang.'});
            }
            res.json({success: false, message: 'OTP Salah!'});
        }
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/req-forgot-otp', (req, res) => {
    try {
        let phone = normalizePhone(req.body.phone);
        let u = getRecord('users', phone);
        if(!u) return res.json({success: false, message: 'Nomor WA tidak terdaftar!'});
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        otpCooldown[phone] = Date.now();

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone + '_forgot'] = { otp, attempts: 0 };
        
        setTimeout(() => { if (tempOtpDB[phone + '_forgot']) delete tempOtpDB[phone + '_forgot']; }, 300000);
        res.json({success: true});

        setTimeout(() => {
            if (globalSock) globalSock.sendMessage(phone + '@s.whatsapp.net', { text: `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nPermintaan Reset Password.\nKode OTP: *${otp}*\n\n_⚠️ Abaikan jika bukan Anda!_` }).catch(e=>{});
        }, 100);
    } catch(e) { if (!res.headersSent) res.json({success: false, message: 'Gagal memproses OTP.'}); }
});

app.post('/api/verify-forgot-otp', (req, res) => {
    try {
        let phone = normalizePhone(req.body.phone); let { otp, newPass } = req.body;
        let session = tempOtpDB[phone + '_forgot'];
        if(!session) return res.json({success: false, message: 'Sesi OTP tidak ditemukan atau sudah expired.'});

        if(session.otp === otp) {
            let u = getRecord('users', phone);
            if(u) { u.password = hashPassword(newPass); saveRecord('users', phone, u); }
            delete tempOtpDB[phone + '_forgot']; res.json({success: true});
        } else {
            session.attempts = (session.attempts || 0) + 1;
            if(session.attempts >= 3) {
                delete tempOtpDB[phone + '_forgot'];
                return res.json({success: false, message: 'Sesi diblokir, silakan request OTP ulang.'});
            }
            res.json({success: false, message: 'Kode OTP Salah!'});
        }
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/topup', verifyToken, async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan.'});
        let config = getRecord('config', 'main') || {};
        if(!config.gopayToken || (!config.qrisUrl && !config.qrisText)) return res.json({success: false, message: "Sistem QRIS belum diatur Admin."});
        
        let { phone, nominal } = req.body;
        let u = getRecord('users', phone);
        if(!u) return res.json({success: false, message: "User tidak ditemukan."});
        
        let nominalAsli = parseInt(nominal);
        
        // MENCEGAH COLLISION KODE UNIK
        let uniqueCode = Math.floor(Math.random() * 999) + 1;
        let totalPay = nominalAsli + uniqueCode;
        let allTopups = getAllRecords('topup');
        while(Object.values(allTopups).some(t => t.status === 'pending' && t.amount_to_pay === totalPay)) {
            uniqueCode = Math.floor(Math.random() * 999) + 1;
            totalPay = nominalAsli + uniqueCode;
        }

        let finalQrisUrl = config.qrisUrl;
        if (config.qrisText) {
            let dynQris = convertToDynamicQris(config.qrisText, totalPay);
            finalQrisUrl = "https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=15&format=jpeg&data=" + encodeURIComponent(dynQris);
        }

        let trxId = "TP-" + Date.now();
        let expiredAt = Date.now() + 10 * 60 * 1000;

        saveRecord('topup', trxId, { 
            phone, trx_id: trxId, amount_to_pay: totalPay, saldo_to_add: totalPay, 
            status: 'pending', timestamp: Date.now(), expired_at: expiredAt, is_order: false 
        });

        u.history = u.history || [];
        u.history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Topup', nama: 'Topup Saldo QRIS', tujuan: 'Sistem Pembayaran', status: 'Pending', sn: trxId, amount: totalPay, qris_url: finalQrisUrl, expired_at: expiredAt
        });
        if(u.history.length > 50) u.history.pop();
        saveRecord('users', phone, u);

        res.json({success: true});
        
        let emailUser = u.email || '-';
        let namaUser = u.username || phone;
        let teleMsg = `⏳ <b>TOPUP PENDING (QRIS)</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${phone}\n💰 Nominal: Rp ${totalPay.toLocaleString('id-ID')}\n🔖 Ref: ${trxId}\n💳 Metode: QRIS Auto\n💳 Saldo Saat Ini: Rp ${u.saldo.toLocaleString('id-ID')}`;
        sendTelegramAdmin(teleMsg);
    } catch(e) { res.json({success: false, message: "Gagal memproses QRIS."}); }
});

app.post('/api/order-qris', verifyToken, async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan.'});
        
        let config = getRecord('config', 'main') || {};
        if(!config.gopayToken || (!config.qrisUrl && !config.qrisText)) return res.json({success: false, message: "Sistem QRIS belum diatur Admin."});
        
        let { phone, sku, tujuan } = req.body; let pNorm = normalizePhone(phone);
        let uNorm = getRecord('users', pNorm);
        let uOri = getRecord('users', phone);
        let targetKey = uNorm ? pNorm : (uOri ? phone : null);
        if (!targetKey) return res.json({success: false, message: 'Sesi Anda tidak valid.'});
        let u = uNorm || uOri;
        
        let p = getRecord('produk', sku);
        if (!p) return res.json({success: false, message: 'Produk tidak ditemukan.'});
        
        let nominalAsli = parseInt(p.harga);
        
        // MENCEGAH COLLISION
        let uniqueCode = Math.floor(Math.random() * 999) + 1; 
        let totalPay = nominalAsli + uniqueCode;
        let allTopups = getAllRecords('topup');
        while(Object.values(allTopups).some(t => t.status === 'pending' && t.amount_to_pay === totalPay)) {
            uniqueCode = Math.floor(Math.random() * 999) + 1;
            totalPay = nominalAsli + uniqueCode;
        }

        let finalQrisUrl = config.qrisUrl;
        if (config.qrisText) {
            let dynQris = convertToDynamicQris(config.qrisText, totalPay);
            finalQrisUrl = "https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=15&format=jpeg&data=" + encodeURIComponent(dynQris);
        }

        let trxId = "OQ-" + Date.now();
        let expiredAt = Date.now() + 10 * 60 * 1000;

        saveRecord('topup', trxId, { 
            phone: targetKey, trx_id: trxId, amount_to_pay: totalPay, saldo_to_add: totalPay, 
            status: 'pending', timestamp: Date.now(), expired_at: expiredAt, 
            is_order: true, sku: sku, tujuan: sanitizeInput(tujuan), nama_produk: p.nama, harga_asli: nominalAsli 
        });

        u.history = u.history || [];
        u.history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Order QRIS', nama: p.nama + ' (QRIS)', tujuan: sanitizeInput(tujuan), status: 'Pending', sn: trxId, amount: totalPay, qris_url: finalQrisUrl, expired_at: expiredAt
        });
        if(u.history.length > 50) u.history.pop();
        saveRecord('users', targetKey, u);

        res.json({success: true});
        
        let emailUser = u.email || '-';
        let namaUser = u.username || targetKey;
        let teleMsg = `🛒 <b>ORDER QRIS PENDING</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${targetKey}\n📦 Produk: ${p.nama}\n🎯 Tujuan: ${tujuan}\n💰 Nominal: Rp ${totalPay.toLocaleString('id-ID')}\n🔖 Ref: ${trxId}\n💳 Metode: QRIS Auto\n💳 Saldo Saat Ini: Rp ${u.saldo.toLocaleString('id-ID')}`;
        sendTelegramAdmin(teleMsg);
    } catch(e) { res.json({success: false, message: "Gagal memproses QRIS."}); }
});

app.post('/api/order', verifyToken, async (req, res) => {
    let targetKey = ""; let hargaFix = 0; let refId = 'WEB-' + Date.now();
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan.'});
        
        let { phone, sku, tujuan } = req.body; let pNorm = normalizePhone(phone);
        let uNorm = getRecord('users', pNorm);
        let uOri = getRecord('users', phone);
        
        targetKey = uNorm ? pNorm : (uOri ? phone : null);
        if (!targetKey) return res.json({success: false, message: 'Sesi Anda tidak valid. Silakan Logout dan Login kembali.'});
        
        let p = getRecord('produk', sku);
        if (!p) return res.json({success: false, message: 'Produk tidak ditemukan.'});
        let config = getRecord('config', 'main') || {};
        let realSku = p.sku_asli || sku;
        hargaFix = parseInt(p.harga);
        
        let atomicRes;
        try {
            atomicRes = atomicDeductBalance(targetKey, hargaFix);
        } catch (err) {
            return res.json({success: false, message: err.message});
        }

        let u = atomicRes.uData;
        let saldoSebelum = atomicRes.saldoTerkini + hargaFix;

        let username = (config.digiflazzUsername || '').trim();
        let apiKey = (config.digiflazzApiKey || '').trim();
        let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

        const response = await axios.post('https://api.digiflazz.com/v1/transaction', { 
            username: username, buyer_sku_code: realSku, customer_no: sanitizeInput(tujuan), ref_id: refId, sign: sign, max_price: hargaFix
        });
        
        const statusOrder = response.data.data.status; 
        
        let emailUser = u.email || '-';
        let namaUser = u.username || targetKey;
        
        if (statusOrder === 'Gagal') {
            let histObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Refund: ' + p.nama, tujuan: tujuan, status: 'Refund', sn: '-', amount: hargaFix, ref_id: refId };
            u = atomicRefundBalance(targetKey, hargaFix, histObj);
            
            let teleMsgFail = `❌ <b>PESANAN GAGAL DIGIFLAZZ</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${targetKey}\n📦 Produk: ${p.nama}\n🎯 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Alasan: ${response.data.data.message}\n💰 Nominal: Rp ${hargaFix.toLocaleString('id-ID')}\n💳 Metode: Saldo Akun\n💰 Saldo Kembali: Rp ${u.saldo.toLocaleString('id-ID')}`;
            sendTelegramAdmin(teleMsgFail);
            
            return res.json({success: false, message: response.data.data.message});
        }
        
        u = getRecord('users', targetKey); // Re-fetch
        u.trx_count = (u.trx_count || 0) + 1;
        u.history = u.history || [];
        u.history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Order', nama: p.nama, tujuan: tujuan, status: statusOrder, sn: response.data.data.sn || '-', amount: hargaFix, ref_id: refId,
            saldo_sebelumnya: saldoSebelum, saldo_sesudah: u.saldo
        });
        if(u.history.length > 50) u.history.pop();
        saveRecord('users', targetKey, u);
        
        let targetJid = u.jid || targetKey + '@s.whatsapp.net';
        saveRecord('trx', refId, { jid: targetJid, sku: realSku, tujuan: tujuan, harga: hargaFix, nama: p.nama, tanggal: Date.now(), phone: targetKey });

        if (statusOrder === 'Sukses') {
            let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
            let gStats = getRecord('global_stats', dateKey) || 0;
            saveRecord('global_stats', dateKey, gStats + 1);

            let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
            unshiftRecordArray('global_trx', { time: timeStr, product: p.nama, user: namaUser, target: maskStringTarget(tujuan), price: hargaFix, method: 'Saldo Akun' });

            sendBroadcastSuccess(p.nama, namaUser, tujuan, hargaFix, 'Saldo Akun');
        }

        res.json({success: true, saldo: u.saldo});

        let teleMsg = `🔔 <b>PESANAN BARU MASUK</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${targetKey}\n📦 Produk: ${p.nama}\n🎯 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status: <b>${statusOrder}</b>\n💰 Nominal: Rp ${hargaFix.toLocaleString('id-ID')}\n💳 Metode: Saldo Akun\n💳 Saldo Sisa: Rp ${u.saldo.toLocaleString('id-ID')}`;
        sendTelegramAdmin(teleMsg);

    } catch (error) { 
        if (!res.headersSent) {
            // SAFEGUARD REFUND JIKA AXIOS ERROR / TIMEOUT (Cegah Saldo Menguap)
            if (targetKey && hargaFix > 0) {
                let histObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Pengembalian: Error API', tujuan: req.body.tujuan, status: 'Refund', sn: '-', amount: hargaFix, ref_id: refId };
                atomicRefundBalance(targetKey, hargaFix, histObj);
            }
            let errInfo = error.response && error.response.data && error.response.data.data ? error.response.data.data.message : error.message;
            return res.json({success: false, message: errInfo});
        }
    }
});

// ==============================================================
// CORE LOGIC: EKSEKUSI PEMBUATAN AKUN VPN KE SERVER VPS 
// ==============================================================
async function executeVpnOrder(phone, protocol, productId, mode, vpnUsername, vpnPassword, expiredDays, refIdAsal = null, paymentMethod = 'Saldo Akun') {
    let targetKey = normalizePhone(phone);
    let u = getRecord('users', targetKey) || getRecord('users', phone);
    if(!u) return { success: false, message: "Sesi tidak valid." };

    let vpnConfig = getRecord('vpn_config', 'main') || {products:{}, servers:{}};
    let prod = vpnConfig.products[productId];
    if(!prod) return { success: false, message: "Produk VPN tidak ditemukan atau telah dihapus." };
    if(mode === 'reguler' && parseInt(prod.stok) <= 0) return { success: false, message: "Stok untuk produk ini sedang habis." };

    let serverKey = prod.server_id;
    let srv = vpnConfig.servers[serverKey];
    if(!srv || !srv.host || !srv.api_key) {
        return { success: false, message: "Server VPN ini sedang gangguan / konfigurasi tidak valid." };
    }

    if (mode === 'trial') {
        if (!u.trial_claims) u.trial_claims = {};
        let lastClaim = u.trial_claims[productId] || 0;
        if (Date.now() - lastClaim < 2 * 60 * 60 * 1000) { 
            return { success: false, message: "⚠️ Gagal: Anda sudah melakukan trial di Produk ini. Silakan coba 2 Jam lagi." };
        }
    }

    let hargaFix = 0;
    let saldoSebelum = parseInt(u.saldo);
    if (mode === 'reguler') {
        let basePrice = parseInt(prod.price) || 0;
        let hari = parseInt(expiredDays) || 30;
        if (hari > 30) hari = 30;
        if (hari < 1) hari = 1;
        hargaFix = Math.ceil((basePrice / 30) * hari);
        
        if (paymentMethod === 'Saldo Akun') {
            try {
                let atomicRes = atomicDeductBalance(targetKey, hargaFix);
                u = atomicRes.uData;
            } catch (err) {
                return { success: false, message: err.message };
            }
        }
    }

    let protoLower = protocol.toLowerCase();
    let endpoint = '';
    
    let vpnLimitIp = parseInt(prod.limit_ip) || 2;
    let vpnKuota = parseInt(prod.kuota) || 200;
    
    let payload = {};
    let cleanHost = srv.host.replace(/^https?:\/\//i, '');

    if (mode === 'trial') {
        payload = { timelimit: "30m", kuota: 2, limitip: 2 };
        if(protoLower === 'ssh') endpoint = `http://${cleanHost}/vps/trialsshvpn`;
        else endpoint = `http://${cleanHost}/vps/trial${protoLower}all`;
    } else {
        payload = { username: sanitizeInput(vpnUsername), expired: parseInt(expiredDays) || 30, limitip: vpnLimitIp, kuota: vpnKuota };
        if(protoLower === 'ssh' || protoLower === 'zivpn') payload.password = sanitizeInput(vpnPassword);
        else payload.uuidv2 = '';
        
        if(protoLower === 'ssh') endpoint = `http://${cleanHost}/vps/sshvpn`;
        else endpoint = `http://${cleanHost}/vps/${protoLower}all`; 
    }

    try {
        let resApi = await axios.post(endpoint, payload, {
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + srv.api_key },
            timeout: 120000,
            validateStatus: () => true, 
            httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false })
        });

        // Re-fetch user in case it changed
        u = getRecord('users', targetKey) || getRecord('users', phone);
        if (!u.trial_claims) u.trial_claims = {};

        let isSuccessResponse = (resApi.status >= 200 && resApi.status < 300) && resApi.data && !resApi.data.error && resApi.data.status !== false;
        let isErrorResponse = resApi.data && (resApi.data.status === false || resApi.data.error || resApi.status >= 400);

        if(isSuccessResponse && !isErrorResponse) {
            let apiData = resApi.data.data || resApi.data || {};
            let domain = srv.host;
            let expDate = apiData.expired || apiData.exp || apiData.to || (mode === 'trial' ? '30 Menit' : `${parseInt(expiredDays) || 30} Hari`);
            let vpnDetails = '';
            
            let fixCity = srv.city || apiData.city || '-';
            let fixIsp = srv.isp || apiData.isp || '-';
            let vpnUser = apiData.username || vpnUsername || "TrialUser";

            if (protoLower === 'ssh') {
                vpnDetails = `Account Created Successfully\n————————————————————————————————————\nDomain Host     : ${domain}\nCity            : ${fixCity}\nISP             : ${fixIsp}\nUsername        : ${vpnUser}\nPassword        : ${apiData.password || vpnPassword || '1'}\n————————————————————————————————————\nExpired         : ${expDate}\n————————————————————————————————————\nTLS             : ${apiData.port?.tls || '443,8443'}\nNone TLS        : ${apiData.port?.none || '80,8080'}\nAny             : 2082,2083,8880\nOpenSSH         : 444\nDropbear        : 90\n————————————————————————————————————\nSlowDNS         : 53,5300\nUDP-Custom      : 1-65535\nOHP + SSH       : 9080\nSquid Proxy     : 3128\nUDPGW           : 7100-7600\nOpenVPN TCP     : 80,1194\nOpenVPN SSL     : 443\nOpenVPN UDP     : 25000\nOpenVPN DNS     : 53\nOHP + OVPN      : 9088\n————————————————————————————————————`;
            } else if (protoLower === 'vmess') {
                vpnDetails = `————————————————————————————————————\n               VMESS\n————————————————————————————————————\nRemarks        : ${vpnUser}\nDomain Host    : ${domain}\nCity           : ${fixCity}\nISP            : ${fixIsp}\nPort TLS       : 443,8443\nPort none TLS  : 80,8080\nPort any       : 2052,2053,8880\nid             : ${apiData.uuid || apiData.id || '-'}\nalterId        : 0\nSecurity       : auto\nnetwork        : ws,grpc,upgrade\npath ws        : /vmess\nserviceName    : vmess\npath upgrade   : /upvmess\nExpired On     : ${expDate}\n————————————————————————————————————\n           VMESS WS TLS\n————————————————————————————————————\n${apiData.link?.tls || '-'}\n————————————————————————————————————\n          VMESS WS NO TLS\n————————————————————————————————————\n${apiData.link?.none || '-'}\n————————————————————————————————————\n             VMESS GRPC\n————————————————————————————————————\n${apiData.link?.grpc || '-'}\n————————————————————————————————————`;
            } else if (protoLower === 'vless') {
                vpnDetails = `————————————————————————————————————\n               VLESS\n————————————————————————————————————\nRemarks        : ${vpnUser}\nDomain Host    : ${domain}\nCity           : ${fixCity}\nISP            : ${fixIsp}\nPort TLS       : 443,8443\nPort none TLS  : 80,8080\nPort any       : 2052,2053,8880\nid             : ${apiData.uuid || apiData.id || '-'}\nEncryption     : none\nNetwork        : ws,grpc,upgrade\nPath ws        : /vless\nserviceName    : vless\nPath upgrade   : /upvless\nExpired On     : ${expDate}\n————————————————————————————————————\n            VLESS WS TLS\n————————————————————————————————————\n${apiData.link?.tls || '-'}\n————————————————————————————————————\n          VLESS WS NO TLS\n————————————————————————————————————\n${apiData.link?.none || '-'}\n————————————————————————————————————\n             VLESS GRPC\n————————————————————————————————————\n${apiData.link?.grpc || '-'}\n————————————————————————————————————`;
            } else if (protoLower === 'trojan') {
                vpnDetails = `————————————————————————————————————\n               TROJAN\n————————————————————————————————————\nRemarks      : ${vpnUser}\nDomain Host  : ${domain}\nCity         : ${fixCity}\nISP          : ${fixIsp}\nPort         : 443,8443\nPort any     : 2052,2053,8880\nKey          : ${apiData.uuid || apiData.id || '-'}\nNetwork      : ws,grpc,upgrade\nPath ws      : /trojan\nserviceName  : trojan\nPath upgrade : /uptrojan\nExpired On   : ${expDate}\n————————————————————————————————————\n           TROJAN WS TLS\n————————————————————————————————————\n${apiData.link?.tls || '-'}\n————————————————————————————————————\n            TROJAN GRPC\n————————————————————————————————————\n${apiData.link?.grpc || '-'}\n————————————————————————————————————`;
            } else {
                vpnDetails = `Detail Akun ZIVPN:\nDomain Host: ${domain}\nCity: ${fixCity}\nISP: ${fixIsp}\nUsername: ${vpnUser}\nExp: ${expDate}\nLimit IP: ${vpnLimitIp}\n\nInfo selengkapnya cek di aplikasi.`;
            }

            let prodName = prod.name;
            if (mode === 'trial') prodName += ' (TRIAL)';
            
            if (mode === 'reguler') {
                u.trx_count = (u.trx_count || 0) + 1;
                vpnConfig = getRecord('vpn_config', 'main');
                vpnConfig.products[productId].stok -= 1;
                saveRecord('vpn_config', 'main', vpnConfig);
            } else if (mode === 'trial') {
                u.trial_claims[productId] = Date.now();
            }
            
            let refId = refIdAsal || ("VPN-" + Date.now());
            
            if (refIdAsal) {
                let existingHist = u.history.find(h => h.sn === refIdAsal);
                if (existingHist) {
                    existingHist.status = 'Sukses';
                    existingHist.vpn_details = vpnDetails;
                    existingHist.nama = prodName;
                    existingHist.type = 'Order VPN';
                    existingHist.saldo_sebelumnya = saldoSebelum;
                    existingHist.saldo_sesudah = u.saldo;
                }
            } else {
                u.history.unshift({
                    ts: Date.now(), 
                    tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
                    type: 'Order VPN', nama: prodName, tujuan: (mode==='trial'?'Sistem':vpnUser), status: 'Sukses', sn: '-', amount: hargaFix, ref_id: refId,
                    saldo_sebelumnya: saldoSebelum, saldo_sesudah: u.saldo,
                    vpn_details: vpnDetails
                });
                if(u.history.length > 50) u.history.pop();
            }
            saveRecord('users', targetKey, u);

            let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
            let gStats = getRecord('global_stats', dateKey) || 0;
            saveRecord('global_stats', dateKey, gStats + 1);

            let namaUser = u.username || targetKey;

            if (mode !== 'trial') {
                let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
                unshiftRecordArray('global_trx', { time: timeStr, product: prodName, user: namaUser, target: maskStringTarget(vpnUser), price: hargaFix, method: paymentMethod });
                sendBroadcastSuccess(prodName, namaUser, vpnUser, hargaFix, paymentMethod);
            }

            let emailUser = u.email || '-';
            let vpnConfNew = getRecord('vpn_config', 'main');
            let teleSuccess = `🚀 <b>ORDER VPN PREMIUM SUKSES</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${targetKey}\n📦 Produk: ${prodName}\n🎯 Username VPN: ${vpnUser}\n💰 Nominal: Rp ${hargaFix.toLocaleString('id-ID')}\n💳 Metode: ${mode === 'trial' ? 'Gratis (Trial)' : paymentMethod}\n📦 Sisa Stok: ${mode === 'reguler' ? vpnConfNew.products[productId].stok : 'Trial'}\n💳 Saldo Terkini: Rp ${u.saldo.toLocaleString('id-ID')}`;
            sendTelegramAdmin(teleSuccess);

            return { success: true };
        } else {
            // Revert Deduction if Failed (Dengan Atomic Refund + Unshift History Pembatalan)
            if (mode === 'reguler' && paymentMethod === 'Saldo Akun') {
                let refHistObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Refund: ' + prod.name, tujuan: vpnUsername, status: 'Refund', sn: '-', amount: hargaFix, ref_id: refIdAsal || 'VPN-'+Date.now() };
                atomicRefundBalance(targetKey, hargaFix, refHistObj);
            }

            let errMsg = "unknown error";
            if (resApi.data && resApi.data.message) errMsg = resApi.data.message;
            else if (resApi.data && resApi.data.error) errMsg = resApi.data.error;
            else if (resApi.statusText) errMsg = resApi.statusText;
            
            if(errMsg.toLowerCase().includes('exist') || errMsg.toLowerCase().includes('already') || errMsg.toLowerCase().includes('sudah ada')) {
                return { success: false, message: "Username sudah ada/terpakai, silakan ganti username lain." };
            }
            return { success: false, message: "Gagal membuat akun di Server VPN. Pesan: " + errMsg };
        }
    } catch(e) {
        if (mode === 'reguler' && paymentMethod === 'Saldo Akun') {
            let refHistObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Refund: ' + prod.name, tujuan: vpnUsername, status: 'Refund', sn: '-', amount: hargaFix, ref_id: refIdAsal || 'VPN-'+Date.now() };
            atomicRefundBalance(targetKey, hargaFix, refHistObj);
        }
        return { success: false, message: "Koneksi ke Server VPN Gagal / Timeout. Pesan: " + e.message };
    }
}

app.post('/api/order-vpn', verifyToken, async (req, res) => {
    if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan.'});
    let { phone, protocol, product_id, mode, username, password, expired } = req.body;
    let result = await executeVpnOrder(phone, protocol, product_id, mode, sanitizeInput(username), sanitizeInput(password), expired, null, 'Saldo Akun');
    res.json(result);
});

app.post('/api/order-vpn-qris', verifyToken, async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan.'});
        
        let config = getRecord('config', 'main') || {};
        if(!config.gopayToken || (!config.qrisUrl && !config.qrisText)) return res.json({success: false, message: "Sistem QRIS belum diatur Admin."});
        
        let { phone, protocol, product_id, mode, username, password, expired } = req.body;
        username = sanitizeInput(username); password = sanitizeInput(password);
        
        let pNorm = normalizePhone(phone);
        let uNorm = getRecord('users', pNorm);
        let uOri = getRecord('users', phone);
        let targetKey = uNorm ? pNorm : (uOri ? phone : null);
        if (!targetKey) return res.json({success: false, message: 'Sesi Anda tidak valid.'});
        let u = uNorm || uOri;
        
        let vpnConfig = getRecord('vpn_config', 'main');
        let prod = vpnConfig.products[product_id];
        if(!prod) return res.json({success: false, message: 'Produk VPN tidak ditemukan.'});
        if(mode === 'reguler' && parseInt(prod.stok) <= 0) return res.json({success: false, message: 'Stok habis.'});

        let basePrice = parseInt(prod.price) || 0;
        let hari = parseInt(expired) || 30;
        if(hari > 30) hari = 30; if(hari < 1) hari = 1;
        let nominalAsli = Math.ceil((basePrice / 30) * hari);
        
        let uniqueCode = Math.floor(Math.random() * 999) + 1; 
        let totalPay = nominalAsli + uniqueCode;
        let allTopups = getAllRecords('topup');
        while(Object.values(allTopups).some(t => t.status === 'pending' && t.amount_to_pay === totalPay)) {
            uniqueCode = Math.floor(Math.random() * 999) + 1;
            totalPay = nominalAsli + uniqueCode;
        }

        let finalQrisUrl = config.qrisUrl;
        if (config.qrisText) {
            let dynQris = convertToDynamicQris(config.qrisText, totalPay);
            finalQrisUrl = "https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=15&format=jpeg&data=" + encodeURIComponent(dynQris);
        }

        let trxId = "VQ-" + Date.now();
        let expiredAt = Date.now() + 10 * 60 * 1000;
        let prodName = prod.name;

        saveRecord('topup', trxId, { 
            phone: targetKey, trx_id: trxId, amount_to_pay: totalPay, saldo_to_add: totalPay, 
            status: 'pending', timestamp: Date.now(), expired_at: expiredAt, 
            is_order: true, vpn_data: { protocol, product_id, mode, username, password, expired, nama_produk: prodName, harga_asli: nominalAsli }
        });

        u.history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Order VPN QRIS', nama: prodName + ' (QRIS)', tujuan: username, status: 'Pending', sn: trxId, amount: totalPay, qris_url: finalQrisUrl, expired_at: expiredAt
        });
        if(u.history.length > 50) u.history.pop();
        saveRecord('users', targetKey, u);

        res.json({success: true});
        
        let emailUser = u.email || '-';
        let namaUser = u.username || targetKey;
        let teleMsg = `🛒 <b>ORDER VPN QRIS PENDING</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${targetKey}\n📦 Produk: ${prodName}\n🎯 Username VPN: ${username}\n💰 Nominal: Rp ${totalPay.toLocaleString('id-ID')}\n🔖 Ref: ${trxId}\n💳 Metode: QRIS Auto\n💳 Saldo Terkini: Rp ${u.saldo.toLocaleString('id-ID')}`;
        sendTelegramAdmin(teleMsg);
    } catch(e) { res.json({success: false, message: "Gagal memproses QRIS VPN."}); }
});

app.post('/api/manual-vpn', verifyToken, async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan.'});
        let { server_id, mode, type, username, password, expired } = req.body;

        let vpnConfig = getRecord('vpn_config', 'main');
        if(!vpnConfig || !vpnConfig.servers || !vpnConfig.servers[server_id]) {
            return res.json({success: false, message: 'Server tidak ditemukan.'});
        }

        let srv = vpnConfig.servers[server_id];
        if(!srv || !srv.host || !srv.api_key) return res.json({success: false, message: 'Konfigurasi server tidak valid.'});

        let limitip_all = 2;
        let kuota_reguler = 200;
        let kuota_trial = 2;
        let timelimit_trial = "30m";

        let endpoint_url = '';
        let payload = {};
        let cleanHost = srv.host.replace(/^https?:\/\//i, '');
        let protoLower = type.toLowerCase();

        if (mode === 'trial') {
            payload = { timelimit: timelimit_trial, kuota: kuota_trial, limitip: limitip_all };
            if(protoLower === 'ssh') endpoint_url = `http://${cleanHost}/vps/trialsshvpn`;
            else endpoint_url = `http://${cleanHost}/vps/trial${protoLower}all`;
        } else {
            payload = { username: sanitizeInput(username), expired: parseInt(expired) || 30, limitip: limitip_all, kuota: kuota_reguler };
            if(protoLower === 'ssh' || protoLower === 'zivpn') payload.password = sanitizeInput(password);
            else payload.uuidv2 = '';

            if(protoLower === 'ssh') endpoint_url = `http://${cleanHost}/vps/sshvpn`;
            else endpoint_url = `http://${cleanHost}/vps/${protoLower}all`;
        }

        const response = await axios.post(endpoint_url, payload, {
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + srv.api_key },
            timeout: 120000,
            validateStatus: () => true,
            httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false })
        });

        let isSuccessResponse = (response.status >= 200 && response.status < 300) && response.data && !response.data.error && response.data.status !== false;
        
        if(isSuccessResponse) {
            let apiData = response.data.data || response.data || {};
            res.json({success: true, data: apiData, server: srv});
        } else {
            let errMsg = "Unknown error";
            if (response.data && response.data.message) errMsg = response.data.message;
            else if (response.data && response.data.error) errMsg = response.data.error;
            res.json({success: false, message: errMsg});
        }
    } catch(e) {
        res.json({success: false, message: e.message});
    }
});

async function prosesAutoOrderVPN(phone, vpnData, refIdAsal) {
    let result = await executeVpnOrder(phone, vpnData.protocol, vpnData.product_id, vpnData.mode, vpnData.username, vpnData.password, vpnData.expired, refIdAsal, 'QRIS');
    let u = getRecord('users', phone);
    
    let hist = u.history.find(h => h.sn === refIdAsal);
    if(!hist) return;

    if(!result.success) {
        let hargaFix = parseInt(vpnData.harga_asli);
        let histObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Refund: ' + vpnData.nama_produk, tujuan: vpnData.username, status: 'Refund', sn: '-', amount: hargaFix, ref_id: refIdAsal };
        let uRefund = atomicRefundBalance(phone, hargaFix, histObj);
        
        hist.status = 'Refund';
        saveRecord('users', phone, uRefund);
        
        let failMsg = result.message || "GAGAL VPS";
        let emailUser = uRefund.email || '-';
        let namaUser = uRefund.username || phone;
        let teleMsg = `⚠️ <b>INFO ORDER VPN QRIS: GAGAL VPS</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${phone}\n🔖 Ref: ${refIdAsal}\n⚙️ Alasan: ${failMsg}\n💰 Saldo Rp ${hargaFix.toLocaleString('id-ID')} telah otomatis di-refund ke akun pengguna.\n💳 Metode: QRIS Auto`;
        sendTelegramAdmin(teleMsg);
    }
}

async function prosesAutoOrderQRIS(phone, sku, tujuan, nama_produk, harga_asli, refIdAsal) {
    try {
        let config = getRecord('config', 'main') || {}; 
        let p = getRecord('produk', sku) || {};
        
        let hargaFix = parseInt(harga_asli);
        let realSku = p.sku_asli || sku;

        let username = (config.digiflazzUsername || '').trim();
        let apiKey = (config.digiflazzApiKey || '').trim();
        let refId = 'WEB-' + Date.now();
        let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

        const response = await axios.post('https://api.digiflazz.com/v1/transaction', { 
            username: username, buyer_sku_code: realSku, customer_no: tujuan, ref_id: refId, sign: sign, max_price: hargaFix
        });
        
        const statusOrder = response.data.data.status; 
        
        let u = getRecord('users', phone);
        let saldoTerkini = parseInt(u.saldo);
        let emailUser = u.email || '-';
        let namaUser = u.username || phone;

        if (statusOrder === 'Gagal') {
            let histObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Refund: ' + nama_produk, tujuan: tujuan, status: 'Refund', sn: '-', amount: hargaFix, ref_id: refId };
            u = atomicRefundBalance(phone, hargaFix, histObj);
            
            let hist = u.history.find(h => h.sn === refIdAsal && h.type === 'Order QRIS');
            if(hist) hist.status = 'Refund';
            saveRecord('users', phone, u);
            
            if(globalSock) {
                globalSock.sendMessage(u.jid || phone + '@s.whatsapp.net', { text: `❌ *PESANAN GAGAL & DI-REFUND*\n\nMaaf, pesanan ${nama_produk} tujuan ${tujuan} ditolak oleh sistem.\n\n💰 Saldo Anda sebesar Rp ${hargaFix.toLocaleString('id-ID')} telah dikembalikan utuh ke akun Website.` }).catch(e=>{});
            }

            let teleMsgFail = `⚠️ <b>INFO ORDER QRIS: GAGAL DIGIFLAZZ</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${phone}\n🔖 Ref: ${refIdAsal}\n⚙️ Status Digiflazz Gagal.\n💰 Saldo Rp ${hargaFix.toLocaleString('id-ID')} telah otomatis di-refund ke akun pengguna.\n💳 Metode: QRIS Auto`;
            sendTelegramAdmin(teleMsgFail);
            return;
        }
        
        u.trx_count = (u.trx_count || 0) + 1;
        let hist = u.history.find(h => h.sn === refIdAsal && h.type === 'Order QRIS');
        if(hist) {
            hist.status = statusOrder;
            hist.sn = response.data.data.sn || '-';
            hist.nama = nama_produk;
            hist.type = 'Order';
            hist.amount = hargaFix;
            hist.ref_id = refId;
            hist.saldo_sebelumnya = saldoTerkini + hargaFix;
            hist.saldo_sesudah = saldoTerkini;
        } else {
            u.history.unshift({ ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Order', nama: nama_produk, tujuan: tujuan, status: statusOrder, sn: response.data.data.sn || '-', amount: hargaFix, ref_id: refId, saldo_sebelumnya: saldoTerkini + hargaFix, saldo_sesudah: saldoTerkini });
            if(u.history.length > 50) u.history.pop();
        }
        saveRecord('users', phone, u);
        
        let targetJid = u.jid || phone + '@s.whatsapp.net';
        saveRecord('trx', refId, { jid: targetJid, sku: realSku, tujuan: tujuan, harga: hargaFix, nama: nama_produk, tanggal: Date.now(), phone: phone });

        if (statusOrder === 'Sukses') {
            let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
            unshiftRecordArray('global_trx', { time: timeStr, product: nama_produk, user: namaUser, target: maskStringTarget(tujuan), price: hargaFix, method: 'QRIS' });
            sendBroadcastSuccess(nama_produk, namaUser, tujuan, hargaFix, 'QRIS');
        }

        let teleMsg = `🚀 <b>AUTO ORDER QRIS BERHASIL DITEMBAK</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${phone}\n📦 Produk: ${nama_produk}\n🎯 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status Awal: <b>${statusOrder}</b>\n💳 Metode: QRIS Auto\n💳 Saldo Terkini: Rp ${u.saldo.toLocaleString('id-ID')}`;
        sendTelegramAdmin(teleMsg);

    } catch(e) {}
}

function doBackupAndSend() {
    let cfg = getRecord('config', 'main') || {};
    if (!cfg.teleToken || !cfg.teleChatId) return;
    exec(`[ -d "/etc/letsencrypt" ] && sudo tar -czf ssl_backup.tar.gz -C / etc/letsencrypt 2>/dev/null; rm -f backup.zip && zip backup.zip tendo_database.db ssl_backup.tar.gz 2>/dev/null`, (err) => {
        if (!err) exec(`curl -s -F chat_id="${cfg.teleChatId}" -F document=@"backup.zip" -F caption="📦 Backup Digital Tendo Store (SQLite)" https://api.telegram.org/bot${cfg.teleToken}/sendDocument`);
    });
}
let cfgBackupCheck = getRecord('config', 'main') || {};
if (cfgBackupCheck.autoBackup) setInterval(doBackupAndSend, (cfgBackupCheck.backupInterval || 720) * 60 * 1000); 

async function startBot() {
    const baileys = await import('@whiskeysockets/baileys');
    const makeWASocket = baileys.default.default || baileys.default;
    const { useMultiFileAuthState, DisconnectReason, Browsers, jidNormalizedUser, fetchLatestBaileysVersion } = baileys;

    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = getRecord('config', 'main') || {};
    const { version } = await fetchLatestBaileysVersion();
    const sock = makeWASocket({ version, auth: state, logger: pino({ level: 'silent' }), browser: Browsers.ubuntu('Chrome'), printQRInTerminal: false, syncFullHistory: false });
    globalSock = sock; 

    if (!sock.authState.creds.registered) {
        setTimeout(async () => {
            try {
                let formattedNumber = config.botNumber.replace(/[^0-9]/g, '');
                const code = await sock.requestPairingCode(formattedNumber);
                console.log(`\n\x1b[36m==================================================\x1b[0m`);
                console.log(`\x1b[32m📱 NOMOR BOT WA  : \x1b[33m+${formattedNumber}\x1b[0m`);
                console.log(`\x1b[32m🔑 KODE PAIRING  : \x1b[1m\x1b[37m${code}\x1b[0m`);
                console.log(`\x1b[36m==================================================\x1b[0m`);
            } catch (error) {}
        }, 8000); 
    }
    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', (u) => { if(u.connection === 'close') setTimeout(startBot, 4000); });

    sock.ev.on('call', async (calls) => { /* Call Logic Omitted for brevity */ });

    setInterval(() => {
        let currentlyMaintenance = cekPemeliharaan();
        let cfg = getRecord('config', 'main') || {};
        let sTime = cfg.maintStart || '23:00';
        let eTime = cfg.maintEnd || '00:30';

        if (currentlyMaintenance && !isMaintenanceNow) {
            isMaintenanceNow = true;
            let msg = `🛠️ *INFO PEMELIHARAAN SISTEM*\n\nSaat ini sistem sedang memasuki jam pemeliharaan rutin (${sTime} - ${eTime} WIB). Transaksi sementara ditutup.`;
            if (globalSock && cfg.waBroadcastId) globalSock.sendMessage(cfg.waBroadcastId, { text: msg }).catch(e=>{});
        } else if (!currentlyMaintenance && isMaintenanceNow) {
            isMaintenanceNow = false;
            let msg = "✅ *PEMELIHARAAN SELESAI*\n\nSistem telah beroperasi normal kembali. Silakan lakukan transaksi seperti biasa. Terima kasih atas pengertiannya.";
            if (globalSock && cfg.waBroadcastId) globalSock.sendMessage(cfg.waBroadcastId, { text: msg }).catch(e=>{});
        }
    }, 60000); 

    let isCheckingQris = false;
    setInterval(async () => {
        if(isCheckingQris) return;
        isCheckingQris = true;
        try {
            let cfg = getRecord('config', 'main') || {};
            let topups = getAllRecords('topup');
            let pendingKeys = Object.keys(topups).filter(k => topups[k].status === 'pending');
            if(pendingKeys.length === 0 || !cfg.gopayToken || !cfg.gopayMerchantId) {
                isCheckingQris = false;
                return;
            }

            const gopayRes = await axios.get('http://gopay.bhm.biz.id/api/transactions', 
                { headers: { 'Authorization': 'Bearer ' + cfg.gopayToken } }
            );
            
            let mutasiArray = Array.isArray(gopayRes.data.data) ? gopayRes.data.data : [];
            let strFallback = JSON.stringify(gopayRes.data);

            for(let key of pendingKeys) {
                let req = topups[key];

                if (Date.now() > req.expired_at) {
                    req.status = 'gagal'; saveRecord('topup', key, req);
                    let u = getRecord('users', req.phone);
                    if(u) {
                        let hist = u.history.find(h => h.sn === req.trx_id);
                        if(hist && hist.status === 'Pending') { hist.status = 'Gagal (Kedaluwarsa)'; saveRecord('users', req.phone, u); }
                        sendTelegramAdmin(`❌ <b>${req.is_order ? 'ORDER QRIS' : 'TOPUP'} KEDALUWARSA</b>\n\n📱 WA: ${req.phone}\n💰 Rp ${req.amount_to_pay.toLocaleString('id-ID')}\n🔖 Ref: ${req.trx_id}`);
                    }
                } 
                else {
                    let amountStr = req.amount_to_pay.toString();
                    let claimMutasiId = null;
                    
                    if (mutasiArray.length > 0) {
                        for (let m of mutasiArray) {
                            let cleanAmount = (m.amount || m.nominal || '').toString().replace(/[^0-9]/g, '');
                            let uniqueMId = m.id || m.transaction_id || m.reference_id || (cleanAmount + "_" + m.timestamp);
                            if (cleanAmount === amountStr) {
                                let checkUsed = dbSqlite.prepare("SELECT id FROM used_mutations WHERE id = ?").get(uniqueMId);
                                if (!checkUsed) { claimMutasiId = uniqueMId; break; }
                            }
                        }
                    } else {
                        // Fallback String Check (Kurang presisi tapi mencegah crash total)
                        let isFound = strFallback.includes(`"${amountStr}"`) || strFallback.includes(`:${amountStr}`);
                        if (isFound) claimMutasiId = "MANUAL_" + amountStr + "_" + Date.now();
                    }

                    if(claimMutasiId) {
                        dbSqlite.prepare("INSERT INTO used_mutations (id, timestamp) VALUES (?, ?)").run(claimMutasiId, Date.now());
                        req.status = 'sukses';
                        saveRecord('topup', key, req);
                        
                        let u = getRecord('users', req.phone);
                        if(u) {
                            if (!req.is_order) {
                                let histObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Topup', nama: 'Topup Saldo QRIS', tujuan: 'Sistem Pembayaran', status: 'Sukses', sn: req.trx_id, amount: req.amount_to_pay, qris_url: '' };
                                atomicAddBalance(req.phone, req.saldo_to_add, histObj);
                                
                                u = getRecord('users', req.phone); // Re-fetch
                                let emailUser = u.email || '-';
                                let namaUser = u.username || req.phone;
                                let teleMsg = `✅ <b>TOPUP QRIS SUKSES MASUK</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${req.phone}\n💰 Saldo Masuk: Rp ${req.saldo_to_add.toLocaleString('id-ID')}\n🔖 Ref: ${req.trx_id}\n💳 Saldo Terkini: Rp ${u.saldo.toLocaleString('id-ID')}`;
                                sendTelegramAdmin(teleMsg);
                            } else {
                                atomicAddBalance(req.phone, req.saldo_to_add, null);
                                if(req.vpn_data) {
                                    prosesAutoOrderVPN(req.phone, req.vpn_data, req.trx_id);
                                } else {
                                    let nominalBeli = parseInt(req.harga_asli);
                                    try { atomicDeductBalance(req.phone, nominalBeli); } catch(err) { }
                                    prosesAutoOrderQRIS(req.phone, req.sku, req.tujuan, req.nama_produk, req.harga_asli, req.trx_id);
                                }
                            }
                        }
                    }
                }
            }
        } catch(e) {}
        isCheckingQris = false;
    }, 30000); 

    let isCheckingDigi = false;
    setInterval(async () => {
        if(isCheckingDigi) return;
        isCheckingDigi = true;
        try {
            let trxs = getAllRecords('trx'); 
            let keys = Object.keys(trxs); 
            if (keys.length === 0) { isCheckingDigi = false; return; }
            
            let cfg = getRecord('config', 'main') || {}; 
            let userAPI = (cfg.digiflazzUsername || '').trim(); 
            let keyAPI = (cfg.digiflazzApiKey || '').trim();
            if (!userAPI || !keyAPI) { isCheckingDigi = false; return; }

            // OPTIMASI: Filter dan Batasi 5 Trx per Cycle (Aman dari Rate Limit)
            let validKeys = keys.filter(ref => (Date.now() - trxs[ref].tanggal) > 60000); 
            let batch = validKeys.slice(0, 5);

            for (let ref of batch) {
                let trx = trxs[ref]; 
                let signCheck = crypto.createHash('md5').update(userAPI + keyAPI + ref).digest('hex');
                try {
                    const cekRes = await axios.post('https://api.digiflazz.com/v1/transaction', { username: userAPI, buyer_sku_code: trx.sku, customer_no: trx.tujuan, ref_id: ref, sign: signCheck });
                    const resData = cekRes.data.data;
                    if (resData.status === 'Sukses' || resData.status === 'Gagal') {
                        let phoneKey = trx.phone || trx.jid.split('@')[0];
                        let u = getRecord('users', phoneKey);
                        let namaUser = u?.username || phoneKey;
                        let emailUser = u?.email || '-';

                        if(resData.status === 'Sukses') {
                            let wasNotSuccess = false;
                            if (u && u.history) {
                                let hist = u.history.find(h => h.ref_id === ref);
                                if (hist && hist.status !== 'Sukses') { 
                                    hist.status = 'Sukses'; hist.sn = resData.sn || '-'; 
                                    saveRecord('users', phoneKey, u); 
                                    wasNotSuccess = true;
                                }
                            }
                            
                            if(wasNotSuccess) {
                                let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
                                let gStats = getRecord('global_stats', dateKey) || 0;
                                saveRecord('global_stats', dateKey, gStats + 1);
                                
                                let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
                                unshiftRecordArray('global_trx', { time: timeStr, product: trx.nama, user: namaUser, target: maskStringTarget(trx.tujuan), price: parseInt(trx.harga), method: 'Sistem Otomatis' });

                                sendBroadcastSuccess(trx.nama, namaUser, trx.tujuan, parseInt(trx.harga), 'Sistem Otomatis');

                                let teleSuccess = `✅ <b>PESANAN SUKSES</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${phoneKey}\n📦 Produk: ${trx.nama}\n🎯 Tujuan: ${trx.tujuan}\n🔖 Ref: ${ref}\n🔑 SN: ${resData.sn || '-'}\n💳 Saldo Terkini: Rp ${u.saldo.toLocaleString('id-ID')}`;
                                sendTelegramAdmin(teleSuccess);
                            }
                            
                        } else {
                            if (u) { 
                                let histObj = { ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Refund', nama: 'Refund: ' + trx.nama, tujuan: trx.tujuan, status: 'Refund', sn: '-', amount: parseInt(trx.harga), ref_id: ref };
                                let uRefund = atomicRefundBalance(phoneKey, parseInt(trx.harga), histObj);
                                
                                if (globalSock) {
                                    globalSock.sendMessage(trx.jid, { text: `❌ *PESANAN GAGAL & DI-REFUND*\n\nMaaf pesanan ${trx.nama} tujuan ${trx.tujuan} gagal diproses pusat.\n\n💰 Saldo Rp ${parseInt(trx.harga).toLocaleString('id-ID')} telah dikembalikan utuh ke akun Anda.` }).catch(e=>{});
                                }
                            }
                            
                            let teleFail = `❌ <b>PESANAN GAGAL & REFUND</b>\n\n👤 Username: ${namaUser}\n📧 Email: ${emailUser}\n📱 WA: ${phoneKey}\n📦 Produk: ${trx.nama}\n🎯 Tujuan: ${trx.tujuan}\n🔖 Ref: ${ref}\n📝 Alasan: ${resData.message}\n\n💰 Saldo telah otomatis dikembalikan.`;
                            sendTelegramAdmin(teleFail);
                        }
                        deleteRecord('trx', ref);
                    } else if (Date.now() - trx.tanggal > 24 * 60 * 60 * 1000) { 
                        deleteRecord('trx', ref);
                    }
                } catch (err) {}
                await new Promise(r => setTimeout(r, 2000)); 
            }
        } catch (err) {}
        isCheckingDigi = false;
    }, 15000); 

    sock.ev.on('messages.upsert', async m => {
        try {
            const msg = m.messages[0]; if (!msg.message || msg.key.fromMe) return;
            const from = msg.key.remoteJid; const senderJid = jidNormalizedUser(msg.key.participant || msg.key.remoteJid);
            const sender = senderJid.split('@')[0]; const body = msg.message.conversation || msg.message.extendedTextMessage?.text || "";
            if (!body) return;

            let u = getRecord('users', sender);
            if (!u) { 
                u = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta' }), jid: senderJid, step: 'idle', trx_count:0, history:[]}; 
                saveRecord('users', sender, u); 
            }
        } catch (err) {}
    });
}

async function tarikDataLayananOtomatis() {
    try {
        let config = getRecord('config', 'main') || {};
        let namaPengguna = (config.digiflazzUsername || '').trim();
        let kunciAkses = (config.digiflazzApiKey || '').trim();
        if (!namaPengguna || !kunciAkses) return;

        let tandaPengenal = crypto.createHash('md5').update(namaPengguna + kunciAkses + 'pricelist').digest('hex');
        
        const balasanPrepaid = await axios.post('https://api.digiflazz.com/v1/price-list', {
            cmd: 'prepaid', username: namaPengguna, sign: tandaPengenal
        });
        
        const balasanPasca = await axios.post('https://api.digiflazz.com/v1/price-list', {
            cmd: 'pasca', username: namaPengguna, sign: tandaPengenal
        });

        let dataPrepaid = balasanPrepaid.data.data || [];
        let dataPasca = balasanPasca.data.data || [];

        if (dataPrepaid.length < 100) return;

        dataPrepaid = dataPrepaid.map(item => ({ ...item, is_pasca_api: false }));
        dataPasca = dataPasca.map(item => ({ ...item, is_pasca_api: true }));

        let daftarPusat = dataPrepaid.concat(dataPasca);
        let produkLama = getAllRecords('produk');
        let daftarLokal = {};
        let m = config.margin || { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
        
        Object.keys(produkLama).forEach(k => {
            if(produkLama[k].is_manual_cat) daftarLokal[k] = produkLama[k];
        });
        
        daftarPusat.forEach(item => {
            let kodeBarang = item.buyer_sku_code;
            let namaBarang = item.product_name;
            let hargaModal = item.price || item.admin || 0;
            
            let statusProduk = (item.buyer_product_status === true && item.seller_product_status === true);
            let catDigi = (item.category || '').trim();
            let catLower = catDigi.toLowerCase();
            let brandLower = (item.brand || '').toLowerCase();
            let kategoriBarang = 'Lainnya';
            
            if (item.is_pasca_api) {
                if (catLower === 'pln pascabayar') kategoriBarang = 'PLN Pasca';
                else if (catLower === 'pdam') kategoriBarang = 'PDAM';
                else if (catLower === 'bpjs kesehatan') kategoriBarang = 'BPJS';
                else if (catLower === 'gas negara') kategoriBarang = 'Gas Negara';
                else if (catLower === 'internet pascabayar') kategoriBarang = 'Internet & TV';
                else if (catLower === 'e-money' || catLower.includes('finance') || catLower.includes('tagihan')) kategoriBarang = 'E-Money Pasca';
                else kategoriBarang = catDigi;
            } else {
                if (catLower === 'pulsa') kategoriBarang = 'Pulsa';
                else if (catLower === 'data') kategoriBarang = 'Data';
                else if (catLower === 'e-money') kategoriBarang = 'E-Money';
                else if (catLower === 'games') kategoriBarang = 'Game';
                else if (catLower === 'pln') kategoriBarang = 'PLN';
                else if (catLower === 'voucher') kategoriBarang = 'Voucher';
                else if (catLower === 'paket sms & telpon') kategoriBarang = 'Paket SMS & Telpon';
                else if (catLower === 'masa aktif') kategoriBarang = 'Masa Aktif';
                else if (catLower === 'aktivasi perdana' || catLower === 'perdana') kategoriBarang = 'Aktivasi Perdana';
                else kategoriBarang = catDigi;
            }
            
            let keuntungan = 0;
            if(hargaModal <= 100) keuntungan = m.t1;
            else if(hargaModal <= 500) keuntungan = m.t2;
            else if(hargaModal <= 1000) keuntungan = m.t3;
            else if(hargaModal <= 2000) keuntungan = m.t4;
            else if(hargaModal <= 3000) keuntungan = m.t5;
            else if(hargaModal <= 4000) keuntungan = m.t6;
            else if(hargaModal <= 5000) keuntungan = m.t7;
            else if(hargaModal <= 10000) keuntungan = m.t8;
            else if(hargaModal <= 25000) keuntungan = m.t9;
            else if(hargaModal <= 50000) keuntungan = m.t10;
            else if(hargaModal <= 75000) keuntungan = m.t11;
            else if(hargaModal <= 100000) keuntungan = m.t12;
            else keuntungan = m.t13;

            let finalPrice = hargaModal + keuntungan;

            for (let k in daftarLokal) {
                if (daftarLokal[k].is_manual_cat && String(daftarLokal[k].sku_asli).toUpperCase() === String(kodeBarang).toUpperCase()) {
                    daftarLokal[k].harga = finalPrice;
                }
            }

            if (!produkLama[kodeBarang] || !produkLama[kodeBarang].is_manual_cat) {
                daftarLokal[kodeBarang] = {
                    sku_asli: kodeBarang,
                    nama: namaBarang,
                    harga: finalPrice,
                    kategori: kategoriBarang,
                    brand: item.brand || 'Lainnya',
                    sub_kategori: item.type || 'Umum',
                    deskripsi: item.desc || 'Proses Otomatis',
                    status_produk: statusProduk,
                    is_manual_cat: false
                };
            }
        });

        dbSqlite.prepare("DELETE FROM produk").run();
        for(let k in daftarLokal) saveRecord('produk', k, daftarLokal[k]);

        console.log('\x1b[32m✅ Data Produk Digiflazz Berhasil Tersinkronisasi ke SQLite!\x1b[0m');

    } catch(err) {
        let errorMsg = err.response && err.response.data && err.response.data.data ? err.response.data.data.message : err.message;
        console.log('\x1b[31m❌ Gagal Sinkronisasi Digiflazz.\x1b[0m Alasan:', errorMsg); 
    }
}

app.get('/api/sync-digiflazz', async (req, res) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
        return res.status(403).json({success: false, message: 'Akses ditolak.'});
    }
    await tarikDataLayananOtomatis();
    res.json({success: true, message: 'Sinkronisasi Selesai.'});
});

setInterval(tarikDataLayananOtomatis, 30 * 60 * 1000);
setTimeout(tarikDataLayananOtomatis, 10000);

if (require.main === module) {
    app.listen(3000, '0.0.0.0', () => { console.log('\x1b[32m🌐 SERVER WEB AKTIF (PORT 3000).\x1b[0m'); });
    startBot().catch(err => {});
}
EOF
}

generate_cek_saldo_script() {
    cat << 'EOF' > cek_saldo.js
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');

async function getSaldo() {
    try {
        let config = {};
        if (fs.existsSync('tendo_database.db')) {
            const Database = require('better-sqlite3');
            const db = new Database('tendo_database.db', { readonly: true });
            let row = db.prepare("SELECT data FROM config WHERE id = 'main'").get();
            if (row) config = JSON.parse(row.data);
        }
        let user = config.digiflazzUsername || '';
        let key = config.digiflazzApiKey || '';
        if(!user || !key) return console.log('Rp 0 (API Belum Diatur)');
        let sign = crypto.createHash('md5').update(user + key + 'depo').digest('hex');
        let res = await axios.post('https://api.digiflazz.com/v1/cek-saldo', {
            cmd: 'deposit', username: user, sign: sign
        });
        console.log('Rp ' + res.data.data.deposit.toLocaleString('id-ID'));
    } catch(e) { console.log('Rp 0 (Gangguan Server)'); }
}
getSaldo();
EOF
}
# === SELESAI ===
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

    echo -ne "${C_MAG}>> Mengatur zona waktu (Asia/Jakarta)...${C_RST}"
    sudo timedatectl set-timezone Asia/Jakarta > /dev/null 2>&1 || sudo ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    echo -e "${C_GREEN}[Selesai]${C_RST}"

    echo -ne "${C_MAG}>> Mengupdate repositori sistem...${C_RST}"
    (sudo -E apt-get update > /dev/null 2>&1 && sudo -E apt-get upgrade -y > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"

    echo -ne "${C_MAG}>> Menginstall dependensi (curl, zip, unzip, build-essential, python3)...${C_RST}"
    sudo -E apt-get install -y curl git wget nano zip unzip build-essential python3 > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"

    echo -ne "${C_MAG}>> Memeriksa dan membuat Swap RAM 2GB...${C_RST}"
    if [ $(swapon --show | wc -l) -eq 0 ]; then
        sudo fallocate -l 2G /swapfile
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile > /dev/null 2>&1
        sudo swapon /swapfile
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
        echo -e "${C_GREEN}[Dibuat]${C_RST}"
    else
        echo -e "${C_GREEN}[Sudah Ada]${C_RST}"
    fi
    
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
    generate_cek_saldo_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Mengunduh modul utama (termasuk SQLite & JWT)...${C_RST}"
    npm install @whiskeysockets/baileys@latest pino qrcode-terminal axios express body-parser node-telegram-bot-api better-sqlite3 jsonwebtoken > install_npm.log 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD}                 ✅ INSTALASI SELESAI!                ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    read -p "Tekan Enter untuk kembali..."
}

menu_tutorial() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             🎬 MANAJEMEN TUTORIAL 🎬               ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Tutorial Baru"
        echo -e "  ${C_GREEN}[2]${C_RST} Edit Tutorial"
        echo -e "  ${C_GREEN}[3]${C_RST} Hapus Tutorial"
        echo -e "  ${C_GREEN}[4]${C_RST} Lihat Daftar Tutorial"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-4]: ${C_RST}"
        read tut_choice

        case $tut_choice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH TUTORIAL BARU ---${C_RST}"
                read -p "Masukkan Judul Tutorial: " t_judul
                if [ -z "$t_judul" ]; then echo "Batal."; sleep 1; continue; fi
                
                echo -e "Anda bisa memasukkan URL video (mp4) untuk didownload otomatis,"
                echo -e "ATAU masukkan path file lokal di VPS (contoh: /root/video.mp4)"
                echo -e "ATAU KOSONGKAN saja jika tutorial ini HANYA BERUPA TEKS."
                read -p "URL / Path Video (Boleh Kosong): " t_video_src
                
                if [ -z "$t_video_src" ]; then
                    t_video_name="-"
                    echo -e "${C_YELLOW}Tutorial ini dibuat tanpa video (hanya teks).${C_RST}"
                else
                    read -p "Nama file saat disimpan (contoh: tutor1.mp4): " t_video_name
                    mkdir -p public/tutorials
                    
                    if [[ "$t_video_src" == http* ]]; then
                        echo -e "${C_CYAN}⏳ Mendownload video...${C_RST}"
                        wget -qO "public/tutorials/$t_video_name" "$t_video_src"
                        if [ $? -eq 0 ]; then
                            echo -e "${C_GREEN}✅ Video berhasil didownload!${C_RST}"
                        else
                            echo -e "${C_RED}❌ Gagal mendownload video.${C_RST}"
                        fi
                    else
                        if [ -f "$t_video_src" ]; then
                            cp "$t_video_src" "public/tutorials/$t_video_name"
                            echo -e "${C_GREEN}✅ Video berhasil dicopy!${C_RST}"
                        else
                            echo -e "${C_RED}❌ File lokal tidak ditemukan. Melanjutkan simpan data saja...${C_RST}"
                        fi
                    fi
                fi
                
                echo -e "Untuk baris baru gunakan tag <br>, atau tulis teks panjang."
                read -p "Masukkan Deskripsi (Bisa paragraf/list): " t_desc
                
                T_JUDUL="$t_judul" T_VIDEO="$t_video_name" T_DESC="$t_desc" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let newId = 'TUT-' + Date.now();
                    let data = { id: newId, title: process.env.T_JUDUL, video: process.env.T_VIDEO, desc: process.env.T_DESC };
                    db.prepare('INSERT OR REPLACE INTO tutorial (id, data) VALUES (?, ?)').run(newId, JSON.stringify(data));
                    console.log('\x1b[32m✅ Data tutorial berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- EDIT TUTORIAL ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT id, data FROM tutorial').all();
                    if(rows.length === 0) { console.log('\x1b[31mBelum ada tutorial.\x1b[0m'); process.exit(0); }
                    rows.forEach((r, i) => { let t = JSON.parse(r.data); console.log('[' + (i+1) + '] ' + t.title + ' (' + t.video + ')'); });
                "
                echo ""
                read -p "Pilih nomor tutorial yang ingin diedit: " t_num
                if [[ "$t_num" =~ ^[0-9]+$ ]]; then
                    read -p "Judul Baru (Kosongkan jika tidak diubah): " t_judul
                    read -p "Nama File Video Baru (Kosongkan jika tidak diubah, isi '-' untuk hapus video): " t_video
                    read -p "Deskripsi Baru (Kosongkan jika tidak diubah): " t_desc
                    
                    T_NUM="$t_num" T_JUDUL="$t_judul" T_VIDEO="$t_video" T_DESC="$t_desc" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let rows = db.prepare('SELECT id, data FROM tutorial').all();
                        let idx = parseInt(process.env.T_NUM) - 1;
                        if(rows[idx]) {
                            let t = JSON.parse(rows[idx].data);
                            if(process.env.T_JUDUL !== '') t.title = process.env.T_JUDUL;
                            if(process.env.T_VIDEO !== '') t.video = process.env.T_VIDEO;
                            if(process.env.T_DESC !== '') t.desc = process.env.T_DESC;
                            db.prepare('UPDATE tutorial SET data = ? WHERE id = ?').run(JSON.stringify(t), t.id);
                            console.log('\x1b[32m✅ Tutorial berhasil diupdate!\x1b[0m');
                        } else {
                            console.log('\x1b[31m❌ Nomor tidak valid.\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_MAG}--- HAPUS TUTORIAL ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT id, data FROM tutorial').all();
                    if(rows.length === 0) { console.log('\x1b[31mBelum ada tutorial.\x1b[0m'); process.exit(0); }
                    rows.forEach((r, i) => { let t = JSON.parse(r.data); console.log('[' + (i+1) + '] ' + t.title); });
                "
                echo ""
                read -p "Pilih nomor tutorial yang ingin dihapus: " t_num
                if [[ "$t_num" =~ ^[0-9]+$ ]]; then
                    T_NUM="$t_num" node -e "
                        const fs = require('fs');
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let rows = db.prepare('SELECT id, data FROM tutorial').all();
                        let idx = parseInt(process.env.T_NUM) - 1;
                        if(rows[idx]) {
                            let t = JSON.parse(rows[idx].data);
                            let videoName = t.video;
                            let filepath = 'public/tutorials/' + videoName;
                            if(videoName !== '-' && fs.existsSync(filepath)) {
                                fs.unlinkSync(filepath);
                                console.log('\x1b[33mFile video ' + videoName + ' dihapus.\x1b[0m');
                            }
                            db.prepare('DELETE FROM tutorial WHERE id = ?').run(t.id);
                            console.log('\x1b[32m✅ Tutorial berhasil dihapus!\x1b[0m');
                        } else {
                            console.log('\x1b[31m❌ Nomor tidak valid.\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_CYAN}--- DAFTAR TUTORIAL ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT id, data FROM tutorial').all();
                    if(rows.length === 0) { console.log('\x1b[33mBelum ada tutorial.\x1b[0m'); }
                    else {
                        rows.forEach((r, i) => {
                            let t = JSON.parse(r.data);
                            console.log('\n\x1b[36m[' + (i+1) + '] ' + t.title + '\x1b[0m');
                            console.log('   Video: ' + t.video);
                            console.log('   Deskripsi: ' + t.desc);
                        });
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_member() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             👥 MANAJEMEN MEMBER BOT 👥             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Saldo Member"
        echo -e "  ${C_GREEN}[2]${C_RST} Kurangi Saldo Member"
        echo -e "  ${C_GREEN}[3]${C_RST} Lihat Daftar Semua Member Aktif"
        echo -e "  ${C_GREEN}[4]${C_RST} Cek Riwayat Transaksi/Topup Member"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-4]: ${C_RST}"
        read subchoice

        case $subchoice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH SALDO ---${C_RST}"
                read -p "Cari Target (Bisa Nomor WA, Email, ATAU Nama Akun): " pencarian
                read -p "Masukkan Jumlah Saldo: " jumlah
                PENCARIAN="$pencarian" JUMLAH="$jumlah" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let input = (process.env.PENCARIAN || '').trim();
                    let normPhone = input.replace(/[^0-9]/g, '');
                    if(input.startsWith('+62')) normPhone = '62' + input.substring(3);
                    else if(input.startsWith('0')) normPhone = '62' + input.substring(1);
                    
                    let rows = db.prepare('SELECT id, data FROM users').all();
                    let target = null;
                    let targetData = null;
                    for(let r of rows) {
                        let u = JSON.parse(r.data);
                        if(r.id === normPhone || (u.email && u.email.toLowerCase() === input.toLowerCase()) || (u.username && u.username.toLowerCase() === input.toLowerCase())) {
                            target = r.id; targetData = u; break;
                        }
                    }
                    
                    if(!target) {
                        if(normPhone === '') {
                            console.log('\x1b[31m\n❌ Akun tidak ditemukan dengan nama atau email tersebut.\x1b[0m');
                            process.exit(0);
                        }
                        target = normPhone;
                        targetData = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta' }), jid: target + '@s.whatsapp.net', trx_count: 0, history: [] };
                    }
                    
                    let namaUser = targetData.username || target;
                    let saldoSebelum = parseInt(targetData.saldo || 0);
                    let nominalTambah = parseInt(process.env.JUMLAH || 0);
                    targetData.saldo = saldoSebelum + nominalTambah;
                    
                    targetData.history = targetData.history || [];
                    targetData.history.unshift({ 
                        ts: Date.now(), 
                        tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
                        type: 'Topup', nama: 'Topup Manual (Admin)', tujuan: 'Sistem', status: 'Sukses', sn: '-', amount: nominalTambah, 
                        saldo_sebelumnya: saldoSebelum, saldo_sesudah: targetData.saldo 
                    });
                    if(targetData.history.length > 50) targetData.history.pop();
                    
                    db.prepare('INSERT OR REPLACE INTO users (id, data) VALUES (?, ?)').run(target, JSON.stringify(targetData));
                    console.log('\x1b[32m\n✅ Saldo Rp ' + nominalTambah.toLocaleString('id-ID') + ' berhasil ditambahkan ke ' + namaUser + ' (' + target + ')!\x1b[0m');
                    console.log('\x1b[33mSaldo Sebelumnya: Rp ' + saldoSebelum.toLocaleString('id-ID') + '\x1b[0m');
                    console.log('\x1b[36mSaldo Sekarang  : Rp ' + targetData.saldo.toLocaleString('id-ID') + '\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- KURANGI SALDO ---${C_RST}"
                read -p "Cari Target (Bisa Nomor WA, Email, ATAU Nama Akun): " pencarian
                read -p "Masukkan Jumlah Saldo yg dikurangi: " jumlah
                PENCARIAN="$pencarian" JUMLAH="$jumlah" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let input = (process.env.PENCARIAN || '').trim();
                    let normPhone = input.replace(/[^0-9]/g, '');
                    if(input.startsWith('+62')) normPhone = '62' + input.substring(3);
                    else if(input.startsWith('0')) normPhone = '62' + input.substring(1);
                    
                    let rows = db.prepare('SELECT id, data FROM users').all();
                    let target = null;
                    let targetData = null;
                    for(let r of rows) {
                        let u = JSON.parse(r.data);
                        if(r.id === normPhone || (u.email && u.email.toLowerCase() === input.toLowerCase()) || (u.username && u.username.toLowerCase() === input.toLowerCase())) {
                            target = r.id; targetData = u; break;
                        }
                    }
                    
                    if(!target) { 
                        console.log('\x1b[31m\n❌ Akun tidak ditemukan di database.\x1b[0m'); 
                    } else {
                        let namaUser = targetData.username || target;
                        let saldoSebelum = parseInt(targetData.saldo || 0);
                        let nominalKurang = parseInt(process.env.JUMLAH || 0);
                        
                        targetData.saldo = saldoSebelum - nominalKurang;
                        if(targetData.saldo < 0) targetData.saldo = 0;
                        
                        targetData.history = targetData.history || [];
                        targetData.history.unshift({ 
                            ts: Date.now(), 
                            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
                            type: 'Topup', nama: 'Pengurangan Saldo (Admin)', tujuan: 'Sistem', status: 'Sukses', sn: '-', amount: nominalKurang, 
                            saldo_sebelumnya: saldoSebelum, saldo_sesudah: targetData.saldo 
                        });
                        if(targetData.history.length > 50) targetData.history.pop();
                        
                        db.prepare('INSERT OR REPLACE INTO users (id, data) VALUES (?, ?)').run(target, JSON.stringify(targetData));
                        console.log('\x1b[32m\n✅ Saldo ' + namaUser + ' (' + target + ') berhasil dikurangi!\x1b[0m');
                        console.log('\x1b[33mSaldo Sebelumnya: Rp ' + saldoSebelum.toLocaleString('id-ID') + '\x1b[0m');
                        console.log('\x1b[36mSaldo Sekarang  : Rp ' + targetData.saldo.toLocaleString('id-ID') + '\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR MEMBER AKTIF ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT id, data FROM users').all();
                    
                    let usersArr = [];
                    db.transaction(() => {
                        for(let r of rows) {
                            let u = JSON.parse(r.data);
                            if (!u.email || u.email.trim() === '-' || u.email.trim() === '') {
                                db.prepare('DELETE FROM users WHERE id = ?').run(r.id);
                            } else {
                                usersArr.push({id: r.id, data: u});
                            }
                        }
                    })();
                    
                    usersArr.sort((a, b) => (b.data.saldo || 0) - (a.data.saldo || 0)); 
                    
                    if(usersArr.length === 0) console.log('\x1b[33mBelum ada member aktif (yang terdaftar email).\x1b[0m');
                    else {
                        usersArr.forEach((m, i) => {
                            let nama = m.data.username || 'Member';
                            let email = m.data.email || '-';
                            console.log((i + 1) + '. Nama: ' + nama + ' | WA: ' + m.id + ' | Email: ' + email + ' | Saldo: Rp ' + m.data.saldo.toLocaleString('id-ID'));
                        });
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_CYAN}--- RIWAYAT TOPUP/TRANSAKSI MEMBER ---${C_RST}"
                read -p "Cari Target (Bisa Nomor WA, Email, ATAU Nama Akun): " pencarian
                if [ ! -z "$pencarian" ]; then
                    PENCARIAN="$pencarian" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let input = (process.env.PENCARIAN || '').trim();
                        let normPhone = input.replace(/[^0-9]/g, '');
                        if(input.startsWith('+62')) normPhone = '62' + input.substring(3);
                        else if(input.startsWith('0')) normPhone = '62' + input.substring(1);
                        
                        let rows = db.prepare('SELECT id, data FROM users').all();
                        let targetData = null;
                        let targetId = null;
                        for(let r of rows) {
                            let u = JSON.parse(r.data);
                            if(r.id === normPhone || (u.email && u.email.toLowerCase() === input.toLowerCase()) || (u.username && u.username.toLowerCase() === input.toLowerCase())) {
                                targetData = u; targetId = r.id; break;
                            }
                        }
                        
                        if(targetData) {
                            let history = targetData.history || [];
                            let targetSaldo = targetData.saldo || 0;
                            let targetNama = targetData.username || 'Member';
                            let topups = history.filter(h => h.type === 'Topup' || h.type === 'Order QRIS' || h.type === 'Refund' || h.type === 'Order' || h.type === 'Order VPN' || h.type === 'Order VPN QRIS').slice(0, 10);
                            
                            console.log('\n\x1b[36m=== 10 RIWAYAT TERBARU: ' + targetNama + ' (' + targetId + ') ===\x1b[0m');
                            console.log('\x1b[32m💰 Saldo Saat Saat Ini: Rp ' + targetSaldo.toLocaleString('id-ID') + '\x1b[0m');
                            if(topups.length === 0) console.log('\x1b[33mBelum ada riwayat topup di akun ini.\x1b[0m');
                            else {
                                topups.forEach(h => {
                                    let str = '- \x1b[33m' + h.tanggal + '\x1b[0m | ' + h.nama + ' | \x1b[32mRp ' + (h.amount || 0).toLocaleString('id-ID') + '\x1b[0m | Status: ' + h.status;
                                    if (h.saldo_sebelumnya !== undefined) str += '\n    └ Saldo Sblm: Rp ' + h.saldo_sebelumnya.toLocaleString('id-ID');
                                    if (h.saldo_sesudah !== undefined) str += ' | Saldo Stlh: Rp ' + h.saldo_sesudah.toLocaleString('id-ID');
                                    console.log(str);
                                });
                            }
                        } else {
                            console.log('\x1b[31m❌ Akun tidak ditemukan berdasarkan pencarian Anda.\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_keuntungan() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             💰 MANAJEMEN KEUNTUNGAN 💰             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        
        node -e "
            const Database = require('better-sqlite3');
            const db = new Database('tendo_database.db', { readonly: true });
            let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
            let c = row ? JSON.parse(row.data).margin || {} : {};
            console.log('  \x1b[32m[1]\x1b[0m  Modal Rp 0 - 100               : Rp ' + (c.t1||50));
            console.log('  \x1b[32m[2]\x1b[0m  Modal Rp 100 - 500             : Rp ' + (c.t2||100));
            console.log('  \x1b[32m[3]\x1b[0m  Modal Rp 500 - 1.000           : Rp ' + (c.t3||250));
            console.log('  \x1b[32m[4]\x1b[0m  Modal Rp 1.000 - 2.000         : Rp ' + (c.t4||500));
            console.log('  \x1b[32m[5]\x1b[0m  Modal Rp 2.000 - 3.000         : Rp ' + (c.t5||1000));
            console.log('  \x1b[32m[6]\x1b[0m  Modal Rp 3.000 - 4.000         : Rp ' + (c.t6||1500));
            console.log('  \x1b[32m[7]\x1b[0m  Modal Rp 4.000 - 5.000         : Rp ' + (c.t7||2000));
            console.log('  \x1b[32m[8]\x1b[0m  Modal Rp 5.000 - 10.000        : Rp ' + (c.t8||2500));
            console.log('  \x1b[32m[9]\x1b[0m  Modal Rp 10.000 - 25.000       : Rp ' + (c.t9||3000));
            console.log('  \x1b[32m[10]\x1b[0m Modal Rp 25.000 - 50.000      : Rp ' + (c.t10||4000));
            console.log('  \x1b[32m[11]\x1b[0m Modal Rp 50.000 - 75.000      : Rp ' + (c.t11||5000));
            console.log('  \x1b[32m[12]\x1b[0m Modal Rp 75.000 - 100.000     : Rp ' + (c.t12||7500));
            console.log('  \x1b[32m[13]\x1b[0m Modal Rp 100.000 - Seterusnya : Rp ' + (c.t13||10000));
        "
        
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST}  Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih nomor rentang yang ingin diubah [0-13]: ${C_RST}"
        read k_choice

        if [ "$k_choice" == "0" ]; then
            break
        elif [[ "$k_choice" -ge 1 && "$k_choice" -le 13 ]]; then
            read -p "Masukkan Keuntungan Baru (Rp) untuk Pilihan $k_choice: " nominal_baru
            
            if [ -z "$nominal_baru" ]; then
                echo -e "${C_RED}❌ Dibatalkan, nominal tidak boleh kosong.${C_RST}"
                sleep 1
                continue
            fi
            
            K_CHOICE="$k_choice" NOMINAL_BARU="$nominal_baru" node -e "
                const Database = require('better-sqlite3');
                const db = new Database('tendo_database.db');
                let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                let config = row ? JSON.parse(row.data) : {};
                if(!config.margin) config.margin = { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
                let tier = 't' + process.env.K_CHOICE;
                config.margin[tier] = parseInt(process.env.NOMINAL_BARU);
                db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
            "
            echo -e "${C_GREEN}✅ Keuntungan tier $k_choice berhasil diubah! Me-refresh Katalog Website...${C_RST}"
            curl -s http://localhost:3000/api/sync-digiflazz > /dev/null
            sleep 1
        else
            echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"
            sleep 1
        fi
    done
}

menu_sinkron() {
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}          🔄 SINKRONISASI PRODUK DIGIFLAZZ 🔄         ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_MAG}Sistem akan menarik seluruh data produk dari API Digiflazz,"
    echo -e "menyesuaikan kategori otomatis, dan menata harga berdasarkan"
    echo -e "Manajemen Keuntungan yang sudah kamu atur sebelumnya.${C_RST}\n"
    
    echo -e "${C_YELLOW}⏳ Memulai sinkronisasi... Harap tunggu beberapa detik.${C_RST}"
    
    curl -s http://localhost:3000/api/sync-digiflazz > /dev/null
    
    echo -e "\n${C_GREEN}✅ Sinkronisasi Selesai! Katalog Website dan Harga sudah terupdate secara realtime.${C_RST}"
    read -p "Tekan Enter untuk kembali..."
}

menu_telegram() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             ⚙️ AUTO-BACKUP KE TELEGRAM ⚙️            ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Aktifkan/Matikan Notifikasi Backup Otomatis"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-1]: ${C_RST}"
        read telechoice

        case $telechoice in
            1)
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
                STATUS="$status" MENIT="$menit" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                    let config = row ? JSON.parse(row.data) : {};
                    config.autoBackup = process.env.STATUS === 'true';
                    config.backupInterval = parseInt(process.env.MENIT);
                    db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_backup() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}               💾 BACKUP & RESTORE 💾               ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Backup Data (Kirim ke Telegram Admin)"
        echo -e "  ${C_GREEN}[2]${C_RST} Restore Database & Bot dari Link"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read backchoice

        case $backchoice in
            1)
                echo -e "\n${C_MAG}⏳ Sedang memproses arsip backup SQLite...${C_RST}"
                if ! command -v zip &> /dev/null; then sudo apt install zip -y > /dev/null 2>&1; fi
                rm -f backup.zip
                if [ -d "/etc/letsencrypt" ]; then
                    sudo tar -czf ssl_backup.tar.gz -C / etc/letsencrypt 2>/dev/null
                fi
                zip backup.zip tendo_database.db ssl_backup.tar.gz 2>/dev/null
                echo -e "${C_GREEN}✅ File backup.zip berhasil dikompresi!${C_RST}"
                node -e "
                    const { exec } = require('child_process');
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db', { readonly: true });
                    let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                    let config = row ? JSON.parse(row.data) : {};
                    
                    if(config.teleToken && config.teleChatId) {
                        console.log('\x1b[36m⏳ Sedang mengirim ke Telegram Admin...\x1b[0m');
                        let cmd = \`curl -s -F chat_id=\"\${config.teleChatId}\" -F document=@\"backup.zip\" -F caption=\"📦 Manual Backup Data SQLite + SSL\" https://api.telegram.org/bot\${config.teleToken}/sendDocument\`;
                        exec(cmd, (err) => {
                            if(err) console.log('\x1b[31m❌ Gagal mengirim ke Telegram.\x1b[0m');
                            else console.log('\x1b[32m✅ File Backup berhasil mendarat di Telegram Admin!\x1b[0m');
                        });
                    } else {
                        console.log('\x1b[33m⚠️ Token Telegram Admin belum diisi di menu setup notifikasi.\x1b[0m');
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
                            if [ -f "ssl_backup.tar.gz" ]; then
                                sudo tar -xzf ssl_backup.tar.gz -C / 2>/dev/null
                                echo -e "${C_GREEN}✅ Sertifikat SSL berhasil direstore!${C_RST}"
                            fi
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

menu_manajemen_produk_instan() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}          📦 MANAJEMEN PRODUK INSTAN 📦             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Produk Instan Otomatis (Digiflazz)"
        echo -e "  ${C_GREEN}[2]${C_RST} Daftar Produk Instan"
        echo -e "  ${C_GREEN}[3]${C_RST} Edit Produk Instan"
        echo -e "  ${C_GREEN}[4]${C_RST} Hapus Produk Instan"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-4]: ${C_RST}"
        read mp_choice

        case $mp_choice in
            1)
                clear
                echo -e "${C_MAG}--- TAMBAH PRODUK INSTAN ---${C_RST}"
                echo -e "Kategori Tersedia:"
                echo -e "1. Pulsa\n2. Data\n3. Game\n4. Voucher\n5. E-Money\n6. PLN\n7. Paket SMS & Telpon\n8. Masa Aktif\n9. Aktivasi Perdana"
                read -p "Pilih kategori [1-9]: " kat_idx
                kat_nama=""
                case $kat_idx in
                    1) kat_nama="Pulsa" ;;
                    2) kat_nama="Data" ;;
                    3) kat_nama="Game" ;;
                    4) kat_nama="Voucher" ;;
                    5) kat_nama="E-Money" ;;
                    6) kat_nama="PLN" ;;
                    7) kat_nama="Paket SMS & Telpon" ;;
                    8) kat_nama="Masa Aktif" ;;
                    9) kat_nama="Aktivasi Perdana" ;;
                    *) echo -e "${C_RED}❌ Kategori tidak valid.${C_RST}"; sleep 1; continue ;;
                esac
                
                read -p "Masukkan Kode SKU Digiflazz: " sku_digi
                if [ -z "$sku_digi" ]; then echo -e "${C_RED}❌ SKU wajib diisi!${C_RST}"; sleep 1; continue; fi
                read -p "Nama Produk: " custom_nama
                read -p "Nama Brand / Provider: " custom_brand
                read -p "Nama Paket (Otomatis tampil paling atas di web): " custom_tipe
                read -p "Deskripsi Singkat: " custom_desc
                
                SKU_DIGI="$sku_digi" CUSTOM_NAMA="$custom_nama" CUSTOM_BRAND="$custom_brand" CUSTOM_TIPE="$custom_tipe" CUSTOM_DESC="$custom_desc" KAT_NAMA="$kat_nama" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let uniqueSku = process.env.SKU_DIGI + '_custom_' + Date.now();
                    
                    let existingPrice = 0;
                    let rows = db.prepare('SELECT data FROM produk').all();
                    for(let r of rows) {
                        let p = JSON.parse(r.data);
                        if(String(p.sku_asli).toUpperCase() === String(process.env.SKU_DIGI).toUpperCase() && !p.is_manual_cat) {
                            existingPrice = p.harga;
                            break;
                        }
                    }

                    let newProd = {
                        sku_asli: process.env.SKU_DIGI, nama: process.env.CUSTOM_NAMA, harga: existingPrice,
                        kategori: process.env.KAT_NAMA, brand: process.env.CUSTOM_BRAND, sub_kategori: '\u200B' + process.env.CUSTOM_TIPE,
                        deskripsi: process.env.CUSTOM_DESC, status_produk: true, is_manual_cat: true
                    };
                    
                    db.prepare('INSERT OR REPLACE INTO produk (id, data) VALUES (?, ?)').run(uniqueSku, JSON.stringify(newProd));
                    
                    console.log('\x1b[32m✅ Produk Instan berhasil ditambahkan!\x1b[0m');
                    if(existingPrice === 0) {
                        console.log('\x1b[33mInfo: Harga saat ini 0, sistem akan menarik harga baru dari pusat otomatis.\x1b[0m');
                    } else {
                        console.log('\x1b[32mInfo: Harga otomatis ditarik dari data produk: Rp ' + existingPrice + '\x1b[0m');
                    }
                "
                curl -s http://localhost:3000/api/sync-digiflazz > /dev/null
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK INSTAN ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT data FROM produk').all();
                    let count = 0;
                    for(let r of rows) {
                        let p = JSON.parse(r.data);
                        if(p.is_manual_cat) {
                            count++;
                            console.log('[' + count + '] SKU Digiflazz: ' + p.sku_asli + ' | Nama: ' + p.nama + ' | Harga Jual: Rp ' + p.harga + ' | Nama Paket: ' + p.sub_kategori.replace('\u200B', ''));
                        }
                    }
                    if(count === 0) console.log('\x1b[33mBelum ada produk instan yang ditambahkan.\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_MAG}--- EDIT PRODUK INSTAN ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT id, data FROM produk').all();
                    let manualProds = [];
                    for(let r of rows) {
                        let p = JSON.parse(r.data);
                        if(p.is_manual_cat) manualProds.push({id: r.id, data: p});
                    }
                    if(manualProds.length === 0) { console.log('\x1b[33mBelum ada produk instan.\x1b[0m'); process.exit(0); }
                    manualProds.forEach((p, i) => {
                        console.log('[' + (i+1) + '] ' + p.data.nama + ' (SKU: ' + p.data.sku_asli + ')');
                    });
                "
                echo ""
                read -p "Pilih nomor urut produk yang ingin diedit: " edit_idx
                if [[ "$edit_idx" =~ ^[0-9]+$ ]]; then
                    read -p "Nama Produk Baru (Kosongkan jika tidak diubah): " e_nama
                    read -p "Deskripsi Baru (Kosongkan jika tidak diubah): " e_desc
                    read -p "Nama Paket Baru (Kosongkan jika tidak diubah): " e_paket
                    
                    EDIT_IDX="$edit_idx" E_NAMA="$e_nama" E_DESC="$e_desc" E_PAKET="$e_paket" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let rows = db.prepare('SELECT id, data FROM produk').all();
                        let manualProds = [];
                        for(let r of rows) {
                            let p = JSON.parse(r.data);
                            if(p.is_manual_cat) manualProds.push({id: r.id, data: p});
                        }
                        
                        let idx = parseInt(process.env.EDIT_IDX) - 1;
                        if(manualProds[idx]) {
                            let key = manualProds[idx].id;
                            let pData = manualProds[idx].data;
                            if(process.env.E_NAMA !== '') pData.nama = process.env.E_NAMA;
                            if(process.env.E_DESC !== '') pData.deskripsi = process.env.E_DESC;
                            if(process.env.E_PAKET !== '') pData.sub_kategori = '\u200B' + process.env.E_PAKET;
                            
                            db.prepare('UPDATE produk SET data = ? WHERE id = ?').run(JSON.stringify(pData), key);
                            console.log('\x1b[32m✅ Produk instan berhasil diupdate!\x1b[0m');
                        } else {
                            console.log('\x1b[31m❌ Nomor urut tidak valid.\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_MAG}--- HAPUS PRODUK INSTAN ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let rows = db.prepare('SELECT id, data FROM produk').all();
                    let manualProds = [];
                    for(let r of rows) {
                        let p = JSON.parse(r.data);
                        if(p.is_manual_cat) manualProds.push({id: r.id, data: p});
                    }
                    if(manualProds.length === 0) { console.log('\x1b[33mBelum ada produk instan.\x1b[0m'); process.exit(0); }
                    manualProds.forEach((p, i) => {
                        console.log('[' + (i+1) + '] ' + p.data.nama + ' (SKU: ' + p.data.sku_asli + ')');
                    });
                "
                echo ""
                read -p "Pilih nomor urut produk yang ingin dihapus: " del_idx
                if [[ "$del_idx" =~ ^[0-9]+$ ]]; then
                    DEL_IDX="$del_idx" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let rows = db.prepare('SELECT id, data FROM produk').all();
                        let manualProds = [];
                        for(let r of rows) {
                            let p = JSON.parse(r.data);
                            if(p.is_manual_cat) manualProds.push({id: r.id});
                        }
                        
                        let idx = parseInt(process.env.DEL_IDX) - 1;
                        if(manualProds[idx]) {
                            db.prepare('DELETE FROM produk WHERE id = ?').run(manualProds[idx].id);
                            console.log('\x1b[32m✅ Produk instan berhasil dihapus dari website!\x1b[0m');
                        } else {
                            console.log('\x1b[31m❌ Nomor urut tidak valid.\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_notifikasi() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}        📢 SETUP INTEGRASI NOTIFIKASI BROADCAST       ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Setup Telegram ADMIN (Laporan Transaksi & Komplain)"
        echo -e "  ${C_GREEN}[2]${C_RST} Setup Telegram PELANGGAN (Kirim Info Web & Saluran)"
        echo -e "  ${C_GREEN}[3]${C_RST} Setup Grup / Saluran WA (Broadcast Sukses)"
        echo -e "  ${C_GREEN}[4]${C_RST} Hapus / Bersihkan Notifikasi di Website"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-4]: ${C_RST}"
        read notif_choice

        case $notif_choice in
            1)
                echo -e "\n${C_MAG}--- SETUP TELEGRAM ADMIN ---${C_RST}"
                echo -e "Notifikasi pesanan masuk, komplain, topup & backup akan dikirim kesini."
                read -p "Masukkan Token Bot Telegram Admin: " token
                read -p "Masukkan Chat ID Admin Anda: " chatid
                TOKEN="$token" CHATID="$chatid" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                    let config = row ? JSON.parse(row.data) : {};
                    if(process.env.TOKEN !== '') config.teleToken = process.env.TOKEN.trim();
                    if(process.env.CHATID !== '') config.teleChatId = process.env.CHATID.trim();
                    db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                    console.log('\x1b[32m\n✅ Konfigurasi Telegram Admin berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- SETUP TELEGRAM PELANGGAN (INFO/SALURAN) ---${C_RST}"
                echo -e "Notifikasi untuk broadcast Global Transaksi Sukses dan Update Info di Web."
                read -p "Masukkan Token Bot Telegram (Boleh bot yang sama/berbeda dari Admin): " token_info
                read -p "Masukkan ID Channel/Saluran Pelanggan (Contoh: -100123456789): " chanid
                TOKEN_INFO="$token_info" CHANID="$chanid" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                    let config = row ? JSON.parse(row.data) : {};
                    if(process.env.TOKEN_INFO !== '') config.teleTokenInfo = process.env.TOKEN_INFO.trim();
                    if(process.env.CHANID !== '') config.teleChannelId = process.env.CHANID.trim();
                    db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                    console.log('\x1b[32m\n✅ Konfigurasi Telegram Pelanggan & Channel berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_MAG}--- SETUP GRUP / SALURAN WHATSAPP ---${C_RST}"
                echo -e "Masukkan ID Grup (contoh: 12345678@g.us) atau Saluran (contoh: 120363xxx@newsletter)."
                echo -e "Bot WA Anda akan mengirim broadcast notifikasi beli sukses kesini."
                read -p "Masukkan ID WA: " waid
                WAID="$waid" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                    let config = row ? JSON.parse(row.data) : {};
                    if(process.env.WAID !== '') config.waBroadcastId = process.env.WAID.trim();
                    db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                    console.log('\x1b[32m\n✅ ID WA Broadcast berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_MAG}--- HAPUS PEMBERITAHUAN WEBSITE ---${C_RST}"
                read -p "Yakin ingin MENGHAPUS semua pemberitahuan di Web? (y/n): " hapus_notif
                if [ "$hapus_notif" == "y" ] || [ "$hapus_notif" == "Y" ]; then
                    node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        db.prepare('DELETE FROM web_notif').run();
                        console.log('\x1b[32m\n✅ Semua pemberitahuan website berhasil dibersihkan!\x1b[0m');
                    "
                else
                    echo -e "${C_YELLOW}Penghapusan dibatalkan.${C_RST}"
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

submenu_server_vpn() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             🌍 MANAJEMEN SERVER VPN 🌍             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah / Edit Koneksi Server"
        echo -e "  ${C_GREEN}[2]${C_RST} List Daftar Server"
        echo -e "  ${C_GREEN}[3]${C_RST} Hapus Koneksi Server"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-3]: ${C_RST}"
        read srv_choice

        case $srv_choice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH / EDIT KONEKSI SERVER ---${C_RST}"
                read -p "Buat ID Server (Unik, misal: srv1 atau SG-VIP): " srv_id
                if [ -z "$srv_id" ]; then echo "Batal."; sleep 1; continue; fi
                
                read -p "Masukkan Nama Server (Misal: VIP Singapura): " srv_name
                read -p "Masukkan Hostname / IP Server: " srv_host
                read -p "Masukkan Port Server (Biarkan kosong jika default): " srv_port
                read -p "Masukkan Username VPS: " srv_user
                read -p "Masukkan Password VPS: " srv_pass
                read -p "Masukkan API Key VPN Panel: " srv_api
                read -p "Masukkan Nama ISP Server: " srv_isp
                read -p "Masukkan Nama Kota/City: " srv_city
                
                SRV_ID="$srv_id" SRV_NAME="$srv_name" SRV_HOST="$srv_host" SRV_PORT="$srv_port" SRV_USER="$srv_user" SRV_PASS="$srv_pass" SRV_API="$srv_api" SRV_ISP="$srv_isp" SRV_CITY="$srv_city" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : {servers:{}, products:{}};
                    if(!vpnDb.servers) vpnDb.servers = {};
                    vpnDb.servers[process.env.SRV_ID] = {
                        server_name: process.env.SRV_NAME, host: process.env.SRV_HOST, port: process.env.SRV_PORT,
                        user: process.env.SRV_USER, pass: process.env.SRV_PASS, api_key: process.env.SRV_API,
                        isp: process.env.SRV_ISP, city: process.env.SRV_CITY
                    };
                    db.prepare(\"INSERT OR REPLACE INTO vpn_config (id, data) VALUES ('main', ?)\").run(JSON.stringify(vpnDb));
                    console.log('\x1b[32m\n✅ Konfigurasi Server (' + process.env.SRV_ID + ') berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_CYAN}--- DAFTAR SERVER VPN ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : {servers:{}, products:{}};
                    let servers = vpnDb.servers || {};
                    let count = 0;
                    for(let id in servers) {
                        count++;
                        let s = servers[id];
                        console.log('- ID: \x1b[33m' + id + '\x1b[0m | Nama: ' + s.server_name + ' | Host: ' + s.host);
                    }
                    if(count === 0) console.log('\x1b[31mBelum ada server VPN yang ditambahkan.\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_MAG}--- HAPUS KONEKSI SERVER ---${C_RST}"
                read -p "Masukkan ID Server yang ingin dihapus: " del_id
                DEL_ID="$del_id" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : null;
                    if(vpnDb && vpnDb.servers && vpnDb.servers[process.env.DEL_ID]) {
                        delete vpnDb.servers[process.env.DEL_ID];
                        db.prepare(\"UPDATE vpn_config SET data = ? WHERE id = 'main'\").run(JSON.stringify(vpnDb));
                        console.log('\x1b[32m\n✅ Server dengan ID (' + process.env.DEL_ID + ') berhasil dihapus!\x1b[0m');
                    } else {
                        console.log('\x1b[31m\n❌ Server dengan ID (' + process.env.DEL_ID + ') tidak ditemukan.\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

submenu_produk_vpn() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             📦 MANAJEMEN PRODUK VPN 📦             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Produk VPN Baru (ID Otomatis Unik)"
        echo -e "  ${C_GREEN}[2]${C_RST} Edit Produk VPN Yang Sudah Ada"
        echo -e "  ${C_GREEN}[3]${C_RST} List Daftar Produk"
        echo -e "  ${C_GREEN}[4]${C_RST} Atur Ulang Stok Produk"
        echo -e "  ${C_GREEN}[5]${C_RST} Hapus Produk"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-5]: ${C_RST}"
        read prod_choice

        case $prod_choice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH PRODUK VPN BARU ---${C_RST}"
                prod_id="VPN-$(date +%s)"
                echo -e "${C_GREEN}Membuat ID Produk Unik: $prod_id${C_RST}"

                echo -e "\nPilih Protokol:"
                echo -e "  [1] SSH\n  [2] Vmess\n  [3] Vless\n  [4] Trojan\n  [5] ZIVPN"
                read -p "Pilihan [1-5]: " proto_opt
                target_proto=""
                case $proto_opt in
                    1) target_proto="SSH" ;;
                    2) target_proto="Vmess" ;;
                    3) target_proto="Vless" ;;
                    4) target_proto="Trojan" ;;
                    5) target_proto="ZIVPN" ;;
                    *) target_proto="SSH" ;;
                esac

                echo -e "\nServer Tersedia:"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : {servers:{}};
                    let servers = vpnDb.servers || {};
                    for(let id in servers) console.log('  - ' + id + ' (' + servers[id].server_name + ')');
                "
                read -p "Ketik ID Server target: " srv_id_target
                read -p "Nama Layanan (Misal: SSH Premium SG VIP): " p_nama
                read -p "Harga Patokan 30 Hari (Rp): " p_harga
                read -p "Limit IP (contoh: 2): " p_limitip
                read -p "Limit Bandwidth Kuota GB (contoh: 200, Kosongkan utk SSH): " p_kuota
                read -p "Jumlah Stok Awal: " p_stok
                read -p "Deskripsi / Fitur Singkat: " p_desc
                
                PROD_ID="$prod_id" TARGET_PROTO="$target_proto" SRV_ID_TARGET="$srv_id_target" P_NAMA="$p_nama" P_HARGA="$p_harga" P_DESC="$p_desc" P_LIMITIP="$p_limitip" P_KUOTA="$p_kuota" P_STOK="$p_stok" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : {servers:{}, products:{}};
                    if(!vpnDb.products) vpnDb.products = {};
                    
                    vpnDb.products[process.env.PROD_ID] = {
                        protocol: process.env.TARGET_PROTO,
                        server_id: process.env.SRV_ID_TARGET,
                        name: process.env.P_NAMA !== '' ? process.env.P_NAMA : 'VPN Premium',
                        price: process.env.P_HARGA !== '' ? parseInt(process.env.P_HARGA) : 0,
                        desc: process.env.P_DESC !== '' ? process.env.P_DESC : 'Proses Otomatis',
                        limit_ip: process.env.P_LIMITIP !== '' ? parseInt(process.env.P_LIMITIP) : 2,
                        kuota: process.env.P_KUOTA !== '' ? parseInt(process.env.P_KUOTA) : 200,
                        stok: process.env.P_STOK !== '' ? parseInt(process.env.P_STOK) : 0
                    };
                    
                    db.prepare(\"INSERT OR REPLACE INTO vpn_config (id, data) VALUES ('main', ?)\").run(JSON.stringify(vpnDb));
                    console.log('\x1b[32m\n✅ Produk VPN Baru (' + process.env.PROD_ID + ') berhasil ditambahkan ke Server!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- EDIT PRODUK VPN ---${C_RST}"
                read -p "Masukkan ID Produk yang ingin diedit: " edit_prod_id
                if [ -z "$edit_prod_id" ]; then echo "Batal."; sleep 1; continue; fi

                echo -e "\nPilih Protokol (KOSONGKAN jika tidak ingin diubah):"
                echo -e "  [1] SSH\n  [2] Vmess\n  [3] Vless\n  [4] Trojan\n  [5] ZIVPN"
                read -p "Pilihan [1-5]: " proto_opt
                target_proto=""
                case $proto_opt in
                    1) target_proto="SSH" ;;
                    2) target_proto="Vmess" ;;
                    3) target_proto="Vless" ;;
                    4) target_proto="Trojan" ;;
                    5) target_proto="ZIVPN" ;;
                    *) target_proto="" ;;
                esac

                echo -e "\nServer Tersedia:"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : {servers:{}};
                    let servers = vpnDb.servers || {};
                    for(let id in servers) console.log('  - ' + id + ' (' + servers[id].server_name + ')');
                "
                read -p "Ketik ID Server target (Kosongkan jika tidak ingin diubah): " srv_id_target
                
                echo -e "\n${C_MAG}*Catatan: KOSONGKAN isian jika tidak ingin mengubah data lama.${C_RST}"
                read -p "Nama Layanan: " p_nama
                read -p "Harga Patokan 30 Hari (Rp): " p_harga
                read -p "Limit IP: " p_limitip
                read -p "Limit Bandwidth Kuota GB: " p_kuota
                read -p "Deskripsi / Fitur Singkat: " p_desc
                
                EDIT_PROD_ID="$edit_prod_id" TARGET_PROTO="$target_proto" SRV_ID_TARGET="$srv_id_target" P_NAMA="$p_nama" P_HARGA="$p_harga" P_DESC="$p_desc" P_LIMITIP="$p_limitip" P_KUOTA="$p_kuota" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : null;
                    if(!vpnDb || !vpnDb.products || !vpnDb.products[process.env.EDIT_PROD_ID]) {
                        console.log('\x1b[31m❌ ID Produk tidak ditemukan!\x1b[0m');
                        process.exit(0);
                    }
                    
                    let existing = vpnDb.products[process.env.EDIT_PROD_ID];
                    
                    vpnDb.products[process.env.EDIT_PROD_ID] = {
                        protocol: process.env.TARGET_PROTO !== '' ? process.env.TARGET_PROTO : existing.protocol,
                        server_id: process.env.SRV_ID_TARGET !== '' ? process.env.SRV_ID_TARGET : existing.server_id,
                        name: process.env.P_NAMA !== '' ? process.env.P_NAMA : existing.name,
                        price: process.env.P_HARGA !== '' ? parseInt(process.env.P_HARGA) : existing.price,
                        desc: process.env.P_DESC !== '' ? process.env.P_DESC : existing.desc,
                        limit_ip: process.env.P_LIMITIP !== '' ? parseInt(process.env.P_LIMITIP) : existing.limit_ip,
                        kuota: process.env.P_KUOTA !== '' ? parseInt(process.env.P_KUOTA) : existing.kuota,
                        stok: existing.stok
                    };
                    
                    db.prepare(\"UPDATE vpn_config SET data = ? WHERE id = 'main'\").run(JSON.stringify(vpnDb));
                    console.log('\x1b[32m\n✅ Produk VPN (' + process.env.EDIT_PROD_ID + ') berhasil diupdate!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK VPN ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : {products:{}};
                    let products = vpnDb.products || {};
                    let count = 0;
                    for(let id in products) {
                        count++;
                        let p = products[id];
                        console.log('- ID: \x1b[33m' + id + '\x1b[0m | Nama: ' + p.name + ' | Proto: ' + p.protocol + ' | Server: ' + p.server_id + ' | Stok: ' + p.stok + ' | Harga: Rp ' + p.price);
                    }
                    if(count === 0) console.log('\x1b[31mBelum ada produk VPN yang ditambahkan.\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_MAG}--- ATUR ULANG STOK PRODUK ---${C_RST}"
                read -p "Masukkan ID Produk: " stok_id
                read -p "Masukkan Jumlah Stok Baru: " stok_baru
                STOK_ID="$stok_id" STOK_BARU="$stok_baru" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : null;
                    if(vpnDb && vpnDb.products && vpnDb.products[process.env.STOK_ID]) {
                        vpnDb.products[process.env.STOK_ID].stok = parseInt(process.env.STOK_BARU) || 0;
                        db.prepare(\"UPDATE vpn_config SET data = ? WHERE id = 'main'\").run(JSON.stringify(vpnDb));
                        console.log('\x1b[32m\n✅ Stok Produk (' + process.env.STOK_ID + ') berhasil diupdate menjadi ' + vpnDb.products[process.env.STOK_ID].stok + '!\x1b[0m');
                    } else {
                        console.log('\x1b[31m\n❌ ID Produk tidak ditemukan.\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            5)
                echo -e "\n${C_MAG}--- HAPUS PRODUK ---${C_RST}"
                read -p "Masukkan ID Produk yang ingin dihapus: " del_id
                DEL_ID="$del_id" node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM vpn_config WHERE id = 'main'\").get();
                    let vpnDb = row ? JSON.parse(row.data) : null;
                    if(vpnDb && vpnDb.products && vpnDb.products[process.env.DEL_ID]) {
                        delete vpnDb.products[process.env.DEL_ID];
                        db.prepare(\"UPDATE vpn_config SET data = ? WHERE id = 'main'\").run(JSON.stringify(vpnDb));
                        console.log('\x1b[32m\n✅ Produk (' + process.env.DEL_ID + ') berhasil dihapus!\x1b[0m');
                    } else {
                        console.log('\x1b[31m\n❌ ID Produk tidak ditemukan.\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_manajemen_vpn() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}              🛡️ MANAJEMEN VPN PREMIUM 🛡️           ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Manajemen Server VPN"
        echo -e "  ${C_GREEN}[2]${C_RST} Manajemen Produk VPN"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read vpn_choice

        case $vpn_choice in
            1) submenu_server_vpn ;;
            2) submenu_produk_vpn ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_etalase_custom() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}          🌟 MANAJEMEN ETALASE CUSTOM 🌟            ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Buat Etalase Baru (Cth: Best Seller)"
        echo -e "  ${C_GREEN}[2]${C_RST} Tambah Produk (SKU) ke Etalase"
        echo -e "  ${C_GREEN}[3]${C_RST} Hapus Produk dari Etalase"
        echo -e "  ${C_GREEN}[4]${C_RST} Hapus Etalase"
        echo -e "  ${C_GREEN}[5]${C_RST} Lihat Daftar Etalase & Produk"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-5]: ${C_RST}"
        read etalase_choice

        case $etalase_choice in
            1)
                echo -e "\n${C_MAG}--- BUAT ETALASE BARU ---${C_RST}"
                read -p "Masukkan Judul Etalase (Cth: Best Seller): " judul_etalase
                if [ ! -z "$judul_etalase" ]; then
                    JUDUL_ETALASE="$judul_etalase" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                        let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                        if(!layoutDb.sections) layoutDb.sections = [];
                        layoutDb.sections.push({title: process.env.JUDUL_ETALASE, skus: []});
                        db.prepare(\"INSERT OR REPLACE INTO custom_layout (id, data) VALUES ('main', ?)\").run(JSON.stringify(layoutDb));
                        console.log('\x1b[32m✅ Etalase \'' + process.env.JUDUL_ETALASE + '\' berhasil dibuat!\x1b[0m');
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- TAMBAH PRODUK KE ETALASE ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                    let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                    if(!layoutDb.sections || layoutDb.sections.length === 0) { console.log('\x1b[31mBelum ada etalase. Buat dulu!\x1b[0m'); process.exit(0); }
                    layoutDb.sections.forEach((sec, idx) => console.log('[' + (idx+1) + '] ' + sec.title));
                "
                echo -e ""
                read -p "Pilih nomor Etalase: " nomor_etalase
                if [[ "$nomor_etalase" =~ ^[0-9]+$ ]]; then
                    read -p "Masukkan KODE SKU Produk: " sku_tambah
                    if [ ! -z "$sku_tambah" ]; then
                        NOMOR_ETALASE="$nomor_etalase" SKU_TAMBAH="$sku_tambah" node -e "
                            const Database = require('better-sqlite3');
                            const db = new Database('tendo_database.db');
                            let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                            let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                            let idx = parseInt(process.env.NOMOR_ETALASE) - 1;
                            if(layoutDb.sections[idx]) {
                                if(!layoutDb.sections[idx].skus.includes(process.env.SKU_TAMBAH)) {
                                    layoutDb.sections[idx].skus.push(process.env.SKU_TAMBAH);
                                    db.prepare(\"UPDATE custom_layout SET data = ? WHERE id = 'main'\").run(JSON.stringify(layoutDb));
                                    console.log('\x1b[32m✅ SKU \'' + process.env.SKU_TAMBAH + '\' berhasil ditambahkan ke ' + layoutDb.sections[idx].title + '!\x1b[0m');
                                } else {
                                    console.log('\x1b[33mSKU sudah ada di etalase ini.\x1b[0m');
                                }
                            } else {
                                console.log('\x1b[31m❌ Nomor etalase tidak valid.\x1b[0m');
                            }
                        "
                    fi
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_MAG}--- HAPUS PRODUK DARI ETALASE ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                    let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                    if(!layoutDb.sections || layoutDb.sections.length === 0) { console.log('\x1b[31mBelum ada etalase.\x1b[0m'); process.exit(0); }
                    layoutDb.sections.forEach((sec, idx) => console.log('[' + (idx+1) + '] ' + sec.title));
                "
                echo -e ""
                read -p "Pilih nomor Etalase: " nomor_etalase
                if [[ "$nomor_etalase" =~ ^[0-9]+$ ]]; then
                    read -p "Masukkan KODE SKU Produk yg ingin dihapus: " sku_hapus
                    if [ ! -z "$sku_hapus" ]; then
                        NOMOR_ETALASE="$nomor_etalase" SKU_HAPUS="$sku_hapus" node -e "
                            const Database = require('better-sqlite3');
                            const db = new Database('tendo_database.db');
                            let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                            let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                            let idx = parseInt(process.env.NOMOR_ETALASE) - 1;
                            if(layoutDb.sections[idx]) {
                                let oldLen = layoutDb.sections[idx].skus.length;
                                layoutDb.sections[idx].skus = layoutDb.sections[idx].skus.filter(s => s !== process.env.SKU_HAPUS);
                                if(layoutDb.sections[idx].skus.length < oldLen) {
                                    db.prepare(\"UPDATE custom_layout SET data = ? WHERE id = 'main'\").run(JSON.stringify(layoutDb));
                                    console.log('\x1b[32m✅ SKU \'' + process.env.SKU_HAPUS + '\' berhasil dihapus dari ' + layoutDb.sections[idx].title + '!\x1b[0m');
                                } else {
                                    console.log('\x1b[31mSKU tidak ditemukan di etalase ini.\x1b[0m');
                                }
                            } else {
                                console.log('\x1b[31m❌ Nomor etalase tidak valid.\x1b[0m');
                            }
                        "
                    fi
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_MAG}--- HAPUS ETALASE ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                    let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                    if(!layoutDb.sections || layoutDb.sections.length === 0) { console.log('\x1b[31mBelum ada etalase.\x1b[0m'); process.exit(0); }
                    layoutDb.sections.forEach((sec, idx) => console.log('[' + (idx+1) + '] ' + sec.title));
                "
                echo -e ""
                read -p "Pilih nomor Etalase yg ingin dihapus: " nomor_etalase
                if [[ "$nomor_etalase" =~ ^[0-9]+$ ]]; then
                    NOMOR_ETALASE="$nomor_etalase" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                        let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                        let idx = parseInt(process.env.NOMOR_ETALASE) - 1;
                        if(layoutDb.sections[idx]) {
                            let title = layoutDb.sections[idx].title;
                            layoutDb.sections.splice(idx, 1);
                            db.prepare(\"UPDATE custom_layout SET data = ? WHERE id = 'main'\").run(JSON.stringify(layoutDb));
                            console.log('\x1b[32m✅ Etalase \'' + title + '\' berhasil dihapus!\x1b[0m');
                        } else {
                            console.log('\x1b[31m❌ Nomor etalase tidak valid.\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            5)
                echo -e "\n${C_CYAN}--- DAFTAR ETALASE & PRODUK ---${C_RST}"
                node -e "
                    const Database = require('better-sqlite3');
                    const db = new Database('tendo_database.db');
                    let row = db.prepare(\"SELECT data FROM custom_layout WHERE id = 'main'\").get();
                    let layoutDb = row ? JSON.parse(row.data) : {sections: []};
                    
                    if(!layoutDb.sections || layoutDb.sections.length === 0) {
                        console.log('\x1b[33mBelum ada etalase yang dibuat.\x1b[0m');
                    } else {
                        layoutDb.sections.forEach((sec, idx) => {
                            console.log('\n\x1b[36m[' + (idx+1) + '] ' + sec.title + '\x1b[0m');
                            if(sec.skus.length === 0) console.log('   (Kosong)');
                            else {
                                sec.skus.forEach(sku => {
                                    let pRow = db.prepare(\"SELECT data FROM produk WHERE id = ?\").get(sku);
                                    let pName = pRow ? JSON.parse(pRow.data).nama : 'Produk Tidak Ditemukan/Dihapus';
                                    console.log('   - ' + sku + ' : ' + pName);
                                });
                            }
                        });
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

menu_pemeliharaan() {
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}          🛠️ ATUR WAKTU PEMELIHARAAN SISTEM 🛠️        ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    node -e "
        const Database = require('better-sqlite3');
        const db = new Database('tendo_database.db');
        let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
        let cfg = row ? JSON.parse(row.data) : {};
        console.log('Waktu Pemeliharaan Saat Ini: ' + (cfg.maintStart || '23:00') + ' s/d ' + (cfg.maintEnd || '00:30') + ' WIB');
    "
    echo -e "${C_MAG}Format waktu 24 Jam (Contoh: 23:00)${C_RST}"
    read -p "Masukkan Jam Mulai Pemeliharaan: " m_start
    read -p "Masukkan Jam Selesai Pemeliharaan: " m_end
    
    if [ ! -z "$m_start" ] && [ ! -z "$m_end" ]; then
        M_START="$m_start" M_END="$m_end" node -e "
            const Database = require('better-sqlite3');
            const db = new Database('tendo_database.db');
            let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
            let cfg = row ? JSON.parse(row.data) : {};
            cfg.maintStart = process.env.M_START;
            cfg.maintEnd = process.env.M_END;
            db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(cfg));
            console.log('\x1b[32m✅ Waktu pemeliharaan berhasil diupdate menjadi ' + process.env.M_START + ' - ' + process.env.M_END + ' WIB!\x1b[0m');
        "
    else
        echo -e "${C_RED}❌ Gagal, format waktu tidak boleh kosong!${C_RST}"
    fi
    read -p "Tekan Enter untuk kembali..."
}

while true; do
    clear
    
    SALDO_DIGI="Rp 0 (Memuat...)"
    if [ -f "cek_saldo.js" ]; then
        SALDO_DIGI=$(node cek_saldo.js 2>/dev/null)
    fi

    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}        🤖 PANEL ADMIN DIGITAL TENDO STORE 🤖         ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD} 💰 Sisa Saldo Digiflazz : ${C_YELLOW}${SALDO_DIGI}${C_RST}"
    echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
    echo -e "${C_MAG}▶ 🟢 SISTEM UTAMA${C_RST}"
    echo -e "  ${C_GREEN}[1]${C_RST}  Install & Perbarui Sistem (Wajib Jalankan Dulu)"
    echo -e "  ${C_GREEN}[2]${C_RST}  Mulai Sistem (Terminal / Scan QR)"
    echo -e "  ${C_GREEN}[3]${C_RST}  Jalankan Sistem di Latar Belakang (PM2)"
    echo -e "  ${C_GREEN}[4]${C_RST}  Hentikan Sistem (PM2)"
    echo -e "  ${C_GREEN}[5]${C_RST}  Lihat Log / Error"
    echo ""
    echo -e "${C_MAG}▶ 📦 MANAJEMEN PRODUK & KATEGORI${C_RST}"
    echo -e "  ${C_GREEN}[6]${C_RST}  🔄 Sinkronisasi Produk Digiflazz"
    echo -e "  ${C_GREEN}[7]${C_RST}  💰 Manajemen Keuntungan Harga (13 Tingkat)"
    echo -e "  ${C_GREEN}[8]${C_RST}  📦 Manajemen Produk Instan (Paket Custom)"
    echo -e "  ${C_GREEN}[9]${C_RST}  🛡️ Manajemen VPN Premium"
    echo -e "  ${C_GREEN}[10]${C_RST} 🌟 Manajemen Etalase Custom (Best Seller)"
    echo -e "  ${C_GREEN}[11]${C_RST} 🎬 Manajemen Tutorial"
    echo ""
    echo -e "${C_MAG}▶ 👥 MANAJEMEN PENGGUNA${C_RST}"
    echo -e "  ${C_GREEN}[12]${C_RST} 👥 Manajemen Saldo & Member"
    echo ""
    echo -e "${C_MAG}▶ ⚙️ PENGATURAN & INTEGRASI${C_RST}"
    echo -e "  ${C_GREEN}[13]${C_RST} 🔌 Ganti API Digiflazz"
    echo -e "  ${C_GREEN}[14]${C_RST} 💳 Setup GoPay Merchant API"
    echo -e "  ${C_GREEN}[15]${C_RST} 📢 Setup Integrasi Notifikasi (Tele/Web)"
    echo -e "  ${C_GREEN}[16]${C_RST} 🌍 Setup Domain & HTTPS (SSL)"
    echo -e "  ${C_GREEN}[17]${C_RST} 🔄 Ganti Akun WA Web OTP (Reset Sesi)"
    echo -e "  ${C_GREEN}[18]${C_RST} 🛠️ Atur Waktu Pemeliharaan Sistem"
    echo ""
    echo -e "${C_MAG}▶ 💾 BACKUP & RESTORE${C_RST}"
    echo -e "  ${C_GREEN}[19]${C_RST} 💾 Backup & Restore Database"
    echo -e "  ${C_GREEN}[20]${C_RST} ⚙️ Pengaturan Auto-Backup Telegram"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -e "  ${C_RED}[0]${C_RST}  Keluar dari Panel"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -ne "${C_YELLOW}Pilih menu [0-20]: ${C_RST}"
    read choice

    case $choice in
        1) install_dependencies ;;
        2) 
            if [ ! -f "index.js" ]; then echo -e "${C_RED}❌ Jalankan Menu 1 (Install) dulu!${C_RST}"; sleep 2; continue; fi
            if [ ! -d "sesi_bot" ] || [ -z "$(ls -A sesi_bot 2>/dev/null)" ]; then
                read -p "📲 Masukkan Nomor WA Bot (Awali 628...): " nomor_bot
                if [ ! -z "$nomor_bot" ]; then
                    NOMOR_BOT="$nomor_bot" node -e "
                        const Database = require('better-sqlite3');
                        const db = new Database('tendo_database.db');
                        let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                        let config = row ? JSON.parse(row.data) : {};
                        config.botNumber = process.env.NOMOR_BOT;
                        config.botName = config.botName || 'Digital Tendo Store';
                        db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                    "
                fi
            fi
            echo -e "\n${C_MAG}⏳ Membersihkan proses lama agar tidak bentrok...${C_RST}"
            pm2 kill >/dev/null 2>&1
            killall node >/dev/null 2>&1
            echo -e "\n${C_MAG}⏳ Menjalankan bot... (Tekan CTRL+C untuk mematikan dan kembali ke menu)${C_RST}"
            export IP_ADDRESS=$(curl -s ifconfig.me)
            node index.js
            echo -e "\n${C_YELLOW}⚠️ Proses bot terhenti.${C_RST}"
            read -p "Tekan Enter untuk kembali ke panel utama..."
            ;;
        3) 
            echo -e "\n${C_MAG}⏳ Membersihkan proses lama agar tidak bentrok...${C_RST}"
            pm2 kill >/dev/null 2>&1
            killall node >/dev/null 2>&1
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
            echo -e "\n${C_GREEN}✅ Sistem dihentikan dan dibersihkan dari latar belakang.${C_RST}"
            sleep 2 ;;
        5) pm2 logs tendo-bot ;;
        6) menu_sinkron ;;
        7) menu_keuntungan ;;
        8) menu_manajemen_produk_instan ;;
        9) menu_manajemen_vpn ;;
        10) menu_etalase_custom ;;
        11) menu_tutorial ;;
        12) menu_member ;;
        13)
            echo -e "\n${C_MAG}--- GANTI API DIGIFLAZZ ---${C_RST}"
            read -p "Username Digiflazz Baru: " user_api
            read -p "API Key Digiflazz Baru: " key_api
            USER_API="$user_api" KEY_API="$key_api" node -e "
                const Database = require('better-sqlite3');
                const db = new Database('tendo_database.db');
                let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                let config = row ? JSON.parse(row.data) : {};
                if(process.env.USER_API !== '') config.digiflazzUsername = process.env.USER_API.trim();
                if(process.env.KEY_API !== '') config.digiflazzApiKey = process.env.KEY_API.trim();
                db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                console.log('\x1b[32m\n✅ Konfigurasi Digiflazz berhasil disimpan!\x1b[0m');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        14)
            echo -e "\n${C_MAG}--- SETUP GOPAY MERCHANT (BHM BIZ API) ---${C_RST}"
            echo -e "${C_YELLOW}Fitur ini akan menghubungkan merchant GoPay Anda dan mengatur QRIS Dinamis!${C_RST}"
            read -p "Masukkan API Token BHM Biz Anda: " gopay_token
            read -p "Masukkan Merchant ID (Angka, contoh: 123): " gopay_mid
            read -p "Masukkan Nomor HP GoPay (08...): " gopay_phone

            if [ ! -z "$gopay_token" ] && [ ! -z "$gopay_phone" ] && [ ! -z "$gopay_mid" ]; then
                echo -e "\n${C_CYAN}>> Mengirim Request OTP ke nomor $gopay_phone...${C_RST}"
                req_otp=$(curl -sS -X POST http://gopay.bhm.biz.id/v1/gopay/merchants/connect/request-otp \
                  -H 'Content-Type: application/json' \
                  -d "{\"phone\":\"$gopay_phone\"}")
                
                echo -e "${C_YELLOW}Respon Server: $req_otp${C_RST}"
                
                read -p "Masukkan 4 Digit OTP dari WA/SMS Gojek: " gopay_otp
                
                if [ ! -z "$gopay_otp" ]; then
                    echo -e "\n${C_CYAN}>> Memverifikasi OTP...${C_RST}"
                    ver_otp=$(curl -sS -X POST http://gopay.bhm.biz.id/v1/gopay/merchants/$gopay_mid/connect/verify-otp \
                      -H "Authorization: Bearer $gopay_token" \
                      -H 'Content-Type: application/json' \
                      -d "{\"otp\":\"$gopay_otp\"}")
                    
                    echo -e "${C_YELLOW}Respon Server: $ver_otp${C_RST}"
                fi
            fi

            echo -e "\n${C_CYAN}Siapkan TEKS STRING dari QRIS Statis Anda.${C_RST}"
            echo -e "Teks QRIS berawalan '000201010211...' dan diakhiri dengan kombinasi 4 huruf/angka (CRC)."
            read -p "Paste TEKS STRING QRIS Anda di sini: " qris_text
            GOPAY_TOKEN="$gopay_token" GOPAY_MID="$gopay_mid" QRIS_TEXT="$qris_text" node -e "
                const Database = require('better-sqlite3');
                const db = new Database('tendo_database.db');
                let row = db.prepare(\"SELECT data FROM config WHERE id = 'main'\").get();
                let config = row ? JSON.parse(row.data) : {};
                if (process.env.GOPAY_TOKEN !== '') config.gopayToken = process.env.GOPAY_TOKEN.trim();
                if (process.env.GOPAY_MID !== '') config.gopayMerchantId = process.env.GOPAY_MID.trim();
                if (process.env.QRIS_TEXT !== '') config.qrisText = process.env.QRIS_TEXT.trim();
                db.prepare(\"INSERT OR REPLACE INTO config (id, data) VALUES ('main', ?)\").run(JSON.stringify(config));
                console.log('\x1b[32m\n✅ Konfigurasi GoPay BHM Biz & QRIS Dinamis berhasil disimpan!\x1b[0m');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        15) menu_notifikasi ;;
        16)
            echo -e "\n${C_MAG}--- SETUP DOMAIN & HTTPS ---${C_RST}"
            read -p "Masukkan Nama Domain Anda (contoh: digitaltendostore.com): " domain_name
            read -p "Masukkan Email Aktif (untuk SSL Let's Encrypt): " ssl_email
            if [ ! -z "$domain_name" ] && [ ! -z "$ssl_email" ]; then
                echo -e "${C_CYAN}>> Menginstal Nginx dan Certbot...${C_RST}"
                sudo apt install -y nginx certbot python3-certbot-nginx > /dev/null 2>&1
                
                cat <<EOF | sudo tee /etc/nginx/sites-available/$domain_name
server {
    listen 80; server_name $domain_name;
    add_header X-Frame-Options "SAMEORIGIN"; add_header X-XSS-Protection "1; mode=block"; add_header X-Content-Type-Options "nosniff";
    location / {
        proxy_pass http://localhost:3000; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection 'upgrade'; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; proxy_read_timeout 90; proxy_connect_timeout 90; proxy_send_timeout 90; proxy_cache_bypass \$http_upgrade;
    }
}
EOF
                sudo ln -sf /etc/nginx/sites-available/$domain_name /etc/nginx/sites-enabled/
                sudo rm -f /etc/nginx/sites-enabled/default
                sudo nginx -t && sudo systemctl restart nginx
                echo -e "${C_CYAN}>> Meminta Sertifikat SSL HTTPS ke Let's Encrypt...${C_RST}"
                sudo certbot --nginx -d $domain_name --non-interactive --agree-tos -m $ssl_email --redirect --keep-until-expiring
                echo -e "\n${C_GREEN}✅ Berhasil diamankan di: https://$domain_name ${C_RST}"
            else
                echo -e "${C_RED}❌ Domain atau Email tidak boleh kosong!${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        17)
            echo -e "\n${C_RED}⚠️ Reset Sesi akan mengeluarkan sistem dari WhatsApp saat ini.${C_RST}"
            read -p "Yakin ingin mereset sesi? (y/n): " reset_sesi
            if [ "$reset_sesi" == "y" ]; then
                pm2 stop tendo-bot >/dev/null 2>&1
                rm -rf sesi_bot
                echo -e "${C_GREEN}✅ Sesi berhasil dihapus. Silakan jalankan sistem kembali untuk menautkan nomor baru.${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        18) menu_pemeliharaan ;;
        19) menu_backup ;;
        20) menu_telegram ;;
        0) echo -e "${C_GREEN}Sampai jumpa!${C_RST}"; exit 0 ;;
        *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
    esac
done
# === SELESAI ===
