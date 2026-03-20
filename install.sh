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
# 2. MODUL ENKRIPSI AES-256 (TENDO CRYPT)
# ==========================================
generate_crypt_module() {
    cat << 'EOF' > tendo_crypt.js
const fs = require('fs');
const crypto = require('crypto');
const ALGO = 'aes-256-cbc';
const KEY = crypto.scryptSync('DigitalTendoStore_SecureKey_2026', 'salt', 32);

function encrypt(text) {
    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv(ALGO, KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv(ALGO, KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

module.exports = {
    load: (file, defaultData = {}) => {
        try {
            if (!fs.existsSync(file)) return defaultData;
            let raw = fs.readFileSync(file, 'utf8');
            if(!raw) return defaultData;
            // Migrasi otomatis jika file masih berupa teks asli (belum dienkripsi)
            if (raw.trim().startsWith('{') || raw.trim().startsWith('[')) {
                let parsed = JSON.parse(raw);
                module.exports.save(file, parsed); // Enkripsi dan simpan ulang
                return parsed;
            }
            return JSON.parse(decrypt(raw));
        } catch(e) {
            return defaultData;
        }
    },
    save: (file, data) => {
        fs.writeFileSync(file, encrypt(JSON.stringify(data, null, 2)));
    }
};
EOF
}

# ==========================================
# 3. FUNGSI MEMBUAT TAMPILAN WEB APLIKASI
# ==========================================
generate_web_app() {
    mkdir -p public/baner1 public/baner2 public/baner3 public/baner4 public/baner5 public/info_images

    cat << 'EOF' > public/manifest.json
{
  "name": "Digital Tendo Store",
  "short_name": "Digital Tendo Store",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ebf0f5",
  "theme_color": "#f8fafc",
  "orientation": "portrait",
  "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/3144/3144456.png", "sizes": "512x512", "type": "image/png"}]
}
EOF

    cat << 'EOF' > public/sw.js
self.addEventListener('install', (e) => { self.skipWaiting(); });
self.addEventListener('activate', (e) => { 
    e.waitUntil(caches.keys().then((keyList) => {
        return Promise.all(keyList.map((key) => caches.delete(key)));
    }));
    self.clients.claim(); 
});
self.addEventListener('fetch', (e) => { 
    // PERBAIKAN: Mencegah error muter-muter saat web direload
    e.respondWith(
        fetch(e.request).catch(() => {
            return caches.match(e.request);
        })
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
    <meta name="theme-color" content="#ffffff">
    <style>
        /* VARIABEL TEMA GELAP / TERANG */
        :root {
            --bg-main: #e9eef5; 
            --bg-card: #f4f7f9; 
            --text-main: #0b2136;
            --text-muted: #64748b;
            --border-color: #d1d9e2;
            --grid-bg: #f4f7f9;
            --grid-shadow: inset 3px 3px 7px rgba(0,0,0,0.06), inset -3px -3px 7px rgba(255,255,255,0.6); 
            --grid-border: 1px solid transparent;
            --nav-bg: #0f172a;
            --nav-text: #64748b;
            --nav-active: #38bdf8;
            --topbar-bg: #f4f7f9;
        }

        .dark-mode {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --grid-bg: #1e293b;
            --grid-shadow: inset 3px 3px 8px rgba(0,0,0,0.4), inset -3px -3px 8px rgba(255,255,255,0.04);
            --grid-border: 1px solid #334155;
            --nav-bg: #0b1120;
            --nav-text: #475569;
            --nav-active: #38bdf8;
            --topbar-bg: #1e293b;
        }

        /* TEMA PREMIUM CSS */
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #cbd5e1; color: var(--text-main); margin: 0; display: flex; justify-content: center; transition: background-color 0.3s;}
        #app { width: 100%; max-width: 480px; background: var(--bg-main); min-height: 100vh; position: relative; overflow-x: hidden; padding-bottom: 140px; box-sizing: border-box; box-shadow: 0 0 20px rgba(0,0,0,0.1); transition: background 0.3s;}
        
        /* TOP BAR */
        .top-bar { background: var(--topbar-bg); color: var(--text-main); padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; transition: background 0.3s;}
        .menu-btn { cursor: pointer; background: none; border: none; padding: 0; margin-right: 15px; display: flex; align-items: center; justify-content: center; z-index: 2;}
        .menu-btn svg { width: 28px; height: 28px; stroke: var(--text-main); fill: none; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round;}
        
        .brand-title { position: absolute; left: 50%; transform: translateX(-50%); font-size: 16px; font-weight: 900; text-align: center; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-main); width: 60%; white-space: nowrap;}
        
        /* TRX BADGE */
        .trx-badge { font-size: 11px; background: var(--bg-main); color: var(--text-main); padding: 5px 12px; border-radius: 12px; font-weight: 800; cursor: pointer; border: 1px solid var(--border-color); transition: transform 0.2s; z-index: 2;}
        .trx-badge:active { transform: scale(0.95); }

        /* DEGRADASI LENGKUNGAN */
        .banner-container { 
            background: var(--topbar-bg); 
            padding: 5px 20px 25px; 
            border-bottom-left-radius: 30px; 
            border-bottom-right-radius: 30px; 
            box-shadow: 0 12px 24px -6px rgba(0, 0, 0, 0.08);
            position: relative;
            z-index: 10;
            transition: background 0.3s;
        }

        /* BANNER SALDO */
        .banner { 
            background: linear-gradient(135deg, #111827 0%, #0f172a 100%); 
            border-radius: 20px; padding: 25px 15px; 
            color: #ffffff; text-align: center; position: relative; overflow: hidden;
            box-shadow: 0 8px 20px rgba(15,23,42,0.15);
        }
        .banner::before { 
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%; 
            background-image: url("data:image/svg+xml,%3Csvg width='100%25' height='100%25' xmlns='http://www.w3.org/2000/svg'%3E%3Cdefs%3E%3Cpattern id='wave' width='100' height='40' patternUnits='userSpaceOnUse'%3E%3Cpath d='M0 20 Q 25 5, 50 20 T 100 20' fill='none' stroke='rgba(255,255,255,0.06)' stroke-width='2'/%3E%3C/pattern%3E%3C/defs%3E%3Crect width='100%25' height='100%25' fill='url(%23wave)'/%3E%3C/svg%3E");
            pointer-events: none; 
        }
        .saldo-title { font-size: 12px; font-weight: 500; opacity: 0.9; margin-bottom: 5px; position: relative; z-index: 2;}
        .saldo-amount { font-size: 34px; font-weight: 900; letter-spacing: -0.5px; margin-bottom: 20px; position: relative; z-index: 2;}
        
        .action-buttons { display: flex; justify-content: center; gap: 10px; position: relative; z-index: 2; }
        .btn-topup-dash, .btn-history-dash, .btn-help-dash { 
            background: transparent; color: #ffffff; border: 1px solid rgba(255,255,255,0.8); 
            padding: 8px 12px; border-radius: 25px; font-weight: 800; font-size: 10px; 
            cursor: pointer; display: flex; align-items: center; justify-content: center; flex: 1; max-width: 110px;
            transition: background 0.2s, color 0.2s; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .btn-topup-dash:active, .btn-history-dash:active, .btn-help-dash:active { background: #ffffff; color: #0f172a; }

        /* SLIDER BANNER */
        .banner-slider-container { margin: 20px 20px 0px; border-radius: 16px; overflow: hidden; position: relative; background: var(--bg-card); box-shadow: 0 4px 10px rgba(0,0,0,0.03);}
        .banner-slider { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; -webkit-overflow-scrolling: touch; scrollbar-width: none; }
        .banner-slider::-webkit-scrollbar { display: none; }
        .banner-slide { flex: 0 0 100%; scroll-snap-align: center; display: flex; justify-content: center; align-items: center; }
        .banner-slide img { width: 100%; height: auto; object-fit: cover; aspect-ratio: 21/9; display: block;}

        /* GRID MENU */
        .grid-title { margin: 25px 20px 15px; font-weight: 900; color: var(--text-main); font-size: 15px;}
        .grid-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; padding: 0 20px;}
        .grid-box { 
            background: var(--grid-bg); border-radius: 16px; padding: 18px 5px; 
            text-align: center; cursor: pointer; display: flex; flex-direction: column; align-items: center; justify-content: flex-start;
            box-shadow: var(--grid-shadow); border: var(--grid-border);
            transition: transform 0.2s, background 0.2s;
        }
        .grid-box:active { transform: scale(0.95); opacity: 0.8; }
        
        .grid-icon-wrap { width: 42px; height: 42px; margin-bottom: 12px; display: flex; justify-content: center; align-items: center; color: var(--text-main);}
        .grid-text { font-size: 10px; color: var(--text-main); font-weight: 800; line-height: 1.3; text-transform: uppercase; letter-spacing: -0.2px;}

        /* STATISTIK GLOBAL */
        .stats-container { margin: 25px 20px; padding: 15px; background: var(--bg-card); border-radius: 16px; border: 1px solid var(--border-color); text-align: center; box-shadow: 0 4px 10px rgba(0,0,0,0.02);}
        .stats-title { font-size: 14px; font-weight: 900; color: var(--text-main); margin-bottom: 15px; text-transform: uppercase; letter-spacing: 0.5px;}
        .stats-grid { display: flex; justify-content: space-between; gap: 10px;}
        .stat-box { flex: 1; padding: 10px 5px; background: var(--bg-main); border-radius: 12px; border: 1px solid var(--border-color); box-shadow: var(--grid-shadow);}
        .stat-val { font-size: 18px; font-weight: 900; color: #0ea5e9; margin-bottom: 5px;}
        .stat-lbl { font-size: 9px; font-weight: 800; color: var(--text-muted); text-transform: uppercase;}

        /* BRAND LIST */
        .brand-list { display: flex; flex-direction: column; padding: 15px 20px; gap: 12px; }
        .brand-row { background: var(--bg-card); padding: 15px; border-radius: 14px; border: 1px solid var(--border-color); display: flex; align-items: center; gap: 15px; box-shadow: 0 2px 6px rgba(0,0,0,0.02); cursor: pointer; transition: transform 0.2s; color: var(--text-main);}
        .brand-row:active { transform: scale(0.98); }
        .b-logo { width: 45px; height: 45px; background: var(--bg-main); color: var(--text-main); border-radius: 50%; font-weight: 900; font-size: 15px; display: flex; justify-content: center; align-items: center; border: 1px solid var(--border-color); flex-shrink: 0;}
        .b-name { font-size: 14px; font-weight: 800; flex: 1;}

        /* BOTTOM NAV MENGAMBANG */
        .bottom-nav { 
            position: fixed; 
            bottom: 20px; 
            left: 50%;
            transform: translateX(-50%);
            width: calc(100% - 40px); 
            max-width: 400px; 
            background: var(--nav-bg); 
            display: flex; 
            justify-content: space-around; 
            padding: 10px 5px; 
            border-radius: 50px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.25); 
            z-index: 900; 
            transition: background 0.3s;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .nav-item { text-align: center; color: var(--nav-text); font-size: 10px; flex: 1; cursor: pointer; display: flex; flex-direction: column; align-items: center; font-weight: 700; transition: color 0.3s;}
        .nav-icon { margin-bottom: 2px; display: flex; justify-content: center; align-items: center;}
        .nav-icon svg { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}
        .nav-item.active { color: var(--nav-active);}

        /* PRODUCT LIST STYLE */
        .product-item { background: var(--bg-card); padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid var(--border-color); display: flex; align-items: center; gap: 15px; box-shadow: 0 2px 6px rgba(0,0,0,0.02); cursor: pointer; transition: 0.2s;}
        .product-item:active { transform: scale(0.98); }
        .prod-logo { width: 45px; height: 45px; background: var(--bg-main); color: var(--text-main); border-radius: 50%; display: flex; justify-content: center; align-items: center; font-weight: 900; font-size: 14px; border: 1px solid var(--border-color); flex-shrink: 0;}
        .prod-info { flex: 1; min-width: 0; }
        .prod-name { font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between; word-wrap: break-word;}
        .badge-open { background: #e0f2fe; color: #0284c7; font-size: 9px; padding: 2px 6px; border-radius: 4px; font-weight: 800; border: 1px solid #bae6fd; flex-shrink: 0; margin-left: 8px;}
        .prod-desc { font-size: 10px; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; text-overflow: ellipsis;}
        .prod-price { color: var(--text-main); font-weight: 900; font-size: 15px;}

        /* SEARCH BAR */
        .search-box { padding: 15px 20px 5px; position: sticky; top: 58px; z-index: 50; background: var(--bg-main); transition: background 0.3s; }
        .search-box input { margin-bottom: 0; box-shadow: 0 2px 5px rgba(0,0,0,0.02); border-radius: 12px; padding: 12px 15px; width: 100%; box-sizing: border-box; font-weight: bold;}

        /* TABS RIWAYAT TRANSAKSI & TOPUP */
        .history-tabs { display: flex; background: var(--bg-card); border-bottom: 1px solid var(--border-color); position: sticky; top: 58px; z-index: 50; }
        .hist-tab { flex: 1; text-align: center; padding: 15px 0; font-size: 13px; font-weight: 800; cursor: pointer; color: var(--text-muted); border-bottom: 3px solid transparent; transition: all 0.2s; text-transform: uppercase;}
        .hist-tab.active { color: var(--nav-active); border-bottom-color: var(--nav-active); }

        /* SIDEBAR */
        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); z-index: 1001; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:0; left:-300px; width: 280px; height: 100%; background: var(--bg-card); z-index: 1002; transition: left 0.3s ease; overflow-y: auto; display: flex; flex-direction: column; box-shadow: 5px 0 15px rgba(0,0,0,0.3);}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 30px 20px; text-align: center; border-bottom: 1px solid var(--border-color); background: #0f172a; color: #ffffff;}
        .sidebar-avatar { width: 70px; height: 70px; background: #ffffff; border-radius: 50%; margin: 0 auto 10px auto; display: flex; justify-content: center; align-items: center; color: #0b2136; font-size: 30px; font-weight: bold;}
        .sidebar-name { font-weight: bold; font-size: 16px; color: #ffffff;}
        .sidebar-phone { font-size: 12px; color: #cbd5e1;}
        .sidebar-menu { padding: 10px 0; flex: 1;}
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: var(--text-main); text-decoration: none; font-size: 14px; border-bottom: 1px solid var(--border-color); font-weight: 600; gap: 15px;}
        .sidebar-item:active { background: var(--bg-main); }
        .sidebar-item svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }

        /* FORMS & COMPONENTS */
        .container { padding: 20px; }
        .card { background: var(--bg-card); padding: 25px 20px; border-radius: 16px; margin-bottom: 20px; border: 1px solid var(--border-color); box-shadow: 0 4px 10px rgba(0,0,0,0.02);}
        input { width: 100%; padding: 15px; margin-bottom: 12px; border: 1px solid var(--border-color); border-radius: 12px; box-sizing: border-box; font-size: 14px; outline: none; background: var(--bg-main); color: var(--text-main); font-weight: 600; transition: border-color 0.2s;}
        input:focus { border-color: #0284c7; background: var(--bg-card);}
        
        .checkbox-container { display: flex; align-items: center; justify-content: flex-start; gap: 8px; margin-bottom: 20px; font-size: 13px; font-weight: 600; color: var(--text-muted); cursor: pointer;}
        .checkbox-container input { width: 16px; height: 16px; margin: 0; padding: 0; cursor: pointer;}
        
        .btn { background: #0b2136; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; transition: opacity 0.2s;}
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-outline { background: var(--bg-card); color: var(--text-main); border: 1.5px solid var(--border-color); padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        .btn-danger { background: #ef4444; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}

        /* PROFILE & MODAL */
        .prof-header { background: #0f172a; color: #ffffff; padding: 30px 20px; text-align: center; border-bottom-left-radius: 25px; border-bottom-right-radius: 25px;}
        
        .prof-avatar-wrap {
            width: 86px; height: 86px;
            background: linear-gradient(135deg, #0ea5e9 0%, #3b82f6 100%);
            border-radius: 50%;
            padding: 4px;
            margin: 0 auto 15px auto;
            box-shadow: 0 10px 25px rgba(14, 165, 233, 0.4);
        }
        .prof-avatar {
            width: 100%; height: 100%;
            background: #ffffff; color: #0f172a;
            border-radius: 50%; font-size: 38px; display: flex; justify-content: center; align-items: center; font-weight: 900;
        }

        .prof-box { background: var(--bg-card); color: var(--text-main); margin: -20px 20px 20px; border-radius: 16px; padding: 20px; position: relative; z-index: 10; border: 1px solid var(--border-color); box-shadow: 0 4px 15px rgba(0,0,0,0.03);}
        .prof-row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px dashed var(--border-color); font-size: 13px;}
        .prof-label { color: var(--text-muted); font-weight: 600;}
        .prof-val { font-weight: 900; text-align: right;}
        
        .prof-actions-container {
            padding: 0 20px;
            margin-bottom: 150px; 
            display: flex;
            flex-direction: column;
            gap: 10px;
            position: relative;
            z-index: 10;
        }
        
        .prof-action-btn { 
            background: var(--bg-main); 
            color: var(--text-main); 
            border: 1px solid var(--border-color); 
            padding: 15px; 
            width: 100%; 
            border-radius: 12px; 
            font-weight: bold; 
            cursor: pointer; 
            font-size: 13px; 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            transition: transform 0.2s; 
        }
        .prof-action-btn:active { transform: scale(0.98); }
        .prof-action-btn svg { fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}

        .hist-item { background: var(--bg-card); color: var(--text-main); padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid var(--border-color); box-shadow: 0 2px 4px rgba(0,0,0,0.02); cursor: pointer;}
        .hist-item:active { transform: scale(0.98); }
        .hist-top { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-bottom: 5px; font-weight: 700;}
        .hist-title { font-weight: 800; font-size: 14px; margin-bottom: 3px;}
        .hist-target { font-size: 12px; font-weight: 600;}
        .stat-badge { padding: 4px 10px; border-radius: 8px; font-weight: bold; font-size: 10px;}
        .stat-Sukses { background: #dcfce7; color: #166534; } 
        .stat-Pending { background: #ffedd5; color: #c2410c; } 
        .stat-Gagal { background: #fee2e2; color: #b91c1c; text-decoration: line-through; }

        .modal-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); display: flex; justify-content: center; align-items: center; z-index: 2000; padding: 20px;}
        .modal-box { background: var(--bg-card); color: var(--text-main); width: 100%; max-width: 340px; border-radius: 20px; padding: 25px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto;}
        .modal-btns { display: flex; gap: 10px; margin-top: 15px;}
        
        .screen-header { padding: 15px 20px; font-weight: 800; font-size: 18px; display: flex; align-items: center; gap: 15px; background: var(--bg-card); color: var(--text-main); border-bottom: 1px solid var(--border-color); position: sticky; top:0; z-index: 10; transition: background 0.3s;}
        .hidden { display: none !important; }
        .back-icon { cursor: pointer; fill: none; stroke: var(--text-main); stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round;}

        /* PROVIDER TOAST FLOATING */
        .provider-toast {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: #0f172a;
            color: #ffffff;
            padding: 8px 18px;
            border-radius: 30px;
            font-size: 12px;
            font-weight: 800;
            z-index: 3000;
            opacity: 0;
            transition: opacity 0.3s, top 0.3s;
            pointer-events: none;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .provider-toast.show {
            opacity: 1;
            top: 40px;
        }

        /* DESKTOP RESPONSIVENESS */
        @media screen and (min-width: 768px) {
            body { 
                padding: 30px 0; 
                background-color: var(--border-color); 
            }
            #app {
                max-width: 800px;
                border-radius: 36px;
                min-height: calc(100vh - 60px);
                box-shadow: 0 25px 60px rgba(0,0,0,0.15);
                padding-bottom: 130px;
            }
            .top-bar {
                border-top-left-radius: 36px;
                border-top-right-radius: 36px;
                padding: 20px 30px;
            }
            .banner-container { padding: 10px 30px 30px; }
            .banner { padding: 40px 30px 35px; }
            .saldo-amount { font-size: 42px; }
            
            .bottom-nav {
                max-width: 740px;
                bottom: 50px;
                padding: 15px 10px;
                border-radius: 60px;
            }
            .nav-item .nav-icon svg { width: 26px; height: 26px; }
            
            .grid-container { 
                grid-template-columns: repeat(4, 1fr); 
                padding: 0 30px; 
                gap: 20px; 
            }
            .stats-container { margin: 30px; }
            .banner-slider-container { margin: 20px 30px 0px; }
            
            #product-list, #brand-list, #history-list {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                padding: 10px 30px 30px !important;
            }
            .product-item, .brand-row, .hist-item { margin: 0 !important; }
            
            #notif-list {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                padding: 30px !important;
            }
            #notif-list .card { margin-bottom: 0 !important; }
            
            #login-screen .card, #register-screen .card, #otp-screen .card, #forgot-screen .card {
                max-width: 450px;
                margin: 0 auto;
                padding: 40px;
            }
            .sidebar { width: 340px; }
        }

        @media screen and (min-width: 1024px) {
            #app { max-width: 1024px; }
            .bottom-nav { max-width: 964px; }
            .grid-container { grid-template-columns: repeat(5, 1fr); }
            #product-list, #brand-list, #history-list, #notif-list {
                grid-template-columns: repeat(3, 1fr);
            }
        }
    </style>
</head>
<body>
    <div id="app">
        <div id="provider-toast" class="provider-toast">Telkomsel</div>

        <div class="top-bar" id="home-topbar">
            <button class="menu-btn" onclick="toggleSidebar()">
                <svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
            <div class="brand-title" id="top-title">
                DIGITAL TENDO STORE
            </div>
            <div class="trx-badge" id="top-trx-badge" onclick="showHistory('Order')">0 Trx</div>
        </div>

        <div class="banner-container" id="banner-container-wrap">
            <div class="banner" id="home-banner">
                <div class="saldo-title">Sisa Saldo Anda</div>
                <div class="saldo-amount" id="user-saldo">Rp 0</div>
                <div class="action-buttons">
                    <button class="btn-topup-dash" onclick="openTopupModal()">ISI SALDO</button>
                    <button class="btn-history-dash" onclick="showHistory('Topup')">RIWAYAT</button>
                    <button class="btn-help-dash" onclick="contactAdmin()">BANTUAN</button>
                </div>
            </div>
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
                    <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> Profil Akun
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showHistory('Order')">
                    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Transaksi Saya
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showNotif()">
                    <svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg> Pemberitahuan
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); contactAdmin()">
                    <svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Hubungi Admin
                </a>
                <a href="#" class="sidebar-item" onclick="toggleTheme()">
                    <svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg> <span id="theme-text">Mode Gelap</span>
                </a>
            </div>
            <div style="padding: 20px;">
                <button class="btn-outline" style="color: #ef4444; border-color: #ef4444;" onclick="logout()">Keluar Akun</button>
            </div>
        </div>

        <div id="login-screen" class="container">
            <div style="text-align:center; margin: 40px 0;">
                <h1 style="color:var(--text-main); margin:0; font-weight:900; font-size: 28px;">Digital Tendo Store</h1>
                <p style="color:var(--text-muted); font-size:13px; margin-top:5px; font-weight: 600;">Solusi Pembayaran Digital</p>
            </div>
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Masuk Akun</h2>
                <input type="email" id="log-email" placeholder="Alamat Email">
                <input type="password" id="log-pass" placeholder="Password">
                <label class="checkbox-container">
                    <input type="checkbox" id="rem-login"> Tetap masuk
                </label>
                <button class="btn" id="btn-login" onclick="login()">Login Sekarang</button>
                <a href="#" onclick="showScreen('forgot-screen')" style="display:block; text-align:center; font-size:13px; font-weight:600; color:var(--text-muted); margin-top:15px; text-decoration:none;">Lupa Password?</a>
                <button class="btn-outline" onclick="showScreen('register-screen')">Buat Akun Baru</button>
            </div>
        </div>

        <div id="register-screen" class="container hidden">
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Daftar Akun</h2>
                <p style="font-size:12px; color:var(--text-muted); text-align: center; margin-bottom: 20px; font-weight: 600;">Gunakan Nomor WhatsApp Aktif (08/62)</p>
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

            <div class="grid-title">Layanan Produk</div>
            <div class="grid-container">
                <div class="grid-box" onclick="loadCategory('Pulsa')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#93C5FD" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <rect x="5" y="2" width="14" height="20" rx="3"></rect>
                            <path d="M12 18h.01" stroke-width="3"></path>
                        </svg>
                    </div>
                    <div class="grid-text">PULSA</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Data')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#86EFAC" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <circle cx="12" cy="12" r="10"></circle>
                            <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">DATA</div>
                </div>

                <div class="grid-box" onclick="loadCategory('Game')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#FCA5A5" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <rect x="2" y="6" width="20" height="12" rx="4"></rect>
                            <line x1="6" y1="12" x2="10" y2="12"></line>
                            <line x1="8" y1="10" x2="8" y2="14"></line>
                            <line x1="15" y1="13" x2="15.01" y2="13"></line>
                            <line x1="18" y1="11" x2="18.01" y2="11"></line>
                        </svg>
                    </div>
                    <div class="grid-text">GAME</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Voucher')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#FDE047" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <rect x="2" y="6" width="20" height="12" rx="2"></rect>
                            <circle cx="2" cy="12" r="2.5" fill="none" stroke="currentColor"></circle>
                            <circle cx="22" cy="12" r="2.5" fill="none" stroke="currentColor"></circle>
                        </svg>
                    </div>
                    <div class="grid-text">VOUCHER</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('E-Money')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#C4B5FD" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <rect x="3" y="6" width="18" height="13" rx="2"></rect>
                            <path d="M16 10h5v4h-5z" fill="#FDE047"></path>
                        </svg>
                    </div>
                    <div class="grid-text">E-WALLET</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('PLN')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#FDE047" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">PLN</div>
                </div>

                <div class="grid-box" onclick="loadCategory('Paket SMS & Telpon')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#F9A8D4" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
                        </svg>
                    </div>
                    <div class="grid-text">SMS TELP</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Masa Aktif')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#FDBA74" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                            <line x1="16" y1="2" x2="16" y2="6"></line>
                            <line x1="8" y1="2" x2="8" y2="6"></line>
                            <line x1="3" y1="10" x2="21" y2="10"></line>
                            <circle cx="12" cy="15" r="1.5" fill="currentColor" stroke="none"></circle>
                            <circle cx="8" cy="15" r="1.5" fill="currentColor" stroke="none"></circle>
                            <circle cx="16" cy="15" r="1.5" fill="currentColor" stroke="none"></circle>
                        </svg>
                    </div>
                    <div class="grid-text">MASA AKTIF</div>
                </div>
                
                <div class="grid-box" onclick="loadCategory('Aktivasi Perdana')">
                    <div class="grid-icon-wrap">
                        <svg viewBox="0 0 24 24" fill="#99F6E4" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
                            <path d="M4 4h12l4 4v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"></path>
                            <rect x="8" y="12" width="8" height="6" rx="1" fill="#FDE047" stroke="currentColor"></rect>
                            <line x1="12" y1="12" x2="12" y2="18"></line>
                        </svg>
                    </div>
                    <div class="grid-text">PERDANA</div>
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
                </div>
            </div>
            
            <div style="padding: 20px; margin: 20px; background: var(--bg-card); border-radius: 16px; text-align: center; border: 1px dashed var(--border-color);" id="install-banner" class="hidden">
                <strong style="color:var(--text-main); font-size:14px;">Aplikasi Digital Tendo Store</strong><br>
                <span style="font-size:12px; color:var(--text-muted); font-weight: 600;">Pasang di layar utama HP Anda untuk akses cepat!</span><br>
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
                <span style="text-transform: uppercase;" id="history-title-text">Riwayat Transaksi</span>
            </div>
            <div class="history-tabs">
                <div class="hist-tab active" id="tab-hist-order" onclick="showHistory('Order')">Produk</div>
                <div class="hist-tab" id="tab-hist-topup" onclick="showHistory('Topup')">Topup Saldo</div>
            </div>
            <div id="history-list" style="padding-top:10px;"></div>
        </div>

        <div id="profile-screen" class="hidden">
            <div class="prof-header">
                <div class="prof-avatar-wrap">
                    <div class="prof-avatar" id="p-avatar">T</div>
                </div>
                <h2 style="margin:0 0 5px 0; font-size: 20px;" id="p-username">Username</h2>
                <div style="font-size:13px; font-weight: bold; color: rgba(255,255,255,0.8);" id="p-id">ID: TD-000000</div>
            </div>
            <div class="prof-box">
                <div class="prof-row"><span class="prof-label">Email</span><span class="prof-val" id="p-email">-</span></div>
                <div class="prof-row"><span class="prof-label">WhatsApp</span><span class="prof-val" id="p-phone">-</span></div>
                <div class="prof-row"><span class="prof-label">Tgl Daftar</span><span class="prof-val" id="p-date">-</span></div>
                <div class="prof-row"><span class="prof-label">Total Transaksi</span><span class="prof-val" id="p-trx">0 Kali</span></div>
            </div>
            
            <div class="prof-actions-container">
                <h3 style="font-size:14px; color:var(--text-muted); margin-bottom:5px;">PENGATURAN</h3>
                <button class="prof-action-btn" onclick="window.openEditModal('email')"><svg viewBox="0 0 24 24" width="20" stroke="currentColor"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg> Ubah Email</button>
                <button class="prof-action-btn" onclick="window.openEditModal('phone')"><svg viewBox="0 0 24 24" width="20" stroke="currentColor"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Ubah Nomor WA</button>
                <button class="prof-action-btn" onclick="window.openEditModal('password')"><svg viewBox="0 0 24 24" width="20" stroke="currentColor"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Ubah Password</button>
                
                <button class="prof-action-btn" onclick="contactAdmin()" style="border-color: #bae6fd; color: #0ea5e9; margin-top: 5px;">
                    <svg viewBox="0 0 24 24" width="20" stroke="currentColor"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Hubungi Admin
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
            <div class="container" id="notif-list" style="margin-bottom: 120px;">
                <div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Memuat info...</div>
            </div>
        </div>

        <div class="bottom-nav" id="main-bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showDashboard()">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg></span>HOME
            </div>
            <div class="nav-item" id="nav-history" onclick="showHistory('Order')">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></span>RIWAYAT
            </div>
            <div class="nav-item" id="nav-notif" onclick="showNotif()">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg></span>INFO
            </div>
            <div class="nav-item" id="nav-profile" onclick="showProfile()">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg></span>PROFIL
            </div>
        </div>

        <div id="order-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Formulir Pesanan</h3>
                <div style="background:var(--bg-main); padding:15px; border-radius:12px; margin-bottom:15px; border: 1px solid var(--border-color); text-align: left;">
                    <strong id="m-name" style="font-size:14px; line-height:1.4; display:block; margin-bottom:5px;">Produk</strong>
                    <div id="m-desc" style="font-size:11px; color:var(--text-muted); margin-bottom:10px; line-height: 1.4;">Deskripsi Produk</div>
                    <span style="font-weight:900; font-size: 20px;" id="m-price">Rp 0</span>
                </div>
                <input type="text" id="m-target" placeholder="Masukkan Nomor/ID Tujuan" style="text-align:center; font-size: 16px; font-weight: bold;" oninput="checkProvider(this.value)">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeOrderModal()">Batal</button>
                    <button class="btn" id="m-submit" onclick="processOrder()">Beli Sekarang</button>
                </div>
            </div>
        </div>

        <div id="order-success-modal" class="modal-overlay hidden">
            <div class="modal-box" style="text-align:center;">
                <div style="width:60px; height:60px; background:#dcfce7; border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 15px;">
                    <svg viewBox="0 0 24 24" width="35" height="35" stroke="#166534" fill="none" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
                <h3 style="margin-top:0; font-size:20px; color:#166534;">Pesanan Berhasil!</h3>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:20px;">Pesanan Anda sedang diproses oleh sistem.</p>
                <div style="background:var(--bg-main); padding:15px; border-radius:12px; margin-bottom:15px; text-align: left; font-size:13px; line-height: 1.6; border: 1px dashed var(--border-color);">
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Produk</span><strong id="os-name" style="text-align:right; max-width:60%;"></strong></div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Tujuan</span><strong id="os-target" style="text-align:right;"></strong></div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Harga</span><strong id="os-price" style="color:#0ea5e9;"></strong></div>
                </div>
                <button class="btn" style="width:100%;" onclick="closeOrderSuccessModal()">Selesai & Cek Riwayat</button>
            </div>
        </div>

        <div id="topup-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Isi Saldo Otomatis</h3>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:20px;">Mendukung khusus <b>QRIS</b> (Tanpa biaya admin). Nominal akan ditambah kode unik.<br>Saldo masuk utuh sesuai nominal transfer.</p>
                <input type="number" id="topup-nominal" placeholder="Nominal (Min. 10000)" style="text-align:center; font-size:18px; font-weight:bold;">
                <div class="modal-btns">
                    <button class="btn-outline" style="margin-top:0;" onclick="closeTopupModal()">Batal</button>
                    <button class="btn" id="btn-topup-submit" onclick="generateQris()">Buat QRIS</button>
                </div>
                <button class="btn-outline" style="margin-top:10px; width:100%; border-color: #0ea5e9; color: #0ea5e9;" onclick="manualTopupWA()">Topup Manual (Hubungi Admin)</button>
            </div>
        </div>

        <div id="topup-success-modal" class="modal-overlay hidden">
            <div class="modal-box" style="text-align:center;">
                <div style="width:60px; height:60px; background:#dcfce7; border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 15px;">
                    <svg viewBox="0 0 24 24" width="35" height="35" stroke="#166534" fill="none" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
                <h3 style="margin-top:0; font-size:20px; color:#166534;">Berhasil Dibuat!</h3>
                <p style="font-size:13px; color:var(--text-muted); margin-bottom:20px;">Silakan bayar menggunakan barcode QRIS yang akan ditampilkan di Riwayat.</p>
                <button class="btn" style="width:100%;" onclick="closeTopupSuccessModal()">Oke, Lanjut Bayar</button>
            </div>
        </div>
        
        <div id="history-detail-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Detail Transaksi</h3>
                
                <div id="hd-qris-box" class="hidden" style="background:var(--bg-main); padding:15px; border-radius:12px; margin-bottom:15px; text-align: center; border: 1px solid var(--border-color);">
                    <p style="font-size:12px; color:var(--text-main); margin-top:0; margin-bottom:10px; font-weight:bold;">Segera bayar dengan QRIS ini:</p>
                    <img id="hd-qris-img" src="" style="width:100%; max-width:200px; border-radius:12px; border:1px solid var(--border-color); margin-bottom:10px; background:#fff;">
                    
                    <button class="btn-outline" style="width:100%; max-width:200px; padding:8px; margin: 0 auto 10px; font-size:11px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="downloadQRIS()">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                        Download QRIS
                    </button>

                    <div style="font-size:11px; color:var(--text-muted); font-weight:bold;">Transfer TEPAT SEBESAR:</div>
                    <div style="font-size:24px; font-weight:900; color:#0ea5e9; margin: 5px 0;" id="hd-qris-amount">Rp 0</div>
                    <div style="font-size:11px; color:#ef4444; font-weight:bold; line-height:1.4;">Batas Waktu: 10 Menit!<br>Harus persis agar otomatis masuk.</div>
                </div>

                <div style="background:var(--bg-main); padding:15px; border-radius:12px; margin-bottom:15px; border: 1px solid var(--border-color); text-align: left; font-size:13px; line-height: 1.6;">
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Waktu</span><strong id="hd-time"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Status</span><strong id="hd-status"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Layanan</span><strong id="hd-name" style="text-align:right; max-width:60%;"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Nominal</span><strong id="hd-amount"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">Tujuan</span><strong id="hd-target"></strong></div>
                    <div style="display:flex; justify-content:space-between;"><span style="color:var(--text-muted);">SN/Ref</span><strong id="hd-sn" style="word-break:break-all;"></strong></div>
                </div>
                <button class="btn-danger hidden" id="hd-complain-btn" onclick="complainAdmin()" style="margin-bottom: 15px;">Hubungi Admin (Komplain)</button>
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
        let currentUser = ""; let userData = {}; let allProducts = {}; let selectedSKU = ""; let tempRegPhone = ""; let tempForgotPhone = ""; let currentEditMode = ""; let currentHistoryItem = null;
        let currentCategory = ""; let currentBrand = ""; let currentHistoryFilter = 'All';
        let bannerInterval;

        // CEK THEME DARI LOKAL (Dark Mode Toggle)
        if(localStorage.getItem('tendo_theme') === 'dark') {
            document.body.classList.add('dark-mode');
            document.getElementById('theme-text').innerText = "Mode Terang";
        }
        function toggleTheme() {
            document.body.classList.toggle('dark-mode');
            let isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('tendo_theme', isDark ? 'dark' : 'light');
            document.getElementById('theme-text').innerText = isDark ? "Mode Terang" : "Mode Gelap";
            toggleSidebar();
        }

        // FUNGSI DETEKSI PROVIDER
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
                toastTimer = setTimeout(() => { 
                    toast.classList.remove('show'); 
                    lastDetected = ""; 
                }, 3000);
            }
        }

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

        // FUNGSI FETCH STATISTIK GLOBAL
        async function fetchGlobalStats() {
            try {
                let res = await apiCall('/api/stats');
                if(res && res.success) {
                    document.getElementById('stat-daily').innerText = res.daily;
                    document.getElementById('stat-weekly').innerText = res.weekly;
                    document.getElementById('stat-monthly').innerText = res.monthly;
                }
            } catch(e){}
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
            ['login-screen', 'register-screen', 'otp-screen', 'forgot-screen', 'dashboard-screen', 'brand-screen', 'produk-screen', 'history-screen', 'profile-screen', 'notif-screen'].forEach(s => {
                document.getElementById(s).classList.add('hidden');
            });
            document.getElementById(id).classList.remove('hidden');
            
            // SIMPAN TAB TERAKHIR KE LOCAL STORAGE UNTUK PERSISTENSI SAAT RELOAD
            if (['dashboard-screen', 'history-screen', 'notif-screen', 'profile-screen'].includes(id)) {
                localStorage.setItem('tendo_last_tab', id);
            }
            if (navId) {
                localStorage.setItem('tendo_last_nav', navId);
                updateNav(navId);
            }
            
            if(id === 'login-screen' || id === 'register-screen' || id === 'otp-screen' || id === 'forgot-screen') {
                document.getElementById('home-topbar').classList.add('hidden');
                document.getElementById('main-bottom-nav').classList.add('hidden');
                document.getElementById('banner-container-wrap').classList.add('hidden');
            } else {
                document.getElementById('home-topbar').classList.remove('hidden');
                document.getElementById('main-bottom-nav').classList.remove('hidden');
                if(id === 'dashboard-screen') {
                    document.getElementById('banner-container-wrap').classList.remove('hidden');
                } else {
                    document.getElementById('banner-container-wrap').classList.add('hidden');
                }
            }
        }

        window.onload = async () => {
            let savedEmail = localStorage.getItem('tendo_email');
            let savedPass = localStorage.getItem('tendo_pass');
            if(savedEmail && savedPass) {
                try {
                    let data = await apiCall('/api/login', {email:savedEmail, password:savedPass});
                    if(data && data.success) {
                        currentUser = data.phone; userData = data.data;
                        fetchAllProducts();
                        fetchGlobalStats();
                        loadBanners();
                        
                        // LOGIKA AUTO-RESTORE TAB SEBELUMNYA
                        let lastTab = localStorage.getItem('tendo_last_tab') || 'dashboard-screen';
                        if (lastTab === 'history-screen') {
                            let savedFilter = localStorage.getItem('tendo_history_filter') || 'Order';
                            showHistory(savedFilter);
                        }
                        else if (lastTab === 'profile-screen') showProfile();
                        else if (lastTab === 'notif-screen') showNotif();
                        else showDashboard();

                    } else { showScreen('login-screen', null); }
                } catch(e) { showScreen('login-screen', null); }
            } else {
                showScreen('login-screen', null);
            }
        }

        function showDashboard() { 
            showScreen('dashboard-screen', 'nav-home'); 
            syncUserData(); 
        }
        
        function showHistory(filter = 'Order') { 
            currentHistoryFilter = filter;
            localStorage.setItem('tendo_history_filter', filter); // Simpan status filter

            // Update style tabs
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
        
        function showProfile() { showScreen('profile-screen', 'nav-profile'); syncUserData(); }
        
        async function showNotif() { 
            showScreen('notif-screen', 'nav-notif'); 
            try {
                let data = await apiCall('/api/notif');
                let html = '';
                if(data && Array.isArray(data) && data.length > 0) {
                    data.forEach(n => {
                        let imgTag = n.image ? `<img src="/info_images/${n.image}" style="width:100%; border-radius:8px; margin-bottom:10px; display:block;">` : '';
                        html += `
                        <div class="card" style="border-left: 4px solid #0ea5e9; margin-bottom:15px; padding:15px;">
                            <div style="font-size:10px; color:var(--text-muted); margin-bottom:5px; font-weight:700;">${n.date}</div>
                            <h3 style="margin-top:0; color: var(--text-main); font-size:15px; margin-bottom:10px;">📢 Info Terbaru</h3>
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

        function openTopupModal() { document.getElementById('topup-nominal').value = ''; document.getElementById('topup-modal').classList.remove('hidden'); }
        function closeTopupModal() { document.getElementById('topup-modal').classList.add('hidden'); }
        
        async function generateQris() {
            let nom = parseInt(document.getElementById('topup-nominal').value);
            if(!nom || nom < 10000) return alert("Minimal Topup Rp 10.000");
            let btn = document.getElementById('btn-topup-submit');
            btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/topup', {phone: currentUser, nominal: nom});
                if(data && data.success) { 
                    closeTopupModal();
                    document.getElementById('topup-success-modal').classList.remove('hidden');
                } 
                else { alert(data.message || "Gagal memuat QRIS. Pastikan Admin sudah mengatur API GoPay."); }
            } catch(e) { alert("Kesalahan server."); }
            
            btn.innerText = "Buat QRIS"; btn.disabled = false;
        }

        async function closeTopupSuccessModal() {
            document.getElementById('topup-success-modal').classList.add('hidden');
            await syncUserData(); 
            showHistory('Topup');
            if(userData.history && userData.history.length > 0) {
                let latest = userData.history.find(h => h.type === 'Topup' && h.status === 'Pending');
                if(latest) openHistoryDetail(latest);
            }
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
                // Fallback jika API membatasi CORS (Download manual tab baru)
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
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }

        function logout() {
            currentUser = ""; userData = {}; 
            localStorage.removeItem('tendo_email'); localStorage.removeItem('tendo_pass');
            localStorage.removeItem('tendo_last_tab');
            localStorage.removeItem('tendo_last_nav');
            localStorage.removeItem('tendo_history_filter');
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
                    
                    // Filter Logika Berdasarkan Tipe
                    historyList = historyList.filter(h => {
                        let type = h.type || 'Order';
                        if (currentHistoryFilter === 'Topup') return type === 'Topup';
                        return type === 'Order';
                    });

                    if(historyList.length === 0) histHTML = '<div style="text-align:center; color:var(--text-muted); font-weight:bold; margin-top: 30px; font-size:13px;">Belum ada transaksi.</div>';
                    else {
                        historyList.forEach((h, idx) => {
                            let statClass = 'stat-Pending';
                            if(h.status === 'Sukses') statClass = 'stat-Sukses';
                            if(h.status === 'Gagal') statClass = 'stat-Gagal';
                            let safeH = JSON.stringify(h).replace(/"/g, '&quot;');
                            histHTML += `
                                <div class="hist-item" onclick='openHistoryDetail(${safeH})'>
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
            document.getElementById('hd-amount').innerText = h.amount ? 'Rp ' + h.amount.toLocaleString('id-ID') : '-';
            document.getElementById('hd-target').innerText = h.tujuan;
            document.getElementById('hd-sn').innerText = h.sn || '-';
            
            // Logika menampilkan tombol hubungi admin
            let btnComplain = document.getElementById('hd-complain-btn');
            if(h.status === 'Pending' || h.status === 'Gagal') {
                btnComplain.classList.remove('hidden');
            } else {
                btnComplain.classList.add('hidden');
            }
            
            let qrisBox = document.getElementById('hd-qris-box');
            if(h.type === 'Topup' && h.status === 'Pending') {
                if(Date.now() < h.expired_at) {
                    document.getElementById('hd-qris-img').src = h.qris_url;
                    document.getElementById('hd-qris-amount').innerText = 'Rp ' + h.amount.toLocaleString('id-ID');
                    qrisBox.classList.remove('hidden');
                } else {
                    qrisBox.classList.add('hidden');
                    document.getElementById('hd-status').innerText = 'Gagal (Kedaluwarsa)';
                }
            } else {
                qrisBox.classList.add('hidden');
            }
            
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
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya ingin komplain/tanya transaksi ini:%0A%0A📦 Layanan: *${h.nama}*%0A📱 Tujuan: *${h.tujuan}*%0A🕒 Waktu: *${h.tanggal}*%0A⚙️ Status: *${h.status}*%0A🔑 SN/Ref: *${h.sn || '-'}*%0A%0AMohon bantuannya dicek. Terima kasih.`;
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

        // FUNGSI LUPA PASSWORD
        async function reqForgotOTP() {
            let phone = document.getElementById('forgot-phone').value.trim();
            if(!phone) return alert('Masukkan Nomor WhatsApp!');
            
            let btn = document.getElementById('btn-req-forgot');
            let ori = btn.innerText; btn.innerText = "Mengirim..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/req-forgot-otp', {phone});
                if(data && data.success) {
                    tempForgotPhone = phone;
                    document.getElementById('forgot-step-1').classList.add('hidden');
                    document.getElementById('forgot-step-2').classList.remove('hidden');
                } else {
                    alert(data && data.message ? data.message : "Nomor tidak terdaftar.");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        async function verifyForgotOTP() {
            let otp = document.getElementById('forgot-otp').value.trim();
            let newPass = document.getElementById('forgot-new-pass').value.trim();
            if(!otp || !newPass) return alert('Isi OTP dan Password Baru!');
            
            let btn = document.getElementById('btn-verify-forgot');
            let ori = btn.innerText; btn.innerText = "Memproses..."; btn.disabled = true;
            
            try {
                let data = await apiCall('/api/verify-forgot-otp', {phone: tempForgotPhone, otp, newPass});
                if(data && data.success) {
                    alert('Password berhasil diubah! Silakan login dengan password baru.');
                    showScreen('login-screen', null);
                    document.getElementById('forgot-step-1').classList.remove('hidden');
                    document.getElementById('forgot-step-2').classList.add('hidden');
                    document.getElementById('forgot-phone').value = '';
                    document.getElementById('forgot-otp').value = '';
                    document.getElementById('forgot-new-pass').value = '';
                } else {
                    alert(data && data.message ? data.message : "Sistem error.");
                }
            } catch(e) { alert('Kesalahan jaringan.'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

        window.openEditModal = function(type) {
            currentEditMode = type;
            let inp = document.getElementById('edit-input');
            document.getElementById('edit-step-1').classList.remove('hidden');
            document.getElementById('edit-step-2').classList.add('hidden');
            
            if(type === 'email') { 
                document.getElementById('edit-title').innerText = "Ganti Email"; 
                inp.type="email"; 
                inp.placeholder="Email baru"; 
                inp.value = (userData && userData.email) ? userData.email : "";
            }
            if(type === 'phone') { 
                document.getElementById('edit-title').innerText = "Ganti Nomor WA"; 
                inp.type="number"; 
                inp.placeholder="Nomor WA baru (08/62)"; 
                inp.value = currentUser ? currentUser : "";
            }
            if(type === 'password') { 
                document.getElementById('edit-title').innerText = "Ganti Password"; 
                inp.type="text"; 
                inp.placeholder="Password baru"; 
                inp.value = "";
            }
            document.getElementById('edit-modal').classList.remove('hidden');
        };
        
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
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
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
            document.getElementById('search-product').value = ''; 
            
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
            document.getElementById('product-list').innerHTML = listHTML || '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">KOSONG</div>';
            showScreen('produk-screen', 'nav-home');
        }

        function goBackFromBrandScreen() {
            let title = document.getElementById('brand-cat-title').innerText;
            if(currentCategory === 'Data' && title.includes('(Paket)')) {
                loadCategory(currentCategory); 
            } else {
                showDashboard(); 
            }
        }

        function goBackFromProducts() {
            if(currentCategory === 'Data') {
                loadSubCategory(currentCategory, currentBrand); 
            } else {
                loadCategory(currentCategory); 
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
        function closeOrderSuccessModal() { 
            document.getElementById('order-success-modal').classList.add('hidden'); 
            showHistory('Order');
        }

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
                    closeOrderModal();
                    syncUserData();
                    
                    // Tampilkan Modal Notifikasi Cantik
                    document.getElementById('os-name').innerText = document.getElementById('m-name').innerText;
                    document.getElementById('os-target').innerText = target;
                    document.getElementById('os-price').innerText = document.getElementById('m-price').innerText;
                    document.getElementById('order-success-modal').classList.remove('hidden');
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
# 4. FUNGSI UNTUK MEMBUAT FILE INDEX.JS
# ==========================================
generate_bot_script() {
    cat << 'EOF' > index.js
process.env.TZ = 'Asia/Jakarta';
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, Browsers, jidNormalizedUser, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const fs = require('fs');
const pino = require('pino');
const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const axios = require('axios'); 
const crypto = require('crypto'); 
const crypt = require('./tendo_crypt.js');

const app = express();
app.disable('x-powered-by');

// SECURITY: Memblokir akses langsung file konfigurasi JSON lewat URL
app.use((req, res, next) => {
    if (req.path.endsWith('.json') && !req.path.endsWith('manifest.json')) {
        return res.status(403).json({success: false, message: 'Akses Ditolak (Sistem Keamanan Tendo)'});
    }
    next();
});

app.use(bodyParser.json());
app.use(express.static('public')); 

const configFile = './config.json';
const dbFile = './database.json';
const produkFile = './produk.json';
const trxFile = './trx.json';
const notifFile = './web_notif.json';
const japriFile = './japri.txt';
const globalStatsFile = './global_stats.json';
const topupFile = './topup.json';

const loadJSON = (file) => crypt.load(file, file === notifFile ? [] : {});
const saveJSON = (file, data) => crypt.save(file, data);

// Fungsi Hashing Password
const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd).digest('hex');

// AUTO-INJECT GOPAY CREDENTIALS FROM USER PROMPT
let configAwal = loadJSON(configFile);
configAwal.botName = configAwal.botName || "Digital Tendo Store";
configAwal.botNumber = configAwal.botNumber || "";
configAwal.gopayToken = configAwal.gopayToken || "eyJhbGciOiJkaXIiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwidHlwIjoiSldUIiwiemlwIjoiREVGIn0..VIQQ-T-biEeLHfw0.A2-r35syEmO_3WI_dsbDM06rN61YEqtJjL4Cl8IMvlLd4qZfsED3U1e7mQQvOnkbaSG1JvFKxEHQTZFNR6sKJ7Vm-j_5BQwc3XyRUN7C67EpayMGoqlgOxQ-FbFAP1LIL3PVrPpX8tq9Kb2cfUHxo4T2YQhdbN-F-xxFqkZE3MniVJ6bKv2j3ENpJ74WV0YO1EQ9inBGsL3LskNp--fkxlDpTP3VEAtJT8VeOXmF0TWkHK1PYvY7iR1BuWncqtPpPao1kYm3Jf9CF48lMPI3MT3kmOdkuWCkzTd71jCza8xnFt37itC36_qB14H0zC3mhLtxgFPQR0VzlVylqcfLYtblVIrgtKvRwFTK2SFCQnlYWJ2DcaXSqL7aie66HmWAl4G3jwqhKumJNTnwfWgJ7MpZA2PiIxLkli8p_5PARbyyhdpZCUPX1r_nJGCy5GmqT6QoSbafu2ps7gpjGbPY4iBa03KEIV-55g3lqbRsJsWSg6FgrPgM7i2o8NsZNQNAd5ZgMI4BCs5AAECXtfBgUL9ZN8OBHbMTeuapsx2wseCZd8I7r3JsAAp-Y70OxVraB-LHCiczAuwpYO8gcr_XGjh_wuicoS7lp8rIxKGNCWEiHR0dhY1FduSqAVE3Ced01A_QRMY4cnFJAHFAUbwFCH17Oy8FDqhPMmLG3hdxJZBqiyCi6v4U9GXBjcckkpVtZ1mg6yN8Mpfe_Le6nt4zGABwZHFeESojkW0YJQJaMzRcUoiUZF88zTnXmT93ZQ-T9my6J3cEGkTSl0J_WT7q2T_BYWFBPqrrv61OggbbnkK1UE2HiI481WmudS4VUuX857SLMxRunFcH0E_FybDd0n1vqvcFjs-osoK5yymM3p2mZT7_gGkR3cm-Jy0r1SCm-28ZY5mK7EA3N9l88yHv0R0dqyXETT3j0wa9N3YbViAre2dku_OgKjGh8ICnjTKhI5VlxIop42k0uFQg_QBECeY65xpmY6qbHFESoC4ii5IxODVyGqM6xVnHFRULSl66-ir-I3111D-l0PgnyUe7mbf3ewffLi6vdGW_e2Pd3jooP_u91Q_du2tqRWUsO3oeNTbJcfer0LRoB06ecsqRHUzCHKuG7XociDXLOifvdYJGwmrItjFGWTIlqSpYs45MZWYe07WEvftwhemXUzEPNtTCecq7kavGOcWDPx0PZJ_VP8Z6y1ocZ64ZnLNp_Zdq2ESU7ATWOaLi6HXavIKecvOo2QFFN4Jrs5HP46IHdp7uqX0mFtBqwMDOSOCmjfgLDsjUltHxCLuYWtGn1SUsTuzE0sqhELrh1CVYReiBk9FFFcXs4qlXpbjPb3FVWIX8TzdN6dQd9RfrMtN71pe69WocXAlE9uRNWY3p07ayKUm7Z1p6GSq0hlH_aPsHlNrVUvupwgg45XHlod6T6_Ki2Lq3pUesSGxMPD-zmPB9N90B-xcqYSBg_LoCU1_gWDxiNlggHWD65hMlxcJolRxV4reLwGn06rbadydyByuz3aC-gbxXYtF7CO9pOkYGms2hAhp6CBOQhmWe3cip3rx_hVNBZYbOgkAvfgaWD3h22v25FVmV9xsecPaA_nLWPvcZLYHcPZzmsOhxpecQaAJDn3uAdi6uu7aUqk7ljq1TIpbafbru3pnOf0TEgElgqXlTUUCKPxYdeQaGSpjM7NGjlBsLyrcRZa74VZ-g1mpCCX3Qxf8l8Mn0PSJHkS1AahS6u1Nqr0dVRyx1ikg6t_F8gCTCE3IF-zRTGJZITwOir0RI0coZUQ1xH7eZ0Rb-oAXDPxf00nFMoYpijiL1QdyKA3yc0RiMcw7nISGoYn8_BWbG7YvjlxVPAdjWaIKen1pXRFf0VC2OinEvATRPP2E31HkJWwJ_jLDTheWqf6kc3oqBAvX3Ch88z-jSuUF2zjzH0F4pWSE6oE2fKstonIdD.Ehu4BT1zjv_MGr1eUh-G8g";
configAwal.gopayMerchantId = configAwal.gopayMerchantId || "G881528152";
configAwal.qrisUrl = configAwal.qrisUrl || "https://upload.wikimedia.org/wikipedia/commons/d/d0/QR_code_for_mobile_English_Wikipedia.svg";
saveJSON(configFile, configAwal);

// File creation checks managed by crypt logic now...
loadJSON(dbFile);
loadJSON(produkFile);
loadJSON(trxFile);
loadJSON(globalStatsFile);
loadJSON(topupFile);
loadJSON(notifFile);

let globalSock = null;
let tempOtpDB = {}; 
let otpCooldown = {}; // Anti spam OTP

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
                let imgFiles = files.filter(f => f.match(/\.(jpg|jpeg|png|gif|webp)$/i));
                if (imgFiles.length > 0) {
                    banners.push(`/baner${i}/${imgFiles[0]}`);
                }
            }
        }
    } catch(e) { console.error(e); }
    res.json({ success: true, data: banners });
});

// GLOBAL STATS API
app.get('/api/stats', (req, res) => {
    try {
        let gStats = loadJSON(globalStatsFile);
        let daily = 0, weekly = 0, monthly = 0;
        let now = new Date();
        
        for(let k in gStats) {
            let d = new Date(k);
            let diffTime = Math.abs(now - d);
            let diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            
            if(now.toISOString().split('T')[0] === k) daily += gStats[k]; // Hari Ini
            if(diffDays <= 7) weekly += gStats[k]; // Minggu Ini
            if(diffDays <= 30) monthly += gStats[k]; // Bulan Ini
        }
        res.json({ success: true, daily, weekly, monthly });
    } catch(e) {
        res.json({ success: false, daily: 0, weekly: 0, monthly: 0 });
    }
});

// API ROUTER
app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });
app.get('/api/notif', (req, res) => { 
    try {
        let notifs = loadJSON(notifFile);
        if(!Array.isArray(notifs)) notifs = [];
        res.json(notifs); 
    } catch(e) {
        res.json([]);
    }
});

app.get('/api/user/:phone', (req, res) => {
    try {
        let db = loadJSON(dbFile); let p = req.params.phone;
        if(db[p]) {
            let safeData = { ...db[p] };
            delete safeData.password; // Mencegah password (hash) bocor ke frontend
            res.json({success: true, data: safeData});
        }
        else res.json({success: false});
    } catch(e) { res.json({success: false}); }
});

app.post('/api/login', (req, res) => {
    try {
        let { email, password } = req.body; let db = loadJSON(dbFile);
        let hashedInput = hashPassword(password);
        
        let userPhone = Object.keys(db).find(k => {
            if (!db[k] || db[k].email !== email) return false;
            // Migrasi otomatis password lama (plain text) ke Hashed
            if (db[k].password === password) {
                db[k].password = hashedInput;
                saveJSON(dbFile, db);
                return true;
            }
            // Cocokkan dengan password yang sudah di-hash
            if (db[k].password === hashedInput) return true;
            return false;
        });

        if (userPhone) {
            let safeData = { ...db[userPhone] };
            delete safeData.password;
            res.json({success: true, data: safeData, phone: userPhone});
        }
        else res.json({success: false, message: 'Email atau Password salah!'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/register', (req, res) => {
    try {
        let { username, email, password } = req.body;
        let phone = normalizePhone(req.body.phone); 
        if(!phone || phone.length < 9) return res.json({success: false, message: 'Nomor WA tidak valid!'});
        
        // Anti Spam
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) {
            return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        }
        otpCooldown[phone] = Date.now();
        
        let db = loadJSON(dbFile);
        let isEmailExist = Object.keys(db).some(k => db[k] && db[k].email === email);
        if (isEmailExist) return res.json({success: false, message: 'Email terdaftar!'});

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        // Simpan password dalam bentuk hash saat register
        tempOtpDB[phone] = { username, email, password: hashPassword(password), otp };

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
                db[phone] = { id_pelanggan: idPelanggan, username: tempOtpDB[phone].username, email: tempOtpDB[phone].email, password: tempOtpDB[phone].password, saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta' }), jid: phone + '@s.whatsapp.net', step: 'idle', trx_count: 0, history: [] };
            }
            saveJSON(dbFile, db); delete tempOtpDB[phone]; res.json({success: true});
        } else res.json({success: false, message: 'Kode OTP Salah!'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/req-edit-otp', (req, res) => {
    try {
        let { phone, type, newValue } = req.body; let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: 'User tidak ditemukan.'});
        
        // Anti Spam
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) {
            return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        }
        otpCooldown[phone] = Date.now();

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        // Hash password jika yang diganti adalah password
        if (type === 'password') newValue = hashPassword(newValue);
        
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

// API LUPA PASSWORD
app.post('/api/req-forgot-otp', (req, res) => {
    try {
        let phone = normalizePhone(req.body.phone);
        let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: 'Nomor WA tidak terdaftar!'});
        
        // Anti Spam
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) {
            return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        }
        otpCooldown[phone] = Date.now();

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone + '_forgot'] = { otp };
        
        res.json({success: true});

        setTimeout(() => {
            try {
                if (globalSock) {
                    let msg = `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nPermintaan Reset Password.\nKode OTP Anda: *${otp}*\n\n_⚠️ Jika Anda tidak merasa memintanya, abaikan pesan ini!_`;
                    globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>{});
                }
            } catch(err) { console.error(err); }
        }, 100);

    } catch(e) { 
        if (!res.headersSent) res.json({success: false, message: 'Gagal memproses OTP.'}); 
    }
});

app.post('/api/verify-forgot-otp', (req, res) => {
    try {
        let phone = normalizePhone(req.body.phone);
        let { otp, newPass } = req.body;
        let db = loadJSON(dbFile);
        
        let session = tempOtpDB[phone + '_forgot'];
        if(session && session.otp === otp) {
            if(db[phone]) {
                db[phone].password = hashPassword(newPass);
                saveJSON(dbFile, db);
            }
            delete tempOtpDB[phone + '_forgot']; 
            res.json({success: true});
        } else {
            res.json({success: false, message: 'Kode OTP Salah!'});
        }
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

// API TOPUP GOPAY MERCHANT LANGSUNG
app.post('/api/topup', async (req, res) => {
    try {
        let config = loadJSON(configFile);
        if(!config.gopayToken || !config.qrisUrl) return res.json({success: false, message: "Sistem QRIS belum diatur Admin."});
        
        let { phone, nominal } = req.body;
        let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: "User tidak ditemukan."});
        
        let nominalAsli = parseInt(nominal);
        // Menambahkan 2 digit unik (1-99) untuk validasi otomatis
        let uniqueCode = Math.floor(Math.random() * 99) + 1;
        let totalPay = nominalAsli + uniqueCode;

        let topups = loadJSON(topupFile);
        let trxId = "TP-" + Date.now();
        let expiredAt = Date.now() + 10 * 60 * 1000; // 10 Menit

        // Saldo yang ditambahkan FULL sesuai yang ditransfer
        topups[trxId] = { phone, trx_id: trxId, amount_to_pay: totalPay, saldo_to_add: totalPay, status: 'pending', timestamp: Date.now(), expired_at: expiredAt };
        saveJSON(topupFile, topups);

        // Rekam ke Riwayat User
        db[phone].history = db[phone].history || [];
        db[phone].history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Topup',
            nama: 'Topup Saldo QRIS', 
            tujuan: 'Sistem Pembayaran', 
            status: 'Pending', 
            sn: trxId, 
            amount: totalPay,
            qris_url: config.qrisUrl,
            expired_at: expiredAt
        });
        if(db[phone].history.length > 20) db[phone].history.pop();
        saveJSON(dbFile, db);

        res.json({success: true});
    } catch(e) {
        res.json({success: false, message: "Gagal memproses QRIS."});
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
        db[targetKey].history.unshift({ ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Order', nama: p.nama, tujuan: tujuan, status: statusOrder, sn: response.data.data.sn || '-', amount: p.harga });
        if(db[targetKey].history.length > 20) db[targetKey].history.pop();
        saveJSON(dbFile, db);
        
        let trxs = loadJSON(trxFile);
        let targetJid = db[targetKey].jid || targetKey + '@s.whatsapp.net';
        trxs[refId] = { jid: targetJid, sku: sku, tujuan: tujuan, harga: p.harga, nama: p.nama, tanggal: Date.now() };
        saveJSON(trxFile, trxs);

        if (statusOrder === 'Sukses') {
            let gStats = loadJSON(globalStatsFile);
            let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
            gStats[dateKey] = (gStats[dateKey] || 0) + 1;
            saveJSON(globalStatsFile, gStats);
        }

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
    exec(`[ -d "/etc/letsencrypt" ] && sudo tar -czf ssl_backup.tar.gz -C / etc/letsencrypt 2>/dev/null; rm -f backup.zip && zip backup.zip config.json database.json trx.json produk.json global_stats.json topup.json web_notif.json ssl_backup.tar.gz 2>/dev/null`, (err) => {
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

    // INTERVAL POLING CEK MUTASI GOPAY MERCHANT (SETIAP 30 DETIK)
    setInterval(async () => {
        try {
            let cfg = loadJSON(configFile);
            let topups = loadJSON(topupFile);
            let pendingKeys = Object.keys(topups).filter(k => topups[k].status === 'pending');
            
            if(pendingKeys.length === 0 || !cfg.gopayToken || !cfg.gopayMerchantId) return;

            const gopayRes = await axios.post('https://gopay.autoftbot.com/api/backend/transactions', 
                { merchant_id: cfg.gopayMerchantId }, 
                { headers: { 'Authorization': 'Bearer ' + cfg.gopayToken, 'Content-Type': 'application/json' } }
            );

            // Ubah seluruh respons API ke string untuk pencarian yang sangat akurat dan tahan error
            let responseStr = JSON.stringify(gopayRes.data);

            let db = loadJSON(dbFile);
            let changedTp = false;
            let changedDb = false;

            for(let key of pendingKeys) {
                let req = topups[key];
                
                // 1. Cek apakah Topup sudah kadaluarsa (lewat 10 menit)
                if (Date.now() > req.expired_at) {
                    req.status = 'gagal';
                    changedTp = true;
                    if(db[req.phone]) {
                        let hist = db[req.phone].history.find(h => h.sn === req.trx_id);
                        if(hist && hist.status === 'Pending') {
                            hist.status = 'Gagal';
                            changedDb = true;
                        }
                    }
                } 
                // 2. Cek apakah nominal unik muncul di JSON response (Format angka, string, atau desimal .00)
                else {
                    let amountStr = req.amount_to_pay.toString();
                    // Pencarian pintar: mengecek format "10011", :10011, "10011.00", :10011.00 di dalam respons
                    let isFound = responseStr.includes(`"${amountStr}"`) ||
                                  responseStr.includes(`:${amountStr}`) ||
                                  responseStr.includes(`"${amountStr}.00"`) ||
                                  responseStr.includes(`:${amountStr}.00`);

                    if(isFound) {
                        req.status = 'sukses';
                        changedTp = true;
                        if(db[req.phone]) {
                            db[req.phone].saldo += req.saldo_to_add; 
                            
                            let hist = db[req.phone].history.find(h => h.sn === req.trx_id);
                            if(hist && hist.status === 'Pending') {
                                hist.status = 'Sukses';
                            }
                            changedDb = true;
                            
                            if(globalSock) {
                                let msg = `✅ *TOPUP QRIS BERHASIL*\n\nTotal Transfer: Rp ${req.amount_to_pay.toLocaleString('id-ID')}\nSaldo Masuk: Rp ${req.saldo_to_add.toLocaleString('id-ID')}\nSaldo Sekarang: Rp ${db[req.phone].saldo.toLocaleString('id-ID')}`;
                                globalSock.sendMessage(db[req.phone].jid, {text: msg}).catch(()=>{});
                            }
                        }
                    }
                }
            }
            if(changedTp) saveJSON(topupFile, topups);
            if(changedDb) saveJSON(dbFile, db);
        } catch(e) {}
    }, 30000); 

    // INTERVAL PENGHAPUSAN RIWAYAT (Lebih 30 Hari) 
    setInterval(() => {
        try {
            let db = loadJSON(dbFile);
            let changed = false;
            let oneMonthAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
            
            for(let k in db) {
                if(db[k].history && db[k].history.length > 0) {
                    let oldLen = db[k].history.length;
                    db[k].history = db[k].history.filter(h => h.ts && h.ts >= oneMonthAgo);
                    if(db[k].history.length !== oldLen) changed = true;
                }
            }
            if(changed) saveJSON(dbFile, db);
        } catch(e) {}
    }, 12 * 60 * 60 * 1000); 

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
                        
                        // Update Global Stats
                        let gStats = loadJSON(globalStatsFile);
                        let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
                        gStats[dateKey] = (gStats[dateKey] || 0) + 1;
                        saveJSON(globalStatsFile, gStats);
                        
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
            if (!db[sender]) { db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta' }), jid: senderJid, step: 'idle', trx_count:0, history:[]}; saveJSON(dbFile, db); }
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
# 5. INSTALASI DEPENDENSI
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

    echo -ne "${C_MAG}>> Mengatur zona waktu (Asia/Jakarta)...${C_RST}"
    sudo timedatectl set-timezone Asia/Jakarta > /dev/null 2>&1 || sudo ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    echo -e "${C_GREEN}[Selesai]${C_RST}"

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
    generate_crypt_module
    generate_bot_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Mengunduh modul (Baileys, XLSX, dll)...${C_RST}"
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser xlsx > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD}                 ✅ INSTALASI SELESAI!                ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    read -p "Tekan Enter untuk kembali..."
}

# ==========================================
# 6. SUB-MENU TELEGRAM SETUP
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
                    const crypt = require('./tendo_crypt.js');
                    let config = crypt.load('config.json');
                    config.teleToken = '$token';
                    config.teleChatId = '$chatid';
                    crypt.save('config.json', config);
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
                    const crypt = require('./tendo_crypt.js');
                    let config = crypt.load('config.json');
                    config.autoBackup = $status;
                    config.backupInterval = parseInt('$menit');
                    crypt.save('config.json', config);
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 7. SUB-MENU BACKUP & RESTORE
# ==========================================
menu_backup() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}               💾 BACKUP & RESTORE 💾               ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Backup Data (Kirim ke Telegram)"
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
                # Backup SSL Let's Encrypt jika ada
                if [ -d "/etc/letsencrypt" ]; then
                    sudo tar -czf ssl_backup.tar.gz -C / etc/letsencrypt 2>/dev/null
                fi
                zip backup.zip config.json database.json trx.json produk.json global_stats.json topup.json web_notif.json ssl_backup.tar.gz 2>/dev/null
                echo -e "${C_GREEN}✅ File backup.zip (termasuk SSL) berhasil dikompresi!${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    const { exec } = require('child_process');
                    let config = crypt.load('config.json');
                    if(config.teleToken && config.teleChatId) {
                        console.log('\x1b[36m⏳ Sedang mengirim ke Telegram...\x1b[0m');
                        let cmd = \`curl -s -F chat_id=\"\${config.teleChatId}\" -F document=@\"backup.zip\" -F caption=\"📦 Manual Backup Data + SSL\" https://api.telegram.org/bot\${config.teleToken}/sendDocument\`;
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

# ==========================================
# 8. SUB-MENU MANAJEMEN MEMBER
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
                    const crypt = require('./tendo_crypt.js');
                    let db = crypt.load('database.json');
                    let input = '$nomor'.trim();
                    let normPhone = input.replace(/[^0-9]/g, '');
                    if(normPhone.startsWith('0')) normPhone = '62' + normPhone.substring(1);
                    
                    let target = Object.keys(db).find(k => k === normPhone || db[k].email === input);
                    
                    if(!target) {
                        target = normPhone || input;
                        db[target] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta' }), jid: target + '@s.whatsapp.net', trx_count: 0, history: [] };
                    }
                    db[target].saldo += parseInt('$jumlah');
                    crypt.save('database.json', db);
                    console.log('\x1b[32m\n✅ Saldo Rp $jumlah berhasil ditambahkan ke ' + target + '!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- KURANGI SALDO ---${C_RST}"
                read -p "Masukkan ID Member (No WA awalan 08/62 atau Email): " nomor
                read -p "Masukkan Jumlah Saldo yg dikurangi: " jumlah
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let db = crypt.load('database.json');
                    let input = '$nomor'.trim();
                    let normPhone = input.replace(/[^0-9]/g, '');
                    if(normPhone.startsWith('0')) normPhone = '62' + normPhone.substring(1);
                    
                    let target = Object.keys(db).find(k => k === normPhone || db[k].email === input);
                    
                    if(!target) { 
                        console.log('\x1b[31m\n❌ Akun tidak ditemukan di database.\x1b[0m'); 
                    } else {
                        db[target].saldo -= parseInt('$jumlah');
                        if(db[target].saldo < 0) db[target].saldo = 0;
                        crypt.save('database.json', db);
                        console.log('\x1b[32m\n✅ Saldo berhasil dikurangi!\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR MEMBER ---${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let db = crypt.load('database.json');
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
# 9. MANAJEMEN PRODUK & HARGA (DENGAN IMPORT)
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
                    const crypt = require('./tendo_crypt.js');
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
                    
                    let produk = crypt.load('produk.json');
                    let key = process.env.TMP_KODE.toUpperCase().replace(/\s+/g, '');
                    produk[key] = { 
                        nama: process.env.TMP_NAMA, 
                        harga: parseInt(process.env.TMP_HARGA),
                        deskripsi: process.env.TMP_DESC,
                        kategori: catName,
                        brand: brandName
                    };
                    crypt.save('produk.json', produk);
                    console.log('\x1b[32m\n✅ Produk [' + key + '] berhasil ditambahkan ke ' + catName + ' - ' + brandName + '!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK UNTUK DIEDIT ---${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let produk = crypt.load('produk.json');
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
                    const crypt = require('./tendo_crypt.js');
                    let produk = crypt.load('produk.json');
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
                
                export NEW_KODE="${new_kode:-$OLD_KODE}"
                export NEW_NAMA="$new_nama"
                export NEW_HARGA="$new_harga"
                export NEW_DESC="$new_desc"
                export NEW_CAT_IDX="$new_cat_idx"
                export NEW_BRAND_IDX="$new_brand_idx"
                
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    const catMap = {'1':'Pulsa', '2':'Data', '3':'Masa Aktif', '4':'SMS Telp', '5':'PLN', '6':'E-Wallet', '7':'Tagihan', '8':'E-Toll', '9':'Digital'};
                    const brandMap = {
                        'Pulsa': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Data': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'Masa Aktif': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'SMS Telp': {'1':'Telkomsel', '2':'XL', '3':'Axis', '4':'Indosat', '5':'Tri', '6':'Smartfren', '7':'By.U'},
                        'E-Wallet': {'1':'Go Pay', '2':'Dana', '3':'Shopee Pay', '4':'OVO', '5':'LinkAja'},
                        'Tagihan': {'1':'PLN Pasca', '2':'BPJS', '3':'PDAM', '4':'Indihome'},
                        'E-Toll': {'1':'Mandiri E-Money', '2':'Brizzi', '3':'TapCash'},
                        'Digital': {'1':'Mobile Legends', '2':'Free Fire', '3':'PUBG', '4':'Vidio', '5':'Netflix'},
                        'PLN': {'1':'Token PLN'}
                    };

                    let produk = crypt.load('produk.json');
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
                    
                    crypt.save('produk.json', produk);
                    console.log('\x1b[32m\n✅ Perubahan pada produk berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK UNTUK DIHAPUS ---${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let produk = crypt.load('produk.json');
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
                    const crypt = require('./tendo_crypt.js');
                    let produk = crypt.load('produk.json');
                    let keys = Object.keys(produk);
                    let idx = parseInt(process.env.NO_DEL) - 1;
                    
                    if(isNaN(idx) || idx < 0 || idx >= keys.length) {
                        console.log('\x1b[31m\n❌ Nomor urut produk tidak valid!\x1b[0m');
                    } else {
                        let key = keys[idx];
                        let nama = produk[key].nama;
                        delete produk[key];
                        crypt.save('produk.json', produk);
                        console.log('\x1b[32m\n✅ Produk [' + key + '] ' + nama + ' berhasil dihapus dari database!\x1b[0m');
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK TOKO ---${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let produk = crypt.load('produk.json');
                    let keys = Object.keys(produk);
                    if(keys.length === 0) {
                        console.log('\x1b[33mBelum ada produk.\x1b[0m');
                    } else {
                        let cats = ['Pulsa', 'Data', 'Game', 'Voucher', 'E-Money', 'PLN', 'Paket SMS & Telpon', 'Masa Aktif', 'Aktivasi Perdana', 'Lainnya'];
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
            5)
                echo -e "\n${C_MAG}--- IMPORT PRODUK VIA EXCEL (.XLSX) / CSV ---${C_RST}"
                echo -e "Sistem Import Cerdas. Format kolom apapun akan terdeteksi!"
                read -p "Apakah Anda ingin MENGHAPUS produk lama agar bersih dari produk nyasar? (y/n): " wipe_data
                export WIPE_DATA="$wipe_data"
                
                read -p "Masukkan nama file lengkap (contoh: daftar-produk-buyer.xlsx ATAU namafile.csv): " nama_file_excel
                if [ ! -f "$nama_file_excel" ]; then
                    echo -e "${C_RED}❌ File tidak ditemukan. Pastikan file $nama_file_excel ada di direktori $(pwd)${C_RST}"
                else
                    export EXCEL_PATH="$nama_file_excel"
                    node -e "
                        const crypt = require('./tendo_crypt.js');
                        const xlsx = require('xlsx');
                        
                        try {
                            let config = crypt.load('config.json');
                            let margins = config.margin || {
                                under100: 50,
                                under1000: 200,
                                under5000: 500,
                                under50000: 1000,
                                under100000: 1500,
                                above: 2000
                            };

                            const workbook = xlsx.readFile(process.env.EXCEL_PATH);
                            const sheet_name = workbook.SheetNames[0];
                            const rawData = xlsx.utils.sheet_to_json(workbook.Sheets[sheet_name]);
                            
                            let produk = {};
                            if (process.env.WIPE_DATA.toLowerCase() !== 'y') {
                                produk = crypt.load('produk.json');
                            }
                            
                            let added = 0;
                            
                            rawData.forEach(row => {
                                let keys = Object.keys(row);
                                let getColStrict = (keywords) => keys.find(k => keywords.includes(k.toLowerCase().trim()));
                                
                                let kodeCol = getColStrict(['buyer_sku_code', 'sku', 'kode produk', 'kode']);
                                let namaCol = getColStrict(['product_name', 'nama produk', 'produk', 'nama']);
                                let hargaCol = getColStrict(['price', 'harga']);
                                let statusCol = getColStrict(['buyer_product_status', 'status']);
                                let descCol = getColStrict(['desc', 'deskripsi']);
                                let brandCol = getColStrict(['brand', 'provider', 'operator']);
                                
                                if(!kodeCol) kodeCol = keys.find(k => k.toLowerCase().includes('kode') || k.toLowerCase().includes('sku'));
                                if(!namaCol) namaCol = keys.find(k => k.toLowerCase().includes('nama') || k.toLowerCase().includes('produk'));
                                if(!hargaCol) hargaCol = keys.find(k => k.toLowerCase().includes('harga') || k.toLowerCase().includes('price'));
                                if(!statusCol) statusCol = keys.find(k => k.toLowerCase().includes('status'));

                                if(!kodeCol || !namaCol || !hargaCol) return;
                                
                                if(statusCol) {
                                    let stat = row[statusCol].toString().toLowerCase();
                                    if(stat !== 'normal' && stat !== 'aktif' && stat !== 'active') return;
                                }

                                let kode = row[kodeCol].toString().trim();
                                let nama = row[namaCol].toString().trim();
                                let hargaAwal = parseInt(row[hargaCol]);
                                let deskripsi = descCol && row[descCol] ? row[descCol].toString().trim() : 'Proses Otomatis';
                                
                                if(isNaN(hargaAwal)) return;

                                // ==============================================
                                // LOGIKA KATEGORI (SUPER KETAT & ANTI NYASAR)
                                // ==============================================
                                let kategori = 'Lainnya';
                                let nLower = ' ' + nama.toLowerCase() + ' '; 
                                let nUpper = nama.toUpperCase();

                                let isVoucher = /\b(voucher|vcr|voc|gesek|spotify|google play|garena|unipin)\b/.test(nLower);
                                let isDataKeyword = /\b(gb|mb|data|kuota|internet|combo|xtra|flash|paket|omg|aigo|owsem|bulk|gamesmax|gamemax|unlimited|maxstream)\b/.test(nLower);
                                let isPerdana = /\b(perdana|aktivasi|kpk)\b/.test(nLower);
                                let isEMoney = /\b(gopay|go-pay|go pay|ovo|dana|shopee|shopeepay|linkaja|link aja|isaku|brizzi|e-toll|etoll|e-money|mtix|grab|gojek|saldo|maxim)\b/.test(nLower);
                                let isGame = /\b(free fire|ff|mobile legend|mobile legends|mobilelegend|mobile_legend|mlbb|ml|pubg|diamond|diamonds|uc|cp|valorant|genshin)\b/.test(nLower);
                                let isPLN = /\b(pln|token listrik|token pln)\b/.test(nLower);
                                let isMasaAktif = /\b(masa aktif)\b/.test(nLower);
                                let isSmsTelp = /\b(sms|telpon|telepon|nelpon|voice|bicara)\b/.test(nLower);
                                let isPulsa = /\b(pulsa|promo|reguler|transfer|tp)\b/.test(nLower);

                                if (isPerdana) {
                                    kategori = 'Aktivasi Perdana';
                                } else if (isVoucher) {
                                    kategori = 'Voucher';
                                } else if (isEMoney) {
                                    kategori = 'E-Money';
                                } else if (isGame && !isDataKeyword && !isPulsa) {
                                    kategori = 'Game';
                                } else if (isPLN) {
                                    kategori = 'PLN';
                                } else if (isMasaAktif) {
                                    kategori = 'Masa Aktif';
                                } else if (isSmsTelp && !isDataKeyword) {
                                    kategori = 'Paket SMS & Telpon';
                                } else if (isDataKeyword) {
                                    kategori = 'Data';
                                } else if (isPulsa) {
                                    kategori = 'Pulsa';
                                } else {
                                    if (/\b(TELKOMSEL|TSEL|AS|SIMPATI|XL|AXIS|INDOSAT|ISAT|IM3|TRI|THREE|BIMA|SMARTFREN|BY\.U|BYU)\b/.test(nUpper)) {
                                        kategori = 'Pulsa';
                                    } else {
                                        kategori = 'Lainnya';
                                    }
                                }

                                // ==============================================
                                // LOGIKA BRAND PROVIDER (SUPER KETAT)
                                // ==============================================
                                let brand = 'Lainnya';
                                if (brandCol && row[brandCol]) {
                                    brand = row[brandCol].toString().trim();
                                } else {
                                    if (kategori === 'E-Money') {
                                        if (/\b(gopay|go-pay|go pay|gojek)\b/.test(nLower)) brand = 'Go Pay';
                                        else if (/\b(ovo)\b/.test(nLower)) brand = 'OVO';
                                        else if (/\b(dana)\b/.test(nLower)) brand = 'Dana';
                                        else if (/\b(shopee|shopeepay)\b/.test(nLower)) brand = 'ShopeePay';
                                        else if (/\b(linkaja|link aja)\b/.test(nLower)) brand = 'LinkAja';
                                        else brand = 'Lainnya';
                                    } 
                                    else if (kategori === 'Game') {
                                        if (/\b(free fire|ff)\b/.test(nLower)) brand = 'Free Fire';
                                        else if (/\b(mobile legend|mobile legends|mobilelegend|mobile_legend|mlbb|ml)\b/.test(nLower)) brand = 'Mobile Legends';
                                        else if (/\b(pubg|uc)\b/.test(nLower)) brand = 'PUBG';
                                        else brand = 'Lainnya';
                                    }
                                    else if (kategori === 'PLN') {
                                        brand = 'PLN';
                                    }
                                    else if (kategori === 'Voucher') {
                                        if (/\b(telkomsel|tsel|as|simpati)\b/.test(nLower)) brand = 'Telkomsel';
                                        else if (/\b(xl)\b/.test(nLower)) brand = 'XL';
                                        else if (/\b(axis)\b/.test(nLower)) brand = 'Axis';
                                        else if (/\b(indosat|isat|im3)\b/.test(nLower)) brand = 'Indosat';
                                        else if (/\b(tri|three|bima)\b/.test(nLower)) brand = 'Tri';
                                        else if (/\b(smartfren)\b/.test(nLower)) brand = 'Smartfren';
                                        else if (/\b(by\.u|byu)\b/.test(nLower)) brand = 'By.U';
                                        else if (/\b(google play)\b/.test(nLower)) brand = 'Google Play';
                                        else if (/\b(spotify)\b/.test(nLower)) brand = 'Spotify';
                                        else brand = 'Tri'; // Semua sisa voucher masuk Tri
                                    }
                                    else {
                                        if (/\b(BY\.U|BYU)\b/.test(nUpper)) brand = 'By.U';
                                        else if (/\b(TELKOMSEL|TSEL|AS|SIMPATI)\b/.test(nUpper)) brand = 'Telkomsel';
                                        else if (/\b(XL)\b/.test(nUpper)) brand = 'XL';
                                        else if (/\b(AXIS)\b/.test(nUpper)) brand = 'Axis';
                                        else if (/\b(INDOSAT|ISAT|IM3)\b/.test(nUpper)) brand = 'Indosat';
                                        else if (/\b(TRI|THREE|BIMA)\b/.test(nUpper)) brand = 'Tri';
                                        else if (/\b(SMARTFREN)\b/.test(nUpper)) brand = 'Smartfren';
                                        else brand = nama.split(' ')[0].toUpperCase(); 
                                    }
                                }

                                // --- LOGIKA SUB-KATEGORI (KHUSUS DATA) ---
                                let subKategori = 'Umum';
                                if (kategori === 'Data') {
                                    let subsMap = {
                                        'Telkomsel': ['bulk','flash revamp','flash','mini','apps kuota','maxstream','umroh haji','umroh','malam','combo sakti','gamesmax unlimited play','ketengan tiktok','gamesmax','musicmax','disney','omg','gigamax','unlimitedmax','orbit','internetmax','harian sepuasnya','harian','mingguan','bulanan','ketengan utama','roamax haji','roamax','combo','eksklusif','tiktok','super seru','dpi','enterprise+','serba lima ribu','magnet','ukm plus','belajar','terbaik untukmu','non puma','videomax'],
                                        'Indosat': ['yellow gift','yellow','freedom combo gift','freedom combo','freedom harian','freedom internet gift','freedom internet 5g','freedom internet','freedom u gift','freedom u','freedom apps','ejbn','umroh haji combo','umroh haji internet','freedom max','gaspol','sachet','smb','ramadan','hifi air','freedom spesial','freedom play'],
                                        'Axis': ['mini','bronet vidio','bronet','owsem','edu confrence','conference','edukasi','ekstra','youtube','sosmed','paket warnet','aigo ss','aigo unlimited','combo mabrur','mabrur','video','musik','apps games','games','viu','pure','drp games','obor'],
                                        'Smartfren': ['unlimited nonstop 5g','unlimited nonstop','unlimited harian 5g','unlimited','volume','youtube','connex evo','nonstop','chat','sosmed','games','kuota 5g','kuota','tiktok','nonton'],
                                        'Tri': ['mini','alwayson','getmore','mix','home','roaming','data transfer','happy play','happy 5g','happy','lokal','sahabat ojol','ibadah','addon','ramadan','hifi air'],
                                        'XL': ['mini','umroh plus','combo umroh haji','internet umroh haji','umroh','hotrod special','hotrod','xtra combo flex','xtra combo plus','xtra combo gift','xtra combo vip plus','xtra combo mini','xtra combo weekend','xtra combo','combo lite','xtra kuota vidio','xtra kuota','conference','edukasi','xtra on','roaming','paket akrab','games','apps games','bonus harian','flexmax','flex mini','flex','east kalsul','ultra 5g+'],
                                        'By.U': ['viu','tiktok','super kaget','kaget','mbps','topping ggwp','vidio','jajan']
                                    };

                                    let bList = subsMap[brand];
                                    if (bList) {
                                        for (let s of bList) {
                                            if (nLower.includes(s.toLowerCase())) {
                                                subKategori = s.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                                                break;
                                            }
                                        }
                                    }

                                    // Hilangkan tulisan "Paket"
                                    if (brand === 'XL' && subKategori === 'Umum') {
                                        subKategori = 'Akrab';
                                    }
                                }

                                let margin = 0;
                                if(kategori === 'Pulsa') margin = 1000;
                                else {
                                    if(hargaAwal < 100) margin = margins.under100;
                                    else if(hargaAwal < 1000) margin = margins.under1000;
                                    else if(hargaAwal < 5000) margin = margins.under5000;
                                    else if(hargaAwal < 50000) margin = margins.under50000;
                                    else if(hargaAwal < 100000) margin = margins.under100000;
                                    else margin = margins.above;
                                }

                                produk[kode] = {
                                    nama: nama,
                                    harga: hargaAwal + margin,
                                    kategori: kategori,
                                    brand: brand,
                                    sub_kategori: subKategori,
                                    deskripsi: deskripsi
                                };
                                added++;
                            });
                            
                            crypt.save('produk.json', produk);
                            console.log('\x1b[32m\n✅ Berhasil mengimport dan merapikan ' + added + ' produk ke dalam databse!\x1b[0m');
                        } catch(err) {
                            console.log('\x1b[31m❌ Gagal memproses file Excel/CSV: ' + err.message + '\x1b[0m');
                        }
                    "
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            6)
                echo -e "\n${C_MAG}--- ATUR MARGIN KEUNTUNGAN IMPORT ---${C_RST}"
                echo -e "${C_YELLOW}Tentukan nominal keuntungan (Rp) untuk masing-masing harga modal.${C_RST}"
                read -p "1. Keuntungan untuk modal di bawah Rp 100: " m_100
                read -p "2. Keuntungan untuk modal di bawah Rp 1.000: " m_1000
                read -p "3. Keuntungan untuk modal di bawah Rp 5.000: " m_5000
                read -p "4. Keuntungan untuk modal di bawah Rp 50.000: " m_50000
                read -p "5. Keuntungan untuk modal di bawah Rp 100.000: " m_100000
                read -p "6. Keuntungan untuk modal di atas Rp 100.000: " m_max

                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let config = crypt.load('config.json');
                    config.margin = {
                        under100: parseInt('$m_100') || 0,
                        under1000: parseInt('$m_1000') || 0,
                        under5000: parseInt('$m_5000') || 0,
                        under50000: parseInt('$m_50000') || 0,
                        under100000: parseInt('$m_100000') || 0,
                        above: parseInt('$m_max') || 0
                    };
                    crypt.save('config.json', config);
                    console.log('\x1b[32m\n✅ Konfigurasi Margin Keuntungan Berhasil Disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 10. MENU UTAMA (PANEL KONTROL)
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
    echo -e "  ${C_GREEN}[7]${C_RST}  🛒 Manajemen Produk & Harga (XLSX/CSV Import)"
    echo -e "  ${C_GREEN}[8]${C_RST}  ⚙️ Pengaturan Bot Telegram (Auto-Backup)"
    echo -e "  ${C_GREEN}[9]${C_RST}  💾 Backup & Restore Data Database"
    echo -e "  ${C_GREEN}[10]${C_RST} 🔌 Ganti API Digiflazz"
    echo -e "  ${C_GREEN}[11]${C_RST} 🔄 Ganti Akun Bot WA (Reset Sesi)"
    echo -e "  ${C_GREEN}[12]${C_RST} 📢 Kirim Pesan Broadcast Kesemua Member (WA)"
    echo -e "  ${C_GREEN}[13]${C_RST} 🌐 Kirim Pemberitahuan ke Website Aplikasi"
    echo -e "  ${C_GREEN}[14]${C_RST} 💬 Kirim Pesan Langsung (Japri) ke Pelanggan"
    echo -e "  ${C_GREEN}[15]${C_RST} 💳 Setup GoPay Merchant API (QRIS Auto)"
    echo -e "  ${C_GREEN}[16]${C_RST} 🌍 Setup Domain & HTTPS (SSL)"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -e "  ${C_RED}[0]${C_RST}  Keluar dari Panel"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -ne "${C_YELLOW}Pilih menu [0-16]: ${C_RST}"
    read choice

    case $choice in
        1) install_dependencies ;;
        2) 
            if [ ! -f "index.js" ]; then echo -e "${C_RED}❌ Jalankan Menu 1 (Install) dulu!${C_RST}"; sleep 2; continue; fi
            if [ ! -d "sesi_bot" ] || [ -z "$(ls -A sesi_bot 2>/dev/null)" ]; then
                read -p "📲 Masukkan Nomor WA Bot (Awali 628...): " nomor_bot
                if [ ! -z "$nomor_bot" ]; then
                    node -e "
                        const crypt = require('./tendo_crypt.js');
                        let config = crypt.load('config.json');
                        config.botNumber = '$nomor_bot';
                        config.botName = config.botName || 'Tendo Store';
                        crypt.save('config.json', config);
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
                const crypt = require('./tendo_crypt.js');
                let config = crypt.load('config.json');
                config.digiflazzUsername = '$user_api'.trim();
                config.digiflazzApiKey = '$key_api'.trim();
                crypt.save('config.json', config);
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
            echo -e "Anda bisa mengupload gambar (opsional) ke folder: ${C_CYAN}public/info_images/${C_RST} di VPS Anda terlebih dahulu."
            echo -e "Sistem menyimpan hingga 10 pengumuman terbaru (Otomatis hapus yang lama).\n"
            read -p "Ketik Pesan Pengumuman: " web_notif_msg
            read -p "Nama File Gambar (contoh: promo.jpg) / Tekan Enter jika teks saja: " web_notif_img
            
            if [ ! -z "$web_notif_msg" ]; then
                export TMP_MSG="$web_notif_msg"
                export TMP_IMG="$web_notif_img"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let notifs = crypt.load('web_notif.json');
                    let newNotif = {
                        date: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric' }),
                        text: process.env.TMP_MSG,
                        image: process.env.TMP_IMG || ''
                    };
                    notifs.unshift(newNotif);
                    if(notifs.length > 10) notifs.pop();
                    crypt.save('web_notif.json', notifs);
                "
                echo -e "\n${C_GREEN}✅ Pengumuman Aplikasi Web berhasil ditambahkan!${C_RST}"
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
        15)
            while true; do
                clear
                echo -e "\n${C_MAG}--- SETUP GOPAY MERCHANT API ---${C_RST}"
                echo -e "  ${C_GREEN}[1]${C_RST} Tambah / Ganti Konfigurasi API"
                echo -e "  ${C_GREEN}[2]${C_RST} Hapus Konfigurasi (Matikan QRIS Auto)"
                echo -e "  ${C_RED}[0]${C_RST} Kembali"
                echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
                read setup_qris_choice

                case $setup_qris_choice in
                    1)
                        echo -e "\n${C_CYAN}Token dan Merchant ID awal Anda sudah tersimpan otomatis.${C_RST}"
                        echo -e "Silakan isi Link URL gambar QRIS statis toko Anda."
                        echo -e "Contoh URL: https://i.ibb.co/gambar-qris-anda.jpg\n"
                        read -p "Masukkan Bearer Token GoPay (Enter jika tidak berubah): " gopay_token
                        read -p "Masukkan Merchant ID (Enter jika tidak berubah): " gopay_merchant
                        read -p "Masukkan URL Link Gambar QRIS Anda: " qris_url
                        
                        node -e "
                            const crypt = require('./tendo_crypt.js');
                            let config = crypt.load('config.json');
                            
                            let inToken = '$gopay_token'.trim();
                            let inMerch = '$gopay_merchant'.trim();
                            let inQris = '$qris_url'.trim();
                            
                            if(inToken) config.gopayToken = inToken;
                            if(inMerch) config.gopayMerchantId = inMerch;
                            if(inQris) config.qrisUrl = inQris;
                            
                            crypt.save('config.json', config);
                            console.log('\x1b[32m\n✅ Konfigurasi GoPay Merchant Berhasil Disimpan!\x1b[0m');
                        "
                        read -p "Tekan Enter untuk kembali..."
                        ;;
                    2)
                        node -e "
                            const crypt = require('./tendo_crypt.js');
                            let config = crypt.load('config.json');
                            delete config.gopayToken;
                            delete config.gopayMerchantId;
                            delete config.qrisUrl;
                            crypt.save('config.json', config);
                            console.log('\x1b[32m\n✅ Konfigurasi QRIS Otomatis berhasil dihapus!\x1b[0m');
                        "
                        read -p "Tekan Enter untuk kembali..."
                        ;;
                    0) break ;;
                    *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
                esac
            done
            ;;
        16)
            clear
            echo -e "${C_MAG}--- SETUP DOMAIN & HTTPS ---${C_RST}"
            echo -e "Pastikan A Record domain Anda sudah diarahkan ke IP VPS ini ($(curl -s ifconfig.me))"
            read -p "Sudah diarahkan? (y/n): " dns_r
            if [[ "$dns_r" != "y" && "$dns_r" != "Y" ]]; then
                echo -e "${C_RED}Silakan arahkan DNS terlebih dahulu dari panel domain Anda sebelum mengatur HTTPS!${C_RST}"
                read -p "Tekan Enter untuk kembali..."
                continue
            fi

            read -p "Masukkan Nama Domain Anda (contoh: store.domain.com): " domain_name
            if [ -z "$domain_name" ]; then
                echo -e "${C_RED}Domain tidak boleh kosong!${C_RST}"
                sleep 2; continue
            fi

            read -p "Masukkan Email (untuk notifikasi SSL Let's Encrypt): " ssl_email

            echo -e "\n${C_CYAN}>> Menginstall Nginx & Certbot...${C_RST}"
            sudo apt-get update >/dev/null 2>&1
            sudo apt-get install -y nginx certbot python3-certbot-nginx >/dev/null 2>&1

            echo -e "${C_CYAN}>> Mengatur Konfigurasi Nginx Web Server...${C_RST}"
            cat <<EOF > /etc/nginx/sites-available/$domain_name
server {
    listen 80;
    server_name $domain_name;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 90;
        proxy_connect_timeout 90;
        proxy_send_timeout 90;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

            sudo ln -sf /etc/nginx/sites-available/$domain_name /etc/nginx/sites-enabled/
            sudo rm -f /etc/nginx/sites-enabled/default
            sudo nginx -t && sudo systemctl restart nginx

            echo -e "${C_CYAN}>> Meminta Sertifikat SSL HTTPS ke Let's Encrypt...${C_RST}"
            # Ditambahkan opsi --keep-until-expiring untuk mencegah rate limit Let's Encrypt
            sudo certbot --nginx -d $domain_name --non-interactive --agree-tos -m $ssl_email --redirect --keep-until-expiring

            echo -e "\n${C_GREEN}✅ Berhasil! Website Digital Tendo Store Anda sekarang bisa diakses dan sudah diamankan di: https://$domain_name ${C_RST}"
            read -p "Tekan Enter untuk kembali..."
            ;;
        0) echo -e "${C_GREEN}Keluar dari panel. Sampai jumpa! 👋${C_RST}"; exit 0 ;;
        *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 2 ;;
    esac
done
