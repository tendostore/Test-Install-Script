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
            // Migrasi otomatis jika file masih berupa teks asli
            if (raw.trim().startsWith('{') || raw.trim().startsWith('[')) {
                let parsed = JSON.parse(raw);
                module.exports.save(file, parsed); 
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
    <meta name="theme-color" content="#0f172a" id="meta-theme">
    <style>
        /* VARIABEL TEMA GELAP / TERANG & SHADOWS */
        :root {
            --bg-main: #e9eef5; 
            --bg-card: #f4f7f9; 
            --text-main: #0b2136;
            --text-muted: #64748b;
            --border-color: #d1d9e2;
            --grid-bg: #f4f7f9;
            --nav-bg: #f4f7f9;
            --nav-text: #64748b;
            --nav-active: #38bdf8;
            --topbar-bg: #f4f7f9;
            --toast-bg: #0f172a;
            --toast-text: #f8fafc;
            
            --shadow-outer: 0 8px 20px rgba(0, 0, 0, 0.12), 0 2px 5px rgba(0, 0, 0, 0.08);
            --shadow-inner: inset 2px 2px 5px rgba(255, 255, 255, 0.8), inset -3px -3px 6px rgba(0, 0, 0, 0.05);
        }

        .dark-mode {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --grid-bg: #1e293b;
            --nav-bg: #1e293b;
            --nav-text: #475569;
            --nav-active: #38bdf8;
            --topbar-bg: #1e293b;
            --toast-bg: #334155;
            --toast-text: #f8fafc;

            --shadow-outer: 0 8px 20px rgba(0, 0, 0, 0.5), 0 2px 5px rgba(0, 0, 0, 0.3);
            --shadow-inner: inset 2px 2px 4px rgba(255, 255, 255, 0.08), inset -3px -3px 6px rgba(0, 0, 0, 0.4);
        }

        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0f172a; color: var(--text-main); margin: 0; display: flex; justify-content: center; transition: background-color 0.3s;}
        #app { width: 100%; max-width: 480px; background: var(--bg-main); min-height: 100vh; position: relative; overflow-x: hidden; padding-bottom: 140px; box-sizing: border-box; box-shadow: 0 0 20px rgba(0,0,0,0.1); transition: background 0.3s;}
        
        .top-bar { background: var(--topbar-bg); color: var(--text-main); padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; transition: background 0.3s;}
        
        .menu-btn { cursor: pointer; background: var(--bg-card); border: 1px solid var(--border-color); padding: 6px 10px; border-radius: 12px; margin-right: 15px; display: flex; align-items: center; justify-content: center; z-index: 2; box-shadow: var(--shadow-outer), var(--shadow-inner); transition: transform 0.2s;}
        .menu-btn:active { transform: scale(0.95); }
        .menu-btn svg { width: 24px; height: 24px; stroke: var(--text-main); fill: none; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round;}
        
        .brand-title { position: absolute; left: 50%; transform: translateX(-50%); font-size: 13px; font-weight: 900; background: var(--text-main); color: var(--bg-main); padding: 8px 0; border-radius: 30px; box-shadow: var(--shadow-outer), var(--shadow-inner); z-index: 2; overflow: hidden; width: 170px; display: flex; align-items: center;}
        .marquee-text { display: inline-block; white-space: nowrap; animation: marquee 6s linear infinite; }
        @keyframes marquee { 0% { transform: translateX(170px); } 100% { transform: translateX(-100%); } }
        
        .trx-badge { font-size: 11px; background: var(--bg-main); color: var(--text-main); padding: 5px 12px; border-radius: 12px; font-weight: 800; cursor: pointer; border: 1px solid var(--border-color); transition: transform 0.2s; z-index: 2;}
        .trx-badge:active { transform: scale(0.95); }

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

        .saldo-card-modern {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-outer), var(--shadow-inner);
            border: 1px solid var(--border-color);
            position: relative;
            z-index: 2;
            flex-wrap: wrap;
            gap: 10px;
        }
        .sc-left { display: flex; align-items: center; gap: 14px; }
        .sc-icon { 
            width: 44px; height: 44px; background: rgba(56, 189, 248, 0.15); 
            border-radius: 12px; display: flex; justify-content: center; align-items: center; color: #38bdf8; 
        }
        .sc-info { display: flex; flex-direction: column; justify-content: center;}
        .sc-title { font-size: 11px; color: var(--text-muted); font-weight: 700; text-transform: uppercase; margin-bottom: 2px;}
        .sc-amount { font-size: 18px; font-weight: 900; color: var(--text-main); letter-spacing: 0.5px;}

        .sc-actions { display: flex; gap: 8px; align-items: center; }
        .sc-btn-action {
            background: var(--bg-main);
            color: var(--text-main);
            border: 1px solid var(--border-color);
            width: 38px; height: 38px;
            border-radius: 12px; display: flex; justify-content: center; align-items: center;
            cursor: pointer; transition: transform 0.2s;
        }
        .sc-btn-action:active { transform: scale(0.95); }
        .sc-btn-action svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2.2; stroke-linecap: round; stroke-linejoin: round; }

        .sc-btn-topup { 
            background: var(--nav-active); color: #ffffff; border: none; 
            padding: 0 16px; height: 38px; border-radius: 12px; font-weight: 800; font-size: 13px; cursor: pointer;
            box-shadow: 0 4px 12px rgba(56, 189, 248, 0.25); transition: transform 0.2s;
        }
        .sc-btn-topup:active { transform: scale(0.95); }

        .banner-slider-container { margin: 20px 20px 0px; border-radius: 16px; overflow: hidden; position: relative; background: var(--bg-card); box-shadow: 0 4px 10px rgba(0,0,0,0.03);}
        .banner-slider { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; -webkit-overflow-scrolling: touch; scrollbar-width: none; }
        .banner-slider::-webkit-scrollbar { display: none; }
        .banner-slide { flex: 0 0 100%; scroll-snap-align: center; display: flex; justify-content: center; align-items: center; }
        .banner-slide img { width: 100%; height: auto; object-fit: cover; aspect-ratio: 21/9; display: block;}

        .grid-title { margin: 25px 20px 15px; font-weight: 900; color: var(--text-main); font-size: 15px;}
        .grid-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; padding: 0 20px;}
        .grid-box { 
            background: var(--grid-bg); border-radius: 18px; padding: 18px 5px; 
            text-align: center; cursor: pointer; display: flex; flex-direction: column; align-items: center; justify-content: flex-start;
            box-shadow: var(--shadow-outer), var(--shadow-inner); border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .grid-box:active { transform: scale(0.95); box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        
        .grid-icon-wrap { 
            width: 50px; height: 50px; margin-bottom: 12px; display: flex; justify-content: center; align-items: center; 
            border-radius: 14px; transition: background 0.3s;
        }
        .ic-pulsa { background: rgba(56, 189, 248, 0.15); color: #0284c7; }
        .ic-data { background: rgba(52, 211, 153, 0.15); color: #059669; }
        .ic-game { background: rgba(248, 113, 113, 0.15); color: #dc2626; }
        .ic-voucher { background: rgba(250, 204, 21, 0.15); color: #ca8a04; }
        .ic-ewallet { background: rgba(167, 139, 250, 0.15); color: #7c3aed; }
        .ic-pln { background: rgba(251, 191, 36, 0.15); color: #d97706; }
        .ic-sms { background: rgba(244, 114, 182, 0.15); color: #db2777; }
        .ic-masa { background: rgba(251, 146, 60, 0.15); color: #ea580c; }
        .ic-perdana { background: rgba(45, 212, 191, 0.15); color: #0d9488; }
        
        .dark-mode .ic-pulsa { background: rgba(56, 189, 248, 0.2); color: #38bdf8; }
        .dark-mode .ic-data { background: rgba(52, 211, 153, 0.2); color: #34d399; }
        .dark-mode .ic-game { background: rgba(248, 113, 113, 0.2); color: #f87171; }
        .dark-mode .ic-voucher { background: rgba(250, 204, 21, 0.2); color: #facc15; }
        .dark-mode .ic-ewallet { background: rgba(167, 139, 250, 0.2); color: #a78bfa; }
        .dark-mode .ic-pln { background: rgba(251, 191, 36, 0.2); color: #fbbf24; }
        .dark-mode .ic-sms { background: rgba(244, 114, 182, 0.2); color: #f472b6; }
        .dark-mode .ic-masa { background: rgba(251, 146, 60, 0.2); color: #fb923c; }
        .dark-mode .ic-perdana { background: rgba(45, 212, 191, 0.2); color: #2dd4bf; }

        .grid-text { font-size: 10.5px; color: var(--text-main); font-weight: 800; line-height: 1.3; text-transform: uppercase; letter-spacing: -0.2px;}

        .stats-container { margin: 25px 20px; padding: 15px; background: var(--bg-card); border-radius: 16px; border: 1px solid var(--border-color); text-align: center; box-shadow: var(--shadow-outer), var(--shadow-inner);}
        .stats-title { font-size: 14px; font-weight: 900; color: var(--text-main); margin-bottom: 15px; text-transform: uppercase; letter-spacing: 0.5px;}
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;}
        .stat-box { flex: 1; padding: 10px 5px; background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border-color); box-shadow: var(--shadow-outer), var(--shadow-inner);}
        .stat-val { font-size: 16px; font-weight: 900; color: #0ea5e9; margin-bottom: 5px;}
        .stat-lbl { font-size: 9px; font-weight: 800; color: var(--text-muted); text-transform: uppercase;}

        .brand-list { display: flex; flex-direction: column; padding: 15px 20px; gap: 12px; }
        .brand-row { background: var(--bg-card); padding: 15px; border-radius: 14px; border: 1px solid var(--border-color); display: flex; align-items: center; gap: 15px; box-shadow: 0 2px 6px rgba(0,0,0,0.02); cursor: pointer; transition: transform 0.2s; color: var(--text-main);}
        .brand-row:active { transform: scale(0.98); }
        .b-logo { width: 45px; height: 45px; background: var(--bg-main); color: var(--text-main); border-radius: 50%; font-weight: 900; font-size: 15px; display: flex; justify-content: center; align-items: center; border: 1px solid var(--border-color); flex-shrink: 0; text-transform: uppercase;}
        .b-name { font-size: 14px; font-weight: 800; flex: 1;}

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
            box-shadow: var(--shadow-outer), var(--shadow-inner); 
            z-index: 900; 
            transition: background 0.3s;
            border: 1px solid var(--border-color);
        }
        .nav-item { text-align: center; color: var(--nav-text); font-size: 10px; flex: 1; cursor: pointer; display: flex; flex-direction: column; align-items: center; font-weight: 700; transition: color 0.3s;}
        .nav-icon { margin-bottom: 2px; display: flex; justify-content: center; align-items: center;}
        .nav-icon svg { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}
        .nav-item.active { color: var(--nav-active);}

        .product-item { background: var(--bg-card); padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid var(--border-color); display: flex; align-items: center; gap: 15px; box-shadow: var(--shadow-outer), var(--shadow-inner); cursor: pointer; transition: transform 0.2s;}
        .product-item:active { transform: scale(0.98); }
        .prod-logo { width: 45px; height: 45px; background: var(--bg-main); color: var(--text-main); border-radius: 50%; display: flex; justify-content: center; align-items: center; font-weight: 900; font-size: 14px; border: 1px solid var(--border-color); flex-shrink: 0; text-transform: uppercase;}
        .prod-info { flex: 1; min-width: 0; }
        .prod-name { font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between; word-wrap: break-word;}
        .badge-open { background: #e0f2fe; color: #0284c7; font-size: 9px; padding: 2px 6px; border-radius: 4px; font-weight: 800; border: 1px solid #bae6fd; flex-shrink: 0; margin-left: 8px;}
        .prod-desc { font-size: 10px; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; text-overflow: ellipsis;}
        .prod-price { color: var(--text-main); font-weight: 900; font-size: 15px;}

        .search-box { padding: 15px 20px 5px; position: sticky; top: 58px; z-index: 50; background: var(--bg-main); transition: background 0.3s; }
        .search-box input { margin-bottom: 0; box-shadow: 0 2px 5px rgba(0,0,0,0.02); border-radius: 12px; padding: 12px 15px; width: 100%; box-sizing: border-box; font-weight: bold;}

        .history-tabs { display: flex; gap: 10px; padding: 10px 20px; background: var(--bg-main); position: sticky; top: 58px; z-index: 50; }
        .hist-tab { flex: 1; text-align: center; padding: 12px 0; font-size: 13px; font-weight: 800; cursor: pointer; color: var(--text-main); background: var(--bg-card); border-radius: 14px; border: 1px solid var(--border-color); box-shadow: var(--shadow-outer), var(--shadow-inner); transition: all 0.2s; text-transform: uppercase;}
        .hist-tab.active { background: var(--nav-active); color: #ffffff; border-color: var(--nav-active); }

        .sidebar-overlay { position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(15,23,42,0.8); z-index: 1001; display: none; opacity: 0; transition: opacity 0.3s;}
        .sidebar { position: fixed; top:-10px; left:-300px; width: 280px; height: 100vh; background: var(--bg-card); z-index: 1002; transition: left 0.3s ease; overflow-y: auto; display: flex; flex-direction: column; box-shadow: 5px 0 15px rgba(0,0,0,0.3);}
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 40px 20px 30px; text-align: center; border-bottom: 1px solid var(--border-color); background: #0f172a; color: #ffffff;}
        .sidebar-avatar { width: 70px; height: 70px; background: #ffffff; border-radius: 50%; margin: 0 auto 10px auto; display: flex; justify-content: center; align-items: center; color: #0b2136; font-size: 30px; font-weight: bold; text-transform: uppercase;}
        .sidebar-name { font-weight: bold; font-size: 16px; color: #ffffff;}
        .sidebar-phone { font-size: 12px; color: #cbd5e1;}
        .sidebar-menu { padding: 10px 0; flex: 1;}
        
        .sidebar-item { padding: 15px 20px; display: flex; align-items: center; color: var(--text-main); text-decoration: none; font-size: 14px; border: 1px solid var(--border-color); font-weight: 600; gap: 15px; background: var(--bg-card); border-radius: 14px; margin: 10px 15px; box-shadow: var(--shadow-outer), var(--shadow-inner); transition: transform 0.2s; }
        .sidebar-item:active { transform: scale(0.95); background: var(--bg-main); }
        .sidebar-item svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }

        .container { padding: 20px; }
        .card { background: var(--bg-card); padding: 25px 20px; border-radius: 16px; margin-bottom: 20px; border: 1px solid var(--border-color); box-shadow: 0 4px 10px rgba(0,0,0,0.02);}
        input, select { width: 100%; padding: 15px; margin-bottom: 12px; border: 1px solid var(--border-color); border-radius: 12px; box-sizing: border-box; font-size: 14px; outline: none; background: var(--bg-main); color: var(--text-main); font-weight: 600; transition: border-color 0.2s;}
        input:focus, select:focus { border-color: #0284c7; background: var(--bg-card);}
        
        .checkbox-container { display: flex; align-items: center; justify-content: flex-start; gap: 8px; margin-bottom: 20px; font-size: 13px; font-weight: 600; color: var(--text-muted); cursor: pointer;}
        .checkbox-container input { width: 16px; height: 16px; margin: 0; padding: 0; cursor: pointer;}
        
        .btn { background: #0b2136; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; transition: opacity 0.2s;}
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-outline { background: var(--bg-card); color: var(--text-main); border: 1.5px solid var(--border-color); padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}
        .btn-danger { background: #ef4444; color: #ffffff; border: none; padding: 15px; width: 100%; border-radius: 12px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px;}

        .prof-header { background: #0f172a; color: #ffffff; padding: 30px 20px; text-align: center; border-bottom-left-radius: 25px; border-bottom-right-radius: 25px;}
        
        .prof-avatar-wrap {
            width: 86px; height: 86px;
            background: transparent;
            border-radius: 50%;
            padding: 0;
            margin: 0 auto 15px auto;
            box-shadow: none;
        }
        .prof-avatar {
            width: 100%; height: 100%;
            background: #ffffff; color: #0f172a;
            border-radius: 50%; font-size: 38px; display: flex; justify-content: center; align-items: center; font-weight: 900; text-transform: uppercase;
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
        
        .prof-action-btn { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border-color); padding: 15px; width: 100%; border-radius: 12px; font-weight: bold; cursor: pointer; font-size: 13px; display: flex; align-items: center; gap: 10px; transition: transform 0.2s; box-shadow: var(--shadow-outer), var(--shadow-inner); }
        .prof-action-btn:active { transform: scale(0.98); }
        .prof-action-btn svg { fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;}

        .hist-item { background: var(--bg-card); color: var(--text-main); padding: 15px; border-radius: 14px; margin: 10px 20px; border: 1px solid var(--border-color); box-shadow: var(--shadow-outer), var(--shadow-inner); cursor: pointer; transition: transform 0.2s;}
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
        .provider-toast.show { opacity: 1; top: 40px; }

        .custom-toast {
            position: fixed;
            top: -100px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--toast-bg);
            color: var(--toast-text);
            padding: 12px 24px;
            border-radius: 30px;
            font-size: 13px;
            font-weight: 800;
            z-index: 9999;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            transition: top 0.4s cubic-bezier(0.68, -0.55, 0.27, 1.55);
            text-align: center;
            width: max-content;
            max-width: 90%;
            display: flex;
            align-items: center;
            gap: 10px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .custom-toast.show { top: 40px; }
        .custom-toast.error { background: #ef4444; color: #fff; }
        .custom-toast.success { background: #10b981; color: #fff; }

        @media screen and (min-width: 768px) {
            body { padding: 30px 0; background-color: #0f172a; }
            #app { max-width: 800px; border-radius: 36px; min-height: calc(100vh - 60px); box-shadow: 0 25px 60px rgba(0,0,0,0.15); padding-bottom: 130px; }
            .top-bar { border-top-left-radius: 36px; border-top-right-radius: 36px; padding: 20px 30px; }
            .banner-container { padding: 10px 30px 30px; }
            .bottom-nav { max-width: 740px; bottom: 50px; padding: 15px 10px; border-radius: 60px; }
            .nav-item .nav-icon svg { width: 26px; height: 26px; }
            .grid-container { grid-template-columns: repeat(4, 1fr); padding: 0 30px; gap: 20px; }
            .stats-container { margin: 30px; }
            .banner-slider-container { margin: 20px 30px 0px; }
            #product-list, #brand-list, #history-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; padding: 10px 30px 30px !important; }
            .product-item, .brand-row, .hist-item { margin: 0 !important; }
            #notif-list, #global-trx-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; padding: 30px !important; }
            #notif-list .card, #global-trx-list .card { margin-bottom: 0 !important; }
            #login-screen .card, #register-screen .card, #otp-screen .card, #forgot-screen .card { max-width: 450px; margin: 0 auto; padding: 40px; }
            .sidebar { width: 340px; }
        }

        @media screen and (min-width: 1024px) {
            #app { max-width: 1024px; }
            .bottom-nav { max-width: 964px; }
            .grid-container { grid-template-columns: repeat(5, 1fr); }
            #product-list, #brand-list, #history-list, #notif-list, #global-trx-list { grid-template-columns: repeat(3, 1fr); }
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

        <div class="top-bar hidden" id="home-topbar">
            <button class="menu-btn" onclick="toggleSidebar()">
                <svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
            <div class="brand-title" style="justify-content: center; padding: 8px 20px; width: auto; white-space: nowrap;">
                <span id="top-title">Digital tendo store</span>
            </div>
            <div class="trx-badge" id="top-trx-badge" onclick="showHistory('Order')">0 Trx</div>
        </div>

        <div class="banner-container hidden" id="banner-container-wrap">
            <div class="saldo-card-modern">
                <div class="sc-left">
                    <div class="sc-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="22" height="22"><path d="M21 12V7H5a2 2 0 0 1 0-4h14v4"></path><path d="M3 5v14a2 2 0 0 0 2 2h16v-5"></path><path d="M18 12a2 2 0 0 0 0 4h4v-4Z"></path></svg>
                    </div>
                    <div class="sc-info">
                        <div class="sc-title">Saldo Aktif</div>
                        <div class="sc-amount" id="user-saldo" data-saldo="0">Rp 0</div>
                    </div>
                </div>
                <div class="sc-actions">
                    <button class="sc-btn-action" onclick="showHistory('Topup')" title="Riwayat Topup">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="12 8 12 12 14 14"></polyline><circle cx="12" cy="12" r="10"></circle></svg>
                    </button>
                    <button class="sc-btn-action" onclick="contactAdmin()" title="Bantuan Admin">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 18v-6a9 9 0 0 1 18 0v6"></path><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"></path></svg>
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
                    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Transaksi Saya
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); showNotif()">
                    <svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg> Pemberitahuan
                </a>
                <a href="#" class="sidebar-item" onclick="toggleSidebar(); contactAdmin()">
                    <svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg> Hubungi Admin
                </a>
                <a href="#" class="sidebar-item" onclick="toggleTheme()">
                    <svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg> <span id="theme-text">Mode Terang</span>
                </a>
            </div>
            <div style="padding: 20px;">
                <button class="btn-outline" style="color: #ef4444; border-color: #ef4444;" onclick="logout()">Keluar Akun</button>
            </div>
        </div>

        <div id="login-screen" class="container hidden">
            <div style="text-align:center; margin: 40px 0;">
                <h1 style="color:var(--text-main); margin:0; font-weight:900; font-size: 28px;">Digital Tendo Store</h1>
                <p style="color:var(--text-muted); font-size:13px; margin-top:5px; font-weight: 600;">Solusi Pembayaran Digital</p>
            </div>
            <div class="card">
                <h2 style="margin-top:0; text-align:center; font-size:18px;">Masuk Akun</h2>
                <input type="email" id="log-email" placeholder="Alamat Email">
                <input type="password" id="log-pass" placeholder="Password">
                <label class="checkbox-container">
                    <input type="checkbox" id="rem-login" checked> Tetap masuk
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
            
            <div id="live-clock" style="text-align:center; font-size:11.5px; font-weight:800; color:var(--text-main); margin: 25px 20px 0; letter-spacing: 0.5px;">Memuat waktu...</div>

            <div class="grid-title">Layanan Produk</div>
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

            <div style="margin: 25px 20px 0; padding: 15px; background: var(--bg-card); border-radius: 16px; border: 1px solid var(--border-color); box-shadow: var(--shadow-outer), var(--shadow-inner);">
                <div style="font-size:14px; font-weight:900; color:var(--text-main); margin-bottom:5px;">📢 Komunitas & Update</div>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:15px; line-height:1.4; font-weight:600;">Dapatkan informasi terbaru seputar Digital Tendo Store melalui Channel Telegram dan Saluran WhatsApp kami.</div>
                <div style="display:flex; gap:10px;">
                    <button class="btn" style="background:#2481cc; flex:1; font-size:12px; padding:12px; border-radius:12px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="window.open('https://t.me/+CMUMhuJYnX44ZjNl', '_blank')">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg> Telegram
                    </button>
                    <button class="btn" style="background:#25D366; flex:1; font-size:12px; padding:12px; border-radius:12px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="window.open('https://whatsapp.com/channel/0029VbCZzAfHQbS4YeW03Z0m', '_blank')">
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
            <div id="history-list" style="padding-top:10px;"></div>
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
                <svg class="back-icon" onclick="goBackGlobal()" viewBox="0 0 24 24" width="28" height="28" style="margin-right:10px;">
                    <polyline points="15 18 9 12 15 6"></polyline>
                </svg>
                <span>Pemberitahuan</span>
            </div>
            <div class="container" id="notif-list" style="margin-bottom: 120px;">
                <div style="text-align:center; color:var(--text-muted); padding:30px; font-size:13px; font-weight:bold;">Memuat info...</div>
            </div>
        </div>

        <div class="bottom-nav hidden" id="main-bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showDashboard()">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg></span>HOME
            </div>
            <div class="nav-item" id="nav-history" onclick="showHistory('Order')">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></span>RIWAYAT
            </div>
            <div class="nav-item" id="nav-notif" onclick="showNotif()">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg></span>INFO
            </div>
            <div class="nav-item" id="nav-global-trx" onclick="showGlobalTrx()">
                <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg></span>TRANSAKSI
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
                
                <div style="margin-bottom:15px; text-align:left;">
                    <label style="font-size:12px; font-weight:800; color:var(--text-muted);">Metode Pembayaran:</label>
                    <select id="m-payment-method" style="width:100%; padding:12px; border-radius:12px; background:var(--bg-main); color:var(--text-main); border:1px solid var(--border-color); font-weight:bold; margin-top:5px; outline:none;">
                        <option value="saldo">💳 Menggunakan Saldo Akun</option>
                        <option value="qris">📲 Langsung Bayar QRIS Otomatis</option>
                    </select>
                </div>

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
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Metode</span><strong id="os-metode" style="color:#0ea5e9;">Saldo Akun</strong></div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span style="color:var(--text-muted);">Harga</span><strong id="os-price" style="text-align:right;"></strong></div>
                </div>
                <button class="btn" style="width:100%;" onclick="closeOrderSuccessModal()">Selesai & Cek Riwayat</button>
            </div>
        </div>

        <div id="topup-modal" class="modal-overlay hidden">
            <div class="modal-box">
                <h3 style="margin-top:0; font-size:18px;">Isi Saldo Otomatis</h3>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:15px;">Pilih atau masukkan nominal (Khusus QRIS Tanpa biaya admin). Saldo masuk utuh.</p>
                
                <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:10px; justify-items:center; margin-bottom:15px; width: 100%;">
                    <div class="trx-badge" style="padding:10px; width:100%; box-sizing:border-box; text-align:center;" onclick="document.getElementById('topup-nominal').value='1000'">Rp.1000</div>
                    <div class="trx-badge" style="padding:10px; width:100%; box-sizing:border-box; text-align:center;" onclick="document.getElementById('topup-nominal').value='5000'">Rp.5000</div>
                    <div class="trx-badge" style="padding:10px; width:100%; box-sizing:border-box; text-align:center;" onclick="document.getElementById('topup-nominal').value='10000'">Rp.10.000</div>
                    <div class="trx-badge" style="padding:10px; width:100%; box-sizing:border-box; text-align:center;" onclick="document.getElementById('topup-nominal').value='50000'">Rp.50.000</div>
                    <div class="trx-badge" style="padding:10px; width:100%; box-sizing:border-box; text-align:center; grid-column: span 2;" onclick="document.getElementById('topup-nominal').value='100000'">Rp.100.000</div>
                </div>

                <input type="number" id="topup-nominal" placeholder="Nominal (Min. 1000)" style="text-align:center; font-size:18px; font-weight:bold;">
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
                    <p style="font-size:12px; color:var(--text-main); margin-top:0; margin-bottom:5px; font-weight:bold;">Sisa Waktu Pembayaran:</p>
                    <div id="qris-countdown" style="font-size:22px; font-weight:900; color:#ef4444; margin-bottom:10px; background:#fee2e2; padding:5px; border-radius:8px; border: 1px solid #fca5a5;">-- : --</div>
                    
                    <p style="font-size:11px; color:var(--text-main); margin-top:0; margin-bottom:10px;">Segera bayar dengan QRIS ini:</p>
                    <img id="hd-qris-img" src="" style="width:100%; max-width:240px; padding:20px; border-radius:16px; border:1px solid var(--border-color); margin-bottom:15px; background:#ffffff; box-sizing: border-box; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
                    
                    <div style="display:flex; gap:10px; justify-content:center; margin-bottom:15px;">
                        <button class="btn-outline" style="flex:1; margin:0; padding:10px 5px; font-size:12px; font-weight: bold; border-color:#16a34a; color:#16a34a; border-radius:20px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="shareQRIS()">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
                            Bagikan
                        </button>
                        <button class="btn-outline" style="flex:1; margin:0; padding:10px 5px; font-size:12px; font-weight: bold; border-color:#16a34a; color:#16a34a; border-radius:20px; display:flex; align-items:center; justify-content:center; gap:5px;" onclick="downloadQRIS()">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            Simpan
                        </button>
                    </div>

                    <div style="font-size:11px; color:var(--text-muted); font-weight:bold;">Transfer TEPAT SEBESAR:</div>
                    <div style="font-size:24px; font-weight:900; color:#0ea5e9; margin: 5px 0;" id="hd-qris-amount">Rp 0</div>
                    <div style="font-size:11px; color:#ef4444; font-weight:bold; line-height:1.4;">Harus persis agar otomatis masuk.</div>
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

    <script>
        // JAM DIGITAL REALTIME & SYSTEM PEMELIHARAAN (23:00 - 00:30)
        setInterval(() => {
            let d = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Jakarta"}));
            
            // Render Live Clock
            let clockEl = document.getElementById('live-clock');
            if(clockEl) {
                let opts = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' };
                clockEl.innerText = d.toLocaleString('id-ID', opts).replace(/\./g, ':') + ' WIB';
            }

            // Render Banner Maintenance
            let h = d.getHours();
            let m = d.getMinutes();
            let isMaint = (h === 23) || (h === 0 && m <= 30);
            
            let mb = document.getElementById('maint-banner');
            let dbScreen = document.getElementById('dashboard-screen');
            if (isMaint && dbScreen) {
                if(!mb) {
                    mb = document.createElement('div');
                    mb.id = 'maint-banner';
                    mb.innerHTML = '🛠️ PEMELIHARAAN SISTEM (23:00 - 00:30 WIB). TRANSAKSI SEMENTARA DITUTUP.';
                    mb.style = 'background:#ef4444; color:#fff; font-size:11px; font-weight:bold; text-align:center; padding:12px; margin: 20px 20px 0; border-radius:12px; box-shadow: 0 4px 10px rgba(239,68,68,0.3);';
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
            else if(s.screen === 'brand-screen') {
                if(s.subcat_mode) loadSubCategoryInternal(s.cat, s.brand);
                else loadCategoryInternal(s.cat);
            }
            else if(s.screen === 'produk-screen') loadProductsInternal(s.cat, s.brand, s.subcat);
            else if(s.screen === 'history-screen') showHistoryInternal(s.filter);
            else if(s.screen === 'profile-screen') showProfileInternal();
            else if(s.screen === 'notif-screen') showNotifInternal();
            else if(s.screen === 'global-trx-screen') showGlobalTrxInternal();
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
            t.innerHTML = icon + msg;
            setTimeout(() => { t.classList.remove('show'); }, 3500);
        }

        let deferredPrompt;
        window.addEventListener('beforeinstallprompt', (e) => { 
            e.preventDefault(); deferredPrompt = e;
        });
        if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

        let currentUser = ""; let userData = {}; let allProducts = {}; let selectedSKU = ""; let tempRegPhone = ""; let tempForgotPhone = ""; let currentEditMode = ""; let currentHistoryItem = null;
        let currentCategory = ""; let currentBrand = ""; let currentHistoryFilter = 'All';
        let bannerInterval; let qrisInterval;

        let savedTheme = localStorage.getItem('tendo_theme');
        if(savedTheme === 'light') {
            document.body.classList.remove('dark-mode');
            document.getElementById('theme-text').innerText = "Mode Terang";
        } else {
            document.body.classList.add('dark-mode');
            document.getElementById('theme-text').innerText = "Mode Terang";
            localStorage.setItem('tendo_theme', 'dark');
        }

        function toggleTheme() {
            document.body.classList.toggle('dark-mode');
            let isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('tendo_theme', isDark ? 'dark' : 'light');
            document.getElementById('theme-text').innerText = isDark ? "Mode Terang" : "Mode Gelap";
            toggleSidebar();
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
            if(bodyData) {
                options.method = 'POST';
                options.headers = {'Content-Type': 'application/json'};
                options.body = JSON.stringify(bodyData);
            }
            let res = await fetch(url, options);
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
                }
            } catch(e){}
        }

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

            ['login-screen', 'register-screen', 'otp-screen', 'forgot-screen', 'dashboard-screen', 'brand-screen', 'produk-screen', 'history-screen', 'profile-screen', 'notif-screen', 'global-trx-screen'].forEach(s => {
                document.getElementById(s).classList.add('hidden');
            });
            document.getElementById(id).classList.remove('hidden');
            
            if (['dashboard-screen', 'history-screen', 'notif-screen', 'profile-screen', 'brand-screen', 'produk-screen', 'global-trx-screen'].includes(id)) {
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
                if(id === 'dashboard-screen') document.getElementById('banner-container-wrap').classList.remove('hidden');
                else document.getElementById('banner-container-wrap').classList.add('hidden');
            }
        }

        document.addEventListener('DOMContentLoaded', async () => {
            let savedEmail = localStorage.getItem('tendo_email');
            let savedPass = localStorage.getItem('tendo_pass');
            if(savedEmail && savedPass) {
                try {
                    let data = await apiCall('/api/login', {email:savedEmail, password:savedPass});
                    if(data && data.success) {
                        currentUser = data.phone; userData = data.data;
                        await fetchAllProducts();
                        fetchGlobalStats();
                        loadBanners();
                        
                        let lastTab = localStorage.getItem('tendo_last_tab') || 'dashboard-screen';
                        currentState = { screen: lastTab };
                        
                        if (lastTab === 'history-screen') {
                            let savedFilter = localStorage.getItem('tendo_history_filter') || 'Order';
                            showHistoryInternal(savedFilter);
                            currentState.filter = savedFilter;
                        }
                        else if (lastTab === 'profile-screen') showProfileInternal();
                        else if (lastTab === 'notif-screen') showNotifInternal();
                        else if (lastTab === 'global-trx-screen') showGlobalTrxInternal();
                        else if (lastTab === 'brand-screen') {
                            let cCat = localStorage.getItem('tendo_current_cat');
                            if(cCat) { loadCategoryInternal(cCat); currentState.cat = cCat; currentState.subcat_mode = false; }
                            else showDashboardInternal();
                        }
                        else if (lastTab === 'produk-screen') {
                            let cCat = localStorage.getItem('tendo_current_cat');
                            let cBrand = localStorage.getItem('tendo_current_brand');
                            let cSub = localStorage.getItem('tendo_current_subcat');
                            if(cCat && cBrand) { 
                                loadProductsInternal(cCat, cBrand, (cSub === 'null' ? null : cSub)); 
                                currentState.cat = cCat; currentState.brand = cBrand; currentState.subcat = (cSub === 'null' ? null : cSub);
                            } else showDashboardInternal();
                        }
                        else showDashboardInternal();

                    } else { showScreen('login-screen', null); }
                } catch(e) { showScreen('login-screen', null); }
            } else {
                showScreen('login-screen', null);
            }
        });

        function showDashboardInternal() { showScreen('dashboard-screen', 'nav-home'); syncUserData(); fetchAllProducts(); }
        function showDashboard() { pushState({screen: 'dashboard-screen'}); showDashboardInternal(); }
        
        function showHistoryInternal(filter) { 
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
        
        function showProfileInternal() { showScreen('profile-screen', 'nav-profile'); syncUserData(); }
        function showProfile() { pushState({screen: 'profile-screen'}); showProfileInternal(); }

        async function showGlobalTrxInternal() {
            showScreen('global-trx-screen', 'nav-global-trx');
            try {
                let data = await apiCall('/api/global-trx');
                let html = '';
                if(data && Array.isArray(data) && data.length > 0) {
                    data.forEach(n => {
                        html += `
                        <div class="card" style="border-left: 4px solid #10b981; margin-bottom:15px; padding:15px;">
                            <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); margin-bottom:5px; font-weight:700;">
                                <span>🕒 ${n.time} WIB</span>
                                <span style="color:#10b981;">Berhasil</span>
                            </div>
                            <div style="font-weight:900; font-size:14px; margin-bottom:4px; color:var(--text-main);">${n.product}</div>
                            <div style="font-size:12px; font-weight:600; color:var(--text-muted);">Akun: ${n.user}</div>
                            <div style="font-size:12px; font-weight:600; color:var(--text-muted);">Tujuan: ${n.target}</div>
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
        function showNotif() { pushState({screen: 'notif-screen'}); showNotifInternal(); }

        function openTopupModal() { document.getElementById('topup-nominal').value = ''; document.getElementById('topup-modal').classList.remove('hidden'); }
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
                let latest = userData.history.find(h => (h.type === 'Topup' || h.type === 'Order QRIS') && h.status === 'Pending');
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
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }

        function logout() {
            currentUser = ""; userData = {}; 
            localStorage.removeItem('tendo_email'); localStorage.removeItem('tendo_pass');
            localStorage.removeItem('tendo_last_tab'); localStorage.removeItem('tendo_last_nav');
            localStorage.removeItem('tendo_history_filter');
            localStorage.removeItem('tendo_current_cat'); localStorage.removeItem('tendo_current_brand');
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

                    document.getElementById('p-avatar').innerHTML = '<img src="' + shanksGif + '" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">';
                    document.getElementById('p-username').innerText = u.username || "Member";
                    document.getElementById('p-id').innerText = "ID: " + (u.id_pelanggan || "TD-000");
                    document.getElementById('p-email').innerText = u.email || '-';
                    document.getElementById('p-phone').innerText = currentUser;
                    document.getElementById('p-date').innerText = u.tanggal_daftar || '-';
                    document.getElementById('p-trx').innerText = (u.trx_count || 0) + ' Kali';

                    let histHTML = '';
                    let historyList = u.history || [];
                    
                    historyList = historyList.filter(h => {
                        let type = h.type || 'Order';
                        if (currentHistoryFilter === 'Topup') return type === 'Topup';
                        return type === 'Order' || type === 'Order QRIS';
                    });

                    if(historyList.length === 0) histHTML = '<div style="text-align:center; color:var(--text-muted); font-weight:bold; margin-top: 30px; font-size:13px;">Belum ada transaksi.</div>';
                    else {
                        historyList.forEach((h, idx) => {
                            let statClass = 'stat-Pending';
                            if(h.status === 'Sukses' || h.status === 'Sukses Bayar') statClass = 'stat-Sukses';
                            if(h.status === 'Gagal' || h.status === 'Gagal (Kedaluwarsa)') statClass = 'stat-Gagal';
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
                    if(currentHistoryItem) currentHistoryItem.status = 'Gagal';
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
            document.getElementById('hd-target').innerText = h.tujuan;
            document.getElementById('hd-sn').innerText = h.sn || '-';
            
            let btnComplain = document.getElementById('hd-complain-btn');
            if(h.status === 'Pending' || h.status === 'Gagal' || h.status === 'Gagal (Kedaluwarsa)') {
                btnComplain.classList.remove('hidden');
            } else {
                btnComplain.classList.add('hidden');
            }
            
            let qrisBox = document.getElementById('hd-qris-box');
            if((h.type === 'Topup' || h.type === 'Order QRIS') && h.status === 'Pending') {
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
            
            document.getElementById('history-detail-modal').classList.remove('hidden');
        }
        
        function closeHistoryModal() { 
            clearInterval(qrisInterval);
            document.getElementById('history-detail-modal').classList.add('hidden'); 
        }
        
        function contactAdmin() {
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya butuh bantuan terkait akun / layanan.`;
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }
        
        function complainAdmin() {
            let h = currentHistoryItem;
            if(!h) { contactAdmin(); return; }
            let email = userData.email || "-";
            let phone = currentUser || "-";
            let pesan = `Halo Admin Digital Tendo Store,%0A%0ASaya ingin komplain/tanya transaksi ini:%0A%0A📧 Email: *${email}*%0A📱 Nomor WA: *${phone}*%0A📦 Layanan: *${h.nama}*%0A📱 Tujuan: *${h.tujuan}*%0A🕒 Waktu: *${h.tanggal}*%0A⚙️ Status: *${h.status}*%0A🔑 SN/Ref: *${h.sn || '-'}*%0A%0AMohon bantuannya dicek. Terima kasih.`;
            window.open(`https://wa.me/6282224460678?text=${pesan}`, '_blank');
        }

        async function login() {
            let email = document.getElementById('log-email').value.trim();
            let pass = document.getElementById('log-pass').value.trim();
            let rem = document.getElementById('rem-login').checked;
            if(!email || !pass) return showToast('Isi Email & Password!', 'error');
            
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
                    showToast(data && data.message ? data.message : "Gagal terhubung.", 'error');
                }
            } catch(e) { showToast('Kesalahan jaringan.', 'error'); }
            
            btn.innerText = ori; btn.disabled = false;
        }

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
                    document.getElementById('log-email').value = document.getElementById('reg-email').value;
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
            
            document.getElementById('brand-cat-title').innerText = cat;
            
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
            } else { showToast('Belum ada produk di kategori ini.', 'error'); }
        }
        function loadCategory(cat) { pushState({screen: 'brand-screen', cat: cat, subcat_mode: false}); loadCategoryInternal(cat); }

        function loadSubCategoryInternal(cat, brand) {
            currentCategory = cat; currentBrand = brand;
            localStorage.setItem('tendo_current_cat', cat);
            localStorage.setItem('tendo_current_brand', brand);
            localStorage.setItem('tendo_current_subcat', '');

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
                let sortedSubs = subs.sort();
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
            } else { showToast('Belum ada paket untuk provider ini.', 'error'); }
        }
        function loadSubCategory(cat, brand) { pushState({screen: 'brand-screen', cat: cat, brand: brand, subcat_mode: true}); loadSubCategoryInternal(cat, brand); }

        function loadProductsInternal(cat, brand, subCat = null) {
            currentCategory = cat; currentBrand = brand;
            localStorage.setItem('tendo_current_cat', cat);
            localStorage.setItem('tendo_current_brand', brand);
            localStorage.setItem('tendo_current_subcat', subCat || 'null');

            document.getElementById('cat-title-text').innerText = subCat ? subCat : brand;
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
                    ? '<span style="background:#fee2e2; color:#b91c1c; font-size:9px; padding:2px 6px; border-radius:4px; font-weight:800; border:1px solid #fca5a5; flex-shrink:0; margin-left:8px;">GANGGUAN</span>' 
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
            document.getElementById('product-list').innerHTML = listHTML || '<div style="text-align:center; padding:30px; font-weight:bold; color:var(--text-muted);">KOSONG</div>';
            showScreen('produk-screen', 'nav-home');
        }
        function loadProducts(cat, brand, subCat = null) { pushState({screen: 'produk-screen', cat: cat, brand: brand, subcat: subCat}); loadProductsInternal(cat, brand, subCat); }

        function openOrderModal(sku, nama, harga, desc) {
            selectedSKU = sku;
            document.getElementById('m-name').innerText = nama;
            document.getElementById('m-price').innerText = 'Rp ' + harga.toLocaleString('id-ID');
            document.getElementById('m-desc').innerText = desc || 'Proses Otomatis';
            document.getElementById('m-target').value = '';
            document.getElementById('m-payment-method').value = 'saldo';
            document.getElementById('order-modal').classList.remove('hidden');
        }
        function closeOrderModal() { document.getElementById('order-modal').classList.add('hidden'); }
        function closeOrderSuccessModal() { 
            document.getElementById('order-success-modal').classList.add('hidden'); 
            showHistory('Order');
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
                    syncUserData();
                    
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
    </script>
</body>
</html>
EOF
}
# Selesai Part 1
# ==========================================
# 4. FUNGSI UNTUK MEMBUAT FILE INDEX.JS (BACKEND)
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
const TelegramBot = require('node-telegram-bot-api');

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
const globalStatsFile = './global_stats.json';
const topupFile = './topup.json';
const globalTrxFile = './global_trx.json'; // File log transaksi untuk website

const loadJSON = (file) => crypt.load(file, (file === notifFile || file === globalTrxFile) ? [] : {});
const saveJSON = (file, data) => crypt.save(file, data);

const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd).digest('hex');

// ==============================================================
// FITUR: SAMARKAN DATA PRIBADI (MASKING)
// ==============================================================
function maskString(str) {
    if (!str) return '-';
    let s = str.toString().trim();
    if (s.length < 6) return s.substring(0, 2) + '***';
    return s.substring(0, 4) + '***' + s.substring(s.length - 3);
}

// ==============================================================
// FITUR: CEK PEMELIHARAAN SISTEM (23:00 - 00:30 WIB)
// ==============================================================
function cekPemeliharaan() {
    let d = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Jakarta"}));
    let h = d.getHours();
    let m = d.getMinutes();
    if (h === 23 || (h === 0 && m <= 30)) {
        return true;
    }
    return false;
}

// ==============================================================
// FITUR: NOTIFIKASI TELEGRAM ADMIN (Bot Notifikasi Utama)
// ==============================================================
function sendTelegramAdmin(message) {
    try {
        let cfg = loadJSON(configFile);
        if (cfg.teleToken && cfg.teleChatId) {
            axios.post(`https://api.telegram.org/bot${cfg.teleToken}/sendMessage`, {
                chat_id: cfg.teleChatId,
                text: message,
                parse_mode: 'Markdown'
            }).catch(e => {});
        }
    } catch(e) {}
}

// ==============================================================
// FITUR: NOTIFIKASI PEMBELIAN SUKSES GLOBAL (TELEGRAM CHANNEL)
// ==============================================================
function sendTelegramChannelSuccess(productName, rawUser, rawTarget) {
    try {
        let cfg = loadJSON(configFile);
        if (cfg.teleTokenInfo && cfg.teleChannelId) {
            let maskUser = maskString(rawUser);
            let maskTarget = maskString(rawTarget);
            let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
            
            let msg = `✅ *PEMBELIAN BERHASIL*\n\n👤 Pelanggan: ${maskUser}\n📦 Layanan: ${productName}\n🎯 Tujuan: ${maskTarget}\n🕒 Waktu: ${timeStr} WIB\n\n_🌐 Transaksi diproses otomatis oleh sistem._`;
            
            axios.post(`https://api.telegram.org/bot${cfg.teleTokenInfo}/sendMessage`, {
                chat_id: cfg.teleChannelId,
                text: msg,
                parse_mode: 'Markdown'
            }).catch(e => {});
        }
    } catch(e) {}
}

// ==============================================================
// FUNGSI KONVERSI QRIS SMART PARSER
// ==============================================================
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

let configAwal = loadJSON(configFile);
configAwal.botName = configAwal.botName || "Digital Tendo Store";
configAwal.botNumber = configAwal.botNumber || "";
configAwal.gopayToken = configAwal.gopayToken || "";
configAwal.gopayMerchantId = configAwal.gopayMerchantId || "";
configAwal.qrisUrl = configAwal.qrisUrl || "https://upload.wikimedia.org/wikipedia/commons/d/d0/QR_code_for_mobile_English_Wikipedia.svg";
configAwal.qrisText = configAwal.qrisText || "";
configAwal.teleTokenInfo = configAwal.teleTokenInfo || ""; 
configAwal.margin = configAwal.margin || { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
saveJSON(configFile, configAwal);

loadJSON(dbFile); loadJSON(produkFile); loadJSON(trxFile); loadJSON(globalStatsFile); loadJSON(topupFile); loadJSON(notifFile); loadJSON(globalTrxFile);

let globalSock = null;
let tempOtpDB = {}; 
let otpCooldown = {}; 

// TELEGRAM BOT POLLING UNTUK BROADCAST INFO PENGUMUMAN
let teleBotInfo = null;
if (configAwal.teleTokenInfo) {
    try {
        teleBotInfo = new TelegramBot(configAwal.teleTokenInfo, {polling: true});
        teleBotInfo.on('message', async (msg) => {
            let cfg = loadJSON(configFile);
            if (!cfg.teleChatId || msg.chat.id.toString() !== cfg.teleChatId.toString()) return;
            
            let text = msg.text || msg.caption || '';
            if (text.startsWith('/info ')) {
                text = text.replace('/info ', '');
                let imageFilename = null;
                
                if (msg.photo) {
                    try {
                        let fileId = msg.photo[msg.photo.length - 1].file_id;
                        let file = await teleBotInfo.getFile(fileId);
                        let url = `https://api.telegram.org/file/bot${cfg.teleTokenInfo}/${file.file_path}`;
                        let ext = file.file_path.split('.').pop() || 'jpg';
                        imageFilename = 'info_' + Date.now() + '.' + ext;
                        let res = await axios.get(url, { responseType: 'stream' });
                        const writer = fs.createWriteStream('./public/info_images/' + imageFilename);
                        res.data.pipe(writer);
                        await new Promise((resolve) => writer.on('finish', resolve));
                    } catch(e) { console.log('Gagal download gambar tele info', e); }
                }
                
                let notifs = loadJSON(notifFile);
                let today = new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'long', year:'numeric' });
                notifs.unshift({ date: today, text: text, image: imageFilename || '' });
                if(notifs.length > 20) notifs.pop();
                saveJSON(notifFile, notifs);

                if (cfg.teleChannelId) {
                    if (imageFilename) teleBotInfo.sendPhoto(cfg.teleChannelId, './public/info_images/' + imageFilename, {caption: text}).catch(e=>{});
                    else teleBotInfo.sendMessage(cfg.teleChannelId, text).catch(e=>{});
                }
                teleBotInfo.sendMessage(cfg.teleChatId, '✅ Info berhasil disebarkan ke Website & Telegram Channel!').catch(e=>{});
            }
        });
    } catch(e) { console.log("Gagal inisialisasi Telegram Bot Info Polling"); }
}

function normalizePhone(phoneStr) {
    if(!phoneStr) return '';
    let num = phoneStr.replace(/[^0-9]/g, '');
    if(num.startsWith('0')) return '62' + num.substring(1);
    return num;
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
        let gStats = loadJSON(globalStatsFile);
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
        res.json({ success: true, daily, weekly, monthly, total });
    } catch(e) { res.json({ success: false, daily: 0, weekly: 0, monthly: 0, total: 0 }); }
});

app.get('/api/produk', (req, res) => { res.json(loadJSON(produkFile)); });
app.get('/api/notif', (req, res) => { res.json(loadJSON(notifFile) || []); });
app.get('/api/global-trx', (req, res) => { res.json(loadJSON(globalTrxFile) || []); });

app.get('/api/user/:phone', (req, res) => {
    try {
        let db = loadJSON(dbFile); let p = req.params.phone;
        if(db[p]) {
            let safeData = { ...db[p] }; delete safeData.password; 
            res.json({success: true, data: safeData});
        } else res.json({success: false});
    } catch(e) { res.json({success: false}); }
});

app.post('/api/login', (req, res) => {
    try {
        let { email, password } = req.body; let db = loadJSON(dbFile);
        let hashedInput = hashPassword(password);
        
        let userPhone = Object.keys(db).find(k => {
            if (!db[k] || db[k].email !== email) return false;
            if (db[k].password === password) {
                db[k].password = hashedInput; saveJSON(dbFile, db); return true;
            }
            if (db[k].password === hashedInput) return true;
            return false;
        });

        if (userPhone) {
            let safeData = { ...db[userPhone] }; delete safeData.password;
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
        
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        otpCooldown[phone] = Date.now();
        
        let db = loadJSON(dbFile);
        let isEmailExist = Object.keys(db).some(k => db[k] && db[k].email === email);
        if (isEmailExist) return res.json({success: false, message: 'Email terdaftar!'});

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone] = { username, email, password: hashPassword(password), otp };

        res.json({success: true});

        setTimeout(() => {
            try {
                if (globalSock) {
                    let msg = `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nHai ${username},\nKode OTP Pendaftaran: *${otp}*\n\n_⚠️ Jangan bagikan kode ini!_`;
                    globalSock.sendMessage(phone + '@s.whatsapp.net', { text: msg }).catch(e=>{});
                }
            } catch(err) {}
        }, 100);

    } catch(e) { if (!res.headersSent) res.json({success: false, message: 'Gagal memproses pendaftaran.'}); }
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
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        otpCooldown[phone] = Date.now();

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        if (type === 'password') newValue = hashPassword(newValue);
        tempOtpDB[phone + '_edit'] = { type, newValue, otp };
        res.json({success: true});

        setTimeout(() => {
            if (globalSock) globalSock.sendMessage(phone + '@s.whatsapp.net', { text: `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nKode OTP perubahan data: *${otp}*\n\n_⚠️ Jangan berikan ke siapapun!_` }).catch(e=>{});
        }, 100);
    } catch(e) { if (!res.headersSent) res.json({success: false, message: 'Gagal memproses OTP.'}); }
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

app.post('/api/req-forgot-otp', (req, res) => {
    try {
        let phone = normalizePhone(req.body.phone); let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: 'Nomor WA tidak terdaftar!'});
        if(otpCooldown[phone] && Date.now() - otpCooldown[phone] < 60000) return res.json({success: false, message: 'Tunggu 1 menit untuk request OTP lagi!'});
        otpCooldown[phone] = Date.now();

        let otp = Math.floor(1000 + Math.random() * 9000).toString();
        tempOtpDB[phone + '_forgot'] = { otp };
        res.json({success: true});

        setTimeout(() => {
            if (globalSock) globalSock.sendMessage(phone + '@s.whatsapp.net', { text: `*🛡️ DIGITAL TENDO STORE 🛡️*\n\nPermintaan Reset Password.\nKode OTP: *${otp}*\n\n_⚠️ Abaikan jika bukan Anda!_` }).catch(e=>{});
        }, 100);
    } catch(e) { if (!res.headersSent) res.json({success: false, message: 'Gagal memproses OTP.'}); }
});

app.post('/api/verify-forgot-otp', (req, res) => {
    try {
        let phone = normalizePhone(req.body.phone); let { otp, newPass } = req.body; let db = loadJSON(dbFile);
        let session = tempOtpDB[phone + '_forgot'];
        if(session && session.otp === otp) {
            if(db[phone]) { db[phone].password = hashPassword(newPass); saveJSON(dbFile, db); }
            delete tempOtpDB[phone + '_forgot']; res.json({success: true});
        } else res.json({success: false, message: 'Kode OTP Salah!'});
    } catch(e) { res.json({success: false, message: 'Server error'}); }
});

app.post('/api/topup', async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan (23:00-00:30 WIB).'});
        
        let config = loadJSON(configFile);
        if(!config.gopayToken || (!config.qrisUrl && !config.qrisText)) return res.json({success: false, message: "Sistem QRIS belum diatur Admin."});
        
        let { phone, nominal } = req.body; let db = loadJSON(dbFile);
        if(!db[phone]) return res.json({success: false, message: "User tidak ditemukan."});
        
        let nominalAsli = parseInt(nominal);
        let uniqueCode = Math.floor(Math.random() * 99) + 1;
        let totalPay = nominalAsli + uniqueCode;

        let finalQrisUrl = config.qrisUrl;
        if (config.qrisText) {
            let dynQris = convertToDynamicQris(config.qrisText, totalPay);
            finalQrisUrl = "https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=15&format=jpeg&data=" + encodeURIComponent(dynQris);
        }

        let topups = loadJSON(topupFile);
        let trxId = "TP-" + Date.now();
        let expiredAt = Date.now() + 10 * 60 * 1000;

        topups[trxId] = { phone, trx_id: trxId, amount_to_pay: totalPay, saldo_to_add: totalPay, status: 'pending', timestamp: Date.now(), expired_at: expiredAt, is_order: false };
        saveJSON(topupFile, topups);

        db[phone].history = db[phone].history || [];
        db[phone].history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Topup', nama: 'Topup Saldo QRIS', tujuan: 'Sistem Pembayaran', status: 'Pending', sn: trxId, amount: totalPay, qris_url: finalQrisUrl, expired_at: expiredAt
        });
        if(db[phone].history.length > 20) db[phone].history.pop();
        saveJSON(dbFile, db);

        res.json({success: true});

        let teleMsg = `⏳ *TOPUP PENDING (QRIS)*\n\n👤 Akun: ${db[phone].username || phone}\n💰 Tagihan: Rp ${totalPay.toLocaleString('id-ID')}\n🔖 Ref: ${trxId}`;
        sendTelegramAdmin(teleMsg);
    } catch(e) { res.json({success: false, message: "Gagal memproses QRIS."}); }
});

app.post('/api/order-qris', async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan (23:00-00:30 WIB).'});
        
        let config = loadJSON(configFile);
        if(!config.gopayToken || (!config.qrisUrl && !config.qrisText)) return res.json({success: false, message: "Sistem QRIS belum diatur Admin."});
        
        let { phone, sku, tujuan } = req.body; let pNorm = normalizePhone(phone);
        let db = loadJSON(dbFile); let produkDB = loadJSON(produkFile);
        let targetKey = db[pNorm] ? pNorm : (db[phone] ? phone : null);
        if (!targetKey) return res.json({success: false, message: 'Sesi Anda tidak valid.'});
        
        let p = produkDB[sku];
        if (!p) return res.json({success: false, message: 'Produk tidak ditemukan.'});
        
        let nominalAsli = parseInt(p.harga);
        let uniqueCode = Math.floor(Math.random() * 50) + 1; 
        let totalPay = nominalAsli + uniqueCode;

        let finalQrisUrl = config.qrisUrl;
        if (config.qrisText) {
            let dynQris = convertToDynamicQris(config.qrisText, totalPay);
            finalQrisUrl = "https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=15&format=jpeg&data=" + encodeURIComponent(dynQris);
        }

        let topups = loadJSON(topupFile);
        let trxId = "OQ-" + Date.now();
        let expiredAt = Date.now() + 10 * 60 * 1000;

        topups[trxId] = { phone: targetKey, trx_id: trxId, amount_to_pay: totalPay, saldo_to_add: totalPay, status: 'pending', timestamp: Date.now(), expired_at: expiredAt, is_order: true, sku: sku, tujuan: tujuan, nama_produk: p.nama, harga_asli: nominalAsli };
        saveJSON(topupFile, topups);

        db[targetKey].history = db[targetKey].history || [];
        db[targetKey].history.unshift({ 
            ts: Date.now(), 
            tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), 
            type: 'Order QRIS', nama: p.nama + ' (QRIS)', tujuan: tujuan, status: 'Pending', sn: trxId, amount: totalPay, qris_url: finalQrisUrl, expired_at: expiredAt
        });
        if(db[targetKey].history.length > 20) db[targetKey].history.pop();
        saveJSON(dbFile, db);

        res.json({success: true});
        
        let teleMsg = `🛒 *ORDER QRIS PENDING*\n\n👤 Akun: ${db[targetKey].username || targetKey}\n📦 Produk: ${p.nama}\n🎯 Tujuan: ${tujuan}\n💰 Tagihan: Rp ${totalPay.toLocaleString('id-ID')}\n🔖 Ref: ${trxId}`;
        sendTelegramAdmin(teleMsg);
    } catch(e) { res.json({success: false, message: "Gagal memproses QRIS."}); }
});

app.post('/api/order', async (req, res) => {
    try {
        if(cekPemeliharaan()) return res.json({success: false, message: 'Sistem sedang pemeliharaan (23:00-00:30 WIB).'});
        
        let { phone, sku, tujuan } = req.body; let pNorm = normalizePhone(phone);
        let db = loadJSON(dbFile); let produkDB = loadJSON(produkFile); let config = loadJSON(configFile);
        
        let targetKey = db[pNorm] ? pNorm : (db[phone] ? phone : null);
        if (!targetKey) return res.json({success: false, message: 'Sesi Anda tidak valid. Silakan Logout dan Login kembali.'});
        
        let p = produkDB[sku];
        if (!p) return res.json({success: false, message: 'Produk tidak ditemukan.'});
        
        let hargaFix = parseInt(p.harga);
        if (parseInt(db[targetKey].saldo) < hargaFix) return res.json({success: false, message: 'Saldo tidak cukup.'});

        let username = (config.digiflazzUsername || '').trim();
        let apiKey = (config.digiflazzApiKey || '').trim();
        let refId = 'WEB-' + Date.now();
        let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

        const response = await axios.post('https://api.digiflazz.com/v1/transaction', { 
            username: username, buyer_sku_code: sku, customer_no: tujuan, ref_id: refId, sign: sign, max_price: hargaFix
        });
        
        const statusOrder = response.data.data.status; 
        if (statusOrder === 'Gagal') return res.json({success: false, message: response.data.data.message});
        
        db[targetKey].saldo = parseInt(db[targetKey].saldo) - hargaFix; 
        db[targetKey].trx_count = (db[targetKey].trx_count || 0) + 1;
        
        db[targetKey].history = db[targetKey].history || [];
        db[targetKey].history.unshift({ ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Order', nama: p.nama, tujuan: tujuan, status: statusOrder, sn: response.data.data.sn || '-', amount: hargaFix, ref_id: refId });
        if(db[targetKey].history.length > 20) db[targetKey].history.pop();
        saveJSON(dbFile, db);
        
        let trxs = loadJSON(trxFile);
        let targetJid = db[targetKey].jid || targetKey + '@s.whatsapp.net';
        trxs[refId] = { jid: targetJid, sku: sku, tujuan: tujuan, harga: hargaFix, nama: p.nama, tanggal: Date.now(), phone: targetKey };
        saveJSON(trxFile, trxs);

        if (statusOrder === 'Sukses') {
            let gStats = loadJSON(globalStatsFile);
            let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
            gStats[dateKey] = (gStats[dateKey] || 0) + 1;
            saveJSON(globalStatsFile, gStats);

            let globalTrx = loadJSON(globalTrxFile);
            let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
            globalTrx.unshift({ time: timeStr, product: p.nama, user: maskString(db[targetKey].username || targetKey), target: maskString(tujuan) });
            if(globalTrx.length > 30) globalTrx.pop();
            saveJSON(globalTrxFile, globalTrx);

            sendTelegramChannelSuccess(p.nama, db[targetKey].username || targetKey, tujuan);
        }

        res.json({success: true, saldo: db[targetKey].saldo});

        let teleMsg = `🔔 *PESANAN BARU MASUK*\n\n👤 Akun: ${db[targetKey].username || targetKey}\n📦 Produk: ${p.nama}\n🎯 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status: *${statusOrder}*\n💰 Harga: Rp ${hargaFix.toLocaleString('id-ID')}`;
        sendTelegramAdmin(teleMsg);

        // WA NOTIF SUDAH DIHAPUS

    } catch (error) { if (!res.headersSent) return res.json({success: false, message: 'Gagal diproses Digiflazz (Nomor Tujuan Salah/Harga Berubah)'}); }
});

async function prosesAutoOrderQRIS(phone, sku, tujuan, nama_produk, harga_asli, refIdAsal) {
    try {
        let db = loadJSON(dbFile); let config = loadJSON(configFile);
        let hargaFix = parseInt(harga_asli);
        
        if (parseInt(db[phone].saldo) < hargaFix) return; 
        
        let username = (config.digiflazzUsername || '').trim();
        let apiKey = (config.digiflazzApiKey || '').trim();
        let refId = 'WEB-' + Date.now();
        let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

        const response = await axios.post('https://api.digiflazz.com/v1/transaction', { 
            username: username, buyer_sku_code: sku, customer_no: tujuan, ref_id: refId, sign: sign, max_price: hargaFix
        });
        
        const statusOrder = response.data.data.status; 
        if (statusOrder === 'Gagal') {
            sendTelegramAdmin(`⚠️ *INFO ORDER QRIS: GAGAL DIGIFLAZZ*\n\nRef: ${refIdAsal}\nStatus Digiflazz Gagal. Saldo utuh di akun pengguna.`);
            return;
        }
        
        db[phone].saldo = parseInt(db[phone].saldo) - hargaFix; 
        db[phone].trx_count = (db[phone].trx_count || 0) + 1;
        
        db[phone].history = db[phone].history || [];
        db[phone].history.unshift({ ts: Date.now(), tanggal: new Date().toLocaleDateString('id-ID', { timeZone: 'Asia/Jakarta', day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }), type: 'Order', nama: nama_produk, tujuan: tujuan, status: statusOrder, sn: response.data.data.sn || '-', amount: hargaFix, ref_id: refId });
        saveJSON(dbFile, db);
        
        let trxs = loadJSON(trxFile);
        let targetJid = db[phone].jid || phone + '@s.whatsapp.net';
        trxs[refId] = { jid: targetJid, sku: sku, tujuan: tujuan, harga: hargaFix, nama: nama_produk, tanggal: Date.now(), phone: phone };
        saveJSON(trxFile, trxs);

        if (statusOrder === 'Sukses') {
            let globalTrx = loadJSON(globalTrxFile);
            let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
            globalTrx.unshift({ time: timeStr, product: nama_produk, user: maskString(db[phone].username || phone), target: maskString(tujuan) });
            if(globalTrx.length > 30) globalTrx.pop();
            saveJSON(globalTrxFile, globalTrx);

            sendTelegramChannelSuccess(nama_produk, db[phone].username || phone, tujuan);
        }

        let teleMsg = `🚀 *AUTO ORDER QRIS BERHASIL DITEMBAK*\n\n👤 Akun: ${db[phone].username || phone}\n📦 Produk: ${nama_produk}\n🎯 Tujuan: ${tujuan}\n🔖 Ref: ${refId}\n⚙️ Status Awal: *${statusOrder}*`;
        sendTelegramAdmin(teleMsg);
        
        // WA NOTIF SUDAH DIHAPUS

    } catch(e) {}
}

function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    exec(`[ -d "/etc/letsencrypt" ] && sudo tar -czf ssl_backup.tar.gz -C / etc/letsencrypt 2>/dev/null; rm -f backup.zip && zip backup.zip config.json database.json trx.json produk.json global_stats.json topup.json web_notif.json global_trx.json ssl_backup.tar.gz 2>/dev/null`, (err) => {
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

    // INTERVAL POLING CEK MUTASI GOPAY MERCHANT BHM BIZ
    setInterval(async () => {
        try {
            let cfg = loadJSON(configFile); let topups = loadJSON(topupFile);
            let pendingKeys = Object.keys(topups).filter(k => topups[k].status === 'pending');
            if(pendingKeys.length === 0 || !cfg.gopayToken || !cfg.gopayMerchantId) return;

            const gopayRes = await axios.get('http://gopay.bhm.biz.id/api/transactions', 
                { headers: { 'Authorization': 'Bearer ' + cfg.gopayToken } }
            );
            
            let responseStr = JSON.stringify(gopayRes.data);
            let db = loadJSON(dbFile); let changedTp = false; let changedDb = false;

            for(let key of pendingKeys) {
                let req = topups[key];
                if (Date.now() > req.expired_at) {
                    req.status = 'gagal'; changedTp = true;
                    if(db[req.phone]) {
                        let hist = db[req.phone].history.find(h => h.sn === req.trx_id);
                        if(hist && hist.status === 'Pending') { hist.status = 'Gagal (Kedaluwarsa)'; changedDb = true; }
                        let tipe = req.is_order ? 'ORDER QRIS' : 'TOPUP';
                        let teleMsg = `❌ *${tipe} KEDALUWARSA*\n\n👤 Akun: ${db[req.phone].username || req.phone}\n💰 Tagihan: Rp ${req.amount_to_pay.toLocaleString('id-ID')}\n🔖 Ref: ${req.trx_id}`;
                        sendTelegramAdmin(teleMsg);
                    }
                } 
                else {
                    let amountStr = req.amount_to_pay.toString();
                    let isFound = responseStr.includes(`"${amountStr}"`) || responseStr.includes(`:${amountStr}`) || responseStr.includes(`"${amountStr}.00"`) || responseStr.includes(`:${amountStr}.00`);
                    if(isFound) {
                        req.status = 'sukses'; changedTp = true;
                        if(db[req.phone]) {
                            db[req.phone].saldo = parseInt(db[req.phone].saldo) + parseInt(req.saldo_to_add); 
                            let hist = db[req.phone].history.find(h => h.sn === req.trx_id);
                            if(hist && hist.status === 'Pending') hist.status = 'Sukses Bayar';
                            changedDb = true;
                            
                            if (req.is_order) {
                                prosesAutoOrderQRIS(req.phone, req.sku, req.tujuan, req.nama_produk, req.harga_asli, req.trx_id);
                            } else {
                                let teleMsg = `✅ *TOPUP QRIS SUKSES MASUK*\n\n👤 Akun: ${db[req.phone].username || req.phone}\n💰 Saldo Masuk: Rp ${req.saldo_to_add.toLocaleString('id-ID')}\n🔖 Ref: ${req.trx_id}`;
                                sendTelegramAdmin(teleMsg);
                            }
                            // WA NOTIF SUDAH DIHAPUS
                        }
                    }
                }
            }
            if(changedTp) saveJSON(topupFile, topups);
            if(changedDb) saveJSON(dbFile, db);
        } catch(e) {}
    }, 30000); 

    // DIGIFLAZZ ORDER STATUS CHECKER
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
                    let db = loadJSON(dbFile); let phoneKey = trx.phone || trx.jid.split('@')[0];
                    if(resData.status === 'Sukses') {
                        if (db[phoneKey] && db[phoneKey].history) {
                            let hist = db[phoneKey].history.find(h => h.ref_id === ref);
                            if (hist) { hist.status = 'Sukses'; hist.sn = resData.sn || '-'; saveJSON(dbFile, db); }
                        }
                        
                        let gStats = loadJSON(globalStatsFile);
                        let dateKey = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
                        gStats[dateKey] = (gStats[dateKey] || 0) + 1; saveJSON(globalStatsFile, gStats);
                        
                        let globalTrx = loadJSON(globalTrxFile);
                        let timeStr = new Date().toLocaleTimeString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
                        globalTrx.unshift({ time: timeStr, product: trx.nama, user: maskString(db[phoneKey]?.username || phoneKey), target: maskString(trx.tujuan) });
                        if(globalTrx.length > 30) globalTrx.pop();
                        saveJSON(globalTrxFile, globalTrx);

                        sendTelegramChannelSuccess(trx.nama, db[phoneKey]?.username || phoneKey, trx.tujuan);

                        let teleSuccess = `✅ *PESANAN SUKSES*\n\n👤 Akun: ${db[phoneKey]?.username || phoneKey}\n📦 Produk: ${trx.nama}\n🎯 Tujuan: ${trx.tujuan}\n🔖 Ref: ${ref}\n🔑 SN: ${resData.sn || '-'}`;
                        sendTelegramAdmin(teleSuccess);
                        
                    } else {
                        if (db[phoneKey]) { 
                            db[phoneKey].saldo = parseInt(db[phoneKey].saldo) + parseInt(trx.harga); 
                            if(db[phoneKey].history) {
                                let hist = db[phoneKey].history.find(h => h.ref_id === ref);
                                if (hist) hist.status = 'Gagal';
                            }
                            saveJSON(dbFile, db); 
                        }
                        
                        let teleFail = `❌ *PESANAN GAGAL*\n\n👤 Akun: ${db[phoneKey]?.username || phoneKey}\n📦 Produk: ${trx.nama}\n🎯 Tujuan: ${trx.tujuan}\n🔖 Ref: ${ref}\n📝 Alasan: ${resData.message}`;
                        sendTelegramAdmin(teleFail);
                    }
                    delete trxs[ref]; saveJSON(trxFile, trxs);
                    // WA NOTIF SUDAH DIHAPUS
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

// ==============================================================
// TUGAS SINKRONISASI DIGIFLAZZ (DIPERCEPAT MENJADI 10 MENIT SEKALI)
// ==============================================================
async function tarikDataLayananOtomatis() {
    try {
        let config = loadJSON(configFile);
        let namaPengguna = (config.digiflazzUsername || '').trim();
        let kunciAkses = (config.digiflazzApiKey || '').trim();
        if (!namaPengguna || !kunciAkses) return;

        let tandaPengenal = crypto.createHash('md5').update(namaPengguna + kunciAkses + 'depo').digest('hex');
        
        const balasan = await axios.post('https://api.digiflazz.com/v1/price-list', {
            cmd: 'prepaid',
            username: namaPengguna,
            sign: tandaPengenal
        });

        if (balasan.data && balasan.data.data) {
            let daftarPusat = balasan.data.data;
            let produkLama = loadJSON(produkFile);
            let daftarLokal = {};
            let m = config.margin || { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
            
            daftarPusat.forEach(item => {
                let kodeBarang = item.buyer_sku_code;
                let namaBarang = item.product_name;
                let hargaModal = item.price;
                
                let statusProduk = (item.buyer_product_status === true && item.seller_product_status === true);
                let catDigi = (item.category || '').trim();
                let catLower = catDigi.toLowerCase();
                let kategoriBarang = 'Lainnya';
                
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

                // PROTEKSI AGAR KATEGORI HASIL TAMBAH MANUAL TIDAK TERTABRAK OLEH SINKRONISASI
                if (produkLama[kodeBarang] && produkLama[kodeBarang].is_manual_cat) {
                    kategoriBarang = produkLama[kodeBarang].kategori;
                    namaBarang = produkLama[kodeBarang].nama || namaBarang;
                    item.brand = produkLama[kodeBarang].brand || item.brand;
                    item.type = produkLama[kodeBarang].sub_kategori || item.type;
                    item.desc = produkLama[kodeBarang].deskripsi || item.desc;
                }
                
                let merekBarang = item.brand || 'Lainnya';
                let subKategori = item.type || 'Umum';

                // PERHITUNGAN KEUNTUNGAN 13 TINGKAT
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

                daftarLokal[kodeBarang] = {
                    nama: namaBarang,
                    harga: hargaModal + keuntungan,
                    kategori: kategoriBarang,
                    brand: merekBarang,
                    sub_kategori: subKategori,
                    deskripsi: item.desc || 'Proses Otomatis',
                    status_produk: statusProduk,
                    is_manual_cat: (produkLama[kodeBarang] ? produkLama[kodeBarang].is_manual_cat : false)
                };
            });

            saveJSON(produkFile, daftarLokal);
            console.log('\x1b[32m✅ Data Produk Digiflazz Berhasil Tersinkronisasi!\x1b[0m');
        }
    } catch(err) { console.log('\x1b[31m❌ Gagal Sinkronisasi Digiflazz.\x1b[0m', err.message); }
}

app.get('/api/sync-digiflazz', async (req, res) => {
    await tarikDataLayananOtomatis();
    res.json({success: true, message: 'Sinkronisasi Selesai.'});
});

setInterval(tarikDataLayananOtomatis, 10 * 60 * 1000);
setTimeout(tarikDataLayananOtomatis, 10000);

if (require.main === module) {
    app.listen(3000, '0.0.0.0', () => { console.log('\x1b[32m🌐 SERVER WEB AKTIF (PORT 3000).\x1b[0m'); });
    startBot().catch(err => {});
}
EOF
}
# ==========================================
# 4.5. SCRIPT CEK SALDO DIGIFLAZZ (UNTUK TERMINAL)
# ==========================================
generate_cek_saldo_script() {
    cat << 'EOF' > cek_saldo.js
const crypto = require('crypto');
const axios = require('axios');
const crypt = require('./tendo_crypt.js');

async function getSaldo() {
    try {
        let config = crypt.load('config.json');
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
    generate_cek_saldo_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Mengunduh modul utama...${C_RST}"
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser node-telegram-bot-api > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD}                 ✅ INSTALASI SELESAI!                ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    read -p "Tekan Enter untuk kembali..."
}

# ==========================================
# 6. SUB-MENU MANAJEMEN MEMBER
# ==========================================
menu_member() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             👥 MANAJEMEN MEMBER BOT 👥             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Saldo Member"
        echo -e "  ${C_GREEN}[2]${C_RST} Kurangi Saldo Member"
        echo -e "  ${C_GREEN}[3]${C_RST} Lihat Daftar Semua Member Aktif"
        echo -e "  ${C_GREEN}[4]${C_RST} Cek Riwayat Topup Member"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-4]: ${C_RST}"
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
                    db[target].saldo = parseInt(db[target].saldo) + parseInt('$jumlah');
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
                        db[target].saldo = parseInt(db[target].saldo) - parseInt('$jumlah');
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
                    let deletedCount = 0;
                    
                    // Filter & hapus member tanpa email
                    members.forEach(m => {
                        if (!db[m].email || db[m].email.trim() === '-' || db[m].email.trim() === '') {
                            delete db[m];
                            deletedCount++;
                        }
                    });
                    if (deletedCount > 0) crypt.save('database.json', db);
                    
                    members = Object.keys(db); 
                    members.sort((a, b) => (db[b].saldo || 0) - (db[a].saldo || 0)); 
                    
                    if(members.length === 0) console.log('\x1b[33mBelum ada member aktif (yang terdaftar email).\x1b[0m');
                    else {
                        members.forEach((m, i) => console.log((i + 1) + '. WA: ' + m + ' | Email: ' + db[m].email + ' | Saldo: Rp ' + db[m].saldo.toLocaleString('id-ID')));
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            4)
                echo -e "\n${C_CYAN}--- RIWAYAT TOPUP MEMBER ---${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let db = crypt.load('database.json');
                    let members = Object.keys(db).filter(m => db[m].email && db[m].email.trim() !== '-' && db[m].email.trim() !== '');
                    if(members.length === 0) {
                        console.log('\x1b[33mBelum ada member yang memiliki email.\x1b[0m');
                        process.exit(0);
                    }
                    members.forEach((m, i) => console.log((i + 1) + '. WA: ' + m + ' | Email: ' + db[m].email));
                "
                read -p "Pilih Nomor Urut Member [Contoh: 1]: " urut_member
                if [[ "$urut_member" =~ ^[0-9]+$ ]]; then
                    node -e "
                        const crypt = require('./tendo_crypt.js');
                        let db = crypt.load('database.json');
                        let members = Object.keys(db).filter(m => db[m].email && db[m].email.trim() !== '-' && db[m].email.trim() !== '');
                        let idx = parseInt('$urut_member') - 1;
                        if(idx >= 0 && idx < members.length) {
                            let target = members[idx];
                            let history = db[target].history || [];
                            let targetSaldo = db[target].saldo || 0;
                            let topups = history.filter(h => h.type === 'Topup' || h.type === 'Order QRIS');
                            console.log('\n\x1b[36m=== RIWAYAT TOPUP: ' + target + ' ===\x1b[0m');
                            console.log('\x1b[32m💰 Saldo Saat Ini: Rp ' + targetSaldo.toLocaleString('id-ID') + '\x1b[0m');
                            if(topups.length === 0) console.log('\x1b[33mBelum ada riwayat topup di akun ini.\x1b[0m');
                            else {
                                topups.forEach(h => console.log('- \x1b[33m' + h.tanggal + '\x1b[0m | ' + h.nama + ' | \x1b[32mRp ' + h.amount.toLocaleString('id-ID') + '\x1b[0m | Status: ' + h.status));
                            }
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

# ==========================================
# 7. MANAJEMEN KEUNTUNGAN FLEKSIBEL (13 TINGKAT DENGAN PILIHAN)
# ==========================================
menu_keuntungan() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             💰 MANAJEMEN KEUNTUNGAN 💰             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        
        node -e "
            const crypt = require('./tendo_crypt.js');
            let c = crypt.load('config.json').margin || {};
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
            
            node -e "
                const crypt = require('./tendo_crypt.js');
                let config = crypt.load('config.json');
                if(!config.margin) config.margin = { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
                let tier = 't' + $k_choice;
                config.margin[tier] = parseInt('$nominal_baru');
                crypt.save('config.json', config);
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

# ==========================================
# 8. SINKRONISASI MANUAL DIGIFLAZZ
# ==========================================
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

# ==========================================
# 9. SUB-MENU AUTO-BACKUP
# ==========================================
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
# 10. SUB-MENU BACKUP & RESTORE
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
                if [ -d "/etc/letsencrypt" ]; then
                    sudo tar -czf ssl_backup.tar.gz -C / etc/letsencrypt 2>/dev/null
                fi
                zip backup.zip config.json database.json trx.json produk.json global_stats.json topup.json web_notif.json global_trx.json ssl_backup.tar.gz 2>/dev/null
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
# 11. SUB-MENU MANAJEMEN PRODUK MANUAL
# ==========================================
menu_manajemen_produk_manual() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}          📦 MANAJEMEN PRODUK MANUAL 📦             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah Produk Instan (Kode Digiflazz)"
        echo -e "  ${C_GREEN}[2]${C_RST} Lihat Daftar & Hapus Produk Manual"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read mp_choice

        case $mp_choice in
            1)
                clear
                echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
                echo -e "${C_YELLOW}${C_BOLD}         ➕ TAMBAH PRODUK INSTAN DIGIFLAZZ ➕         ${C_RST}"
                echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
                echo -e "Pilih Kategori untuk produk yang akan ditambahkan:"
                echo -e "  ${C_GREEN}[1]${C_RST} Pulsa"
                echo -e "  ${C_GREEN}[2]${C_RST} Data"
                echo -e "  ${C_GREEN}[3]${C_RST} Game"
                echo -e "  ${C_GREEN}[4]${C_RST} Voucher"
                echo -e "  ${C_GREEN}[5]${C_RST} E-Money"
                echo -e "  ${C_GREEN}[6]${C_RST} PLN"
                echo -e "  ${C_GREEN}[7]${C_RST} Paket SMS & Telpon"
                echo -e "  ${C_GREEN}[8]${C_RST} Masa Aktif"
                echo -e "  ${C_GREEN}[9]${C_RST} Aktivasi Perdana"
                echo -e "  ${C_GREEN}[10]${C_RST} Custom (Buat Kategori Sendiri)"
                echo -ne "\n${C_YELLOW}Pilih kategori [1-10]: ${C_RST}"
                read kat_idx
                
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
                    10) 
                        read -p "Masukkan Nama Kategori Custom: " kat_custom
                        if [ -z "$kat_custom" ]; then
                            echo -e "${C_RED}❌ Kategori tidak boleh kosong.${C_RST}"; sleep 1; continue
                        fi
                        kat_nama="$kat_custom"
                        ;;
                    *) echo -e "${C_RED}❌ Pilihan kategori tidak valid.${C_RST}"; sleep 1; continue ;;
                esac
                
                read -p "Masukkan KODE SKU Digiflazz: " sku_digi
                if [ -z "$sku_digi" ]; then 
                    echo -e "${C_RED}❌ Kode SKU tidak boleh kosong.${C_RST}"; sleep 1; continue
                fi
                
                read -p "Masukkan Nama Produk (Kosongkan utk pakai nama Asli): " custom_nama
                read -p "Masukkan Brand / Operator (Misal: Telkomsel / Free Fire): " custom_brand
                read -p "Masukkan Tipe (Misal: Umum / Data Promo): " custom_tipe
                read -p "Masukkan Deskripsi Produk (Kosongkan utk pakai 'Proses Otomatis'): " custom_desc
                
                echo -e "\n${C_MAG}⏳ Menghubungkan ke API Digiflazz untuk menarik data harga dan status...${C_RST}"
                node -e "
                    const axios = require('axios');
                    const crypto = require('crypto');
                    const crypt = require('./tendo_crypt.js');
                    
                    async function addManual() {
                        try {
                            let config = crypt.load('config.json');
                            let username = (config.digiflazzUsername || '').trim();
                            let key = (config.digiflazzApiKey || '').trim();
                            if(!username || !key) return console.log('\x1b[31m❌ API Digiflazz belum diatur.\x1b[0m');
                            
                            let sign = crypto.createHash('md5').update(username + key + 'depo').digest('hex');
                            let res = await axios.post('https://api.digiflazz.com/v1/price-list', { cmd: 'prepaid', username, sign });
                            
                            let items = res.data.data || [];
                            let sku = '$sku_digi'.trim();
                            let found = items.find(i => i.buyer_sku_code === sku);
                            
                            if(!found) {
                                return console.log('\x1b[31m❌ GAGAL: Kode SKU \"' + sku + '\" tidak ditemukan di daftar harga Digiflazz Anda.\x1b[0m');
                            }
                            
                            let m = config.margin || { t1:50, t2:100, t3:250, t4:500, t5:1000, t6:1500, t7:2000, t8:2500, t9:3000, t10:4000, t11:5000, t12:7500, t13:10000 };
                            let hargaModal = found.price;
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

                            let customNama = '$custom_nama'.trim();
                            let customBrand = '$custom_brand'.trim();
                            let customTipe = '$custom_tipe'.trim();
                            let customDesc = '$custom_desc'.trim();

                            let finalNama = customNama !== '' ? customNama : found.product_name;
                            let finalBrand = customBrand !== '' ? customBrand : (found.brand || 'Lainnya');
                            let finalTipe = customTipe !== '' ? customTipe : (found.type || 'Umum');
                            let finalDesc = customDesc !== '' ? customDesc : (found.desc || 'Proses Otomatis');

                            let dbProd = crypt.load('produk.json');
                            dbProd[sku] = {
                                nama: finalNama,
                                harga: hargaModal + keuntungan,
                                kategori: '$kat_nama',
                                brand: finalBrand,
                                sub_kategori: finalTipe,
                                deskripsi: finalDesc,
                                status_produk: (found.buyer_product_status && found.seller_product_status),
                                is_manual_cat: true
                            };
                            
                            crypt.save('produk.json', dbProd);
                            console.log('\x1b[32m✅ BERHASIL: Produk \"' + finalNama + '\" (' + sku + ') telah ditambahkan secara manual dan terintegrasi!\x1b[0m');
                        } catch(e) {
                            console.log('\x1b[31m❌ Gagal menghubungi server Digiflazz. Periksa koneksi internet.\x1b[0m');
                        }
                    }
                    addManual();
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK MANUAL ---${C_RST}"
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let dbProd = crypt.load('produk.json');
                    let manualItems = Object.keys(dbProd).filter(k => dbProd[k].is_manual_cat);
                    if(manualItems.length === 0) {
                        console.log('\x1b[33mBelum ada produk yang ditambahkan secara manual.\x1b[0m');
                        process.exit(0);
                    }
                    manualItems.forEach((sku, i) => {
                        console.log('[' + (i + 1) + '] SKU: ' + sku + ' | Nama: ' + dbProd[sku].nama + ' | Kat: ' + dbProd[sku].kategori + ' | Brand: ' + dbProd[sku].brand);
                    });
                "
                echo -e ""
                read -p "Masukkan Nomor Urut produk yang ingin dihapus (Kosongkan/Ketik 0 untuk batal): " urut_hapus
                if [[ "$urut_hapus" =~ ^[0-9]+$ ]] && [ "$urut_hapus" -gt 0 ]; then
                    node -e "
                        const crypt = require('./tendo_crypt.js');
                        let dbProd = crypt.load('produk.json');
                        let manualItems = Object.keys(dbProd).filter(k => dbProd[k].is_manual_cat);
                        let idx = parseInt('$urut_hapus') - 1;
                        if(idx >= 0 && idx < manualItems.length) {
                            let skuToDel = manualItems[idx];
                            let namaToDel = dbProd[skuToDel].nama;
                            delete dbProd[skuToDel];
                            crypt.save('produk.json', dbProd);
                            console.log('\x1b[32m✅ Berhasil menghapus produk manual: ' + namaToDel + ' (' + skuToDel + ')\x1b[0m');
                        } else {
                            console.log('\x1b[31m❌ Nomor urut tidak ditemukan.\x1b[0m');
                        }
                    "
                else
                    echo -e "${C_YELLOW}Dibatalkan.${C_RST}"
                fi
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 13. MENU INTEGRASI NOTIFIKASI
# ==========================================
menu_notifikasi() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}        📢 SETUP INTEGRASI NOTIFIKASI BROADCAST       ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Set API Telegram (Token Admin & Token Info/Web)"
        echo -e "  ${C_GREEN}[2]${C_RST} Set Channel Telegram ID (Untuk Info & Transaksi Global)"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read notif_choice

        case $notif_choice in
            1)
                echo -e "\n${C_MAG}--- SET API TELEGRAM ADMIN & INFO ---${C_RST}"
                read -p "Masukkan Token Bot Telegram (Untuk Notif Transaksi Admin): " token
                read -p "Masukkan Token Bot Telegram (Untuk Update Info Web & Notif Global): " token_info
                read -p "Masukkan Chat ID Admin Anda: " chatid
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let config = crypt.load('config.json');
                    if('$token' !== '') config.teleToken = '$token'.trim();
                    if('$token_info' !== '') config.teleTokenInfo = '$token_info'.trim();
                    if('$chatid' !== '') config.teleChatId = '$chatid'.trim();
                    crypt.save('config.json', config);
                    console.log('\x1b[32m\n✅ Data Telegram Admin & Info berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- SET CHANNEL TELEGRAM ---${C_RST}"
                echo -e "Pastikan Bot Telegram INFO sudah dimasukkan sebagai Admin di Channel."
                read -p "Masukkan ID Channel (Contoh: -100123456789): " chanid
                node -e "
                    const crypt = require('./tendo_crypt.js');
                    let config = crypt.load('config.json');
                    if('$chanid' !== '') config.teleChannelId = '$chanid'.trim();
                    crypt.save('config.json', config);
                    console.log('\x1b[32m\n✅ ID Channel Telegram berhasil disimpan!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 12. MENU UTAMA (PANEL KONTROL 15 OPSI)
# ==========================================
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
    echo -e "${C_MAG}▶ MANAJEMEN BOT & WEB APP${C_RST}"
    echo -e "  ${C_GREEN}[1]${C_RST}  Install & Perbarui Sistem (Wajib Jalankan Dulu)"
    echo -e "  ${C_GREEN}[2]${C_RST}  Mulai Sistem (Terminal / Scan QR)"
    echo -e "  ${C_GREEN}[3]${C_RST}  Jalankan Sistem di Latar Belakang (PM2)"
    echo -e "  ${C_GREEN}[4]${C_RST}  Hentikan Sistem (PM2)"
    echo -e "  ${C_GREEN}[5]${C_RST}  Lihat Log / Error"
    echo ""
    echo -e "${C_MAG}▶ MANAJEMEN TOKO & SISTEM${C_RST}"
    echo -e "  ${C_GREEN}[6]${C_RST}  👥 Manajemen Saldo & Member"
    echo -e "  ${C_GREEN}[7]${C_RST}  💰 Manajemen Keuntungan Harga (13 Tingkat)"
    echo -e "  ${C_GREEN}[8]${C_RST}  🔄 Sinkronisasi Produk Digiflazz (Perbarui Katalog)"
    echo -e "  ${C_GREEN}[9]${C_RST}  ⚙️ Pengaturan Auto-Backup Telegram"
    echo -e "  ${C_GREEN}[10]${C_RST} 💾 Backup & Restore Database"
    echo -e "  ${C_GREEN}[11]${C_RST} 🔌 Ganti API Digiflazz"
    echo -e "  ${C_GREEN}[12]${C_RST} 🔄 Ganti Akun WA Web OTP (Reset Sesi)"
    echo -e "  ${C_GREEN}[13]${C_RST} 📢 Setup Integrasi Notifikasi (Tele/Web)"
    echo -e "  ${C_GREEN}[14]${C_RST} 💳 Setup GoPay Merchant API (BHM Biz)"
    echo -e "  ${C_GREEN}[15]${C_RST} 🌍 Setup Domain & HTTPS (SSL)"
    echo -e "  ${C_GREEN}[16]${C_RST} 📦 Manajemen Produk Manual Instan"
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
                        config.botName = config.botName || 'Digital Tendo Store';
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
            echo -e "\n${C_GREEN}✅ Sistem dihentikan dan dibersihkan dari latar belakang.${C_RST}"
            sleep 2 ;;
        5) pm2 logs tendo-bot ;;
        6) menu_member ;;
        7) menu_keuntungan ;;
        8) menu_sinkron ;;
        9) menu_telegram ;;
        10) menu_backup ;;
        11)
            echo -e "\n${C_MAG}--- GANTI API DIGIFLAZZ ---${C_RST}"
            read -p "Username Digiflazz Baru: " user_api
            read -p "API Key Digiflazz Baru: " key_api
            node -e "
                const crypt = require('./tendo_crypt.js');
                let config = crypt.load('config.json');
                if('$user_api' !== '') config.digiflazzUsername = '$user_api'.trim();
                if('$key_api' !== '') config.digiflazzApiKey = '$key_api'.trim();
                crypt.save('config.json', config);
                console.log('\x1b[32m\n✅ Konfigurasi Digiflazz berhasil disimpan!\x1b[0m');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        12)
            echo -e "\n${C_RED}⚠️ Reset Sesi akan mengeluarkan sistem dari WhatsApp saat ini.${C_RST}"
            read -p "Yakin ingin mereset sesi? (y/n): " reset_sesi
            if [ "$reset_sesi" == "y" ]; then
                pm2 stop tendo-bot >/dev/null 2>&1
                rm -rf sesi_bot
                echo -e "${C_GREEN}✅ Sesi berhasil dihapus. Silakan jalankan sistem kembali untuk menautkan nomor baru.${C_RST}"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        13) menu_notifikasi ;;
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
            node -e "
                const crypt = require('./tendo_crypt.js'); let config = crypt.load('config.json');
                if ('$gopay_token' !== '') config.gopayToken = '$gopay_token'.trim();
                if ('$gopay_mid' !== '') config.gopayMerchantId = '$gopay_mid'.trim();
                if ('$qris_text' !== '') config.qrisText = '$qris_text'.trim();
                crypt.save('config.json', config);
                console.log('\x1b[32m\n✅ Konfigurasi GoPay BHM Biz & QRIS Dinamis berhasil disimpan!\x1b[0m');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        15)
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
        16) menu_manajemen_produk_manual ;;
        0) echo -e "${C_GREEN}Sampai jumpa!${C_RST}"; exit 0 ;;
        *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
    esac
done
