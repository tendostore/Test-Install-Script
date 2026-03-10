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

# Buka Port 3000 di VPS agar Web bisa diakses
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
# FUNGSI MEMBUAT TAMPILAN WEB APLIKASI (FRONTEND)
# ==========================================
generate_web_app() {
    echo -e "${C_CYAN}⏳ Meracik Tampilan Web App...${C_RST}"
    mkdir -p public
    cat << 'EOF' > public/index.html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Tendo Store App</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 0; display: flex; justify-content: center; }
        #app { width: 100%; max-width: 480px; background: #fafafa; min-height: 100vh; box-shadow: 0 0 20px rgba(0,0,0,0.05); position: relative; padding-bottom: 50px;}
        .header { background: linear-gradient(135deg, #0088cc, #005580); color: white; padding: 20px; text-align: center; font-size: 22px; font-weight: bold; border-bottom-left-radius: 20px; border-bottom-right-radius: 20px; box-shadow: 0 4px 15px rgba(0,136,204,0.2);}
        .container { padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.03); margin-bottom: 20px; border: 1px solid #f0f0f0;}
        .card-saldo { background: linear-gradient(135deg, #11998e, #38ef7d); color: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 15px rgba(17,153,142,0.3); margin-bottom: 25px;}
        .btn { background: #0088cc; color: white; border: none; padding: 15px; width: 100%; border-radius: 10px; font-size: 16px; font-weight: bold; cursor: pointer; transition: 0.2s;}
        .btn:active { transform: scale(0.98); }
        input { width: 100%; padding: 15px; margin-bottom: 15px; border: 1.5px solid #ddd; border-radius: 10px; box-sizing: border-box; font-size: 16px; outline: none;}
        input:focus { border-color: #0088cc; }
        .hidden { display: none; }
        .product-item { background: white; padding: 15px; border-radius: 12px; margin-bottom: 12px; border: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.02);}
        .product-info { flex: 1; }
        .product-name { font-weight: bold; font-size: 15px; color: #333; margin-bottom: 5px;}
        .product-cat { font-size: 11px; font-weight: bold; color: #fff; background: #888; padding: 3px 8px; border-radius: 5px; display: inline-block; letter-spacing: 0.5px;}
        .cat-pulsa { background: #ff9800; }
        .cat-data { background: #2196f3; }
        .cat-game { background: #9c27b0; }
        .product-price { color: #0088cc; font-weight: bold; font-size: 16px; white-space: nowrap;}
        .section-title { font-size: 18px; color: #444; margin-bottom: 15px; font-weight: 800; }
    </style>
</head>
<body>
    <div id="app">
        <div class="header">📱 Tendo Store App</div>
        <div class="container">
            
            <div id="login-screen">
                <div class="card" style="margin-top: 20px;">
                    <h2 style="margin-top:0; color: #333; text-align: center;">Masuk Member</h2>
                    <p style="font-size:14px; color:#666; text-align: center; margin-bottom: 25px;">Masukkan ID Member atau Nomor WhatsApp Anda yang terdaftar di sistem kami.</p>
                    <input type="number" id="phone-input" placeholder="Contoh: 628123456789">
                    <button class="btn" onclick="login()">Masuk ke Aplikasi</button>
                </div>
            </div>

            <div id="dashboard-screen" class="hidden">
                <div class="card-saldo">
                    <div style="font-size:14px; opacity: 0.9; margin-bottom: 5px;">Total Saldo Anda</div>
                    <h1 style="margin: 0; font-size: 32px;" id="user-saldo">Rp 0</h1>
                    <div style="font-size:13px; opacity: 0.8; margin-top: 10px; background: rgba(0,0,0,0.1); display: inline-block; padding: 4px 10px; border-radius: 20px;" id="user-id">ID: -</div>
                </div>
                
                <div class="section-title">🛒 Katalog Produk</div>
                <div id="product-list">
                    <div style="text-align:center; padding: 20px; color: #888;">Memuat data dari server...</div>
                </div>
            </div>
            
        </div>
    </div>

    <script>
        // FUNGSI LOGIN / CEK DATABASE
        async function login() {
            let phone = document.getElementById('phone-input').value.trim();
            if(!phone) return alert('Silakan masukkan nomor WhatsApp Anda!');
            
            let btn = document.querySelector('.btn');
            btn.innerText = 'Memeriksa...';
            btn.style.opacity = '0.7';
            
            try {
                let res = await fetch('/api/member', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({phone: phone})
                });
                let data = await res.json();
                
                if(data.success) {
                    document.getElementById('login-screen').classList.add('hidden');
                    document.getElementById('dashboard-screen').classList.remove('hidden');
                    document.getElementById('user-saldo').innerText = 'Rp ' + data.data.saldo.toLocaleString('id-ID');
                    document.getElementById('user-id').innerText = 'Member ID: ' + phone;
                    loadProducts(); // Panggil data harga
                } else {
                    alert('Nomor belum terdaftar! Silakan chat Bot WA Tendo Store terlebih dahulu agar nomor terdaftar otomatis.');
                    btn.innerText = 'Masuk ke Aplikasi';
                    btn.style.opacity = '1';
                }
            } catch(e) {
                alert('Gagal terhubung ke server.');
                btn.innerText = 'Masuk ke Aplikasi';
                btn.style.opacity = '1';
            }
        }

        // FUNGSI MENGAMBIL DATA PRODUK DARI VPS
        async function loadProducts() {
            try {
                let res = await fetch('/api/produk');
                let produk = await res.json();
                let listHTML = '';
                
                for(let key in produk) {
                    let p = produk[key];
                    let badgeClass = 'cat-pulsa';
                    if(p.kategori === 'Paket Data') badgeClass = 'cat-data';
                    if(p.kategori === 'Topup Game') badgeClass = 'cat-game';
                    
                    listHTML += `
                        <div class="product-item">
                            <div class="product-info">
                                <div class="product-name">${p.nama}</div>
                                <div class="product-cat ${badgeClass}">${p.kategori} - ${p.brand || 'Lainnya'}</div>
                            </div>
                            <div class="product-price">Rp ${p.harga.toLocaleString('id-ID')}</div>
                        </div>
                    `;
                }
                
                if(!listHTML) listHTML = '<div style="text-align:center; color:#888;">Produk sedang kosong</div>';
                document.getElementById('product-list').innerHTML = listHTML;
            } catch(e) {
                document.getElementById('product-list').innerHTML = '<div style="text-align:center; color:red;">Gagal memuat produk.</div>';
            }
        }
    </script>
</body>
</html>
EOF
}

# ==========================================
# 2. FUNGSI UNTUK MEMBUAT FILE INDEX.JS (BOT + API SERVER)
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
// 🌟 MENGAKTIFKAN FOLDER PUBLIC UNTUK WEB APP
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

// ==========================================
// 🚀 API ENDPOINT UNTUK WEB APP MENGAMBIL DATA
// ==========================================

// API Mengambil Katalog Produk
app.get('/api/produk', (req, res) => {
    let produk = loadJSON(produkFile);
    res.json(produk);
});

// API Cek Data Member (Login Web)
app.post('/api/member', (req, res) => {
    let db = loadJSON(dbFile);
    let phone = req.body.phone; 
    
    // Hapus karakter non-angka untuk keamanan
    if(phone) phone = phone.replace(/[^0-9]/g, '');
    
    if (db[phone]) {
        res.json({success: true, data: db[phone]});
    } else {
        res.json({success: false, message: "Nomor tidak terdaftar"});
    }
});


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
    console.log("\x1b[36m\n⏳ Sedang menyiapkan mesin bot...\x1b[0m");
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = loadJSON(configFile);
    
    console.log("\x1b[36m⏳ Mengambil konfigurasi keamanan WhatsApp terbaru...\x1b[0m");
    const { version, isLatest } = await fetchLatestBaileysVersion();
    
    const sock = makeWASocket({
        version,
        auth: state,
        logger: pino({ level: 'silent' }),
        browser: Browsers.ubuntu('Chrome'),
        printQRInTerminal: false,
        syncFullHistory: false
    });

    if (!sock.authState.creds.registered && !pairingRequested) {
        pairingRequested = true;
        let phoneNumber = config.botNumber;
        
        if (!phoneNumber) {
            console.log('\x1b[31m\n❌ NOMOR BOT BELUM DIATUR! Keluar...\x1b[0m');
            process.exit(0);
        }

        setTimeout(async () => {
            try {
                let formattedNumber = phoneNumber.replace(/[^0-9]/g, '');
                const code = await sock.requestPairingCode(formattedNumber);
                console.log(`\x1b[32m\n=======================================================\x1b[0m`);
                console.log(`\x1b[1m\x1b[33m🔑 KODE TAUTAN ANDA :  ${code}  \x1b[0m`);
                console.log(`\x1b[32m=======================================================\x1b[0m`);
                console.log('👉 Buka WA di HP -> Perangkat Tertaut -> Tautkan dengan nomor telepon saja.');
                console.log('\x1b[31m⚠️ SEGERA MASUKKAN KODENYA KE HP ANDA!\x1b[0m\n');
            } catch (error) {
                pairingRequested = false; 
            }
        }, 8000); 
    }

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'close') {
            let reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
            if (reason === DisconnectReason.loggedOut) {
                process.exit(0);
            } else {
                pairingRequested = false;
                setTimeout(startBot, 4000);
            }
        } else if (connection === 'open') {
            console.log('\x1b[32m\n✅ BOT WHATSAPP BERHASIL TERHUBUNG DENGAN AMAN!\x1b[0m');
        }
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
                    username: userAPI,
                    buyer_sku_code: trx.sku,
                    customer_no: trx.tujuan,
                    ref_id: ref,
                    sign: signCheck
                });

                const resData = cekRes.data.data;
                const statusUpdate = resData.status;
                const sn = resData.sn || '-';

                if (statusUpdate === 'Sukses') {
                    let msg = `✅ *UPDATE STATUS: SUKSES*\n\n📦 Produk: ${trx.nama}\n📱 Tujuan: ${trx.tujuan}\n🔖 Ref: ${ref}\n🔑 SN/Catatan: ${sn}`;
                    await sock.sendMessage(trx.jid, { text: msg });
                    delete trxs[ref];
                    saveJSON(trxFile, trxs);
                } else if (statusUpdate === 'Gagal') {
                    let db = loadJSON(dbFile);
                    let senderNum = trx.jid.split('@')[0];
                    if (db[senderNum]) {
                        db[senderNum].saldo += trx.harga;
                        saveJSON(dbFile, db);
                    }
                    let msg = `❌ *UPDATE STATUS: GAGAL*\n\n📦 Produk: ${trx.nama}\n📱 Tujuan: ${trx.tujuan}\n🔖 Ref: ${ref}\nAlasan: ${resData.message}\n\n_💰 Saldo Rp ${trx.harga.toLocaleString('id-ID')} telah dikembalikan._`;
                    await sock.sendMessage(trx.jid, { text: msg });
                    delete trxs[ref];
                    saveJSON(trxFile, trxs);
                } else {
                    if (Date.now() - trx.tanggal > 24 * 60 * 60 * 1000) {
                        delete trxs[ref];
                        saveJSON(trxFile, trxs);
                    }
                }
            } catch (err) {}
            await new Promise(r => setTimeout(r, 2000)); 
        }
    }, 15000); 

    const brandStructure = {
        'Pulsa': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri'],
        'Paket Data': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri'],
        'Topup Game': ['Mobile Legends', 'Free Fire'],
        'Topup E-Wallet': ['Gopay', 'Dana', 'Shopee Pay'],
        'Token Listrik': ['Token Listrik'],
        'Masa Aktif': ['Telkomsel', 'XL', 'Axis', 'Indosat', 'Tri']
    };

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
            let produkDB = loadJSON(produkFile);
            let namaBot = config.botName || "Tendo Store";

            if (!db[sender]) {
                db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle', temp_sku: '', temp_category: '', temp_brand: '' };
                saveJSON(dbFile, db);
            } else {
                if (!db[sender].step) db[sender].step = 'idle';
                if (!db[sender].temp_sku) db[sender].temp_sku = '';
                if (!db[sender].temp_category) db[sender].temp_category = '';
                if (!db[sender].temp_brand) db[sender].temp_brand = '';
            }

            let bodyLower = body.trim().toLowerCase();
            let rawCommand = bodyLower.split(' ')[0];

            if (['batal', 'cancel', 'bot', 'menu', '.menu', 'p', 'ping'].includes(rawCommand)) {
                if (db[sender].step !== 'idle') {
                    db[sender].step = 'idle';
                    db[sender].temp_sku = '';
                    db[sender].temp_category = '';
                    db[sender].temp_brand = '';
                    saveJSON(dbFile, db);
                    if (['batal', 'cancel'].includes(rawCommand)) {
                        await sock.sendMessage(from, { text: `✅ Proses pesanan dibatalkan.\n\n_Ketik *bot* untuk kembali ke menu utama._` });
                        return;
                    }
                }
            }

            if (db[sender].step === 'select_brand') {
                let cat = db[sender].temp_category;
                let brands = brandStructure[cat];
                let inputNum = parseInt(body.trim());
                
                if (!isNaN(inputNum) && inputNum > 0 && inputNum <= brands.length) {
                    db[sender].temp_brand = brands[inputNum - 1];
                    db[sender].step = 'order_product';
                    saveJSON(dbFile, db);
                    
                    let filteredKeys = Object.keys(produkDB).filter(k => 
                        (produkDB[k].kategori || 'Lainnya') === cat && (produkDB[k].brand || 'Lainnya') === db[sender].temp_brand
                    );
                    
                    if (filteredKeys.length === 0) {
                        db[sender].step = 'idle'; saveJSON(dbFile, db);
                        return await sock.sendMessage(from, { text: `🛒 Maaf, produk untuk *${cat} - ${db[sender].temp_brand}* sedang kosong.\n_Ketik *bot* untuk kembali._`});
                    }
                    
                    let textCat = `🛒 *PILIH PRODUK: ${cat.toUpperCase()} - ${db[sender].temp_brand.toUpperCase()}*\n\n`;
                    filteredKeys.forEach((k, i) => {
                        textCat += `*${i+1}.* ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`;
                        if (produkDB[k].deskripsi) textCat += `   └ _${produkDB[k].deskripsi}_\n`;
                    });
                    textCat += `\n👉 *Balas pesan ini dengan NOMOR URUT produknya saja (Contoh: ketik 1)*\n\n_Ketik *batal* untuk membatalkan pesanan._`;
                    
                    await sock.sendMessage(from, { text: textCat.trim() });
                    return;
                } else {
                    return await sock.sendMessage(from, { text: `❌ Pilihan tidak valid!\nSilakan balas dengan *angka urutan* yang ada.\n\n_Ketik *batal* jika ingin membatalkan pesanan._` });
                }
            }

            if (db[sender].step === 'order_product') {
                let cat = db[sender].temp_category;
                let brand = db[sender].temp_brand;
                let filteredKeys = Object.keys(produkDB).filter(k => 
                    (produkDB[k].kategori || 'Lainnya') === cat && (produkDB[k].brand || 'Lainnya') === brand
                );
                
                let inputKode = body.trim();
                
                if (!isNaN(inputKode) && Number(inputKode) > 0 && Number(inputKode) <= filteredKeys.length) {
                    db[sender].temp_sku = filteredKeys[Number(inputKode) - 1];
                    db[sender].step = 'order_target';
                    saveJSON(dbFile, db);
                    
                    let p = produkDB[db[sender].temp_sku];
                    let msgBalasan = `📦 Produk dipilih: *${p.nama}*\n`;
                    msgBalasan += `💰 Harga: Rp ${p.harga.toLocaleString('id-ID')}\n\n`;
                    if (p.deskripsi) msgBalasan += `📝 *Info Detail:*\n${p.deskripsi}\n\n`;
                    msgBalasan += `📱 *Silakan balas dengan NOMOR/ID TUJUAN pengisian!*\n`;
                    msgBalasan += `_(Pastikan nomor tujuan benar)_\n\n`;
                    msgBalasan += `_Ketik *batal* untuk membatalkan pesanan._`;
                    
                    await sock.sendMessage(from, { text: msgBalasan });
                    return;
                } else {
                    await sock.sendMessage(from, { text: `❌ Pilihan tidak valid!\nSilakan balas dengan *angka urutan* produk saja (contoh: 1).\n\n_Ketik *batal* jika ingin membatalkan pesanan._` });
                    return;
                }
            }

            if (db[sender].step === 'order_target') {
                let tujuan = body.trim(); 
                let kodeProduk = db[sender].temp_sku;
                
                db[sender].step = 'idle';
                db[sender].temp_sku = '';
                db[sender].temp_category = '';
                db[sender].temp_brand = '';
                saveJSON(dbFile, db);

                if(!tujuan || tujuan.length < 4) {
                    return await sock.sendMessage(from, { text: `❌ Format nomor/ID tujuan salah. Pesanan dibatalkan. Silakan ulangi dari awal.` });
                }

                const hargaProduk = produkDB[kodeProduk].harga;

                if (db[sender].saldo < hargaProduk) {
                    return await sock.sendMessage(from, { text: `❌ *Saldo tidak mencukupi!*\n\n💰 Saldo Anda: Rp ${db[sender].saldo.toLocaleString('id-ID')}\n🏷️ Harga Produk: Rp ${hargaProduk.toLocaleString('id-ID')}\n\nSilakan isi saldo terlebih dahulu.` });
                }

                let username = (config.digiflazzUsername || '').trim();
                let apiKey = (config.digiflazzApiKey || '').trim();

                if (!username || !apiKey) {
                    return await sock.sendMessage(from, { text: `❌ Sistem bermasalah: API Digiflazz belum dikonfigurasi oleh Admin.` });
                }

                let refId = 'TENDO-' + Date.now();
                let sign = crypto.createHash('md5').update(username + apiKey + refId).digest('hex');

                await sock.sendMessage(from, { text: `⏳ *Sedang memproses pesanan...*\n\n📦 Produk: ${produkDB[kodeProduk].nama}\n📱 Tujuan: ${tujuan}\n🔖 Ref: ${refId}` });

                try {
                    const response = await axios.post('https://api.digiflazz.com/v1/transaction', {
                        username: username,
                        buyer_sku_code: kodeProduk,
                        customer_no: tujuan,
                        ref_id: refId,
                        sign: sign
                    });

                    const resData = response.data.data;
                    const statusOrder = resData.status; 
                    const sn = resData.sn || '-';
                    const message = resData.message || '';

                    if (statusOrder === 'Gagal') {
                        await sock.sendMessage(from, { text: `❌ *Transaksi Gagal!*\nAlasan: ${message}\n\n_Saldo Anda tidak dipotong._` });
                    } else if (statusOrder === 'Pending') {
                        db[sender].saldo -= hargaProduk;
                        saveJSON(dbFile, db);

                        let trxs = loadJSON(trxFile);
                        trxs[refId] = { jid: from, sku: kodeProduk, tujuan: tujuan, harga: hargaProduk, nama: produkDB[kodeProduk].nama, tanggal: Date.now() };
                        saveJSON(trxFile, trxs);

                        let pesanPending = `⏳ *PESANAN SEDANG DIPROSES*\n\n`;
                        pesanPending += `📦 Produk: ${produkDB[kodeProduk].nama}\n`;
                        pesanPending += `📱 Tujuan: ${tujuan}\n`;
                        pesanPending += `🔖 Ref ID: ${refId}\n`;
                        pesanPending += `⚙️ Status: *Pending (Menunggu)*\n\n`;
                        pesanPending += `_Sistem akan otomatis menginformasikan jika transaksi sukses atau gagal._`;

                        await sock.sendMessage(from, { text: pesanPending });
                    } else {
                        db[sender].saldo -= hargaProduk;
                        saveJSON(dbFile, db);

                        let pesanSukses = `✅ *PESANAN BERHASIL DIPROSES*\n\n`;
                        pesanSukses += `📦 Produk: ${produkDB[kodeProduk].nama}\n`;
                        pesanSukses += `📱 Tujuan: ${tujuan}\n`;
                        pesanSukses += `🔖 Ref ID: ${refId}\n`;
                        pesanSukses += `⚙️ Status: *${statusOrder}*\n`;
                        pesanSukses += `🔑 SN/Catatan: ${sn}\n\n`;
                        pesanSukses += `💰 Sisa Saldo: Rp ${db[sender].saldo.toLocaleString('id-ID')}`;

                        await sock.sendMessage(from, { text: pesanSukses });
                    }
                } catch (error) {
                    let errMessage = error.response?.data?.data?.message || 'Terjadi kesalahan saat menghubungi server Digiflazz/API Down.';
                    await sock.sendMessage(from, { text: `❌ *Transaksi Gagal!*\nAlasan: ${errMessage}\n\n_Saldo Anda tidak dipotong._` });
                }
                return;
            }

            let command = '';
            const catMap = {
                '3': 'Pulsa', 'pulsa': 'Pulsa',
                '4': 'Paket Data', 'paket': 'Paket Data', 'data': 'Paket Data',
                '5': 'Topup Game', 'game': 'Topup Game',
                '6': 'Topup E-Wallet', 'ewallet': 'Topup E-Wallet', 'dana': 'Topup E-Wallet', 'gopay': 'Topup E-Wallet',
                '7': 'Token Listrik', 'token': 'Token Listrik', 'pln': 'Token Listrik', 'listrik': 'Token Listrik',
                '8': 'Masa Aktif', 'masa': 'Masa Aktif', 'aktif': 'Masa Aktif'
            };

            if (['bot', 'menu', '.menu', 'help', 'halo', 'hai', 'p', 'ping', 'info'].includes(rawCommand)) command = 'bot';
            else if (['1', '1.', '1.saldo', 'saldo', '.saldo'].includes(rawCommand)) command = '.saldo';
            else if (['2', '2.', '2.harga', 'harga', '.harga', 'list'].includes(rawCommand)) command = '.harga';
            else if (catMap[rawCommand]) {
                command = '.show_cat';
                db[sender].temp_category = catMap[rawCommand];
            } else if (rawCommand === 'order' || rawCommand === '.order') {
                command = '.order_bypass';
            }

            if (command === 'bot') {
                let menuText = `👋 Selamat Datang di *${namaBot}* (v25)\n`;
                menuText += `📌 *ID Member:* ${sender}\n\n`;
                menuText += `1. *Cek Saldo*\n`;
                menuText += `2. *Cek Semua Harga*\n`;
                menuText += `3. *Pulsa*\n`;
                menuText += `4. *Paket Data*\n`;
                menuText += `5. *Topup Game*\n`;
                menuText += `6. *Topup E-Wallet*\n`;
                menuText += `7. *Token Listrik*\n`;
                menuText += `8. *Masa Aktif*\n\n`;
                menuText += `_👉 Cukup balas dengan angka pilihan di atas untuk order/cek (Contoh: ketik *3* untuk membeli Pulsa)._\n\n`;
                menuText += `🌐 *Akses Web App Tendo Store sekarang untuk kemudahan bertransaksi!*`;
                await sock.sendMessage(from, { text: menuText });
                return;
            }

            if (command === '.saldo') {
                await sock.sendMessage(from, { text: `💰 Saldo Anda saat ini: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` });
                return;
            }

            if (command === '.harga') {
                let keys = Object.keys(produkDB);
                if (keys.length === 0) {
                    return await sock.sendMessage(from, { text: `🛒 *Daftar Harga ${namaBot}*\n\nMaaf, belum ada produk yang tersedia saat ini.`});
                }
                
                let textHarga = `🛒 *KATALOG PRODUK LENGKAP*\n\n`;
                let cats = ["Pulsa", "Paket Data", "Topup Game", "Topup E-Wallet", "Token Listrik", "Masa Aktif", "Lainnya"];
                
                cats.forEach(c => {
                    let catKeys = keys.filter(k => (produkDB[k].kategori || 'Lainnya') === c);
                    if(catKeys.length > 0) {
                        textHarga += `➖ *${c.toUpperCase()}* ➖\n`;
                        let brands = [...new Set(catKeys.map(k => produkDB[k].brand || 'Lainnya'))];
                        brands.forEach(b => {
                            textHarga += `🔸 *${b.toUpperCase()}*\n`;
                            let brandKeys = catKeys.filter(k => (produkDB[k].brand || 'Lainnya') === b);
                            brandKeys.forEach(k => {
                                textHarga += `   ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`;
                                if(produkDB[k].deskripsi) textHarga += `   └ _${produkDB[k].deskripsi}_\n`;
                            });
                        });
                        textHarga += `\n`;
                    }
                });
                
                textHarga += `_💡 Ketik angka kategori di menu utama (misal: ketik 3 untuk Pulsa) untuk mulai membeli._`;
                await sock.sendMessage(from, { text: textHarga.trim() });
                return;
            }

            if (command === '.show_cat') {
                let cat = db[sender].temp_category;
                let brands = brandStructure[cat] || [];
                
                if (brands.length === 1) {
                    db[sender].temp_brand = brands[0];
                    db[sender].step = 'order_product';
                    saveJSON(dbFile, db);
                    
                    let filteredKeys = Object.keys(produkDB).filter(k => 
                        (produkDB[k].kategori || 'Lainnya') === cat && (produkDB[k].brand || 'Lainnya') === db[sender].temp_brand
                    );
                    
                    if (filteredKeys.length === 0) {
                        db[sender].step = 'idle'; saveJSON(dbFile, db);
                        return await sock.sendMessage(from, { text: `🛒 Maaf, produk untuk kategori *${cat}* sedang kosong.\n_Ketik *bot* untuk kembali._`});
                    }
                    
                    let textCat = `🛒 *PILIH PRODUK: ${cat.toUpperCase()}*\n\n`;
                    filteredKeys.forEach((k, i) => {
                        textCat += `*${i+1}.* ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`;
                        if (produkDB[k].deskripsi) textCat += `   └ _${produkDB[k].deskripsi}_\n`;
                    });
                    textCat += `\n👉 *Silakan balas pesan ini dengan NOMOR URUT produknya saja (Contoh: ketik 1)*\n\n_Ketik *batal* untuk membatalkan._`;
                    
                    await sock.sendMessage(from, { text: textCat.trim() });
                    return;
                } else {
                    db[sender].step = 'select_brand';
                    saveJSON(dbFile, db);
                    
                    let textBrand = `🛒 *PILIH PROVIDER / GAME / E-WALLET*\n\n`;
                    textBrand += `Kategori: *${cat.toUpperCase()}*\n\n`;
                    brands.forEach((b, i) => {
                        textBrand += `*${i+1}.* ${b}\n`;
                    });
                    textBrand += `\n👉 *Balas pesan ini dengan ANGKA pilihannya (Contoh: ketik 1)*\n\n_Ketik *batal* untuk membatalkan._`;
                    await sock.sendMessage(from, { text: textBrand });
                    return;
                }
            }

            if (command === '.order_bypass') {
                const args = body.split(' ').slice(1);
                if (args.length >= 2) {
                    let kodeProduk = args[0].toUpperCase();
                    const tujuan = args[1].replace(/[^0-9]/g, '');
                    if (!produkDB[kodeProduk]) return await sock.sendMessage(from, { text: `❌ Kode tidak ditemukan.` });
                    
                    db[sender].step = 'order_target'; 
                    db[sender].temp_sku = kodeProduk;
                    saveJSON(dbFile, db);
                    
                    m.messages[0].message.conversation = tujuan;
                    sock.ev.emit('messages.upsert', m);
                } else {
                    await sock.sendMessage(from, { text: `Ketik *bot* untuk melihat menu, atau pilih angka kategori langsung.` });
                }
            }

        } catch (err) {
            console.error("Kesalahan sistem WhatsApp: ", err);
        }
    });

    if (global.broadcastInterval) clearInterval(global.broadcastInterval);
    global.broadcastInterval = setInterval(async () => {
        if (fs.existsSync('./broadcast.txt')) {
            let textBroadcast = fs.readFileSync('./broadcast.txt', 'utf-8');
            fs.unlinkSync('./broadcast.txt');

            if (textBroadcast.trim()) {
                let db = loadJSON(dbFile);
                let config = loadJSON(configFile);
                let namaBot = config.botName || "Tendo Store";
                let members = Object.keys(db);
                for (let num of members) {
                    try {
                        let targetJid = db[num].jid || (num + '@s.whatsapp.net');
                        await sock.sendMessage(targetJid, { text: `📢 *INFORMASI ${namaBot}*\n\n${textBroadcast.trim()}` });
                        await new Promise(res => setTimeout(res, 3000));
                    } catch (err) {}
                }
            }
        }
    }, 5000);
}

if (require.main === module) {
    app.listen(3000, '0.0.0.0', () => {
        console.log('\x1b[32m🌐 SERVER WEB APLIKASI AKTIF PADA PORT 3000.\x1b[0m');
    }).on('error', (err) => {
        console.log('\x1b[31m⚠️ Gagal menjalankan server web. Mungkin port 3000 sudah dipakai.\x1b[0m');
    });
    startBot().catch(err => console.error(err));
}
EOF
}

# ==========================================
# 3. FUNGSI INSTALASI DEPENDENSI
# ==========================================
install_dependencies() {
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}             🚀 MENGINSTALL SISTEM BOT 🚀             ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1

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
    (sudo -E apt-get update > /dev/null 2>&1 && sudo -E apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Menginstall dependensi...${C_RST}"
    sudo -E apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl git wget nano zip unzip > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Menginstall Node.js...${C_RST}"
    (curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - > /dev/null 2>&1 && sudo -E apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nodejs > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Memperbarui NPM & Install PM2...${C_RST}"
    (sudo npm install -g npm@11.11.0 > /dev/null 2>&1 && sudo npm install -g pm2 > /dev/null 2>&1) &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Meracik sistem utama bot (v25)...${C_RST}"
    generate_bot_script
    generate_web_app
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -ne "${C_MAG}>> Mengunduh modul WhatsApp Baileys...${C_RST}"
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser > /dev/null 2>&1 &
    spin $!
    echo -e "${C_GREEN}[Selesai]${C_RST}"
    
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD}                 ✅ INSTALASI SELESAI!                ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    read -p "Tekan Enter untuk kembali ke Panel Utama..."
}

# ==========================================
# LAIN-LAIN: SUB-MENU TELEGRAM & BACKUP 
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
                read -p "Masukkan ID Member: " nomor
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
                read -p "Masukkan ID Member: " nomor
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
                        members.forEach((m, i) => console.log((i + 1) + '. ID: ' + m + ' | Saldo: Rp ' + db[m].saldo.toLocaleString('id-ID')));
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
# 7. MANAJEMEN PRODUK (DENGAN KATEGORI & BRAND)
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
# 8. MENU UTAMA (PANEL KONTROL)
# ==========================================
while true; do
    clear
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_YELLOW}${C_BOLD}             🤖 PANEL ADMIN TENDO STORE 🤖            ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_MAG}▶ MANAJEMEN BOT${C_RST}"
    echo -e "  ${C_GREEN}[1]${C_RST}  Install & Perbarui Sistem"
    echo -e "  ${C_GREEN}[2]${C_RST}  Mulai Bot (Terminal / Scan QR)"
    echo -e "  ${C_GREEN}[3]${C_RST}  Jalankan Bot di Latar Belakang (PM2)"
    echo -e "  ${C_GREEN}[4]${C_RST}  Hentikan Bot (PM2)"
    echo -e "  ${C_GREEN}[5]${C_RST}  Lihat Log / Error Bot"
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
            node index.js
            echo -e "\n${C_YELLOW}⚠️ Proses bot terhenti.${C_RST}"
            read -p "Tekan Enter untuk kembali ke panel utama..."
            ;;
        3) 
            pm2 delete tendo-bot >/dev/null 2>&1
            pm2 start index.js --name "tendo-bot" >/dev/null 2>&1
            pm2 save >/dev/null 2>&1
            pm2 startup >/dev/null 2>&1
            echo -e "\n${C_GREEN}✅ Bot berhasil berjalan di latar belakang!${C_RST}"
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
