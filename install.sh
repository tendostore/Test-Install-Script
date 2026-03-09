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

# ==========================================
# 1. BIKIN SHORTCUT 'BOT' OTOMATIS DI VPS
# ==========================================
if [ ! -f "/usr/bin/bot" ]; then
    if [ -f "/usr/bin/menu" ]; then sudo rm -f /usr/bin/menu; fi
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/bot > /dev/null
    sudo chmod +x /usr/bin/bot
fi

# ==========================================
# 2. FUNGSI UNTUK MEMBUAT FILE INDEX.JS
# ==========================================
generate_bot_script() {
    echo -e "${C_CYAN}⏳ Meracik sistem utama bot...${C_RST}"
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
saveJSON(configFile, configAwal);

if (!fs.existsSync(dbFile)) saveJSON(dbFile, {});
if (!fs.existsSync(produkFile)) saveJSON(produkFile, {});
if (!fs.existsSync(trxFile)) saveJSON(trxFile, {});

let pairingRequested = false; 

// FUNGSI AUTO BACKUP KE TELEGRAM 
function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    
    console.log("\x1b[36m⏳ Memulai proses Auto-Backup ke Telegram...\x1b[0m");
    exec(`rm -f backup.zip && zip backup.zip config.json database.json trx.json index.js install.sh package-lock.json package.json produk.json 2>/dev/null`, (err) => {
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
    setInterval(doBackupAndSend, 12 * 60 * 60 * 1000); 
}

async function startBot() {
    console.log("\x1b[36m\n⏳ Sedang menyiapkan mesin bot...\x1b[0m");
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = loadJSON(configFile);
    
    console.log("\x1b[36m⏳ Mengambil konfigurasi keamanan WhatsApp terbaru...\x1b[0m");
    const { version, isLatest } = await fetchLatestBaileysVersion();
    console.log(`\x1b[34m📡 Menghubungkan ke WA Web v${version.join('.')} (Stabil: ${isLatest})\x1b[0m`);
    
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

    // AUTO-POLLING CEK STATUS PENDING DIGIFLAZZ
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
                db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid, step: 'idle', temp_sku: '' };
                saveJSON(dbFile, db);
            } else {
                if (!db[sender].step) db[sender].step = 'idle';
                if (!db[sender].temp_sku) db[sender].temp_sku = '';
            }

            let bodyLower = body.trim().toLowerCase();

            // KONTROL PEMBATALAN PESANAN
            if (bodyLower === 'batal' || bodyLower === 'cancel') {
                if (db[sender].step !== 'idle') {
                    db[sender].step = 'idle';
                    db[sender].temp_sku = '';
                    saveJSON(dbFile, db);
                    await sock.sendMessage(from, { text: `✅ Proses pemesanan berhasil dibatalkan.\n\n_Ketik *bot* untuk kembali ke menu utama._` });
                    return;
                }
            }

            // TAHAP 1: Tunggu Balasan Nomor Urut Produk
            if (db[sender].step === 'order_product') {
                let keys = Object.keys(produkDB);
                let inputKode = body.trim();
                
                if (!isNaN(inputKode) && Number(inputKode) > 0 && Number(inputKode) <= keys.length) {
                    db[sender].temp_sku = keys[Number(inputKode) - 1];
                    db[sender].step = 'order_target';
                    saveJSON(dbFile, db);
                    
                    let p = produkDB[db[sender].temp_sku];
                    await sock.sendMessage(from, { text: `📦 Produk dipilih: *${p.nama}*\n💰 Harga: Rp ${p.harga.toLocaleString('id-ID')}\n\n📱 *Silakan balas dengan NOMOR TUJUAN pengisian!*\n_(Misal: 081234567890)_\n\n_Ketik *batal* untuk membatalkan pesanan._` });
                    return;
                } else {
                    await sock.sendMessage(from, { text: `❌ Pilihan tidak valid!\nSilakan balas dengan *angka urutan* produk saja (contoh: 1).\n\n_Ketik *batal* jika ingin membatalkan pesanan._` });
                    return;
                }
            }

            // TAHAP 2: Tunggu Balasan Nomor HP dan Eksekusi
            if (db[sender].step === 'order_target') {
                let tujuan = body.trim().replace(/[^0-9]/g, ''); 
                let kodeProduk = db[sender].temp_sku;
                
                db[sender].step = 'idle';
                db[sender].temp_sku = '';
                saveJSON(dbFile, db);

                if(!tujuan || tujuan.length < 8) {
                    return await sock.sendMessage(from, { text: `❌ Format nomor tujuan salah. Pesanan dibatalkan. Silakan ulangi dari awal.` });
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


            // KECERDASAN MEMBACA PERINTAH NORMAL
            let rawCommand = body.split(' ')[0].toLowerCase();
            let command = rawCommand;
            
            if (['bot', 'menu', '.menu', 'help', 'halo', 'hai', 'p', 'ping', 'info'].includes(rawCommand)) {
                command = 'bot';
            } else if (['1', '1.', '1.saldo', 'saldo', '.saldo'].includes(rawCommand)) {
                command = '.saldo';
            } else if (['3', '3.', '3.harga', 'harga', '.harga', 'list'].includes(rawCommand)) {
                command = '.harga';
            } else if (['2', '2.', '2.order', 'order', '.order', 'beli'].includes(rawCommand)) {
                command = '.order';
            }

            if (command === 'bot') {
                let menuText = `👋 Selamat Datang di *${namaBot}* (v14)\n`;
                menuText += `📌 *ID Member:* ${sender}\n\n`;
                menuText += `1. *Saldo*\n`;
                menuText += `2. *Order*\n`;
                menuText += `3. *Harga*\n\n`;
                menuText += `_👉 Cukup balas dengan angka pilihan di atas (Contoh: ketik *2* untuk mulai membeli)._`;
                await sock.sendMessage(from, { text: menuText });
                return;
            }

            if (command === '.saldo') {
                await sock.sendMessage(from, { 
                    text: `💰 Saldo Anda saat ini: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` 
                });
                return;
            }

            if (command === '.harga') {
                let keys = Object.keys(produkDB);
                if (keys.length === 0) {
                    await sock.sendMessage(from, { text: `🛒 *Daftar Harga ${namaBot}*\n\nMaaf, belum ada produk yang tersedia saat ini.`});
                    return;
                }
                let textHarga = `🛒 *DAFTAR PRODUK ${namaBot}*\n\n`;
                keys.forEach((k, i) => {
                    textHarga += `*${i+1}.* ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`;
                });
                textHarga += `\n_💡 Ketik *2* jika Anda ingin mulai melakukan pembelian._`;
                await sock.sendMessage(from, { text: textHarga.trim() });
                return;
            }

            if (command === '.order') {
                const args = body.split(' ').slice(1);
                
                if (args.length >= 2) {
                    let inputKode = args[0].toUpperCase();
                    const tujuan = args[1].replace(/[^0-9]/g, '');
                    let kodeProduk = inputKode;
                    let keys = Object.keys(produkDB);

                    if (!isNaN(inputKode) && Number(inputKode) > 0 && Number(inputKode) <= keys.length) {
                        kodeProduk = keys[Number(inputKode) - 1];
                    }

                    if (!produkDB[kodeProduk]) {
                        return await sock.sendMessage(from, { text: `❌ Nomor produk atau Kode tidak ditemukan.` });
                    }
                    
                    db[sender].step = 'order_target'; 
                    db[sender].temp_sku = kodeProduk;
                    saveJSON(dbFile, db);
                    
                    m.messages[0].message.conversation = tujuan;
                    sock.ev.emit('messages.upsert', m);
                    return;
                } 
                else {
                    let keys = Object.keys(produkDB);
                    if (keys.length === 0) {
                        return await sock.sendMessage(from, { text: `🛒 Maaf, belum ada produk yang tersedia saat ini.`});
                    }

                    let textHarga = `🛒 *PILIH PRODUK UNTUK DIORDER*\n\n`;
                    keys.forEach((k, i) => {
                        textHarga += `*${i+1}.* ${produkDB[k].nama} - Rp ${produkDB[k].harga.toLocaleString('id-ID')}\n`;
                    });
                    textHarga += `\n👉 *Silakan balas pesan ini dengan NOMOR URUT produknya saja (Contoh: ketik 1)*\n\n_Ketik *batal* untuk membatalkan pesanan._`;
                    
                    db[sender].step = 'order_product';
                    saveJSON(dbFile, db);
                    
                    await sock.sendMessage(from, { text: textHarga.trim() });
                    return;
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
    app.listen(3000, () => {
        console.log('\x1b[32m🌐 Server Webhook siap.\x1b[0m');
    }).on('error', (err) => {});
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

    echo -e "${C_MAG}>> Mengupdate repositori sistem...${C_RST}"
    sudo -E apt-get update > /dev/null 2>&1
    sudo -E apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" > /dev/null 2>&1
    
    echo -e "${C_MAG}>> Menginstall dependensi (curl, git, wget, zip)...${C_RST}"
    sudo -E apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl git wget nano zip unzip > /dev/null 2>&1
    
    echo -e "${C_MAG}>> Menginstall Node.js...${C_RST}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - > /dev/null 2>&1
    sudo -E apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nodejs > /dev/null 2>&1
    
    sudo npm install -g npm@11.11.0 > /dev/null 2>&1
    sudo npm install -g pm2 > /dev/null 2>&1
    
    generate_bot_script
    if [ ! -f "package.json" ]; then npm init -y > /dev/null 2>&1; fi
    rm -rf node_modules package-lock.json
    
    echo -e "${C_MAG}>> Mengunduh modul WhatsApp Baileys...${C_RST}"
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser > /dev/null 2>&1
    
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    echo -e "${C_GREEN}${C_BOLD}                 ✅ INSTALASI SELESAI!                ${C_RST}"
    echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
    read -p "Tekan Enter untuk kembali ke Panel Utama..."
}

# ==========================================
# 4. SUB-MENU TELEGRAM SETUP
# ==========================================
menu_telegram() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             ⚙️ BOT TELEGRAM SETUP ⚙️              ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Change BOT API & CHAT ID"
        echo -e "  ${C_GREEN}[2]${C_RST} Set Notifikasi Backup Otomatis (12 Jam)"
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
                read -p "Aktifkan Auto-Backup ke Telegram setiap 12 Jam? (y/n): " set_auto
                if [ "$set_auto" == "y" ] || [ "$set_auto" == "Y" ]; then
                    status="true"
                    echo -e "\n${C_GREEN}✅ Auto-Backup DIAKTIFKAN!${C_RST}"
                else
                    status="false"
                    echo -e "\n${C_RED}❌ Auto-Backup DIMATIKAN!${C_RST}"
                fi
                node -e "
                    const fs = require('fs');
                    let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                    config.autoBackup = $status;
                    fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                "
                echo -e "${C_YELLOW}⚠️ Silakan restart bot (Menu 4 lalu 3) agar fitur aktif.${C_RST}"
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo -e "${C_RED}❌ Pilihan tidak valid!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 5. SUB-MENU BACKUP & RESTORE
# ==========================================
menu_backup() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}               💾 BACKUP & RESTORE 💾               ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Backup Sekarang (Kirim file ZIP ke Telegram)"
        echo -e "  ${C_GREEN}[2]${C_RST} Restore Database & Bot dari Direct Link"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-2]: ${C_RST}"
        read backchoice

        case $backchoice in
            1)
                echo -e "\n${C_MAG}⏳ Sedang memproses arsip backup. Mohon tunggu...${C_RST}"
                if ! command -v zip &> /dev/null; then sudo apt install zip -y > /dev/null 2>&1; fi
                
                rm -f backup.zip
                zip backup.zip config.json database.json trx.json index.js install.sh package-lock.json package.json produk.json 2>/dev/null
                echo -e "${C_GREEN}✅ File backup.zip berhasil dikompresi!${C_RST}"
                
                node -e "
                    const fs = require('fs');
                    const { exec } = require('child_process');
                    let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                    if(config.teleToken && config.teleChatId) {
                        console.log('\x1b[36m⏳ Sedang mengirim ke Telegram Anda...\x1b[0m');
                        let cmd = \`curl -s -F chat_id=\"\${config.teleChatId}\" -F document=@\"backup.zip\" -F caption=\"📦 Manual Backup Tendo Store\" https://api.telegram.org/bot\${config.teleToken}/sendDocument\`;
                        exec(cmd, (err) => {
                            if(err) console.log('\x1b[31m❌ Gagal mengirim ke Telegram. Pastikan Token & Chat ID benar.\x1b[0m');
                            else console.log('\x1b[32m✅ File Backup berhasil mendarat di Telegram Anda!\x1b[0m');
                        });
                    } else {
                        console.log('\x1b[33m⚠️ Token/Chat ID Telegram belum diisi di Menu 8. File hanya tersimpan di VPS.\x1b[0m');
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
                        echo -e "${C_MAG}⏳ Mendownload file dari link...${C_RST}"
                        wget -qO restore.zip "$linkzip"
                        if [ -f "restore.zip" ]; then
                            if ! command -v unzip &> /dev/null; then sudo apt install unzip -y > /dev/null 2>&1; fi
                            echo -e "${C_MAG}⏳ Mengekstrak dan memulihkan file...${C_RST}"
                            unzip -o restore.zip > /dev/null 2>&1
                            rm restore.zip
                            echo -e "${C_GREEN}✅ Berhasil diekstrak!${C_RST}"
                            echo -e "${C_MAG}⏳ Memulihkan library Node.js (Mohon tunggu)...${C_RST}"
                            npm install > /dev/null 2>&1
                            echo -e "\n${C_GREEN}${C_BOLD}✅ RESTORE BERHASIL SEPENUHNYA!${C_RST}"
                            echo -e "${C_YELLOW}⚠️ Silakan restart bot (Menu 4 lalu 3) agar sistem update.${C_RST}"
                        else
                            echo -e "${C_RED}❌ Gagal mendownload file dari link tersebut.${C_RST}"
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
        echo -e "  ${C_GREEN}[3]${C_RST} Lihat Daftar Semua Member"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-3]: ${C_RST}"
        read subchoice

        case $subchoice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH SALDO ---${C_RST}"
                read -p "Masukkan ID Member: " nomor
                read -p "Masukkan Jumlah Saldo: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let target = '$nomor';
                    if(!db[target]) db[target] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: target + '@s.whatsapp.net' };
                    db[target].saldo += parseInt('$jumlah');
                    fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                    console.log('\x1b[32m\n✅ Saldo Rp $jumlah berhasil ditambahkan ke ID ' + target + '!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- KURANGI SALDO ---${C_RST}"
                read -p "Masukkan ID Member: " nomor
                read -p "Masukkan Jumlah Saldo yg dikurangi: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let target = '$nomor';
                    if(!db[target]) {
                        console.log('\x1b[31m\n❌ ID belum terdaftar di database.\x1b[0m');
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
                        members.forEach((m, i) => console.log((i + 1) + '. ID: ' + m + ' | Saldo: Rp ' + db[m].saldo.toLocaleString('id-ID')));
                        console.log('\n\x1b[36mTotal Member: ' + members.length + '\x1b[0m');
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
# 7. SUB-MENU MANAJEMEN PRODUK
# ==========================================
menu_produk() {
    while true; do
        clear
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "${C_YELLOW}${C_BOLD}             🛒 MANAJEMEN PRODUK BOT 🛒             ${C_RST}"
        echo -e "${C_CYAN}${C_BOLD}======================================================${C_RST}"
        echo -e "  ${C_GREEN}[1]${C_RST} Tambah / Edit Produk"
        echo -e "  ${C_GREEN}[2]${C_RST} Hapus Produk"
        echo -e "  ${C_GREEN}[3]${C_RST} Lihat Daftar Produk"
        echo -e "${C_CYAN}------------------------------------------------------${C_RST}"
        echo -e "  ${C_RED}[0]${C_RST} Kembali ke Panel Utama"
        echo -e "${C_CYAN}======================================================${C_RST}"
        echo -ne "${C_YELLOW}Pilih menu [0-3]: ${C_RST}"
        read prodchoice

        case $prodchoice in
            1)
                echo -e "\n${C_MAG}--- TAMBAH PRODUK BARU ---${C_RST}"
                read -p "Kode Produk (Contoh: TSEL10): " kode
                read -p "Nama Produk (Contoh: Telkomsel 10K): " nama
                read -p "Harga Jual (Contoh: 12000): " harga
                node -e "
                    const fs = require('fs');
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let key = '$kode'.toUpperCase().replace(/\s+/g, '');
                    produk[key] = { nama: '$nama', harga: parseInt('$harga') };
                    fs.writeFileSync('produk.json', JSON.stringify(produk, null, 2));
                    console.log('\x1b[32m\n✅ Produk [' + key + '] $nama berhasil ditambahkan dengan harga Rp $harga!\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo -e "\n${C_MAG}--- HAPUS PRODUK ---${C_RST}"
                read -p "Masukkan Kode Produk yg ingin dihapus: " kode
                node -e "
                    const fs = require('fs');
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let key = '$kode'.toUpperCase().replace(/\s+/g, '');
                    if(produk[key]) {
                        delete produk[key];
                        fs.writeFileSync('produk.json', JSON.stringify(produk, null, 2));
                        console.log('\x1b[32m\n✅ Produk ' + key + ' berhasil dihapus!\x1b[0m');
                    } else console.log('\x1b[31m\n❌ Kode Produk ' + key + ' tidak ditemukan.\x1b[0m');
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo -e "\n${C_CYAN}--- DAFTAR PRODUK TOKO ---${C_RST}"
                node -e "
                    const fs = require('fs');
                    let produk = fs.existsSync('produk.json') ? JSON.parse(fs.readFileSync('produk.json')) : {};
                    let keys = Object.keys(produk);
                    if(keys.length === 0) console.log('\x1b[33mBelum ada produk.\x1b[0m');
                    else {
                        keys.forEach((k, i) => console.log((i + 1) + '. [' + k + '] ' + produk[k].nama + ' - Rp ' + produk[k].harga.toLocaleString('id-ID')));
                        console.log('\n\x1b[36mTotal Produk: ' + keys.length + '\x1b[0m');
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
    echo -e "  ${C_GREEN}[1]${C_RST} Install & Perbarui Sistem"
    echo -e "  ${C_GREEN}[2]${C_RST} Mulai Bot (Terminal / Scan QR)"
    echo -e "  ${C_GREEN}[3]${C_RST} Jalankan Bot di Latar Belakang (PM2)"
    echo -e "  ${C_GREEN}[4]${C_RST} Hentikan Bot (PM2)"
    echo -e "  ${C_GREEN}[5]${C_RST} Lihat Log / Error Bot"
    echo ""
    echo -e "${C_MAG}▶ MANAJEMEN TOKO & SISTEM${C_RST}"
    echo -e "  ${C_GREEN}[6]${C_RST} 👥 Manajemen Saldo Member"
    echo -e "  ${C_GREEN}[7]${C_RST} 🛒 Manajemen Daftar Produk & Harga"
    echo -e "  ${C_GREEN}[8]${C_RST} ⚙️  Pengaturan Bot Telegram (Auto-Backup)"
    echo -e "  ${C_GREEN}[9]${C_RST} 💾 Backup & Restore Data Database"
    echo -e "  ${C_GREEN}[10]${C_RST}🔌 Ganti API Digiflazz"
    echo -e "  ${C_GREEN}[11]${C_RST}🔄 Ganti Akun Bot WA (Reset Sesi)"
    echo -e "  ${C_GREEN}[12]${C_RST}📢 Kirim Pesan Broadcast"
    echo -e "${C_CYAN}======================================================${C_RST}"
    echo -e "  ${C_RED}[0]${C_RST} Keluar dari Panel"
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
