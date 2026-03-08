#!/bin/bash

# ==========================================
# 1. BIKIN SHORTCUT 'MENU' OTOMATIS
# ==========================================
if [ ! -f "/usr/bin/menu" ]; then
    echo -e '#!/bin/bash\ncd "'$(pwd)'"\n./install.sh' | sudo tee /usr/bin/menu > /dev/null
    sudo chmod +x /usr/bin/menu
fi

# ==========================================
# 2. FUNGSI UNTUK MEMBUAT FILE INDEX.JS
# ==========================================
generate_bot_script() {
    echo "Membuat file index.js..."
    cat << 'EOF' > index.js
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, Browsers, jidNormalizedUser, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const fs = require('fs');
const pino = require('pino');
const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');

const app = express();
app.use(bodyParser.json());

const configFile = './config.json';
const dbFile = './database.json';
const produkFile = './produk.json';

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

let pairingRequested = false; 

// DATABASE SESI UNTUK ORDER PINTAR (Daya Ingat Bot)
const userSessions = {};

function doBackupAndSend() {
    let cfg = loadJSON(configFile);
    if (!cfg.teleToken || !cfg.teleChatId) return;
    exec(`rm -f backup.zip && zip backup.zip *.js *.json *.sh`, (err) => {
        if (!err) {
            let caption = `📦 *Auto-Backup Tendo Store*\n⏰ Waktu: ${new Date().toLocaleString('id-ID')}`;
            exec(`curl -s -F chat_id="${cfg.teleChatId}" -F document=@"backup.zip" -F caption="${caption}" https://api.telegram.org/bot${cfg.teleToken}/sendDocument`);
        }
    });
}

if (configAwal.autoBackup) setInterval(doBackupAndSend, 12 * 60 * 60 * 1000); 

async function startBot() {
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    const { version } = await fetchLatestBaileysVersion();
    
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
        let phoneNumber = loadJSON(configFile).botNumber;
        if (phoneNumber) {
            setTimeout(async () => {
                try {
                    const code = await sock.requestPairingCode(phoneNumber.replace(/[^0-9]/g, ''));
                    console.log(`\n🔑 KODE TAUTAN ANDA :  ${code}  \n`);
                } catch (error) { pairingRequested = false; }
            }, 8000); 
        }
    }

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'close') {
            let reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
            if (reason !== DisconnectReason.loggedOut) {
                pairingRequested = false;
                setTimeout(startBot, 4000);
            }
        } else if (connection === 'open') {
            console.log('\n✅ BOT WHATSAPP BERHASIL TERHUBUNG!');
        }
    });

    sock.ev.on('messages.upsert', async m => {
        const msg = m.messages[0];
        if (!msg.message || msg.key.fromMe) return;

        const from = msg.key.remoteJid;
        const senderJid = jidNormalizedUser(msg.key.participant || msg.key.remoteJid);
        const sender = senderJid.split('@')[0]; 
        
        const body = msg.message.conversation || msg.message.extendedTextMessage?.text || "";
        const command = body.split(' ')[0].toLowerCase();
        
        let config = loadJSON(configFile);
        let namaBot = config.botName || "Tendo Store";
        let db = loadJSON(dbFile);
        let produkDB = loadJSON(produkFile);
        let keys = Object.keys(produkDB);

        if (!db[sender]) {
            db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid };
            saveJSON(dbFile, db);
        }

        // 1. FITUR BATALKAN TRANSAKSI
        if (command === '.batal' || command === 'batal') {
            if (userSessions[sender]) {
                delete userSessions[sender];
                return await sock.sendMessage(from, { text: "✅ Transaksi berhasil dibatalkan." });
            }
        }

        // 2. CEK SESI (Jika Bot sedang menunggu Nomor Tujuan dari pelanggan ini)
        if (userSessions[sender] && userSessions[sender].step === 'awaiting_target') {
            // Jika pelanggan malah mengetik perintah lain (dimulai dengan titik), batalkan sesi otomatis
            if (command.startsWith('.')) {
                delete userSessions[sender];
            } else {
                let targetNumber = body.trim();
                let prodKey = userSessions[sender].productKey;
                let prodInfo = produkDB[prodKey];

                if (!prodInfo) {
                    delete userSessions[sender];
                    return await sock.sendMessage(from, { text: "❌ Terjadi kesalahan produk. Transaksi dibatalkan." });
                }

                let prodPrice = prodInfo.harga;

                // Cek Saldo
                if (db[sender].saldo < prodPrice) {
                    delete userSessions[sender];
                    return await sock.sendMessage(from, { text: `❌ Saldo Anda tidak cukup!\n\n💳 Harga: Rp ${prodPrice.toLocaleString('id-ID')}\n💰 Saldo Anda: Rp ${db[sender].saldo.toLocaleString('id-ID')}\n\nSilakan isi saldo terlebih dahulu.` });
                }

                // Potong Saldo (Simulasi Order Berhasil)
                db[sender].saldo -= prodPrice;
                saveJSON(dbFile, db);
                
                delete userSessions[sender]; // Hapus daya ingat setelah selesai

                // Nanti integrasi Digiflazz dipasang di antara dua pesan ini
                await sock.sendMessage(from, { text: `⏳ Pesanan sedang diproses...\n\n📦 Produk: ${prodInfo.nama}\n📱 Tujuan: ${targetNumber}` });
                
                return await sock.sendMessage(from, { text: `✅ *Pesanan Berhasil!* (Simulasi)\n\nSisa saldo Anda: Rp ${db[sender].saldo.toLocaleString('id-ID')}` });
            }
        }

        // 3. FITUR ORDER PINTAR (Jika pelanggan hanya mengetik angka murni)
        if (/^\d+$/.test(body.trim())) {
            let index = parseInt(body.trim()) - 1;
            
            // Cek apakah angka yang diketik sesuai dengan nomor urut produk
            if (index >= 0 && index < keys.length) {
                let prodKey = keys[index];
                let prodInfo = produkDB[prodKey];
                
                // Simpan Sesi
                userSessions[sender] = {
                    step: 'awaiting_target',
                    productKey: prodKey
                };

                return await sock.sendMessage(from, { text: `🛒 Anda memilih:\n*${prodInfo.nama}*\n💰 Harga: Rp ${prodInfo.harga.toLocaleString('id-ID')}\n\n👉 *Silakan balas pesan ini dengan Nomor Tujuan* (Contoh: 08123456789 atau ID Game).\n\n_Ketik *batal* jika ingin membatalkan._` });
            }
        }

        // MENU STANDAR
        if (command === '.menu') {
            await sock.sendMessage(from, { 
                text: `👋 Selamat Datang di *${namaBot}*\n📌 *ID Member:* ${sender}\n\n1. *.saldo* (Cek saldo)\n2. *.harga* (Lihat & Beli Produk)\n\n_Ketik perintah di atas untuk menggunakan bot._`
            });
        }

        if (command === '.saldo') {
            await sock.sendMessage(from, { 
                text: `💰 Saldo Anda saat ini: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` 
            });
        }

        // FORMAT DAFTAR HARGA BARU YANG LEBIH CLEAN
        if (command === '.harga') {
            if (keys.length === 0) return await sock.sendMessage(from, { text: `🛒 Maaf, belum ada produk yang tersedia saat ini.`});

            let textHarga = `🛒 *DAFTAR PRODUK ${namaBot}*\n\n`;
            keys.forEach((k, i) => {
                textHarga += `*${i+1}. ${produkDB[k].nama}*\n`;
                textHarga += `   Harga: *Rp ${produkDB[k].harga.toLocaleString('id-ID')}*\n\n`;
            });
            textHarga += `💡 *Cara Beli:* Ketik angka produknya saja.\n_(Contoh: ketik *1* untuk membeli ${produkDB[keys[0]].nama})_`;
            
            await sock.sendMessage(from, { text: textHarga.trim() });
        }
    });

    if (global.broadcastInterval) clearInterval(global.broadcastInterval);
    global.broadcastInterval = setInterval(async () => {
        if (fs.existsSync('./broadcast.txt')) {
            let textBroadcast = fs.readFileSync('./broadcast.txt', 'utf-8');
            fs.unlinkSync('./broadcast.txt');
            if (textBroadcast.trim()) {
                let db = loadJSON(dbFile);
                for (let num of Object.keys(db)) {
                    try {
                        await sock.sendMessage(db[num].jid, { text: `📢 *INFORMASI ${loadJSON(configFile).botName}*\n\n${textBroadcast.trim()}` });
                        await new Promise(res => setTimeout(res, 3000));
                    } catch (err) {}
                }
            }
        }
    }, 5000);
}

if (require.main === module) startBot().catch(err => console.error(err));
EOF
}

# ==========================================
# 3. FUNGSI INSTALASI DEPENDENSI
# ==========================================
install_dependencies() {
    clear
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y curl git wget nano zip unzip
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    sudo npm install -g npm@11.11.0
    sudo npm install -g pm2
    generate_bot_script
    if [ ! -f "package.json" ]; then npm init -y; fi
    rm -rf node_modules package-lock.json
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser
    echo "✅ INSTALASI SELESAI!"
    read -p "Tekan Enter..."
}

# ==========================================
# (FUNGSI SUB-MENU LAINNYA TETAP SAMA)
# ==========================================
menu_member() {
    while true; do
        clear
        echo "--- 👥 MANAJEMEN MEMBER ---"
        echo "1. Tambah Saldo | 2. Kurangi Saldo | 3. List Member | 0. Kembali"
        read -p "Pilih [0-3]: " sub
        case $sub in
            1) read -p "ID Member: " nom; read -p "Jumlah: " jum; node -e "const fs=require('fs'); let d=JSON.parse(fs.readFileSync('database.json')); let t='$nom'; if(!d[t]) d[t]={saldo:0, jid:t+'@s.whatsapp.net'}; d[t].saldo+=parseInt('$jum'); fs.writeFileSync('database.json', JSON.stringify(d,null,2)); console.log('✅ Sukses!');"; read -p "Enter..." ;;
            2) read -p "ID Member: " nom; read -p "Jumlah Kurangi: " jum; node -e "const fs=require('fs'); let d=JSON.parse(fs.readFileSync('database.json')); let t='$nom'; if(d[t]){ d[t].saldo-=parseInt('$jum'); if(d[t].saldo<0)d[t].saldo=0; fs.writeFileSync('database.json', JSON.stringify(d,null,2)); console.log('✅ Sukses!');}"; read -p "Enter..." ;;
            3) node -e "const fs=require('fs'); let d=JSON.parse(fs.readFileSync('database.json')); Object.keys(d).forEach((m,i)=>console.log((i+1)+'. ID: '+m+' | Rp '+d[m].saldo.toLocaleString('id-ID')));"; read -p "Enter..." ;;
            0) break ;;
        esac
    done
}

menu_produk() {
    while true; do
        clear
        echo "--- 🛒 MANAJEMEN PRODUK ---"
        echo "1. Tambah/Edit Produk | 2. Hapus Produk | 3. List Produk | 0. Kembali"
        read -p "Pilih [0-3]: " ps
        case $ps in
            1) read -p "Kode: " k; read -p "Nama: " n; read -p "Harga Jual: " h; node -e "const fs=require('fs'); let p=JSON.parse(fs.readFileSync('produk.json')); p['$k'.toUpperCase().replace(/\s+/g,'')]={nama:'$n', harga:parseInt('$h')}; fs.writeFileSync('produk.json', JSON.stringify(p,null,2)); console.log('✅ Sukses!');"; read -p "Enter..." ;;
            2) read -p "Kode Hapus: " k; node -e "const fs=require('fs'); let p=JSON.parse(fs.readFileSync('produk.json')); delete p['$k'.toUpperCase()]; fs.writeFileSync('produk.json', JSON.stringify(p,null,2)); console.log('✅ Sukses dihapus!');"; read -p "Enter..." ;;
            3) node -e "const fs=require('fs'); let p=JSON.parse(fs.readFileSync('produk.json')); Object.keys(p).forEach((k,i)=>console.log((i+1)+'. ['+k+'] '+p[k].nama+' - Rp '+p[k].harga.toLocaleString('id-ID')));"; read -p "Enter..." ;;
            0) break ;;
        esac
    done
}

menu_telegram() {
    clear
    echo "--- ⚙️ SETUP TELEGRAM ---"
    read -p "Token Bot Telegram: " tk; read -p "Chat ID: " cid; read -p "Auto Backup tiap 12 Jam? (y/n): " ab
    st="false"; if [ "$ab" == "y" ]; then st="true"; fi
    node -e "const fs=require('fs'); let c=JSON.parse(fs.readFileSync('config.json')); c.teleToken='$tk'; c.teleChatId='$cid'; c.autoBackup=$st; fs.writeFileSync('config.json', JSON.stringify(c,null,2)); console.log('✅ Tersimpan!');"
    read -p "Enter..."
}

menu_backup() {
    clear
    echo "--- 💾 BACKUP & RESTORE ---"
    echo "1. Backup ke Telegram | 2. Restore dari Link"
    read -p "Pilih: " bs
    if [ "$bs" == "1" ]; then
        rm -f backup.zip && zip backup.zip *.js *.json *.sh > /dev/null
        node -e "const fs=require('fs'); const {exec}=require('child_process'); let c=JSON.parse(fs.readFileSync('config.json')); if(c.teleToken){ exec(\`curl -s -F chat_id=\"\${c.teleChatId}\" -F document=@\"backup.zip\" https://api.telegram.org/bot\${c.teleToken}/sendDocument\`); console.log('✅ Backup super ringan dikirim ke Telegram!'); }"
        read -p "Enter..."
    elif [ "$bs" == "2" ]; then
        read -p "Link ZIP: " l; wget -O r.zip "$l" && unzip -o r.zip && npm install && echo "✅ Restore Selesai!"; read -p "Enter..."
    fi
}

# ==========================================
# 8. MENU UTAMA (PANEL KONTROL)
# ==========================================
while true; do
    clear
    echo "==============================================="
    echo "      🤖 PANEL PENGELOLA TENDO STORE 🤖      "
    echo "==============================================="
    echo "1. Install & Buat File Bot Otomatis"
    echo "2. Mulai Bot (Terminal)"
    echo "3. Jalankan Bot di Latar Belakang (PM2)"
    echo "4. Hentikan Bot (PM2)"
    echo "5. Lihat Log / Error Bot"
    echo "-----------------------------------------------"
    echo "6. 👥 Manajemen Member & Saldo"
    echo "7. 🛒 Manajemen Produk & Harga"
    echo "8. ⚙️ Setup Telegram & Backup"
    echo "9. 🔌 Ganti API Digiflazz"
    echo "10. 🔄 Reset Sesi WA"
    echo "0. Keluar"
    echo "==============================================="
    read -p "Pilih menu [0-10]: " choice

    case $choice in
        1) install_dependencies ;;
        2) node index.js; read -p "Enter..." ;;
        3) pm2 start index.js --name "tendo-bot" && pm2 save; sleep 2 ;;
        4) pm2 stop tendo-bot; sleep 2 ;;
        5) pm2 logs tendo-bot ;;
        6) menu_member ;;
        7) menu_produk ;;
        8) menu_telegram; menu_backup ;;
        9) read -p "User Digiflazz: " u; read -p "API Key Digiflazz: " k; node -e "const fs=require('fs'); let c=JSON.parse(fs.readFileSync('config.json')); c.digiflazzUsername='$u'; c.digiflazzApiKey='$k'; fs.writeFileSync('config.json', JSON.stringify(c,null,2)); console.log('✅ Tersimpan!');"; read -p "Enter..." ;;
        10) pm2 stop tendo-bot 2>/dev/null; rm -rf sesi_bot; echo "✅ Sesi dihapus!"; read -p "Enter..." ;;
        0) exit 0 ;;
    esac
done
