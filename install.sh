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

const app = express();
app.use(bodyParser.json());

const configFile = './config.json';
const dbFile = './database.json';

const loadJSON = (file) => fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
const saveJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

let configAwal = loadJSON(configFile);
configAwal.botName = configAwal.botName || "Tendo Store";
configAwal.botNumber = configAwal.botNumber || "";
saveJSON(configFile, configAwal);

if (!fs.existsSync(dbFile)) saveJSON(dbFile, {});

let pairingRequested = false; 

async function startBot() {
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = loadJSON(configFile);
    
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
            console.log('\n❌ NOMOR BOT BELUM DIATUR! Keluar...');
            process.exit(0);
        }

        setTimeout(async () => {
            try {
                let formattedNumber = phoneNumber.replace(/[^0-9]/g, '');
                const code = await sock.requestPairingCode(formattedNumber);
                console.log(`\n=======================================================`);
                console.log(`🔑 KODE TAUTAN ANDA :  ${code}  `);
                console.log(`=======================================================`);
                console.log('👉 Buka WA di HP -> Perangkat Tertaut -> Tautkan dengan nomor telepon saja.');
                console.log('⚠️ SEGERA MASUKKAN KODENYA KE HP ANDA!\n');
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
            console.log('\n✅ BOT WHATSAPP BERHASIL TERHUBUNG DENGAN AMAN!');
        }
    });

    sock.ev.on('messages.upsert', async m => {
        const msg = m.messages[0];
        if (!msg.message || msg.key.fromMe) return;

        const from = msg.key.remoteJid;
        const senderJid = jidNormalizedUser(msg.key.participant || msg.key.remoteJid);
        
        // Mengambil angka murni sebagai ID Member
        const sender = senderJid.split('@')[0]; 
        
        const body = msg.message.conversation || msg.message.extendedTextMessage?.text || "";
        const command = body.split(' ')[0].toLowerCase();
        
        let config = loadJSON(configFile);
        let namaBot = config.botName || "Tendo Store";
        let db = loadJSON(dbFile);

        if (!db[sender]) {
            db[sender] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: senderJid };
            saveJSON(dbFile, db);
        }

        // PERUBAHAN: Menu menampilkan ID, Saldo hanya menampilkan saldo
        if (command === '.menu') {
            await sock.sendMessage(from, { 
                text: `👋 Selamat Datang di *${namaBot}*\n📌 *ID Member:* ${sender}\n\n1. *.saldo* (Cek saldo)\n2. *.order* [kode] [tujuan]\n3. *.harga* (Cek harga)\n\n_Ketik perintah di atas untuk menggunakan bot._`
            });
        }

        if (command === '.saldo') {
            await sock.sendMessage(from, { 
                text: `💰 Saldo Anda saat ini: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` 
            });
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
    
    app.post('/webhook', async (req, res) => {
        res.sendStatus(200);
    });
}

if (require.main === module) {
    app.listen(3000, () => console.log('🌐 Server Webhook berjalan di Port 3000'));
    startBot();
}
EOF
}

# ==========================================
# 3. FUNGSI INSTALASI DEPENDENSI
# ==========================================
install_dependencies() {
    clear
    echo "==============================================="
    echo "      🚀 MENGINSTALL SISTEM BOT 🚀      "
    echo "==============================================="
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y curl git wget nano
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    sudo npm install -g npm@11.11.0
    sudo npm install -g pm2
    generate_bot_script
    if [ ! -f "package.json" ]; then npm init -y; fi
    rm -rf node_modules package-lock.json
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser
    echo "==============================================="
    echo " ✅ INSTALASI SELESAI! "
    echo "==============================================="
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}

# ==========================================
# 4. SUB-MENU MANAJEMEN MEMBER
# ==========================================
menu_member() {
    while true; do
        clear
        echo "==============================================="
        echo "          👥 MANAJEMEN MEMBER BOT 👥           "
        echo "==============================================="
        echo "1. Tambah Saldo Member"
        echo "2. Kurangi Saldo Member"
        echo "3. Lihat Daftar Semua Member"
        echo "0. Kembali ke Menu Utama"
        echo "==============================================="
        read -p "Pilih menu [0-3]: " subchoice

        case $subchoice in
            1)
                echo "--- TAMBAH SALDO MEMBER ---"
                read -p "Masukkan ID Member (Sesuai yg tampil di bot): " nomor
                read -p "Masukkan Jumlah Saldo: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let target = '$nomor';
                    if(!db[target]) {
                        db[target] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID'), jid: target + '@s.whatsapp.net' };
                    }
                    db[target].saldo += parseInt('$jumlah');
                    fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                    console.log('\n✅ Saldo Rp $jumlah berhasil ditambahkan ke ID ' + target + '!');
                    console.log('💰 Saldo saat ini: Rp ' + db[target].saldo.toLocaleString('id-ID'));
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            2)
                echo "--- KURANGI SALDO MEMBER ---"
                read -p "Masukkan ID Member: " nomor
                read -p "Masukkan Jumlah Saldo yg dikurangi: " jumlah
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let target = '$nomor';
                    if(!db[target]) {
                        console.log('\n❌ ID belum terdaftar di database.');
                    } else {
                        db[target].saldo -= parseInt('$jumlah');
                        if(db[target].saldo < 0) db[target].saldo = 0;
                        fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                        console.log('\n✅ Saldo berhasil dikurangi!');
                        console.log('💰 Saldo saat ini: Rp ' + db[target].saldo.toLocaleString('id-ID'));
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            3)
                echo "--- DAFTAR MEMBER TERDAFTAR ---"
                node -e "
                    const fs = require('fs');
                    let db = fs.existsSync('database.json') ? JSON.parse(fs.readFileSync('database.json')) : {};
                    let members = Object.keys(db);
                    if(members.length === 0) {
                        console.log('Belum ada member yang berinteraksi dengan bot.');
                    } else {
                        members.forEach((m, index) => {
                            console.log((index + 1) + '. ID: ' + m + ' | Saldo: Rp ' + db[m].saldo.toLocaleString('id-ID'));
                        });
                        console.log('\nTotal Member: ' + members.length);
                    }
                "
                read -p "Tekan Enter untuk kembali..."
                ;;
            0) break ;;
            *) echo "❌ Pilihan tidak valid!"; sleep 1 ;;
        esac
    done
}

# ==========================================
# 5. MENU UTAMA (PANEL KONTROL)
# ==========================================
while true; do
    clear
    echo "==============================================="
    echo "      🤖 PANEL PENGELOLA TENDO STORE 🤖      "
    echo "==============================================="
    echo "--- MANAJEMEN BOT ---"
    echo "1. Install & Buat File Bot Otomatis"
    echo "2. Mulai Bot (Login Pakai Kode Tautan)"
    echo "3. Jalankan Bot di Latar Belakang (PM2)"
    echo "4. Hentikan Bot (PM2)"
    echo "5. Lihat Log / Error Bot"
    echo ""
    echo "--- PENGATURAN LAINNYA ---"
    echo "6. 👥 Buka Menu Manajemen Member"
    echo "7. Ganti API Digiflazz"
    echo "8. Ganti Akun Bot WhatsApp (Reset Sesi)"
    echo "9. 📢 Kirim Pesan Broadcast ke Semua Member"
    echo "0. Keluar"
    echo "==============================================="
    read -p "Pilih menu [0-9]: " choice

    case $choice in
        1) install_dependencies ;;
        2) 
            if [ ! -f "index.js" ]; then echo "❌ Anda harus menjalankan Menu 1 dulu!"; sleep 2; continue; fi
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
            node index.js
            read -p "Tekan Enter untuk kembali ke menu utama..."
            ;;
        3) 
            pm2 start index.js --name "tendo-bot"
            pm2 save
            pm2 startup
            echo "✅ Bot berhasil berjalan di latar belakang!"
            sleep 2 ;;
        4) pm2 stop tendo-bot; sleep 2 ;;
        5) pm2 logs tendo-bot ;;
        6) menu_member ;;
        7)
            read -p "Username Digiflazz Baru: " user_api
            read -p "API Key Digiflazz Baru: " key_api
            node -e "
                const fs = require('fs');
                let config = fs.existsSync('config.json') ? JSON.parse(fs.readFileSync('config.json')) : {};
                config.digiflazzUsername = '$user_api';
                config.digiflazzApiKey = '$key_api';
                fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                console.log('\n✅ Konfigurasi API Digiflazz berhasil disimpan!');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        8)
            echo "⚠️  Ini akan menghapus sesi login WhatsApp saat ini."
            read -p "Lanjutkan? (y/n): " konfirmasi
            if [ "$konfirmasi" == "y" ] || [ "$konfirmasi" == "Y" ]; then
                pm2 stop tendo-bot 2>/dev/null
                rm -rf sesi_bot
                echo "✅ Sesi dihapus! Silakan pilih menu 2 untuk Login Ulang."
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        9)
            echo "Gunakan \n untuk baris baru."
            read -p "Ketik Pesan Broadcast: " pesan_bc
            if [ ! -z "$pesan_bc" ]; then
                echo -e "$pesan_bc" > broadcast.txt
                echo -e "\n✅ Pesan berhasil masuk antrean broadcast!"
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        0) echo "Keluar dari panel. Sampai jumpa!"; exit 0 ;;
        *) echo "❌ Pilihan tidak valid!"; sleep 2 ;;
    esac
done
