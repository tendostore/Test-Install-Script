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
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason } = require('@whiskeysockets/baileys');
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

if (!fs.existsSync(configFile)) saveJSON(configFile, { botName: "Tendo Store", botNumber: "", adminNumber: "", digiflazzUsername: "", digiflazzApiKey: "" });
if (!fs.existsSync(dbFile)) saveJSON(dbFile, {});

// Mencegah permintaan kode tautan berkali-kali (Anti-Spam)
let isPairingRequested = false; 

async function startBot() {
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    let config = loadJSON(configFile);
    
    const sock = makeWASocket({
        auth: state,
        logger: pino({ level: 'silent' }),
        browser: ['Ubuntu', 'Chrome', '20.0.04'],
        printQRInTerminal: false 
    });

    // SISTEM LOGIN KODE TAUTAN (Sangat Stabil)
    if (!sock.authState.creds.registered && !isPairingRequested) {
        isPairingRequested = true;
        let phoneNumber = config.botNumber;
        
        if (!phoneNumber) {
            console.log('\n❌ NOMOR BOT BELUM DIATUR!');
            console.log('Tutup bot ini (CTRL+C), lalu pilih Menu 2 untuk memasukkan nomor WA Bot Anda.');
            process.exit(0);
        }

        setTimeout(async () => {
            try {
                let formattedNumber = phoneNumber.replace(/[^0-9]/g, '');
                const code = await sock.requestPairingCode(formattedNumber);
                console.log(`\n=======================================================`);
                console.log(`🔑 KODE TAUTAN ANDA :  ${code}  `);
                console.log(`=======================================================`);
                console.log('1. Buka aplikasi WhatsApp di HP Anda.');
                console.log('2. Klik titik 3 di kanan atas -> Perangkat Tertaut.');
                console.log('3. Klik tombol "Tautkan Perangkat".');
                console.log('4. DI BAWAH layar kamera, klik "Tautkan dengan nomor telepon saja".');
                console.log('5. Masukkan 8 huruf KODE TAUTAN di atas.\n');
            } catch (error) {
                console.log('❌ Gagal mendapatkan kode. Pastikan format nomor benar (awali 628).');
                isPairingRequested = false;
            }
        }, 3000);
    }

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;

        if (connection === 'close') {
            let reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
            
            // PERBAIKAN: Tidak lagi menghapus folder secara barbar agar terhindar dari error ENOENT
            if (reason === DisconnectReason.loggedOut) {
                console.log('❌ WhatsApp dikeluarkan (Logged Out). Silakan pilih Menu 9 untuk Reset Sesi.');
                process.exit(0);
            } else {
                console.log(`⚠️ Jaringan terputus sejenak (Kode: ${reason}). Mencoba menyambung kembali dengan aman...`);
                setTimeout(startBot, 3000);
            }
        } else if (connection === 'open') {
            console.log('\n✅ BOT WHATSAPP BERHASIL TERHUBUNG!');
        }
    });

    sock.ev.on('messages.upsert', async m => {
        const msg = m.messages[0];
        if (!msg.message || msg.key.fromMe) return;

        const from = msg.key.remoteJid;
        const sender = msg.key.participant || msg.key.remoteJid;
        const body = msg.message.conversation || msg.message.extendedTextMessage?.text || "";
        const command = body.split(' ')[0].toLowerCase();
        
        let config = loadJSON(configFile);
        let db = loadJSON(dbFile);

        if (!db[sender]) {
            if (command.startsWith('.')) {
                await sock.sendMessage(from, { 
                    text: `❌ *AKSES DITOLAK*\n\nMaaf, nomor Anda belum terdaftar sebagai member di *${config.botName}*.\nSilakan hubungi Admin untuk pendaftaran.` 
                });
            }
            return;
        }

        if (command === '.menu') {
            await sock.sendMessage(from, { 
                text: `👋 Selamat Datang kembali di *${config.botName}*\n\n1. *.saldo* (Cek saldo)\n2. *.order* [kode] [tujuan]\n3. *.harga* (Cek harga)\n\n_Ketik perintah di atas untuk menggunakan bot._`
            });
        }

        if (command === '.saldo') {
            await sock.sendMessage(from, { 
                text: `💰 Saldo Anda saat ini: *Rp ${db[sender].saldo.toLocaleString('id-ID')}*` 
            });
        }
    });

    setInterval(async () => {
        if (fs.existsSync('./broadcast.txt')) {
            let textBroadcast = fs.readFileSync('./broadcast.txt', 'utf-8');
            fs.unlinkSync('./broadcast.txt');

            if (textBroadcast.trim()) {
                let db = loadJSON(dbFile);
                let members = Object.keys(db);
                
                for (let jid of members) {
                    try {
                        await sock.sendMessage(jid, { text: `📢 *INFORMASI ${loadJSON(configFile).botName}*\n\n${textBroadcast.trim()}` });
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

app.listen(3000, () => console.log('🌐 Server Webhook berjalan di Port 3000'));
startBot();
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
# 4. MENU UTAMA (PANEL KONTROL)
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
    echo "--- MANAJEMEN MEMBER & DATABASE ---"
    echo "6. Tambah Member Baru (Akses Bot)"
    echo "7. Tambah Saldo Member"
    echo "8. Ganti API Digiflazz"
    echo "9. Ganti Akun Bot WhatsApp (Reset Sesi)"
    echo "10. 📢 Kirim Pesan Broadcast ke Semua Member"
    echo "0. Keluar"
    echo "==============================================="
    read -p "Pilih menu [0-10]: " choice

    case $choice in
        1) install_dependencies ;;
        2) 
            if [ ! -f "index.js" ]; then echo "❌ Anda harus menjalankan Menu 1 dulu!"; sleep 2; continue; fi
            
            # MEMINTA NOMOR DI BASH DENGAN AMAN
            if [ ! -d "sesi_bot" ] || [ -z "$(ls -A sesi_bot 2>/dev/null)" ]; then
                echo -e "\n--- PERSIAPAN LOGIN BARU ---"
                read -p "📲 Masukkan Nomor WA Bot (Awali 628...): " nomor_bot
                if [ ! -z "$nomor_bot" ]; then
                    node -e "
                        const fs = require('fs');
                        if(!fs.existsSync('config.json')) fs.writeFileSync('config.json', '{}');
                        let config = JSON.parse(fs.readFileSync('config.json'));
                        config.botNumber = '$nomor_bot';
                        fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                    "
                fi
            fi

            echo -e "\nMenjalankan bot... (Tekan CTRL+C untuk mematikan)"
            node index.js
            echo -e "\n⚠️ Proses bot terhenti."
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
        6)
            echo "--- TAMBAH MEMBER BARU ---"
            read -p "Masukkan Nomor WA (contoh: 62812...): " nomor
            node -e "
                const fs = require('fs');
                if(!fs.existsSync('database.json')) fs.writeFileSync('database.json', '{}');
                let db = JSON.parse(fs.readFileSync('database.json'));
                let target = '$nomor@s.whatsapp.net';
                if(db[target]) {
                    console.log('⚠️ Nomor tersebut sudah terdaftar!');
                } else {
                    db[target] = { saldo: 0, tanggal_daftar: new Date().toLocaleDateString('id-ID') };
                    fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                    console.log('\n✅ Nomor $nomor berhasil didaftarkan!');
                }
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        7)
            echo "--- TAMBAH SALDO MEMBER ---"
            read -p "Masukkan Nomor WA (contoh: 62812...): " nomor
            read -p "Masukkan Jumlah Saldo: " jumlah
            node -e "
                const fs = require('fs');
                if(!fs.existsSync('database.json')) fs.writeFileSync('database.json', '{}');
                let db = JSON.parse(fs.readFileSync('database.json'));
                let target = '$nomor@s.whatsapp.net';
                if(!db[target]) {
                    console.log('❌ Gagal: Nomor belum terdaftar!');
                } else {
                    db[target].saldo += parseInt('$jumlah');
                    fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                    console.log('\n✅ Saldo Rp $jumlah berhasil ditambahkan!');
                }
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        8)
            echo "--- PENGATURAN API DIGIFLAZZ ---"
            read -p "Username Digiflazz Baru: " user_api
            read -p "API Key Digiflazz Baru: " key_api
            node -e "
                const fs = require('fs');
                if(!fs.existsSync('config.json')) fs.writeFileSync('config.json', '{}');
                let config = JSON.parse(fs.readFileSync('config.json'));
                config.digiflazzUsername = '$user_api';
                config.digiflazzApiKey = '$key_api';
                fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                console.log('\n✅ Konfigurasi API Digiflazz berhasil disimpan!');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        9)
            echo "⚠️  Ini akan menghapus sesi login WhatsApp saat ini."
            read -p "Lanjutkan? (y/n): " konfirmasi
            if [ "$konfirmasi" == "y" ] || [ "$konfirmasi" == "Y" ]; then
                pm2 stop tendo-bot 2>/dev/null
                rm -rf sesi_bot
                echo "✅ Sesi dihapus! Silakan pilih menu 2 untuk Login Ulang."
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        10)
            echo "--- 📢 BROADCAST PESAN ---"
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
