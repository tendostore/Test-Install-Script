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
const readline = require('readline');

const app = express();
app.use(bodyParser.json());

const configFile = './config.json';
const dbFile = './database.json';

const loadJSON = (file) => fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
const saveJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

if (!fs.existsSync(configFile)) saveJSON(configFile, { botName: "Tendo Store", adminNumber: "", digiflazzUsername: "", digiflazzApiKey: "" });
if (!fs.existsSync(dbFile)) saveJSON(dbFile, {});

// Fungsi untuk membaca input dari terminal
const question = (text) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(text, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
};

async function startBot() {
    const { state, saveCreds } = await useMultiFileAuthState('sesi_bot');
    
    const sock = makeWASocket({
        auth: state,
        logger: pino({ level: 'silent' }),
        browser: ['Ubuntu', 'Chrome', '20.0.04'],
        printQRInTerminal: false // MATIKAN QR CODE AGAR TIDAK ERROR 405
    });

    // SISTEM LOGIN BARU: MENGGUNAKAN KODE TAUTAN (PAIRING CODE)
    if (!sock.authState.creds.registered) {
        setTimeout(async () => {
            console.log("\n=======================================================");
            let phoneNumber = await question('📲 Masukkan Nomor WA Bot Anda (Awali dengan 628...): ');
            phoneNumber = phoneNumber.replace(/[^0-9]/g, '');
            
            try {
                const code = await sock.requestPairingCode(phoneNumber);
                console.log(`\n🔑 KODE TAUTAN ANDA :  ${code}  `);
                console.log('\n[CARA LOGIN DI HP ANDA]:');
                console.log('1. Buka aplikasi WhatsApp di HP yang nomornya dijadikan bot.');
                console.log('2. Klik titik 3 di kanan atas -> Perangkat Tertaut.');
                console.log('3. Klik tombol "Tautkan Perangkat".');
                console.log('4. DI BAWAH layar kamera, klik "Tautkan dengan nomor telepon saja".');
                console.log('5. Masukkan 8 huruf KODE TAUTAN di atas.');
                console.log("=======================================================\n");
            } catch (error) {
                console.log('❌ Gagal mendapatkan kode. Pastikan nomor benar dan tidak memakai spasi/+.');
            }
        }, 3000);
    }

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;

        if (connection === 'close') {
            let reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
            
            if (reason === DisconnectReason.badSession || reason === 405) {
                console.log('❌ Sesi ditolak server (Error 405). Menghapus otomatis dan mengulang...');
                fs.rmSync('./sesi_bot', { recursive: true, force: true });
                setTimeout(startBot, 2000);
            } else if (reason === DisconnectReason.connectionClosed) {
                console.log('⚠️ Koneksi ditutup, mencoba menyambung ulang...');
                setTimeout(startBot, 3000);
            } else if (reason === DisconnectReason.connectionLost) {
                console.log('⚠️ Kehilangan koneksi server, menyambung ulang...');
                setTimeout(startBot, 3000);
            } else if (reason === DisconnectReason.loggedOut) {
                console.log('❌ WhatsApp dikeluarkan (Logged Out). Hapus sesi dan login ulang.');
                fs.rmSync('./sesi_bot', { recursive: true, force: true });
                setTimeout(startBot, 2000);
            } else if (reason === DisconnectReason.restartRequired) {
                console.log('🔄 Server meminta restart...');
                startBot();
            } else {
                console.log(`⚠️ Terputus (Kode Error: ${reason}). Mencoba lagi...`);
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
                
                console.log(`\n📢 Memulai Broadcast ke ${members.length} member...`);
                for (let jid of members) {
                    try {
                        await sock.sendMessage(jid, { text: `📢 *INFORMASI ${loadJSON(configFile).botName}*\n\n${textBroadcast.trim()}` });
                        await new Promise(res => setTimeout(res, 3000));
                    } catch (err) {
                        console.log(`❌ Gagal kirim ke ${jid}`);
                    }
                }
                console.log('✅ Broadcast Selesai!\n');
            }
        }
    }, 5000);
    
    app.post('/webhook', async (req, res) => {
        console.log("🔔 Webhook Digiflazz Masuk:", req.body);
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
    echo "Memperbarui sistem VPS..."
    sudo apt update && sudo apt upgrade -y

    echo "Menginstall Node.js & Tools..."
    sudo apt install -y curl git wget nano
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    echo "Memperbarui versi NPM ke 11.11.0..."
    sudo npm install -g npm@11.11.0
    
    echo "Menginstall PM2 Process Manager..."
    sudo npm install -g pm2

    echo "Membuat file konfigurasi bot..."
    generate_bot_script
    
    if [ ! -f "package.json" ]; then
        npm init -y
    fi
    
    echo "Membersihkan cache sistem untuk mencegah error..."
    rm -rf node_modules package-lock.json
    
    echo "Menginstall library Bot WhatsApp..."
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
            echo "Menjalankan bot... (Tekan CTRL+C untuk mematikan)"
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
