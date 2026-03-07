#!/bin/bash

# Fungsi untuk proses instalasi dependensi
install_dependencies() {
    clear
    echo "==============================================="
    echo "      🚀 MENGINSTALL DEPENDENSI SISTEM 🚀      "
    echo "==============================================="
    echo "Memperbarui sistem VPS..."
    sudo apt update && sudo apt upgrade -y

    echo "Menginstall curl, wget, nano, dan Node.js..."
    sudo apt install -y curl git wget nano
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs

    echo "Menginstall PM2 Process Manager..."
    sudo npm install -g pm2

    echo "Menginstall library Bot WhatsApp..."
    if [ ! -f "package.json" ]; then
        npm init -y
    fi
    npm install @whiskeysockets/baileys pino qrcode-terminal axios express body-parser

    # Membuat file dasar jika belum ada
    if [ ! -f "config.json" ]; then
        echo '{"botName": "Tendo Store", "adminNumber": "", "digiflazzUsername": "", "digiflazzApiKey": ""}' > config.json
    fi
    if [ ! -f "database.json" ]; then
        echo '{}' > database.json
    fi

    echo "==============================================="
    echo " ✅ INSTALASI SELESAI! "
    echo "==============================================="
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}

# Looping Menu Utama
while true; do
    clear
    echo "==============================================="
    echo "      🤖 PANEL PENGELOLA TENDO STORE 🤖      "
    echo "==============================================="
    echo "--- MANAJEMEN BOT ---"
    echo "1. Install / Update Dependensi Bot"
    echo "2. Mulai Bot (Terminal / Scan QR Code)"
    echo "3. Jalankan Bot di Latar Belakang (PM2)"
    echo "4. Hentikan Bot (PM2)"
    echo "5. Lihat Log / Error Bot"
    echo ""
    echo "--- PENGATURAN & DATABASE ---"
    echo "6. Tambah Saldo Member"
    echo "7. Ganti API Digiflazz"
    echo "8. Ganti Akun Bot WhatsApp (Reset Sesi)"
    echo "0. Keluar"
    echo "==============================================="
    read -p "Pilih menu [0-8]: " choice

    case $choice in
        1)
            install_dependencies
            ;;
        2)
            echo "Menjalankan bot di terminal... (Tekan CTRL+C untuk mematikan)"
            node index.js
            ;;
        3)
            echo "Menjalankan bot dengan PM2..."
            pm2 start index.js --name "tendo-bot"
            pm2 save
            echo "Bot berhasil berjalan di latar belakang!"
            sleep 2
            ;;
        4)
            echo "Menghentikan bot..."
            pm2 stop tendo-bot
            sleep 2
            ;;
        5)
            echo "Membuka log PM2... (Tekan CTRL+C untuk keluar dari log)"
            pm2 logs tendo-bot
            ;;
        6)
            echo "--- TAMBAH SALDO MEMBER ---"
            read -p "Masukkan Nomor WA (contoh: 62812...): " nomor
            read -p "Masukkan Jumlah Saldo yang ditambahkan: " jumlah
            
            # Eksekusi Node.js satu baris untuk mengupdate database.json
            node -e "
                const fs = require('fs');
                let db = JSON.parse(fs.readFileSync('database.json'));
                let target = '$nomor@s.whatsapp.net';
                if(!db[target]) db[target] = { saldo: 0 };
                db[target].saldo += parseInt('$jumlah');
                fs.writeFileSync('database.json', JSON.stringify(db, null, 2));
                console.log('✅ Saldo berhasil ditambahkan! Saldo akhir: Rp ' + db[target].saldo);
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        7)
            echo "--- PENGATURAN API DIGIFLAZZ ---"
            read -p "Masukkan Username Digiflazz Baru: " user_api
            read -p "Masukkan API Key Digiflazz Baru: " key_api
            
            # Eksekusi Node.js untuk mengupdate config.json
            node -e "
                const fs = require('fs');
                let config = JSON.parse(fs.readFileSync('config.json'));
                config.digiflazzUsername = '$user_api';
                config.digiflazzApiKey = '$key_api';
                fs.writeFileSync('config.json', JSON.stringify(config, null, 2));
                console.log('✅ Konfigurasi API Digiflazz berhasil disimpan!');
            "
            read -p "Tekan Enter untuk kembali..."
            ;;
        8)
            echo "--- GANTI AKUN WHATSAPP ---"
            echo "⚠️  PERINGATAN: Ini akan menghapus sesi login WhatsApp saat ini."
            echo "Bot akan meminta Anda untuk Scan QR Code baru setelah ini."
            read -p "Apakah Anda yakin ingin melanjutkan? (y/n): " konfirmasi
            
            if [ "$konfirmasi" == "y" ] || [ "$konfirmasi" == "Y" ]; then
                # Hentikan PM2 dulu jika menyala agar tidak error
                pm2 stop tendo-bot 2>/dev/null
                # Hapus folder sesi (sesuaikan nama folder 'sesi_bot' dengan yang ada di script JS Anda)
                rm -rf sesi_bot
                echo "✅ Sesi lama berhasil dihapus!"
                echo "Silakan pilih menu nomor 2 untuk Scan QR Code dengan nomor baru."
            else
                echo "Dibatalkan."
            fi
            read -p "Tekan Enter untuk kembali..."
            ;;
        0)
            echo "Keluar dari panel pengelola. Sampai jumpa!"
            exit 0
            ;;
        *)
            echo "❌ Pilihan tidak valid! Silakan masukkan angka 0-8."
            sleep 2
            ;;
    esac
done
