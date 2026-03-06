# Menghapus perintah restart lama yang tertahan
sed -i '/Sedang me-restart layanan/d' /usr/bin/menu
sed -i '/nohup bash -c "sleep/d' /usr/bin/menu

# Mencegah duplikasi jika Anda menempelkan kode ini dua kali
sed -i '/systemctl restart xray >\/dev\/null 2>&1 &/d' /usr/bin/menu
sed -i '/systemctl restart zivpn >\/dev\/null 2>&1 &/d' /usr/bin/menu

# Menyisipkan auto-restart di latar belakang saat detail akun muncul
sed -i 's/function show_account_xray() {/function show_account_xray() {\n    systemctl restart xray >\/dev\/null 2>\&1 \&/g' /usr/bin/menu
sed -i 's/function show_account_zivpn() {/function show_account_zivpn() {\n    systemctl restart zivpn >\/dev\/null 2>\&1 \&/g' /usr/bin/menu

echo "Fix Auto-Restart VPS berhasil diterapkan!"
