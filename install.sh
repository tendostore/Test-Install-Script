#!/bin/bash
# ====================================================
# SCRIPT INSTALL TOKO ONLINE TAS & VPS PANEL MANAJEMEN
# ====================================================

echo "Memulai instalasi sistem Toko Tas..."

# 1. Update sistem dan install dependensi dasar
sudo apt update -y
sudo apt install -y curl build-essential

# 2. Install Node.js (Versi 20.x)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Install PM2 secara global untuk menjaga server tetap hidup di VPS
sudo npm install -y pm2 -g

# 4. Buat direktori proyek toko tas
mkdir -p /var/www/tokotas
cd /var/www/tokotas

# 5. Inisialisasi proyek Node.js dan install library yang dibutuhkan
npm init -y
npm install express sqlite3 ejs multer body-parser

# 6. Buat struktur folder untuk gambar dan tampilan web
mkdir -p public/uploads
mkdir -p views

# 7. Download gambar default/sementara agar error tidak terjadi saat pertama kali buka
wget -qO public/uploads/default.jpg https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=400

# 8. Buat file inisialisasi Database SQLite (init_db.js)
cat << 'EOF' > init_db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./tokotas.db');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, description TEXT, image_url TEXT)");
  
  // Masukkan data tas pertama sebagai contoh
  db.run("INSERT INTO products (name, price, description, image_url) VALUES ('Tas Ransel Kulit Premium', 250000, 'Tas ransel dengan bahan kulit sintetis berkualitas tinggi, cocok untuk kerja dan kuliah.', '/uploads/default.jpg')");
});

db.close();
console.log("Database toko tas berhasil dibuat.");
EOF

# Jalankan inisialisasi database
node init_db.js

# 9. Buat script utama server (server.js) - BERSIH DARI MENU UNINSTALL
cat << 'EOF' > server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');

const app = express();
const port = 80;

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));

const db = new sqlite3.Database('./tokotas.db');

// Konfigurasi sistem upload gambar
const storage = multer.diskStorage({
  destination: './public/uploads/',
  filename: function(req, file, cb){
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Rute: Halaman Utama Toko Tas (Frontend)
app.get('/', (req, res) => {
  db.all("SELECT * FROM products ORDER BY id DESC", [], (err, rows) => {
    if (err) throw err;
    res.render('index', { products: rows });
  });
});

// Rute: Panel Admin VPS (Manajemen Produk)
app.get('/vps-panel', (req, res) => {
  db.all("SELECT * FROM products ORDER BY id DESC", [], (err, rows) => {
    if (err) throw err;
    res.render('admin', { products: rows });
  });
});

// Aksi: Tambah Produk
app.post('/vps-panel/add', upload.single('image'), (req, res) => {
  const { name, price, description } = req.body;
  const imageUrl = req.file ? '/uploads/' + req.file.filename : '/uploads/default.jpg';
  
  db.run("INSERT INTO products (name, price, description, image_url) VALUES (?, ?, ?, ?)", 
    [name, price, description, imageUrl], 
    (err) => {
      if (err) throw err;
      res.redirect('/vps-panel');
  });
});

// Aksi: Hapus Produk
app.post('/vps-panel/delete/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", req.params.id, (err) => {
    if (err) throw err;
    res.redirect('/vps-panel');
  });
});

// Jalankan Server
app.listen(port, () => {
  console.log(`Server toko berjalan pada port ${port}`);
});
EOF

# 10. Buat Tampilan Halaman Toko (views/index.ejs)
cat << 'EOF' > views/index.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Katalog Tas Online</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #f4f7f6; margin: 0; padding: 0; }
    .nav { background: #2c3e50; color: white; padding: 20px; text-align: center; }
    .container { max-width: 1100px; margin: 30px auto; padding: 0 20px; }
    .product-grid { display: flex; flex-wrap: wrap; gap: 20px; justify-content: center; }
    .product-card { background: white; width: 250px; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
    .product-card img { width: 100%; height: 200px; object-fit: cover; }
    .product-info { padding: 15px; text-align: center; }
    .product-info h3 { margin: 10px 0; color: #333; }
    .price { color: #e67e22; font-size: 1.2em; font-weight: bold; }
    .wa-btn { display: block; background: #25d366; color: white; text-decoration: none; padding: 10px; border-radius: 5px; margin-top: 10px; font-weight: bold; }
  </style>
</head>
<body>
  <div class="nav">
    <h1>Toko Tas Online</h1>
  </div>
  <div class="container">
    <div class="product-grid">
      <% products.forEach(function(product) { %>
        <div class="product-card">
          <img src="<%= product.image_url %>">
          <div class="product-info">
            <h3><%= product.name %></h3>
            <p style="font-size: 0.9em; color: #666;"><%= product.description %></p>
            <div class="price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
            <a href="https://wa.me/6281234567890?text=Halo,%20saya%20mau%20beli%20<%= encodeURIComponent(product.name) %>" class="wa-btn">Order via WA</a>
          </div>
        </div>
      <% }); %>
    </div>
  </div>
</body>
</html>
EOF

# 11. Buat Tampilan Panel Admin VPS (views/admin.ejs) - BERSIH DARI MENU UNINSTALL
cat << 'EOF' > views/admin.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Panel Manajemen VPS</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #ecf0f1; padding: 20px; }
    .panel { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
    h2 { border-bottom: 2px solid #3498db; padding-bottom: 10px; color: #2c3e50; }
    .form-group { margin-bottom: 15px; }
    input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
    .btn-add { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
    .btn-delete { background: #e74c3c; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="panel">
    <h2>Manajemen Produk Tas</h2>
    <form action="/vps-panel/add" method="POST" enctype="multipart/form-data">
      <div class="form-group"><input type="text" name="name" placeholder="Nama Tas" required></div>
      <div class="form-group"><input type="number" name="price" placeholder="Harga (Contoh: 200000)" required></div>
      <div class="form-group"><textarea name="description" placeholder="Deskripsi Singkat"></textarea></div>
      <div class="form-group"><input type="file" name="image" required></div>
      <button type="submit" class="btn-add">+ Simpan Tas Baru</button>
    </form>

    <table>
      <tr>
        <th>Tas</th>
        <th>Harga</th>
        <th>Aksi</th>
      </tr>
      <% products.forEach(function(product) { %>
        <tr>
          <td><%= product.name %></td>
          <td>Rp <%= parseInt(product.price).toLocaleString('id-ID') %></td>
          <td>
            <form action="/vps-panel/delete/<%= product.id %>" method="POST">
              <button type="submit" class="btn-delete">Hapus</button>
            </form>
          </td>
        </tr>
      <% }); %>
    </table>
    <br>
    <a href="/" style="color: #3498db; text-decoration: none; font-weight: bold;">← Kembali ke Toko</a>
  </div>
</body>
</html>
EOF

# 12. MEMBUAT MENU COMMAND LINE DI TERMINAL VPS (toko)
cat << 'EOF' > /usr/local/bin/toko
#!/bin/bash
clear
echo "==================================================="
echo "         MENU MANAJEMEN TOKO TAS (VPS CLI)         "
echo "==================================================="
echo "1. Backup Website & Database"
echo "2. Restore Website & Database"
echo "3. Uninstall & Reset Sistem"
echo "4. Keluar"
echo "==================================================="
read -p "Pilih menu (1-4): " pilihan

case $pilihan in
  1)
    echo ""
    echo "Memproses Backup..."
    TANGGAL=$(date +%Y%m%d_%H%M%S)
    NAMA_BACKUP="/root/backup_tokotas_${TANGGAL}.tar.gz"
    tar -czvf $NAMA_BACKUP -C /var/www tokotas
    echo "==================================================="
    echo "Backup Berhasil!"
    echo "File tersimpan di: $NAMA_BACKUP"
    echo "==================================================="
    ;;
  2)
    echo ""
    echo "Daftar Backup Tersedia di /root/ :"
    ls -1 /root/backup_tokotas_*.tar.gz 2>/dev/null || echo "Belum ada file backup ditemukan."
    echo ""
    read -p "Masukkan NAMA FILE backup (contoh: backup_tokotas_2026...tar.gz) atau ketik 'batal': " file_restore
    if [ "$file_restore" == "batal" ]; then
      echo "Restore dibatalkan."
    elif [ -f "/root/$file_restore" ]; then
      echo "Memproses Restore..."
      pm2 stop tokotas
      rm -rf /var/www/tokotas
      tar -xzvf /root/$file_restore -C /var/www
      pm2 restart tokotas
      echo "==================================================="
      echo "Restore Berhasil! Website telah dipulihkan."
      echo "==================================================="
    else
      echo "File tidak ditemukan! Pastikan nama file benar."
    fi
    ;;
  3)
    echo ""
    echo "PERINGATAN BAHAYA!"
    echo "Ini akan menghapus seluruh file website, gambar, dan database toko."
    read -p "Ketik 'YAKIN' untuk melanjutkan uninstall: " konfirmasi
    if [ "$konfirmasi" == "YAKIN" ]; then
      echo "Menghapus sistem..."
      pm2 delete tokotas 2>/dev/null || true
      rm -rf /var/www/tokotas
      echo "==================================================="
      echo "Uninstall Selesai! VPS sekarang bersih."
      echo "Silakan jalankan script instalasi GitHub lagi jika ingin memasang ulang."
      echo "==================================================="
    else
      echo "Uninstall dibatalkan."
    fi
    ;;
  4)
    echo "Keluar dari menu."
    ;;
  *)
    echo "Pilihan tidak valid!"
    ;;
esac
EOF

# Berikan akses eksekusi agar command 'toko' bisa dijalankan
sudo chmod +x /usr/local/bin/toko

# 13. Menjalankan server
sudo pm2 delete tokotas 2>/dev/null || true
sudo pm2 start server.js --name "tokotas"
sudo pm2 save
sudo pm2 startup

echo "================================================================"
echo " INSTALASI & UPDATE BERHASIL! "
echo "================================================================"
echo "Halaman Toko: http://[IP_VPS]/"
echo "Panel Tambah Produk: http://[IP_VPS]/vps-panel"
echo " "
echo ">>> CARA BUKA MENU TERMINAL (BACKUP/RESTORE/UNINSTALL) <<<"
echo "Ketik perintah ini di layar terminal VPS kamu lalu tekan Enter:"
echo " "
echo "toko"
echo " "
echo "================================================================"
