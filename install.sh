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

# 9. Buat script utama server (server.js)
cat << 'EOF' > server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const { exec } = require('child_process');

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

// Rute: Halaman Utama Toko Tas (Frontend - BERSIH DARI MENU UNINSTALL)
app.get('/', (req, res) => {
  db.all("SELECT * FROM products ORDER BY id DESC", [], (err, rows) => {
    if (err) throw err;
    res.render('index', { products: rows });
  });
});

// Rute: Panel Admin VPS (Manajemen Produk & Uninstall)
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

// Aksi: UNINSTALL & RESET SISTEM (HANYA ADA DI PANEL VPS)
app.post('/vps-panel/uninstall', (req, res) => {
  res.send(`
    <html>
      <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #ecf0f1;">
        <h1 style="color: #c0392b;">Uninstall Berhasil!</h1>
        <p>Sistem telah dihapus dari direktori /var/www/tokotas.</p>
        <p>Proses PM2 telah dihentikan. VPS sekarang bersih dan siap untuk instalasi baru.</p>
      </body>
    </html>
  `);
  
  setTimeout(() => {
    console.log("Mengeksekusi pembersihan sistem...");
    exec('pm2 delete tokotas && rm -rf /var/www/tokotas', (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
    });
  }, 2000);
});

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

# 11. Buat Tampilan Panel Admin VPS (views/admin.ejs)
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
    .danger-zone { margin-top: 50px; background: #fdf2f2; border: 2px dashed #e74c3c; padding: 20px; border-radius: 10px; }
    .btn-uninstall { background: #c0392b; color: white; border: none; width: 100%; padding: 15px; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 1.1em; }
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

    <div class="danger-zone">
      <h3 style="color: #c0392b; margin-top:0;">🔧 Panel Uninstall & Reset</h3>
      <p style="font-size: 0.9em; color: #666;">Klik tombol di bawah untuk menghapus seluruh file website dan database. Gunakan ini jika Anda ingin melakukan update skrip dari GitHub tanpa perlu rebuild VPS.</p>
      <form action="/vps-panel/uninstall" method="POST" onsubmit="return confirm('APAKAH ANDA YAKIN?\nSemua data produk dan file website akan terhapus permanen.');">
        <button type="submit" class="btn-uninstall">Uninstall & Reset Website Sekarang</button>
      </form>
    </div>
  </div>
</body>
</html>
EOF

# 12. Menjalankan server
sudo pm2 delete tokotas 2>/dev/null || true
sudo pm2 start server.js --name "tokotas"
sudo pm2 save
sudo pm2 startup

echo "================================================================"
echo " UPDATE BERHASIL! "
echo "================================================================"
echo "Halaman Toko: http://[IP_VPS]/"
echo "Panel Manajemen & Uninstall: http://[IP_VPS]/vps-panel"
echo "================================================================"
