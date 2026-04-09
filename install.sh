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

# 4. Buat direktori proyek toko tas (Akan menimpa/membuat ulang jika belum ada)
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
const port = 80; // Berjalan di port 80 agar bisa diakses langsung via IP VPS

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

// Aksi: Tambah Produk Tas Baru dari VPS Panel
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

// Aksi: Hapus Produk Tas
app.post('/vps-panel/delete/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", req.params.id, (err) => {
    if (err) throw err;
    res.redirect('/vps-panel');
  });
});

// Aksi: UNINSTALL & RESET SISTEM
app.post('/vps-panel/uninstall', (req, res) => {
  res.send(`
    <html>
      <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #ecf0f1;">
        <h1 style="color: #c0392b;">Proses Uninstall Dimulai!</h1>
        <p>Sistem sedang menghapus data, database, dan mematikan server VPS.</p>
        <p>Website ini akan mati dalam beberapa detik. Silakan jalankan script instalasi baru dari GitHub Anda melalui terminal VPS.</p>
      </body>
    </html>
  `);
  
  // Memberikan jeda 2 detik agar halaman di atas sempat dimuat oleh browser sebelum server bunuh diri
  setTimeout(() => {
    console.log("Mengeksekusi perintah uninstall...");
    exec('pm2 delete tokotas && rm -rf /var/www/tokotas', (error, stdout, stderr) => {
      if (error) {
        console.error(`Error saat uninstall: ${error.message}`);
        return;
      }
    });
  }, 2000);
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
  <title>Toko Tas Elegan</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; margin: 0; padding: 0; }
    .header { background: #2c3e50; color: white; text-align: center; padding: 40px 20px; margin-bottom: 30px; }
    .header h1 { margin: 0; font-size: 2.5em; }
    .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    .grid { display: flex; flex-wrap: wrap; gap: 25px; justify-content: center; padding-bottom: 50px; }
    .card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); width: 280px; text-align: center; transition: transform 0.3s ease; }
    .card:hover { transform: translateY(-5px); }
    .card img { max-width: 100%; height: 220px; object-fit: cover; border-radius: 8px; margin-bottom: 15px; }
    .card h3 { margin: 0 0 10px 0; color: #333; font-size: 1.2em; }
    .desc { color: #7f8c8d; font-size: 0.9em; margin-bottom: 15px; height: 60px; overflow: hidden; }
    .price { color: #e67e22; font-weight: bold; font-size: 1.4em; margin-bottom: 15px; }
    .buy-btn { background: #27ae60; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; font-weight: bold; width: 100%; box-sizing: border-box; }
    .buy-btn:hover { background: #2ecc71; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Toko Tas Elegan</h1>
    <p>Koleksi tas pria dan wanita kualitas premium</p>
  </div>
  
  <div class="container">
    <div class="grid">
      <% if (products.length === 0) { %>
        <p style="text-align:center; width:100%; color:#7f8c8d;">Belum ada tas yang dijual. Silakan tambahkan dari Panel VPS.</p>
      <% } %>
      
      <% products.forEach(function(product) { %>
        <div class="card">
          <img src="<%= product.image_url %>" alt="<%= product.name %>">
          <h3><%= product.name %></h3>
          <p class="desc"><%= product.description %></p>
          <div class="price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
          <a href="https://wa.me/6281234567890?text=Halo,%20saya%20tertarik%20membeli%20<%= encodeURIComponent(product.name) %>" class="buy-btn">Beli via WhatsApp</a>
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
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #ecf0f1; margin: 0; padding: 20px; }
    .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
    h1, h3 { color: #2c3e50; }
    .form-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 5px; font-weight: bold; color: #34495e; }
    input[type="text"], input[type="number"], textarea, input[type="file"] { width: 100%; padding: 12px; border: 1px solid #bdc3c7; border-radius: 6px; box-sizing: border-box; }
    textarea { resize: vertical; height: 100px; }
    .btn-submit { background: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-size: 1em; font-weight: bold; }
    .btn-submit:hover { background: #2980b9; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 15px; border-bottom: 1px solid #ecf0f1; text-align: left; }
    th { background: #34495e; color: white; }
    .delete-btn { background: #e74c3c; padding: 8px 12px; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .delete-btn:hover { background: #c0392b; }
    .link-store { display: inline-block; margin-top: 20px; color: #16a085; text-decoration: none; font-weight: bold; }
    .danger-zone { margin-top: 50px; padding: 20px; border: 2px dashed #e74c3c; border-radius: 8px; background: #fadbd8; }
    .btn-danger { background: #c0392b; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-size: 1em; font-weight: bold; width: 100%; }
    .btn-danger:hover { background: #a93226; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Panel Manajemen VPS - Toko Tas</h1>
    <hr>
    
    <h3>Tambah Stok Tas Baru</h3>
    <form action="/vps-panel/add" method="POST" enctype="multipart/form-data">
      <div class="form-group">
        <label>Nama Tas:</label>
        <input type="text" name="name" placeholder="Misal: Tas Selempang Canvas" required>
      </div>
      <div class="form-group">
        <label>Harga (Hanya Angka):</label>
        <input type="number" name="price" placeholder="Misal: 150000" required>
      </div>
      <div class="form-group">
        <label>Deskripsi:</label>
        <textarea name="description" placeholder="Jelaskan bahan, ukuran, dan keunggulan tas ini..." required></textarea>
      </div>
      <div class="form-group">
        <label>Upload Foto Tas:</label>
        <input type="file" name="image" accept="image/*" required>
      </div>
      <button type="submit" class="btn-submit">+ Simpan Produk</button>
    </form>

    <h3 style="margin-top:40px;">Daftar Produk Saat Ini</h3>
    <table>
      <tr>
        <th>Foto</th>
        <th>Nama Tas</th>
        <th>Harga</th>
        <th>Aksi</th>
      </tr>
      <% products.forEach(function(product) { %>
        <tr>
          <td><img src="<%= product.image_url %>" width="60" height="60" style="object-fit:cover; border-radius:4px;"></td>
          <td><strong><%= product.name %></strong></td>
          <td>Rp <%= parseInt(product.price).toLocaleString('id-ID') %></td>
          <td>
            <form action="/vps-panel/delete/<%= product.id %>" method="POST" style="margin:0;">
              <button type="submit" class="delete-btn">Hapus</button>
            </form>
          </td>
        </tr>
      <% }); %>
    </table>
    
    <a href="/" class="link-store">← Kembali Lihat Halaman Toko</a>

    <div class="danger-zone">
      <h3 style="margin-top: 0; color: #c0392b;">Zona Berbahaya (Reset Sistem)</h3>
      <p style="color: #7f8c8d;">Gunakan fitur ini <strong>HANYA</strong> jika Anda ingin mengupdate script dari GitHub. Tombol ini akan menghapus seluruh file website, gambar produk, dan database, lalu mematikan server agar Anda bisa menjalankan instalasi ulang tanpa rebuild VPS.</p>
      
      <form action="/vps-panel/uninstall" method="POST" onsubmit="return confirm('PERINGATAN KERAS!\n\nApakah Anda yakin ingin menghapus SEMUA script dan data toko ini?\nWebsite akan mati total setelah Anda menekan OK sampai Anda menginstallnya kembali dari terminal VPS.');">
        <button type="submit" class="btn-danger">Uninstall & Reset Website Sekarang</button>
      </form>
    </div>

  </div>
</body>
</html>
EOF

# 12. Menghentikan proses lama (jika ada) dan menjalankan server baru melalui PM2
# pm2 delete digunakan agar jika script ini dijalankan ulang, port tidak tabrakan
sudo pm2 delete tokotas 2>/dev/null || true
sudo pm2 start server.js --name "tokotas"
sudo pm2 save
sudo pm2 startup

# 13. Selesai
echo "================================================================"
echo " INSTALASI SELESAI DENGAN SUKSES! "
echo "================================================================"
echo "Website toko tas kamu sudah berjalan."
echo "Untuk mengaksesnya, buka browser dan ketik Alamat IP VPS kamu:"
echo " "
echo " -> Toko Utama         : http://[IP_VPS_KAMU]/"
echo " -> Panel Manajemen VPS: http://[IP_VPS_KAMU]/vps-panel"
echo " "
echo "Ganti [IP_VPS_KAMU] dengan alamat IP server kamu yang asli."
echo "Catatan: Jangan lupa edit nomor WhatsApp pada file views/index.ejs agar pesanan masuk ke nomor kamu!"
echo "================================================================"

