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
  <title>Katalog Toko Online</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #f4f7f6; margin: 0; padding: 0; }
    
    /* Navigasi Atas */
    .nav { background: #2c3e50; color: white; padding: 20px; text-align: center; position: relative; }
    .nav h1 { margin: 0; font-size: 2em; }
    
    /* Tombol Garis Tiga (Hamburger Menu) */
    .menu-btn { font-size: 30px; cursor: pointer; position: absolute; left: 20px; top: 15px; color: white; user-select: none; }
    
    /* Sidebar Menu Kiri */
    .sidebar { height: 100%; width: 0; position: fixed; z-index: 100; top: 0; left: 0; background-color: #1a252f; overflow-x: hidden; transition: 0.3s; padding-top: 60px; box-shadow: 2px 0 10px rgba(0,0,0,0.5); }
    .sidebar a { padding: 15px 25px; text-decoration: none; font-size: 1.2em; color: #bdc3c7; display: block; transition: 0.2s; border-bottom: 1px solid #2c3e50; }
    .sidebar a:hover { color: #ffffff; background-color: #34495e; }
    .sidebar .closebtn { position: absolute; top: 10px; right: 25px; font-size: 36px; padding: 0; border: none; background: none; margin-left: 50px; }

    .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
    
    /* Kategori Tas, Sepatu, Baju */
    .categories { text-align: center; margin-bottom: 40px; }
    .categories h2 { color: #2c3e50; margin-bottom: 15px; font-size: 1.5em; }
    .cat-badges { display: flex; justify-content: center; gap: 15px; flex-wrap: wrap; }
    .badge { background: #3498db; color: white; padding: 10px 30px; border-radius: 25px; font-weight: bold; text-decoration: none; font-size: 1.1em; transition: 0.3s; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    .badge:hover { background: #2980b9; transform: translateY(-2px); }

    /* Product Grid: 3 Menyamping */
    .product-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 25px; }
    
    /* Jika layar mengecil (HP/Tablet) ukurannya menyesuaikan */
    @media (max-width: 900px) { .product-grid { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 600px) { .product-grid { grid-template-columns: 1fr; } }
    
    /* Desain Kartu Produk */
    .product-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 5px 15px rgba(0,0,0,0.08); display: flex; flex-direction: column; transition: transform 0.3s ease; }
    .product-card:hover { transform: translateY(-5px); }
    .product-card img { width: 100%; height: 250px; object-fit: cover; }
    .product-info { padding: 20px; text-align: center; display: flex; flex-direction: column; flex-grow: 1; }
    .product-info h3 { margin: 0 0 10px 0; color: #333; font-size: 1.3em; }
    .desc { font-size: 0.9em; color: #7f8c8d; flex-grow: 1; margin-bottom: 15px; }
    .price { color: #e67e22; font-size: 1.4em; font-weight: bold; }
    .wa-btn { display: block; background: #25d366; color: white; text-decoration: none; padding: 12px; border-radius: 8px; margin-top: 15px; font-weight: bold; transition: 0.2s; }
    .wa-btn:hover { background: #20b858; }
  </style>
</head>
<body>

  <div id="mySidebar" class="sidebar">
    <a href="javascript:void(0)" class="closebtn" onclick="toggleMenu()">&times;</a>
    <a href="/">🏠 Beranda</a>
    <a href="#">👜 Tas</a>
    <a href="#">👟 Sepatu</a>
    <a href="#">👕 Baju</a>
    <a href="#">📞 Hubungi Kami</a>
  </div>

  <div class="nav">
    <div class="menu-btn" onclick="toggleMenu()">&#9776;</div>
    <h1>Toko Online Kekinian</h1>
  </div>
  
  <div class="container">
    <div class="categories">
      <h2>Kategori Belanja:</h2>
      <div class="cat-badges">
        <span class="badge">Tas</span>
        <span class="badge">Sepatu</span>
        <span class="badge">Baju</span>
      </div>
    </div>

    <div class="product-grid">
      <% if (products.length === 0) { %>
        <p style="text-align:center; grid-column: 1 / -1; color:#7f8c8d; font-size: 1.2em;">Belum ada produk yang dijual. Silakan tambahkan lewat Panel VPS.</p>
      <% } %>
      
      <% products.forEach(function(product) { %>
        <div class="product-card">
          <img src="<%= product.image_url %>" alt="<%= product.name %>">
          <div class="product-info">
            <h3><%= product.name %></h3>
            <p class="desc"><%= product.description %></p>
            <div class="price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
            <a href="https://wa.me/6281234567890?text=Halo,%20saya%20mau%20beli%20<%= encodeURIComponent(product.name) %>" class="wa-btn">Order via WhatsApp</a>
          </div>
        </div>
      <% }); %>
    </div>
  </div>

  <script>
    function toggleMenu() {
      var sidebar = document.getElementById("mySidebar");
      if (sidebar.style.width === "250px") {
        sidebar.style.width = "0";
      } else {
        sidebar.style.width = "250px";
      }
    }
  </script>
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
    input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
    .btn-add { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; width: 100%; font-size: 1.1em; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
    .btn-delete { background: #e74c3c; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="panel">
    <h2>Manajemen Produk Toko</h2>
    <form action="/vps-panel/add" method="POST" enctype="multipart/form-data">
      <div class="form-group"><input type="text" name="name" placeholder="Nama Barang" required></div>
      <div class="form-group"><input type="number" name="price" placeholder="Harga (Contoh: 200000)" required></div>
      <div class="form-group"><textarea name="description" placeholder="Deskripsi Barang"></textarea></div>
      <div class="form-group"><input type="file" name="image" required></div>
      <button type="submit" class="btn-add">+ Simpan Barang Baru</button>
    </form>

    <table>
      <tr>
        <th>Foto</th>
        <th>Nama Barang</th>
        <th>Harga</th>
        <th>Aksi</th>
      </tr>
      <% products.forEach(function(product) { %>
        <tr>
          <td><img src="<%= product.image_url %>" style="width:50px; height:50px; object-fit:cover; border-radius:5px;"></td>
          <td><%= product.name %></td>
          <td>Rp <%= parseInt(product.price).toLocaleString('id-ID') %></td>
          <td>
            <form action="/vps-panel/delete/<%= product.id %>" method="POST" style="margin:0;">
              <button type="submit" class="btn-delete">Hapus</button>
            </form>
          </td>
        </tr>
      <% }); %>
    </table>
    <br>
    <a href="/" style="color: #3498db; text-decoration: none; font-weight: bold;">← Kembali Lihat Toko</a>
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
echo " UPDATE TAMPILAN BERHASIL! "
echo "================================================================"
echo "Website sudah diperbarui dengan Grid 3 Kolom & Garis Tiga Menu."
echo "Halaman Toko: http://[IP_VPS]/"
echo "Panel Tambah Produk: http://[IP_VPS]/vps-panel"
echo " "
echo ">>> CARA BUKA MENU TERMINAL (BACKUP/RESTORE/UNINSTALL) <<<"
echo "Ketik: toko (lalu tekan Enter)"
echo "================================================================"
