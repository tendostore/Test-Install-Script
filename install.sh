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
  let query = "SELECT * FROM products ORDER BY id DESC";
  let params = [];
  
  // Fitur pencarian sederhana jika ada input dari search bar
  if (req.query.q) {
    query = "SELECT * FROM products WHERE name LIKE ? ORDER BY id DESC";
    params = ['%' + req.query.q + '%'];
  }

  db.all(query, params, (err, rows) => {
    if (err) throw err;
    res.render('index', { products: rows, searchQuery: req.query.q || '' });
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

# 10. Buat Tampilan Halaman Toko Ala Marketplace (views/index.ejs)
cat << 'EOF' > views/index.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Toko Onlineku</title>
  <style>
    /* CSS Variabel untuk Warna Tema (Merah ala Alfagift) */
    :root {
      --primary-red: #e3000f;
      --dark-red: #c8000b;
      --bg-gray: #f4f5f7;
    }
    
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg-gray); margin: 0; padding: 0; color: #333; }
    
    /* Header Utama */
    .header { background: var(--primary-red); padding: 12px 15px; display: flex; align-items: center; gap: 15px; position: sticky; top: 0; z-index: 50; }
    .menu-icon { color: white; font-size: 24px; cursor: pointer; user-select: none; }
    .search-box { flex-grow: 1; background: white; border-radius: 8px; display: flex; align-items: center; padding: 6px 12px; }
    .search-box input { border: none; outline: none; width: 100%; font-size: 14px; }
    .search-box button { background: none; border: none; cursor: pointer; color: #777; }
    .cart-icon { color: white; font-size: 22px; cursor: pointer; }

    /* Bar Lokasi */
    .location-bar { background: var(--dark-red); color: white; font-size: 12px; padding: 8px 15px; display: flex; align-items: center; gap: 5px; }

    /* Banner Slider */
    .banner-container { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; gap: 10px; padding: 15px; scrollbar-width: none; }
    .banner-container::-webkit-scrollbar { display: none; }
    .banner-item { flex: 0 0 90%; scroll-snap-align: center; border-radius: 12px; overflow: hidden; position: relative; }
    .banner-item img { width: 100%; display: block; border-radius: 12px; height: 160px; object-fit: cover; }

    /* Kategori Ikon */
    .category-container { display: flex; justify-content: space-around; padding: 15px; background: white; margin-bottom: 10px; }
    .cat-item { text-align: center; font-size: 12px; font-weight: bold; color: #555; text-decoration: none; }
    .cat-circle { width: 50px; height: 50px; background: #ffe6e6; border-radius: 50%; display: flex; justify-content: center; align-items: center; margin: 0 auto 8px; font-size: 24px; }

    /* Produk Rekomendasi */
    .section-title { font-size: 18px; font-weight: bold; padding: 15px 15px 5px; margin: 0; }
    
    /* Grid Produk: 2 kolom di HP, 4 kolom di PC */
    .product-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; padding: 15px; }
    @media (min-width: 768px) { .product-grid { grid-template-columns: repeat(4, 1fr); } }
    
    .product-card { background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.06); display: flex; flex-direction: column; }
    .product-card img { width: 100%; aspect-ratio: 1/1; object-fit: cover; }
    .product-info { padding: 12px; display: flex; flex-direction: column; flex-grow: 1; }
    .product-title { font-size: 13px; margin: 0 0 5px; color: #333; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
    .product-price { font-size: 15px; font-weight: bold; color: var(--primary-red); margin-bottom: 10px; }
    .btn-buy { background: var(--primary-red); color: white; text-align: center; text-decoration: none; padding: 8px; border-radius: 6px; font-size: 13px; font-weight: bold; margin-top: auto; border: none; cursor: pointer; }

    /* Sidebar Menu Kiri */
    .sidebar { height: 100%; width: 0; position: fixed; z-index: 1000; top: 0; left: 0; background-color: white; overflow-x: hidden; transition: 0.3s; box-shadow: 4px 0 15px rgba(0,0,0,0.2); }
    .sidebar-header { background: var(--primary-red); color: white; padding: 20px; font-size: 18px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
    .closebtn { color: white; font-size: 28px; text-decoration: none; }
    .sidebar-menu a { padding: 15px 20px; text-decoration: none; font-size: 15px; color: #333; display: block; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 10px;}
    .sidebar-menu a:hover { background: #f9f9f9; }
    .admin-link { background: #fff0f0; color: var(--primary-red) !important; font-weight: bold; }
  </style>
</head>
<body>

  <div id="mySidebar" class="sidebar">
    <div class="sidebar-header">
      <span>Halo, Pelanggan!</span>
      <a href="javascript:void(0)" class="closebtn" onclick="toggleMenu()">&times;</a>
    </div>
    <div class="sidebar-menu">
      <a href="/">🏠 Beranda Utama</a>
      <a href="#">👜 Kategori Tas</a>
      <a href="#">👟 Kategori Sepatu</a>
      <a href="#">👕 Kategori Baju</a>
      <a href="#">📞 Hubungi Admin</a>
      <a href="/vps-panel" class="admin-link">⚙️ Tambah Produk (Panel VPS)</a>
    </div>
  </div>

  <div class="header">
    <div class="menu-icon" onclick="toggleMenu()">&#9776;</div>
    <form action="/" method="GET" class="search-box">
      <input type="text" name="q" placeholder="Temukan produk favoritmu disini" value="<%= searchQuery %>">
      <button type="submit">🔍</button>
    </form>
    <div class="cart-icon">🛒</div>
  </div>

  <div class="location-bar">
    📍 Kirim ke: <strong>JABODETABEK.</strong> Masuk untuk ubah lokasi.
  </div>

  <div class="banner-container">
    <div class="banner-item">
      <img src="https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=800&q=80" alt="Banner Promo 1">
    </div>
    <div class="banner-item">
      <img src="https://images.unsplash.com/photo-1555529771-835f59fc5efe?w=800&q=80" alt="Banner Promo 2">
    </div>
  </div>

  <div class="category-container">
    <a href="#" class="cat-item">
      <div class="cat-circle">👜</div>
      Tas Pria/Wanita
    </a>
    <a href="#" class="cat-item">
      <div class="cat-circle">👟</div>
      Sepatu
    </a>
    <a href="#" class="cat-item">
      <div class="cat-circle">👕</div>
      Baju/Kaos
    </a>
  </div>

  <h2 class="section-title">Produk Rekomendasi</h2>
  <div class="product-grid">
    <% if (products.length === 0) { %>
      <div style="grid-column: 1 / -1; text-align: center; padding: 40px 20px; color: #888;">
        Belum ada produk. Klik menu Garis Tiga di kiri atas lalu pilih "Tambah Produk (Panel VPS)".
      </div>
    <% } %>
    
    <% products.forEach(function(product) { %>
      <div class="product-card">
        <img src="<%= product.image_url %>" alt="<%= product.name %>">
        <div class="product-info">
          <h3 class="product-title"><%= product.name %></h3>
          <div class="product-price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
          <a href="https://wa.me/6281234567890?text=Halo,%20saya%20tertarik%20membeli%20<%= encodeURIComponent(product.name) %>" class="btn-buy">+ Keranjang / Beli</a>
        </div>
      </div>
    <% }); %>
  </div>

  <script>
    function toggleMenu() {
      var sidebar = document.getElementById("mySidebar");
      if (sidebar.style.width === "280px") {
        sidebar.style.width = "0";
      } else {
        sidebar.style.width = "280px";
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
    h2 { border-bottom: 2px solid #e3000f; padding-bottom: 10px; color: #2c3e50; }
    .form-group { margin-bottom: 15px; }
    input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
    .btn-add { background: #e3000f; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; width: 100%; font-size: 1.1em; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
    .btn-delete { background: #333; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="panel">
    <h2>⚙️ Panel Tambah Produk</h2>
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
    <a href="/" style="color: #e3000f; text-decoration: none; font-weight: bold;">← Kembali ke Halaman Depan Toko</a>
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
echo " UPDATE DESAIN ALA MARKETPLACE BERHASIL! "
echo "================================================================"
echo "Website sudah diperbarui dengan Header Merah, Search Bar, Banners,"
echo "Kategori Ikon, dan Menu Garis Tiga."
echo " "
echo "Halaman Toko: http://[IP_VPS]/"
echo " "
echo ">>> FITUR TAMBAH PRODUK VIA WEBSITE <<<"
echo "Sekarang kamu bisa klik Garis Tiga (pojok kiri atas web) dan klik"
echo "'Tambah Produk (Panel VPS)', atau langsung buka:"
echo "http://[IP_VPS]/vps-panel"
echo " "
echo "================================================================"
