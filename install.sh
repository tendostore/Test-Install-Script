#!/bin/bash
# ====================================================
# SCRIPT INSTALL TOKO ONLINE TAS & VPS PANEL MANAJEMEN
# ====================================================

echo "Memulai instalasi sistem Toko Tas Hitam Putih..."

# 1. Update sistem dan install dependensi dasar
sudo apt update -y
sudo apt install -y curl build-essential

# 2. Install Node.js (Versi 20.x)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Install PM2 secara global untuk menjaga server tetap hidup di VPS
sudo npm install -y pm2 -g

# 4. Buat direktori proyek
mkdir -p /var/www/tokotas
cd /var/www/tokotas

# 5. Inisialisasi proyek Node.js dan install library yang dibutuhkan
npm init -y
npm install express sqlite3 ejs multer body-parser

# 6. Buat struktur folder untuk gambar dan tampilan web
mkdir -p public/uploads
mkdir -p views

# 7. Download gambar default/sementara
wget -qO public/uploads/default.jpg https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=400

# 8. Buat file inisialisasi Database SQLite (init_db.js)
cat << 'EOF' > init_db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./tokotas.db');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, description TEXT, image_url TEXT)");
  
  db.run("INSERT INTO products (name, price, description, image_url) VALUES ('Tas Minimalis Black Edition', 250000, 'Tas dengan desain elegan warna hitam, cocok untuk profesional.', '/uploads/default.jpg')");
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

// Rute: Halaman Utama Toko (Frontend)
app.get('/', (req, res) => {
  let query = "SELECT * FROM products ORDER BY id DESC";
  let params = [];
  
  if (req.query.q) {
    query = "SELECT * FROM products WHERE name LIKE ? ORDER BY id DESC";
    params = ['%' + req.query.q + '%'];
  }

  db.all(query, params, (err, rows) => {
    if (err) throw err;
    res.render('index', { products: rows, searchQuery: req.query.q || '' });
  });
});

// Rute: Panel Admin VPS (Manajemen Produk - RAHASIA)
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

# 10. Buat Tampilan Halaman Toko (views/index.ejs) - DESAIN HITAM PUTIH PREMIUM
cat << 'EOF' > views/index.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Toko Online Premium</title>
  <style>
    /* Tema Hitam Putih (Monochrome) */
    :root {
      --black: #000000;
      --dark-gray: #333333;
      --light-gray: #f9f9f9;
      --white: #ffffff;
      --border: #e0e0e0;
    }
    
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: var(--light-gray); margin: 0; padding: 0; color: var(--black); }
    
    /* Header Utama Hitam */
    .header { background: var(--black); padding: 15px 20px; display: flex; align-items: center; gap: 15px; position: sticky; top: 0; z-index: 50; }
    
    /* Ikon SVG Clean */
    .icon-btn { background: none; border: none; color: var(--white); cursor: pointer; display: flex; align-items: center; padding: 0; }
    .icon-btn svg { width: 24px; height: 24px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }
    
    /* Search Box Putih Minimalis */
    .search-box { flex-grow: 1; background: var(--white); border-radius: 4px; display: flex; align-items: center; padding: 8px 12px; }
    .search-box input { border: none; outline: none; width: 100%; font-size: 14px; color: var(--black); }
    .search-box button { background: none; border: none; cursor: pointer; color: var(--dark-gray); display: flex; align-items: center; padding: 0; }
    .search-box button svg { width: 18px; height: 18px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }

    /* Banner Placeholder Minimalis */
    .banner-container { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; gap: 15px; padding: 20px; scrollbar-width: none; }
    .banner-container::-webkit-scrollbar { display: none; }
    .banner-item { flex: 0 0 90%; scroll-snap-align: center; background: var(--black); border-radius: 8px; overflow: hidden; position: relative; display: flex; align-items: center; justify-content: center; height: 160px; color: var(--white); font-weight: bold; letter-spacing: 2px; text-transform: uppercase; }
    
    /* Kategori Minimalis (Tanpa Emoji) */
    .category-container { display: flex; justify-content: center; gap: 15px; padding: 0 20px 20px; }
    .cat-item { padding: 10px 20px; border: 1px solid var(--black); border-radius: 4px; color: var(--black); text-decoration: none; font-size: 13px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; transition: 0.2s; background: var(--white); }
    .cat-item:hover { background: var(--black); color: var(--white); }

    /* Produk Rekomendasi */
    .section-title { font-size: 18px; font-weight: bold; padding: 10px 20px; margin: 0; text-transform: uppercase; letter-spacing: 1px; }
    
    /* Grid Produk */
    .product-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; padding: 20px; }
    @media (min-width: 768px) { .product-grid { grid-template-columns: repeat(4, 1fr); } }
    
    .product-card { background: var(--white); border: 1px solid var(--border); overflow: hidden; display: flex; flex-direction: column; transition: 0.3s; }
    .product-card:hover { border-color: var(--black); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    .product-card img { width: 100%; aspect-ratio: 1/1; object-fit: cover; border-bottom: 1px solid var(--border); }
    .product-info { padding: 15px; display: flex; flex-direction: column; flex-grow: 1; }
    .product-title { font-size: 14px; margin: 0 0 8px; color: var(--dark-gray); line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
    .product-price { font-size: 16px; font-weight: bold; color: var(--black); margin-bottom: 15px; }
    
    /* Tombol Beli Hitam */
    .btn-buy { background: var(--black); color: var(--white); text-align: center; text-decoration: none; padding: 10px; font-size: 13px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; margin-top: auto; border: none; cursor: pointer; transition: 0.2s; }
    .btn-buy:hover { background: var(--dark-gray); }

    /* Sidebar Menu Kiri */
    .sidebar { height: 100%; width: 0; position: fixed; z-index: 1000; top: 0; left: 0; background-color: var(--white); overflow-x: hidden; transition: 0.3s; box-shadow: 2px 0 10px rgba(0,0,0,0.1); border-right: 1px solid var(--border); }
    .sidebar-header { background: var(--black); color: var(--white); padding: 20px; font-size: 16px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; letter-spacing: 1px; text-transform: uppercase; }
    .closebtn { color: var(--white); font-size: 28px; text-decoration: none; font-weight: normal; }
    .sidebar-menu a { padding: 18px 20px; text-decoration: none; font-size: 14px; font-weight: bold; color: var(--black); display: block; border-bottom: 1px solid var(--border); text-transform: uppercase; letter-spacing: 1px; }
    .sidebar-menu a:hover { background: var(--light-gray); }
  </style>
</head>
<body>

  <div id="mySidebar" class="sidebar">
    <div class="sidebar-header">
      <span>Menu Toko</span>
      <a href="javascript:void(0)" class="closebtn" onclick="toggleMenu()">&times;</a>
    </div>
    <div class="sidebar-menu">
      <a href="/">Beranda</a>
      <a href="#">Kategori Tas</a>
      <a href="#">Kategori Sepatu</a>
      <a href="#">Kategori Baju</a>
      <a href="#">Cara Pemesanan</a>
    </div>
  </div>

  <div class="header">
    <button class="icon-btn" onclick="toggleMenu()">
      <svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
    </button>
    
    <form action="/" method="GET" class="search-box">
      <input type="text" name="q" placeholder="Temukan produk disini" value="<%= searchQuery %>">
      <button type="submit">
        <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      </button>
    </form>
    
    <div class="icon-btn">
      <svg viewBox="0 0 24 24"><circle cx="9" cy="21" r="1"></circle><circle cx="20" cy="21" r="1"></circle><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path></svg>
    </div>
  </div>

  <div class="banner-container">
    <div class="banner-item" style="background: #111;">NEW ARRIVAL</div>
    <div class="banner-item" style="background: #333;">BEST SELLER</div>
  </div>

  <div class="category-container">
    <a href="#" class="cat-item">TAS</a>
    <a href="#" class="cat-item">SEPATU</a>
    <a href="#" class="cat-item">BAJU</a>
  </div>

  <h2 class="section-title">Produk Pilihan</h2>
  <div class="product-grid">
    <% if (products.length === 0) { %>
      <div style="grid-column: 1 / -1; text-align: center; padding: 40px 20px; color: #888; font-size: 14px;">
        Belum ada produk yang tersedia.
      </div>
    <% } %>
    
    <% products.forEach(function(product) { %>
      <div class="product-card">
        <img src="<%= product.image_url %>" alt="<%= product.name %>">
        <div class="product-info">
          <h3 class="product-title"><%= product.name %></h3>
          <div class="product-price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
          <a href="https://wa.me/6281234567890?text=Halo,%20saya%20tertarik%20membeli%20<%= encodeURIComponent(product.name) %>" class="btn-buy">Beli Sekarang</a>
        </div>
      </div>
    <% }); %>
  </div>

  <script>
    function toggleMenu() {
      var sidebar = document.getElementById("mySidebar");
      if (sidebar.style.width === "260px") {
        sidebar.style.width = "0";
      } else {
        sidebar.style.width = "260px";
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
  <title>Admin Panel - Toko Hitam Putih</title>
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: #f9f9f9; padding: 20px; color: #000; }
    .panel { max-width: 800px; margin: 0 auto; background: #fff; padding: 30px; border: 1px solid #e0e0e0; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
    h2 { border-bottom: 2px solid #000; padding-bottom: 10px; margin-top: 0; text-transform: uppercase; letter-spacing: 1px; }
    .form-group { margin-bottom: 15px; }
    input, textarea { width: 100%; padding: 12px; border: 1px solid #ccc; box-sizing: border-box; font-family: inherit; }
    input:focus, textarea:focus { border-color: #000; outline: none; }
    .btn-add { background: #000; color: #fff; border: none; padding: 12px 20px; cursor: pointer; font-weight: bold; width: 100%; text-transform: uppercase; letter-spacing: 1px; transition: 0.2s; }
    .btn-add:hover { background: #333; }
    table { width: 100%; border-collapse: collapse; margin-top: 30px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
    th { background: #f0f0f0; text-transform: uppercase; font-size: 13px; letter-spacing: 1px; }
    .btn-delete { background: #fff; color: #000; border: 1px solid #000; padding: 6px 12px; cursor: pointer; font-size: 12px; font-weight: bold; transition: 0.2s; }
    .btn-delete:hover { background: #000; color: #fff; }
  </style>
</head>
<body>
  <div class="panel">
    <h2>Manajemen Produk (Admin)</h2>
    <form action="/vps-panel/add" method="POST" enctype="multipart/form-data">
      <div class="form-group"><input type="text" name="name" placeholder="Nama Barang" required></div>
      <div class="form-group"><input type="number" name="price" placeholder="Harga (Contoh: 200000)" required></div>
      <div class="form-group"><textarea name="description" placeholder="Deskripsi Barang"></textarea></div>
      <div class="form-group"><input type="file" name="image" required></div>
      <button type="submit" class="btn-add">Simpan Produk Baru</button>
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
          <td><img src="<%= product.image_url %>" style="width:60px; height:60px; object-fit:cover; border: 1px solid #eee;"></td>
          <td><%= product.name %></td>
          <td>Rp <%= parseInt(product.price).toLocaleString('id-ID') %></td>
          <td>
            <form action="/vps-panel/delete/<%= product.id %>" method="POST" style="margin:0;">
              <button type="submit" class="btn-delete">HAPUS</button>
            </form>
          </td>
        </tr>
      <% }); %>
    </table>
    <br><br>
    <a href="/" style="color: #000; text-decoration: none; font-weight: bold; border-bottom: 1px solid #000;">KEMBALI KE TOKO</a>
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
echo " UPDATE TEMA HITAM PUTIH BERHASIL! "
echo "================================================================"
echo "Halaman Utama Toko (Dilihat Pembeli):"
echo "-> http://[IP_VPS]/"
echo " "
echo "Halaman Admin Tambah Produk (Rahasia, Tidak ada di menu web):"
echo "-> http://[IP_VPS]/vps-panel"
echo " "
echo "================================================================"
