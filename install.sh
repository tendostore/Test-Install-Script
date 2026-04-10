#!/bin/bash
# ====================================================
# SCRIPT INSTALL TOKO ONLINE TAS & VPS PANEL MANAJEMEN
# ====================================================

echo "Memulai instalasi/update sistem Toko Tas Hitam Putih..."

# 1. Update sistem dan install dependensi dasar
sudo apt update -y
sudo apt install -y curl build-essential

# 2. Install Node.js (Versi 20.x)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Install PM2 secara global
sudo npm install -y pm2 -g

# 4. Buat direktori proyek
mkdir -p /var/www/tokotas
cd /var/www/tokotas

# 5. Inisialisasi proyek Node.js dan install library
npm init -y
npm install express sqlite3 ejs multer body-parser

# 6. Buat struktur folder
mkdir -p public/uploads
mkdir -p views

# 7. File inisialisasi Database SQLite (init_db.js)
cat << 'EOF' > init_db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./tokotas.db');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, description TEXT, image_url TEXT, category TEXT)");
  db.all("PRAGMA table_info(products)", (err, columns) => {
     const hasCategory = columns.some(col => col.name === 'category');
     if (!hasCategory) db.run("ALTER TABLE products ADD COLUMN category TEXT DEFAULT 'Lainnya'");
  });
  db.run("CREATE TABLE IF NOT EXISTS banners (id INTEGER PRIMARY KEY AUTOINCREMENT, image_url TEXT)");
});

db.close();
console.log("Database toko berhasil diperbarui.");
EOF

# Jalankan inisialisasi database
node init_db.js

# 8. Buat script utama server (server.js)
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

const storage = multer.diskStorage({
  destination: './public/uploads/',
  filename: function(req, file, cb){
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Rute: Halaman Utama
app.get('/', (req, res) => {
  let query = "SELECT * FROM products WHERE 1=1";
  let params = [];
  if (req.query.q) { query += " AND name LIKE ?"; params.push('%' + req.query.q + '%'); }
  if (req.query.category) { query += " AND category = ?"; params.push(req.query.category); }
  query += " ORDER BY id DESC";

  db.all(query, params, (err, products) => {
    if (err) throw err;
    db.all("SELECT * FROM banners ORDER BY id DESC LIMIT 4", [], (err, banners) => {
       if (err) throw err;
       res.render('index', { products: products, banners: banners, searchQuery: req.query.q || '', selectedCategory: req.query.category || '' });
    });
  });
});

// Rute: Halaman Detail Produk
app.get('/product/:id', (req, res) => {
  db.get("SELECT * FROM products WHERE id = ?", [req.params.id], (err, product) => {
    if (err) throw err;
    if (!product) return res.redirect('/');
    res.render('detail', { product: product });
  });
});

// Rute BARU: Halaman Keranjang
app.get('/cart', (req, res) => {
  res.render('cart');
});

// Rute: Panel Admin
app.get('/vps-panel', (req, res) => {
  db.all("SELECT * FROM products ORDER BY id DESC", [], (err, products) => {
    if (err) throw err;
    db.all("SELECT * FROM banners ORDER BY id DESC", [], (err, banners) => {
       if (err) throw err;
       res.render('admin', { products: products, banners: banners });
    });
  });
});

// Aksi Admin
app.post('/vps-panel/add', upload.single('image'), (req, res) => {
  const { name, price, description, category } = req.body;
  const imageUrl = req.file ? '/uploads/' + req.file.filename : '/uploads/default.jpg';
  db.run("INSERT INTO products (name, price, description, image_url, category) VALUES (?, ?, ?, ?, ?)", [name, price, description, imageUrl, category || 'Lainnya'], (err) => {
      if (err) throw err; res.redirect('/vps-panel');
  });
});

app.post('/vps-panel/delete/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", req.params.id, (err) => { if (err) throw err; res.redirect('/vps-panel'); });
});

app.post('/vps-panel/banner-add', upload.single('image'), (req, res) => {
  if (!req.file) return res.redirect('/vps-panel');
  const imageUrl = '/uploads/' + req.file.filename;
  db.run("INSERT INTO banners (image_url) VALUES (?)", [imageUrl], (err) => { if (err) throw err; res.redirect('/vps-panel'); });
});

app.post('/vps-panel/banner-delete/:id', (req, res) => {
  db.run("DELETE FROM banners WHERE id = ?", req.params.id, (err) => { if (err) throw err; res.redirect('/vps-panel'); });
});

app.listen(port, () => { console.log(`Server berjalan di port ${port}`); });
EOF

# 9. Buat Tampilan Halaman Utama Toko (views/index.ejs)
cat << 'EOF' > views/index.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Toko Online Premium</title>
  <style>
    html, body { margin: 0; padding: 0; width: 100%; }
    :root { --black: #000000; --dark-gray: #333333; --light-gray: #f9f9f9; --white: #ffffff; --border: #e0e0e0; --red: #e74c3c; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: var(--light-gray); color: var(--black); }
    
    .header { background: var(--black); padding: 12px 15px 12px 2px; display: flex; align-items: center; gap: 8px; position: sticky; top: 0; z-index: 50; }
    .icon-btn { background: none; border: none; color: var(--white); cursor: pointer; display: flex; align-items: center; padding: 5px; margin: 0; position: relative;}
    .icon-btn svg { width: 24px; height: 24px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }
    
    .cart-badge { position: absolute; top: 0; right: 0; background: var(--red); color: white; font-size: 10px; font-weight: bold; border-radius: 50%; padding: 2px 6px; display: none; }

    .search-box { flex-grow: 1; background: var(--white); border-radius: 4px; display: flex; align-items: center; padding: 8px 12px; }
    .search-box input { border: none; outline: none; width: 100%; font-size: 14px; color: var(--black); }
    .search-box button { background: none; border: none; cursor: pointer; color: var(--dark-gray); display: flex; align-items: center; padding: 0; }
    .search-box button svg { width: 18px; height: 18px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }

    .banner-wrapper { padding: 15px; background: var(--light-gray); }
    .banner-container { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; gap: 15px; padding: 0; scrollbar-width: none; scroll-behavior: smooth;}
    .banner-container::-webkit-scrollbar { display: none; }
    .banner-item { flex: 0 0 100%; scroll-snap-align: center; height: 180px; display: flex; justify-content: center; align-items: center; background: #222; color: #fff; border-radius: 12px; overflow: hidden; text-transform: uppercase; letter-spacing: 2px; }
    .banner-item img { width: 100%; height: 100%; object-fit: cover; border-radius: 12px;}
    
    .category-container { display: flex; justify-content: center; gap: 10px; padding: 5px 20px 20px; flex-wrap: wrap; }
    .cat-item { padding: 8px 18px; border: 1px solid var(--black); border-radius: 4px; color: var(--black); text-decoration: none; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; transition: 0.2s; background: var(--white); }
    .cat-item.active { background: var(--black); color: var(--white); }
    .cat-item:hover { background: var(--black); color: var(--white); }

    .section-title { font-size: 18px; font-weight: bold; padding: 0 20px; margin: 0; text-transform: uppercase; letter-spacing: 1px; }
    .product-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; padding: 20px; }
    @media (min-width: 768px) { .product-grid { grid-template-columns: repeat(4, 1fr); } }
    
    .product-card { background: var(--white); border: 1px solid var(--border); overflow: hidden; display: flex; flex-direction: column; transition: 0.3s; position: relative;}
    .product-card:hover { border-color: var(--black); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    .product-card img { width: 100%; aspect-ratio: 1/1; object-fit: cover; border-bottom: 1px solid var(--border); }
    .cat-badge { position: absolute; top: 10px; left: 10px; background: var(--black); color: var(--white); padding: 4px 8px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
    .product-info { padding: 15px; display: flex; flex-direction: column; flex-grow: 1; }
    .product-title { font-size: 14px; margin: 0 0 8px; color: var(--dark-gray); line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
    .product-price { font-size: 16px; font-weight: bold; color: var(--black); margin-bottom: 15px; }
    .btn-detail { background: var(--white); color: var(--black); border: 1px solid var(--black); text-align: center; text-decoration: none; padding: 10px; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; margin-top: auto; cursor: pointer; transition: 0.2s; }
    .btn-detail:hover { background: var(--black); color: var(--white); }

    .sidebar { height: 100%; width: 0; position: fixed; z-index: 1000; top: 0; left: 0; background-color: var(--white); overflow-x: hidden; transition: 0.3s; box-shadow: 2px 0 10px rgba(0,0,0,0.1); border-right: 1px solid var(--border); }
    .sidebar-header { background: var(--black); color: var(--white); padding: 20px; font-size: 16px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; letter-spacing: 1px; text-transform: uppercase; }
    .closebtn { color: var(--white); font-size: 28px; text-decoration: none; font-weight: normal; }
    .sidebar-menu a { padding: 18px 20px; text-decoration: none; font-size: 14px; font-weight: bold; color: var(--black); display: block; border-bottom: 1px solid var(--border); text-transform: uppercase; letter-spacing: 1px; }
    .sidebar-menu a:hover { background: var(--light-gray); }
  </style>
</head>
<body>

  <div id="mySidebar" class="sidebar">
    <div class="sidebar-header"><span>Menu Toko</span><a href="javascript:void(0)" class="closebtn" onclick="toggleMenu()">&times;</a></div>
    <div class="sidebar-menu">
      <a href="/">Semua Produk</a><a href="/?category=Tas">Kategori Tas</a><a href="/?category=Sepatu">Kategori Sepatu</a><a href="/?category=Baju">Kategori Baju</a><a href="/cart">🛒 Keranjang Saya</a>
    </div>
  </div>

  <div class="header">
    <button class="icon-btn" onclick="toggleMenu()"><svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg></button>
    <form action="/" method="GET" class="search-box">
      <input type="text" name="q" placeholder="Temukan produk disini" value="<%= searchQuery %>">
      <button type="submit"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></button>
    </form>
    <a href="/cart" class="icon-btn" style="padding-right: 0; text-decoration:none;">
      <svg viewBox="0 0 24 24"><circle cx="9" cy="21" r="1"></circle><circle cx="20" cy="21" r="1"></circle><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path></svg>
      <span id="cart-badge" class="cart-badge">0</span>
    </a>
  </div>

  <div class="banner-wrapper"><div class="banner-container" id="bannerContainer">
    <% if (banners.length === 0) { %><div class="banner-item">BANNER KOSONG</div><% } else { %>
      <% banners.forEach(function(banner) { %><div class="banner-item"><img src="<%= banner.image_url %>"></div><% }); %>
    <% } %>
  </div></div>

  <div class="category-container">
    <a href="/" class="cat-item <%= selectedCategory === '' ? 'active' : '' %>">SEMUA</a>
    <a href="/?category=Tas" class="cat-item <%= selectedCategory === 'Tas' ? 'active' : '' %>">TAS</a>
    <a href="/?category=Sepatu" class="cat-item <%= selectedCategory === 'Sepatu' ? 'active' : '' %>">SEPATU</a>
    <a href="/?category=Baju" class="cat-item <%= selectedCategory === 'Baju' ? 'active' : '' %>">BAJU</a>
  </div>

  <h2 class="section-title"><%= selectedCategory ? 'KATEGORI: ' + selectedCategory : 'PRODUK PILIHAN' %></h2>
  <div class="product-grid">
    <% if (products.length === 0) { %><div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: #888;">Belum ada produk.</div><% } %>
    <% products.forEach(function(product) { %>
      <div class="product-card">
        <span class="cat-badge"><%= product.category %></span><img src="<%= product.image_url %>">
        <div class="product-info">
          <h3 class="product-title"><%= product.name %></h3>
          <div class="product-price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
          <a href="/product/<%= product.id %>" class="btn-detail">Detail Produk</a>
        </div>
      </div>
    <% }); %>
  </div>

  <script>
    function toggleMenu() { document.getElementById("mySidebar").style.width = document.getElementById("mySidebar").style.width === "260px" ? "0" : "260px"; }
    const bc = document.getElementById('bannerContainer'); const bs = document.querySelectorAll('.banner-item'); let cb = 0;
    if (bs.length > 1) setInterval(() => { cb = (cb + 1) % bs.length; bc.scrollTo({ left: bs[cb].offsetLeft, behavior: 'smooth' }); }, 4000);
    
    // JS untuk memperbarui angka di keranjang
    function updateCartBadge() {
      let cart = JSON.parse(localStorage.getItem('tokotas_cart')) || [];
      let badge = document.getElementById('cart-badge');
      if (cart.length > 0) { badge.innerText = cart.length; badge.style.display = 'block'; } else { badge.style.display = 'none'; }
    }
    updateCartBadge();
  </script>
</body>
</html>
EOF

# 10. Buat Tampilan Halaman Detail Produk (views/detail.ejs)
cat << 'EOF' > views/detail.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Detail Produk - <%= product.name %></title>
  <style>
    html, body { margin: 0; padding: 0; width: 100%; }
    :root { --black: #000000; --dark-gray: #333333; --light-gray: #f9f9f9; --white: #ffffff; --border: #e0e0e0; --red: #e74c3c; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: var(--light-gray); color: var(--black); }
    
    .header { background: var(--black); padding: 12px 15px 12px 2px; display: flex; align-items: center; gap: 8px; position: sticky; top: 0; z-index: 50; }
    .icon-btn { background: none; border: none; color: var(--white); cursor: pointer; display: flex; align-items: center; padding: 5px; margin: 0; position:relative;}
    .icon-btn svg { width: 24px; height: 24px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }
    .cart-badge { position: absolute; top: 0; right: 0; background: var(--red); color: white; font-size: 10px; font-weight: bold; border-radius: 50%; padding: 2px 6px; display: none; }
    .search-box { flex-grow: 1; background: var(--white); border-radius: 4px; display: flex; align-items: center; padding: 8px 12px; }
    .search-box input { border: none; outline: none; width: 100%; font-size: 14px; color: var(--black); }
    .search-box button { background: none; border: none; cursor: pointer; color: var(--dark-gray); display: flex; align-items: center; padding: 0; }
    .search-box button svg { width: 18px; height: 18px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }

    .detail-wrapper { max-width: 800px; margin: 20px auto; background: var(--white); border: 1px solid var(--border); overflow: hidden; display: flex; flex-direction: column; }
    @media (min-width: 768px) { .detail-wrapper { flex-direction: row; margin: 40px auto; border-radius: 8px; } }
    .detail-img-box { flex: 1; border-bottom: 1px solid var(--border); background: var(--light-gray); }
    @media (min-width: 768px) { .detail-img-box { border-bottom: none; border-right: 1px solid var(--border); } }
    .detail-img-box img { width: 100%; height: 100%; object-fit: cover; display: block; max-height: 400px; }

    .detail-info-box { flex: 1; padding: 25px; display: flex; flex-direction: column; }
    .badge { display: inline-block; background: var(--black); color: var(--white); padding: 4px 10px; font-size: 11px; font-weight: bold; text-transform: uppercase; margin-bottom: 15px; letter-spacing: 1px; }
    .title { margin: 0 0 10px 0; font-size: 22px; color: var(--black); line-height: 1.3; }
    .price { font-size: 24px; font-weight: bold; color: var(--dark-gray); margin-bottom: 20px; }
    .desc-title { font-size: 13px; font-weight: bold; text-transform: uppercase; border-bottom: 1px solid var(--border); padding-bottom: 5px; margin-bottom: 10px; color: var(--black); }
    .description { font-size: 14px; color: #555; line-height: 1.6; margin-bottom: 30px; white-space: pre-wrap; flex-grow: 1;}
    
    .action-group { display: flex; gap: 10px; margin-bottom: 15px; }
    .btn-cart { flex: 1; background: var(--white); color: var(--black); border: 2px solid var(--black); text-align: center; text-decoration: none; padding: 15px 5px; font-size: 13px; font-weight: bold; text-transform: uppercase; cursor: pointer; transition: 0.2s; border-radius: 4px; }
    .btn-cart:hover { background: var(--black); color: var(--white); }
    .btn-buy { flex: 1; background: var(--black); color: var(--white); border: 2px solid var(--black); text-align: center; text-decoration: none; padding: 15px 5px; font-size: 13px; font-weight: bold; text-transform: uppercase; cursor: pointer; transition: 0.2s; border-radius: 4px; }
    .btn-buy:hover { background: var(--dark-gray); border-color: var(--dark-gray); }
    .btn-back { display: block; background: var(--white); color: var(--black); border: 1px solid var(--border); text-align: center; text-decoration: none; padding: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; transition: 0.2s; border-radius: 4px; }
    .btn-back:hover { background: var(--light-gray); }
  </style>
</head>
<body>
  <div class="header">
    <a href="/" class="icon-btn"><svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"></polyline></svg></a>
    <form action="/" method="GET" class="search-box"><input type="text" name="q" placeholder="Cari barang lain..."><button type="submit"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></button></form>
    <a href="/cart" class="icon-btn" style="padding-right: 0; text-decoration:none;">
      <svg viewBox="0 0 24 24"><circle cx="9" cy="21" r="1"></circle><circle cx="20" cy="21" r="1"></circle><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path></svg>
      <span id="cart-badge" class="cart-badge">0</span>
    </a>
  </div>

  <div class="detail-wrapper">
    <div class="detail-img-box"><img src="<%= product.image_url %>" alt="<%= product.name %>"></div>
    <div class="detail-info-box">
      <div><span class="badge"><%= product.category %></span></div>
      <h1 class="title"><%= product.name %></h1>
      <div class="price">Rp <%= parseInt(product.price).toLocaleString('id-ID') %></div>
      <div class="desc-title">Deskripsi Lengkap</div>
      <div class="description"><%= product.description || '-' %></div>
      
      <div class="action-group">
        <button onclick="addToCart('<%= product.id %>', '<%= product.name.replace(/'/g, "\\'") %>', <%= product.price %>, '<%= product.category %>', '<%= product.image_url %>')" class="btn-cart">Masuk Keranjang</button>
        <a href="https://wa.me/628222446067?text=Halo%20Admin,%20saya%20mau%20pesan:%0A%0ABarang:%20<%= encodeURIComponent(product.name) %>%0AHarga:%20Rp%20<%= parseInt(product.price).toLocaleString('id-ID') %>%0A%0AMohon%20info%20ketersediaannya." class="btn-buy" target="_blank">Beli</a>
      </div>
      <a href="/" class="btn-back">Lihat Produk Lainnya</a>
    </div>
  </div>

  <script>
    function updateCartBadge() {
      let cart = JSON.parse(localStorage.getItem('tokotas_cart')) || [];
      let badge = document.getElementById('cart-badge');
      if (cart.length > 0) { badge.innerText = cart.length; badge.style.display = 'block'; } else { badge.style.display = 'none'; }
    }
    
    function addToCart(id, name, price, category, img) {
      let cart = JSON.parse(localStorage.getItem('tokotas_cart')) || [];
      cart.push({ id: id, name: name, price: price, category: category, img: img });
      localStorage.setItem('tokotas_cart', JSON.stringify(cart));
      updateCartBadge();
      alert('Produk berhasil ditambahkan ke keranjang!');
    }
    updateCartBadge();
  </script>
</body>
</html>
EOF

# 11. Buat File Baru HALAMAN KERANJANG (views/cart.ejs) - UPDATE BARU
cat << 'EOF' > views/cart.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keranjang Belanja</title>
  <style>
    html, body { margin: 0; padding: 0; width: 100%; }
    :root { --black: #000000; --dark-gray: #333333; --light-gray: #f9f9f9; --white: #ffffff; --border: #e0e0e0; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: var(--light-gray); color: var(--black); }
    
    .header { background: var(--black); padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 50; }
    .header-title { color: var(--white); font-weight: bold; text-transform: uppercase; letter-spacing: 1px; font-size: 16px; margin: 0;}
    .icon-btn { background: none; border: none; color: var(--white); cursor: pointer; display: flex; align-items: center; padding: 0; text-decoration: none;}
    .icon-btn svg { width: 24px; height: 24px; stroke: currentColor; stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round; }
    
    .cart-container { max-width: 800px; margin: 20px auto; padding: 0 15px; }
    .cart-item { display: flex; background: var(--white); padding: 15px; border: 1px solid var(--border); margin-bottom: 15px; border-radius: 8px; align-items: center; gap: 15px; }
    .cart-item img { width: 80px; height: 80px; object-fit: cover; border-radius: 6px; border: 1px solid var(--border); }
    .item-info { flex-grow: 1; }
    .item-title { font-size: 15px; font-weight: bold; margin: 0 0 5px; color: var(--black); }
    .item-cat { font-size: 12px; color: #777; margin: 0 0 5px; text-transform: uppercase; }
    .item-price { font-size: 15px; font-weight: bold; color: var(--dark-gray); }
    .btn-remove { background: #e74c3c; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; }

    .cart-summary { background: var(--white); padding: 20px; border: 1px solid var(--border); border-radius: 8px; margin-top: 20px; text-align: right; }
    .total-text { font-size: 18px; margin-bottom: 15px; }
    .total-price { font-size: 24px; font-weight: bold; color: var(--black); }
    .btn-buy-all { background: var(--black); color: var(--white); text-align: center; text-decoration: none; padding: 15px; font-size: 14px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; border: none; cursor: pointer; border-radius: 4px; display: block; width: 100%; box-sizing: border-box; }
    .btn-buy-all:hover { background: var(--dark-gray); }
    .empty-cart { text-align: center; padding: 50px 20px; color: #777; font-size: 16px; }
  </style>
</head>
<body>
  <div class="header">
    <a href="/" class="icon-btn"><svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"></polyline></svg></a>
    <h1 class="header-title">Keranjang Saya</h1>
    <div style="width:24px;"></div> </div>

  <div class="cart-container" id="cart-content">
    </div>

  <script>
    function loadCart() {
      const cartContainer = document.getElementById('cart-content');
      let cart = JSON.parse(localStorage.getItem('tokotas_cart')) || [];
      
      if (cart.length === 0) {
        cartContainer.innerHTML = '<div class="empty-cart">Keranjang Anda masih kosong.<br><br><a href="/" style="color: black; font-weight: bold;">Mulai Belanja</a></div>';
        return;
      }

      let html = '';
      let total = 0;
      let waText = "Halo Admin, saya mau pesan barang dari keranjang:\n\n";

      cart.forEach((item, index) => {
        total += item.price;
        waText += `${index + 1}. ${item.name}\n   Kategori: ${item.category}\n   Harga: Rp ${item.price.toLocaleString('id-ID')}\n\n`;
        
        html += `
          <div class="cart-item">
            <img src="${item.img}" alt="${item.name}">
            <div class="item-info">
              <div class="item-title">${item.name}</div>
              <div class="item-cat">${item.category}</div>
              <div class="item-price">Rp ${item.price.toLocaleString('id-ID')}</div>
            </div>
            <button class="btn-remove" onclick="removeItem(${index})">Hapus</button>
          </div>
        `;
      });

      waText += `*TOTAL KESELURUHAN: Rp ${total.toLocaleString('id-ID')}*\n\nMohon info ketersediaannya.`;
      const waLink = `https://wa.me/628222446067?text=${encodeURIComponent(waText)}`;

      html += `
        <div class="cart-summary">
          <div class="total-text">Total Harga: <br><span class="total-price">Rp ${total.toLocaleString('id-ID')}</span></div>
          <a href="${waLink}" class="btn-buy-all" target="_blank" onclick="clearCartAfterBuy()">BELI SEMUA VIA WHATSAPP</a>
        </div>
      `;

      cartContainer.innerHTML = html;
    }

    function removeItem(index) {
      let cart = JSON.parse(localStorage.getItem('tokotas_cart')) || [];
      cart.splice(index, 1);
      localStorage.setItem('tokotas_cart', JSON.stringify(cart));
      loadCart();
    }

    function clearCartAfterBuy() {
      // Opsional: Jika ingin keranjang otomatis kosong setelah klik beli WA
      // localStorage.removeItem('tokotas_cart');
      // setTimeout(loadCart, 2000); 
    }

    // Jalankan saat halaman dibuka
    loadCart();
  </script>
</body>
</html>
EOF

# 12. Buat Tampilan Panel Admin VPS (views/admin.ejs)
cat << 'EOF' > views/admin.ejs
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel - Toko Hitam Putih</title>
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: #f9f9f9; padding: 20px; color: #000; }
    .panel { max-width: 800px; margin: 0 auto 30px; background: #fff; padding: 30px; border: 1px solid #e0e0e0; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
    h2 { border-bottom: 2px solid #000; padding-bottom: 10px; margin-top: 0; text-transform: uppercase; letter-spacing: 1px; }
    .form-group { margin-bottom: 15px; }
    label { font-weight: bold; font-size: 13px; text-transform: uppercase; display: block; margin-bottom: 5px; }
    input, textarea, select { width: 100%; padding: 12px; border: 1px solid #ccc; box-sizing: border-box; font-family: inherit; }
    input:focus, textarea:focus, select:focus { border-color: #000; outline: none; }
    .btn-add { background: #000; color: #fff; border: none; padding: 12px 20px; cursor: pointer; font-weight: bold; width: 100%; text-transform: uppercase; letter-spacing: 1px; transition: 0.2s; }
    .btn-add:hover { background: #333; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
    th { background: #f0f0f0; text-transform: uppercase; font-size: 13px; letter-spacing: 1px; }
    .btn-delete { background: #fff; color: #000; border: 1px solid #000; padding: 6px 12px; cursor: pointer; font-size: 12px; font-weight: bold; transition: 0.2s; }
    .btn-delete:hover { background: #000; color: #fff; }
  </style>
</head>
<body>
  <div class="panel">
    <h2>Manajemen Banner Depan (Maks 4)</h2>
    <form action="/vps-panel/banner-add" method="POST" enctype="multipart/form-data">
      <div class="form-group"><label>Upload Foto Banner Baru:</label><input type="file" name="image" required></div>
      <button type="submit" class="btn-add">TAMBAH BANNER</button>
    </form>
    <table>
      <tr><th>Foto Banner</th><th>Aksi</th></tr>
      <% banners.forEach(function(banner) { %>
        <tr>
          <td><img src="<%= banner.image_url %>" style="width:120px; height:60px; object-fit:cover; border: 1px solid #eee;"></td>
          <td><form action="/vps-panel/banner-delete/<%= banner.id %>" method="POST" style="margin:0;"><button type="submit" class="btn-delete">HAPUS</button></form></td>
        </tr>
      <% }); %>
    </table>
  </div>
  <div class="panel">
    <h2>Manajemen Produk Barang</h2>
    <form action="/vps-panel/add" method="POST" enctype="multipart/form-data">
      <div class="form-group">
        <label>Kategori Produk</label>
        <select name="category" required><option value="Tas">Tas</option><option value="Sepatu">Sepatu</option><option value="Baju">Baju</option></select>
      </div>
      <div class="form-group"><input type="text" name="name" placeholder="Nama Barang" required></div>
      <div class="form-group"><input type="number" name="price" placeholder="Harga (Contoh: 200000)" required></div>
      <div class="form-group"><textarea name="description" placeholder="Deskripsi Barang Lengkap" style="height: 100px;"></textarea></div>
      <div class="form-group"><label>Upload Foto Barang:</label><input type="file" name="image" required></div>
      <button type="submit" class="btn-add">SIMPAN PRODUK BARU</button>
    </form>
    <table>
      <tr><th>Foto</th><th>Kategori</th><th>Nama Barang</th><th>Harga</th><th>Aksi</th></tr>
      <% products.forEach(function(product) { %>
        <tr>
          <td><img src="<%= product.image_url %>" style="width:50px; height:50px; object-fit:cover; border: 1px solid #eee;"></td>
          <td><b><%= product.category %></b></td>
          <td><%= product.name %></td>
          <td>Rp <%= parseInt(product.price).toLocaleString('id-ID') %></td>
          <td><form action="/vps-panel/delete/<%= product.id %>" method="POST" style="margin:0;"><button type="submit" class="btn-delete">HAPUS</button></form></td>
        </tr>
      <% }); %>
    </table>
    <br><br><a href="/" style="color: #000; text-decoration: none; font-weight: bold; border-bottom: 1px solid #000;">KEMBALI KE TOKO</a>
  </div>
</body>
</html>
EOF

# 13. MEMBUAT MENU COMMAND LINE DI TERMINAL VPS (menu)
cat << 'EOF' > /usr/local/bin/menu
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
    echo "Menghapus sistem..."
    pm2 delete tokotas 2>/dev/null || true
    rm -rf /var/www/tokotas
    echo "==================================================="
    echo "Uninstall Selesai! VPS sekarang bersih."
    echo "Silakan jalankan script instalasi GitHub lagi jika ingin memasang ulang."
    echo "==================================================="
    ;;
  4)
    echo "Keluar dari menu."
    ;;
  *)
    echo "Pilihan tidak valid!"
    ;;
esac
EOF

# Berikan akses eksekusi agar command 'menu' bisa dijalankan
sudo chmod +x /usr/local/bin/menu

# 14. Menjalankan server melalui PM2
sudo pm2 delete tokotas 2>/dev/null || true
sudo pm2 start server.js --name "tokotas"
sudo pm2 save
sudo pm2 startup

echo "================================================================"
echo " UPDATE KERANJANG BELANJA & WA MULTIPLE ITEM BERHASIL! "
echo "================================================================"
echo "Website sudah mendukung sistem Cart dengan notifikasi angka."
echo "Halaman Utama: http://[IP_VPS]/"
echo "================================================================"
