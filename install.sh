#!/bin/bash

# ==========================================
# Script Name: GoPay Direct API (Dashboard UI)
# Version: 4.0
# Description: Instalasi Node.js dengan UI Dashboard Modern
# ==========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

clear
echo -e "${YELLOW}==========================================${NC}"
echo -e "${GREEN}  Mulai Instalasi GoPay API (Dashboard)   ${NC}"
echo -e "${YELLOW}==========================================${NC}"
sleep 1

# 1. Setup Direktori Aplikasi
APP_DIR="/var/www/gopay-direct"
sudo mkdir -p $APP_DIR/views
sudo chown -R $USER:$USER $APP_DIR
cd $APP_DIR

# Pastikan package terinstal (jika belum)
if [ ! -f "package.json" ]; then
    npm init -y
    npm install express axios ejs body-parser
fi

# 2. Menulis File Backend (server.js)
echo -e "\n${YELLOW}[1/2] Menulis file server.js...${NC}"

cat << 'EOF' > server.js
const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));

const GOJEK_API_URL = "https://api.gojekapi.com";
let GOJEK_HEADERS = {
    'Content-Type': 'application/json',
    'X-AppVersion': '4.80.1', 
    'X-UniqueId': 'Masukkan_Device_ID_Disini', 
    'User-Agent': 'Gojek/4.80.1 (com.gojek.app; build:12345; Android 11)'
};

let SESSION_TOKEN = ""; 
let lastTransactionId = null;

app.get('/', async (req, res) => {
    if(!SESSION_TOKEN) {
        return res.render('index', { 
            profile: null, 
            transactions: [], 
            isConnected: false,
            error: null, 
            success: null 
        });
    }
    try {
        const txResponse = await axios.get(`${GOJEK_API_URL}/wallet/history?page=1&limit=10`, { 
            headers: { ...GOJEK_HEADERS, 'Authorization': `Bearer ${SESSION_TOKEN}` } 
        });
        
        res.render('index', { 
            profile: { balance: "Aktif (Cek App)" }, 
            transactions: txResponse.data.data.success || [], 
            isConnected: true,
            error: null, 
            success: null 
        });
    } catch (err) {
        res.render('index', { 
            profile: null, 
            transactions: [], 
            isConnected: false,
            error: "Sesi terputus. Silakan login ulang.", 
            success: null 
        });
    }
});

app.post('/request-otp', async (req, res) => {
    try {
        const response = await axios.post(`${GOJEK_API_URL}/v3/customers/login_with_phone`, { phone: req.body.phone }, { headers: GOJEK_HEADERS });
        const loginToken = response.data.data.otp_token; 
        res.render('index', { profile: null, transactions: [], isConnected: false, error: null, success: `OTP Token: ${loginToken}` });
    } catch (err) {
        res.render('index', { profile: null, transactions: [], isConnected: false, error: "Gagal mengirim OTP.", success: null });
    }
});

app.post('/verify-otp', async (req, res) => {
    try {
        const response = await axios.post(`${GOJEK_API_URL}/v3/customers/login_with_otp`, { 
            otp: req.body.otp,
            otp_token: req.body.api_token 
        }, { headers: GOJEK_HEADERS });
        
        SESSION_TOKEN = response.data.data.access_token; 
        res.redirect('/');
    } catch (err) {
        res.render('index', { profile: null, transactions: [], isConnected: false, error: "Verifikasi Gagal", success: null });
    }
});

app.listen(PORT, () => console.log(`Dashboard aktif di port ${PORT}`));
EOF
SELESAI
# 3. Menulis File Frontend Dashboard (views/index.ejs)
echo -e "\n${YELLOW}[2/2] Menulis file views/index.ejs...${NC}"

cat << 'EOF' > views/index.ejs
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GoPay API Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>
        :root { --sidebar-width: 260px; --primary-color: #00aa13; }
        body { background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .sidebar { width: var(--sidebar-width); height: 100vh; position: fixed; background: #ffffff; border-right: 1px solid #dee2e6; z-index: 100; }
        .main-content { margin-left: var(--sidebar-width); padding: 30px; }
        .nav-link { color: #495057; padding: 12px 20px; border-radius: 8px; margin: 4px 15px; transition: 0.3s; }
        .nav-link:hover, .nav-link.active { background: #e9f7eb; color: var(--primary-color); }
        .card-stat { border: none; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); transition: 0.3s; }
        .card-stat:hover { transform: translateY(-5px); }
        .bg-gopay { background: linear-gradient(135deg, #00aa13 0%, #008924 100%); color: white; }
        .table-container { background: white; border-radius: 15px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .badge-status { padding: 6px 12px; border-radius: 20px; font-weight: 500; }
    </style>
</head>
<body>

<div class="sidebar d-none d-md-block">
    <div class="p-4 mb-3">
        <h4 class="fw-bold" style="color: var(--primary-color);"><i class="bi bi-wallet2 me-2"></i>GoPay API</h4>
    </div>
    <nav class="nav flex-column">
        <a class="nav-link active" href="#"><i class="bi bi-speedometer2 me-2"></i> Dashboard</a>
        <a class="nav-link" href="#"><i class="bi bi-journal-text me-2"></i> Riwayat Mutasi</a>
        <a class="nav-link" href="#"><i class="bi bi-gear me-2"></i> Pengaturan</a>
        <hr class="mx-4">
        <a class="nav-link text-danger" href="#"><i class="bi bi-box-arrow-left me-2"></i> Logout</a>
    </nav>
</div>

<div class="main-content">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="fw-bold mb-0">Dashboard Overview</h2>
            <p class="text-muted">Pantau transaksi GoPay Merchant Anda secara real-time.</p>
        </div>
        <div class="text-end">
            <span class="badge <%= isConnected ? 'bg-success' : 'bg-danger' %> badge-status mb-1">
                <i class="bi bi-circle-fill me-1" style="font-size: 8px;"></i> 
                <%= isConnected ? 'Terhubung ke Gojek' : 'Sesi Terputus' %>
            </span>
            <div class="small text-muted">Last update: <%= new Date().toLocaleTimeString() %></div>
        </div>
    </div>

    <% if (error) { %>
        <div class="alert alert-danger alert-dismissible fade show mb-4 border-0 shadow-sm" role="alert">
            <i class="bi bi-exclamation-triangle-fill me-2"></i> <%= error %>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <% } %>

    <% if (success) { %>
        <div class="alert alert-success alert-dismissible fade show mb-4 border-0 shadow-sm" role="alert">
            <i class="bi bi-check-circle-fill me-2"></i> <%= success %>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <% } %>

    <div class="row mb-4">
        <div class="col-md-6 col-lg-4 mb-3">
            <div class="card card-stat bg-gopay p-4">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <p class="mb-1 opacity-75">Saldo Merchant</p>
                        <h2 class="fw-bold mb-0">Rp <%= profile ? profile.balance : '0' %></h2>
                    </div>
                    <i class="bi bi-cash-stack fs-1 opacity-50"></i>
                </div>
            </div>
        </div>
        <div class="col-md-6 col-lg-4 mb-3">
            <div class="card card-stat p-4 bg-white">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <p class="mb-1 text-muted">Transaksi Hari Ini</p>
                        <h2 class="fw-bold mb-0"><%= transactions.length %></h2>
                    </div>
                    <i class="bi bi-arrow-repeat fs-1 text-primary opacity-25"></i>
                </div>
            </div>
        </div>
        <div class="col-md-12 col-lg-4 mb-3">
            <div class="card card-stat p-4 bg-white">
                <p class="mb-2 text-muted fw-bold">Login Sesi Baru</p>
                <form action="/request-otp" method="POST" class="input-group input-group-sm">
                    <input type="text" name="phone" class="form-control" placeholder="No HP Gojek">
                    <button class="btn btn-dark" type="submit">OTP</button>
                </form>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-lg-8 mb-4">
            <div class="table-container">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h5 class="fw-bold mb-0">Transaksi Terakhir</h5>
                    <button class="btn btn-sm btn-outline-primary rounded-pill px-3">Lihat Semua</button>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead class="text-muted">
                            <tr>
                                <th>Keterangan</th>
                                <th>Nominal</th>
                                <th>Waktu</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% if (transactions.length > 0) { %>
                                <% transactions.forEach(tx => { %>
                                    <tr>
                                        <td>
                                            <div class="fw-bold text-dark"><%= tx.description || 'Penerimaan Dana' %></div>
                                            <small class="text-muted">ID: <%= tx.id %></small>
                                        </td>
                                        <td class="fw-bold text-success">+ Rp <%= tx.amount.value %></td>
                                        <td><%= tx.transaction_date %></td>
                                        <td><span class="badge bg-light text-success rounded-pill px-3 py-2 border border-success border-opacity-25">Berhasil</span></td>
                                    </tr>
                                <% }) %>
                            <% } else { %>
                                <tr>
                                    <td colspan="4" class="text-center py-5 text-muted">Belum ada transaksi ditemukan.</td>
                                </tr>
                            <% } %>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="table-container">
                <h5 class="fw-bold mb-4">Verifikasi OTP</h5>
                <form action="/verify-otp" method="POST">
                    <div class="mb-3">
                        <label class="form-label small text-muted">OTP Token (Response Server)</label>
                        <input type="text" name="api_token" class="form-control" placeholder="Masukkan token sesi">
                    </div>
                    <div class="mb-4">
                        <label class="form-label small text-muted">Kode OTP 4 Digit</label>
                        <input type="text" name="otp" class="form-control form-control-lg text-center fw-bold" placeholder="0 0 0 0">
                    </div>
                    <button class="btn btn-success w-100 py-3 fw-bold rounded-pill" type="submit">
                        <i class="bi bi-shield-check me-2"></i> AKTIFKAN SESI
                    </button>
                </form>
                <div class="mt-4 p-3 bg-light rounded-3">
                    <small class="text-muted"><i class="bi bi-info-circle me-1"></i> Sesi token GoPay Merchant biasanya bertahan beberapa hari jika server VPS tetap aktif melakukan polling mutasi.</small>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# 4. Restart Aplikasi & Output Final
echo -e "\n${YELLOW}[3/3] Me-restart PM2 & Menyelesaikan...${NC}"
pm2 restart gopay-direct
pm2 save

echo -e "\n${GREEN}==========================================${NC}"
echo -e "${YELLOW}DASHBOARD SIAP DIGUNAKAN!${NC}"
echo -e "Silakan akses: http://IP_VPS_ANDA:3000"
echo -e "Ingat: Lakukan sniffing header untuk koneksi yang stabil."
echo -e "${GREEN}==========================================${NC}"

# SELESAI

