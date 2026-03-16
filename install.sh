#!/bin/bash

echo "==================================================="
echo "  Proses Installasi & Update Harga Tendo Store"
echo "==================================================="

# 1. Update dan Install Dependencies di VPS
echo "[1/3] Menginstall Python dan Library yang dibutuhkan..."
apt-get update -y
apt-get install python3 python3-pip python3-pandas -y
pip3 install openpyxl --break-system-packages 2>/dev/null || pip3 install openpyxl

# 2. Membuat file Python secara otomatis
echo "[2/3] Membuat script pemroses harga..."
cat << 'EOF' > edit_harga.py
import pandas as pd
import re
import os
import sys

# Konfigurasi Nama File
file_name = 'daftar-produk-buyer.xlsx - Worksheet.csv'
output_file = 'daftar-produk-harga-jual.xlsx'

# Pengecekan ketersediaan file CSV
if not os.path.exists(file_name):
    print(f"ERROR: File '{file_name}' tidak ditemukan di folder ini!")
    print("Pastikan file CSV sudah di-upload ke VPS sebelum menjalankan script.")
    sys.exit(1)

print(f"Membaca data dari {file_name}...")
df = pd.read_csv(file_name)

# Fungsi deteksi kategori dari nama produk
def tentukan_kategori(nama_produk):
    nama = str(nama_produk).lower()
    if re.search(r'pln|token', nama): return 'pln'
    if re.search(r'pulsa|reguler', nama): return 'pulsa'
    if re.search(r'dana|ovo|gopay|shopeepay|linkaja|saldo|e-money|maxim|gojek|grab', nama): return 'e-money'
    if re.search(r'game|diamond|uc|free fire|mobile legends|pubg|valorant', nama): return 'game'
    if re.search(r'voucher', nama): return 'voucher'
    if re.search(r'masa aktif', nama): return 'masa_aktif'
    if re.search(r'sms|telpon|nelfon|telepon|voice', nama): return 'sms_telpon'
    if re.search(r'perdana|aktivasi|kpk', nama): return 'perdana'
    return 'data' 

# Fungsi hitung margin sesuai aturan Tendo Store
def hitung_harga_jual(row):
    kategori = tentukan_kategori(row['Produk'])
    try:
        harga_modal = float(row['Harga'])
    except ValueError:
        harga_modal = 0.0
        
    margin = 0
    
    # Aturan Pulsa & PLN
    if kategori == 'pulsa':
        margin = 1500
    elif kategori == 'pln':
        margin = 1000
        
    # Aturan E-Money
    elif kategori == 'e-money':
        if harga_modal < 100: margin = 0
        elif harga_modal < 1000: margin = 300
        elif harga_modal < 5000: margin = 600
        else: margin = 1000 # Untuk < 50k dan > 50k untungnya sama Rp.1.000
        
    # Aturan Data, Game, Voucher, SMS, Masa Aktif, Aktivasi Perdana
    else: 
        if harga_modal < 100: margin = 0
        elif harga_modal < 1000: margin = 300
        elif harga_modal < 5000: margin = 600
        elif harga_modal < 50000: margin = 1500
        else: margin = 2000
            
    return harga_modal + margin

print("Menerapkan rumus margin keuntungan...")
df['Harga Jual'] = df.apply(hitung_harga_jual, axis=1)

# Merapikan urutan kolom (Harga Jual diletakkan di sebelah Harga)
if 'Harga' in df.columns and 'Harga Jual' in df.columns:
    cols = list(df.columns)
    cols.remove('Harga Jual')
    idx_harga = cols.index('Harga')
    cols.insert(idx_harga + 1, 'Harga Jual')
    df = df[cols]

print(f"Menyimpan hasil ke {output_file}...")
df.to_excel(output_file, index=False, engine='openpyxl')

print("=== SELESAI ===")
print(f"File berhasil diperbarui: {output_file}")
EOF

# 3. Menjalankan Python Script
echo "[3/3] Menjalankan script Python..."
python3 edit_harga.py
