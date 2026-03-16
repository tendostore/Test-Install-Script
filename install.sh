import pandas as pd
import re

# Membaca file produk
file_name = 'daftar-produk-buyer.xlsx - Worksheet.csv'
df = pd.read_csv(file_name)

# Fungsi untuk mendeteksi kategori dari nama produk
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
    # Jika tidak masuk kategori di atas, otomatis masuk ke Data/Internet
    return 'data' 

# Fungsi untuk menghitung harga jual sesuai margin yang diminta
def hitung_harga_jual(row):
    kategori = tentukan_kategori(row['Produk'])
    harga_modal = float(row['Harga'])
    margin = 0
    
    # Aturan Margin PLN & Pulsa
    if kategori == 'pulsa':
        margin = 1500
    elif kategori == 'pln':
        margin = 1000
        
    # Aturan Margin E-Money
    elif kategori == 'e-money':
        if harga_modal < 100:
            margin = 0
        elif harga_modal < 1000:
            margin = 300
        elif harga_modal < 5000:
            margin = 600
        else: # Untuk < 50.000 dan > 50.000 sama-sama untung Rp. 1.000
            margin = 1000
            
    # Aturan Margin Data, Game, Voucher, SMS, Masa Aktif, Perdana
    else:
        if harga_modal < 100:
            margin = 0
        elif harga_modal < 1000:
            margin = 300
        elif harga_modal < 5000:
            margin = 600
        elif harga_modal < 50000:
            margin = 1500
        else: # Harga di atas Rp. 50.000
            margin = 2000
            
    return harga_modal + margin

# Menerapkan rumus untuk membuat kolom 'Harga Jual' baru
df['Harga Jual'] = df.apply(hitung_harga_jual, axis=1)

# Menyimpan hasil ke file Excel (.xlsx) baru
output_file = 'daftar-produk-harga-jual.xlsx'
df.to_excel(output_file, index=False, engine='openpyxl')

print(f"Selesai! File berhasil disimpan dengan nama: {output_file}")
