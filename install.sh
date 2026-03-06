# Mengembalikan input manual untuk menu Create Akun X-ray
sed -i 's/^[ \t]*quota=100$/               read -p " Quota Bandwidth GB (0 for unlimited): " quota; [[ -z "$quota" ]] \&\& quota=0/g' /usr/bin/menu

# Mengembalikan kuota menjadi unlimited/0 untuk menu Trial Akun X-ray
sed -i 's/limit=1; quota=100;/limit=1; quota=0;/g' /usr/bin/menu

# Menghapus sisa komentar hardcode agar script rapi
sed -i 's/# KUOTA OTOMATIS 100GB//g' /usr/bin/menu
sed -i 's/# TRIAL JUGA OTOMATIS 100GB//g' /usr/bin/menu

echo "Fix berhasil! Silakan ketik 'menu' lagi di terminal."
