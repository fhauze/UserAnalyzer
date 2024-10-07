import re
import os
import pandas as pd
import logging
import sys
import csv

from flask import Flask, request, jsonify
# Inisialisasi Flask
app = Flask(__name__)
#buat logging
logging.basicConfig(filename='user_behavior.log', 
                    level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s:%(message)s')


# Menerima argumen dari command line
ip_address = sys.argv[1]
url = sys.argv[2]
url_full = sys.argv[3]
request_type = sys.argv[4]
user_agent = sys.argv[5]
log_file_path = sys.argv[6]
timestamp = sys.argv[7]
statuscode = sys.argv[8]

suspec_data = {
    'ip_address': [ip_address],
    'url': [url],
    'url_full':[url_full],
    'request_type': [request_type],
    'user_agent': [user_agent],
    'timestamp':[timestamp],
    'status_code':[statuscode],
}

#kalau mencurigakan
def is_suspicious(row):
    global suspec_type
    # Pola yang mencurigakan: request dengan response 403 atau 404
    if row['status_code'] in [403, 404]:
        suspec_data['detected_attack'] = ['URL Forcebrute']
        return True
    
    # Percobaan SQL Injection
    if  str(row['url_full']).find('1=1') != -1 or str(row['url_full']).find("' OR 1=1") or "UNION SELECT" in row['url_full'] or "1=1" in row['url_full']:
        suspec_data['detected_attack'] = ["SQL Injection"]
        return True

    # Akses halaman sensitif (/admin, /login) berulang kali
    sensitive_pages = ['/admin', '/login', '/wp-admin']
    if any(page in row['url'] for page in sensitive_pages):
        suspec_data['detected_attack'] = ['URL Shaking']
        print("Sensitif")
        return True

    return False

# 1. Load data log pengguna dan file upload
# Asumsikan data log yang berisi kolom 'ip_address', 'url', 'request_type', 'response_code', 'user_agent', 'timestamp', dan 'file_path' untuk file yang diupload
data = pd.read_csv(log_file_path,chunksize=100000)

# 2. Definisikan pola untuk berbagai jenis serangan
attack_patterns = {
    'XSS': [
        r"<script.*?>.*?</script>",  # Tag <script>
        r"javascript:.*",            # javascript: di dalam atribut
        r"eval\(.*?\)",              # Fungsi eval() yang berbahaya
        r"document\.cookie",         # Pencurian cookie
        r"alert\(.*?\)",             # Fungsi alert() yang sering digunakan dalam XSS
        r"<iframe.*?>",              # Tag iframe yang mencurigakan
        r"<img.*?onerror=.*?>",      # XSS melalui gambar dengan onerror
        r"on\w+=.*"                  # Event handlers dalam tag HTML
    ],
    'SQL Injection': [
        r"'.*?--",                   # Tanda kutip tunggal diikuti komentar SQL
        r"SELECT.*?FROM",            # Pola query SELECT
        r"INSERT INTO.*?VALUES",     # Pola query INSERT
        r"DROP TABLE",               # Pola query DROP
        r"OR 1=1",                   # Pola umum SQL Injection
    ],
    'CSRF': [
        r"<input.*?type=['\"]hidden['\"].*?value=['\"].*?>",  # Hidden input fields
        r"form.*?action=['\"].*?>",  # Form action yang mencurigakan
    ],
    'File Inclusion': [
        r"include\(.*?\)",           # PHP include
        r"require\(.*?\)",           # PHP require
        r"file_get_contents\(.*?\)",  # PHP file_get_contents
        r"shell_exec\(.*?\)",        # Eksekusi perintah shell
        r"https?:\/\/",              # URL referensi untuk file inclusion dari jarak jauh
    ]
}

# 3. Fungsi untuk mendeteksi jenis serangan
def detect_attack_type(file_content):
    detected_attacks = []
    for attack_type, patterns in attack_patterns.items():
        for pattern in patterns:
            if re.search(pattern, file_content, re.IGNORECASE):
                detected_attacks.append(attack_type)
                break
    return detected_attacks

# 4. Fungsi untuk membaca body file dan mengklasifikasikan jenis serangan
def check_file_body_for_attack(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            return detect_attack_type(content)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

# 5. Hapus file jika ada serangan berbahaya
def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)

# 6. Fungsi untuk menganalisa file yang diupload (nama file dan konten body file)
def analyze_uploaded_files(row):
    file_path = row['file_path']  # Asumsikan kolom ini berisi path ke file yang diupload
    
    # Cek body file apakah ada jenis serangan yang terdeteksi
    attack_types = check_file_body_for_attack(file_path)
    
    if attack_types:
        print(f"Malicious script detected in file: {file_path}. Types of attack: {', '.join(attack_types)}. Deleting the file...")
        delete_file(file_path)
        return attack_types
    
    return []

# 7. Terapkan deteksi serangan pada setiap file yang diupload
# data['detected_attacks'] = data.apply(analyze_uploaded_files, axis=1)

# 8. Filter aktivitas yang mengandung serangan
# malicious_files = data[data['detected_attacks'].apply(lambda x: len(x) > 0)]
# print("Total malicious files detected and deleted:", malicious_files.shape[0])

# 9. Simpan hasil deteksi serangan
# malicious_files.to_csv('malicious_files_detected.csv', index=False)

# 10. Output hasil analisis
# print(malicious_files.head())


# Menjalankan server Flask di localhost:8000
# if __name__ == '__main__':
#     app.run(debug=True)
#     app.run(host='0.0.0.0', port=8000)

# Melanjutkan dengan logika deteksi atau penyimpanan data di sini
# Misalnya, menyimpan ke CSV
log_data = {
    'ip_address': [ip_address],
    'url': [url],
    'url_full':[url_full],
    'request_type': [request_type],
    'user_agent': [user_agent],
    'timestamp':[timestamp],
    'status_code':[statuscode]
}

# Mengonversi ke DataFrame dan simpan ke CSV
# log_data = pd.DataFrame(log_data)

# new
# Path ke file CSV
slash = log_file_path.rfind("\\")

# Menentukan path penyimpanan
if slash != -1:
    log_file = log_file_path[:slash + 1] + "py_logs.csv"
    suspec_log = log_file_path[:slash + 1] + "spc_logs.csv"
else:
    print("no path found")
    log_file = log_file_path + "py_logs.csv"
    suspec_log = log_file_path + "spc_logs.csv"

print(f"Mencurigakan ",is_suspicious(suspec_data) , "Atau : ", url_full.find('1=1') or url_full.find("' OR 1=1"))
#Kalau mencurigakan
if is_suspicious(suspec_data):
    try:
        # Cek apakah file sudah ada
        file_exists = os.path.isfile(suspec_log)
        # Buka file untuk penambahan atau buat baru
        with open(suspec_log, 'a', newline='') as csvfile:
            fieldnames = ['ip_address', 'url', 'url_full', 'request_type', 'user_agent', 'timestamp','status_code','detected_attack']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Jika file belum ada, tulis header
            if not file_exists:
                logging.info(f"File {log_file} tidak ditemukan. Membuat file baru dengan header.")
                writer.writeheader()
            
            # Jika ada data log, tulis log ke file CSV
            
            if suspec_data:
                
                #if using dictionary
                for row in zip(*suspec_data.values()):
                    writer.writerow(dict(zip(suspec_data.keys(), row)))
                    print(f"Writing file done indicator : ", suspec_type)
                # logging.info(f"Log berhasil ditulis ke {log_file}")
            else:
                logging.info("Tidak ada data log untuk ditulis.")

    except Exception as e:
        print(f"path ditemukan di {log_file_path} dan {log_data} dan apakah file {file_exists} Error: {e}")
        logging.error(f"Error menulis file CSV: {e}")

#Rekam Aktifitas
try:
    # Cek apakah file sudah ada
    file_exists = os.path.isfile(log_file)
    # Buka file untuk penambahan atau buat baru
    with open(log_file, 'a', newline='') as csvfile:
        fieldnames = ['ip_address', 'url', 'url_full', 'request_type', 'user_agent', 'timestamp','status_code']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Jika file belum ada, tulis header
        if not file_exists:
            logging.info(f"File {log_file} tidak ditemukan. Membuat file baru dengan header.")
            writer.writeheader()
        
        # Jika ada data log, tulis log ke file CSV
        
        if log_data:
            #if using dile
            # wr = writer.writerows(log_data)
            #if using dictionary
            for row in zip(*log_data.values()):
                writer.writerow(dict(zip(log_data.keys(), row)))
                print("Writing file done")
            # logging.info(f"Log berhasil ditulis ke {log_file}")
        else:
            logging.info("Tidak ada data log untuk ditulis.")

except Exception as e:
    logging.error(f"Error menulis file CSV: {e}")

# Debug: cek apakah file berhasil dibuat
# if os.path.isfile(log_file):
#     print(f"File {log_file} berhasil dibuat.",os.path)
# else:
#     print(f"File {log_file} tidak dapat dibuat.")

