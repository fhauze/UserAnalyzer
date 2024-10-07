import re
import os
import pandas as pd
import logging

from flask import Flask, request, jsonify
# Inisialisasi Flask
app = Flask(__name__)

# 1. Load data log pengguna dan file upload
# Asumsikan data log yang berisi kolom 'ip_address', 'url', 'request_type', 'response_code', 'user_agent', 'timestamp', dan 'file_path' untuk file yang diupload
# data = pd.read_csv('user_logs.csv')

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

# Route untuk menangkap request
@app.route('/', methods=['GET', 'POST'])
def log_request():
    print("Request come")
    # if request.method == 'POST':

    if request:
        # Ambil data dari body request
        data = request.get_data(as_text=True)
        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Mendeteksi apakah ada serangan yang terdeteksi di dalam body request
        attack_types = detect_attack_type(data)

        # Simpan log ke dalam file CSV (user_logs.csv)
        log_data = {
            'ip_address': request.remote_addr + "localhost//",
            'user_agent': user_agent,
            'request_data': data,
            'detected_attacks': ', '.join(attack_types) if attack_types else 'None'
        }
        log_df = pd.DataFrame([log_data])
        try:
            log_df.to_csv('user_logs.csv', mode='a', index=False, header=not os.path.isfile('user_logs.csv'))
        except Exception as e:
            print(f"Error writing to CSV: {e}")

        # log_df.to_csv('user_logs.csv', mode='a', index=False, header=False)
        logging.info(log_data)
        # Respon jika ada serangan terdeteksi
        if attack_types:
            return jsonify({"message": "Attack detected", "attacks": attack_types}), 403
        else:
            return jsonify({"message": "No attack detected"}), 200

    return jsonify({"message": "Send a POST request to log data"}), 200

# Menjalankan server Flask di localhost:8000
# if __name__ == '__main__':
#     app.run(debug=True)
#     app.run(host='0.0.0.0', port=8000)