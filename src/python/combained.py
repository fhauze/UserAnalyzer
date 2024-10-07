import re
import os
import pandas as pd
from flask import Flask, request, jsonify

app = Flask(__name__)

# 1. Path file log
log_file_path = 'user_logs.csv'

# 2. Definisikan pola untuk berbagai jenis serangan
attack_patterns = {
    'XSS': [
        r"<script.*?>.*?</script>",
        r"javascript:.*",
        r"eval\(.*?\)",
        r"document\.cookie",
        r"alert\(.*?\)",
        r"<iframe.*?>",
        r"<img.*?onerror=.*?>",
        r"on\w+=.*"
    ],
    'SQL Injection': [
        r"'.*?--",
        r"SELECT.*?FROM",
        r"INSERT INTO.*?VALUES",
        r"DROP TABLE",
        r"OR 1=1",
    ],
    'CSRF': [
        r"<input.*?type=['\"]hidden['\"].*?value=['\"].*?>",
        r"form.*?action=['\"].*?>",
    ],
    'File Inclusion': [
        r"include\(.*?\)",
        r"require\(.*?\)",
        r"file_get_contents\(.*?\)",
        r"shell_exec\(.*?\)",
        r"https?:\/\/",
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

# 4. Fungsi untuk menyimpan log request
def log_request(ip_address, user_agent, request_data, detected_attacks):
    log_data = {
        'ip_address': ip_address,
        'user_agent': user_agent,
        'request_data': request_data,
        'detected_attacks': ', '.join(detected_attacks) if detected_attacks else 'None'
    }

    log_df = pd.DataFrame([log_data])
    
    # Pastikan file CSV selalu ada dan header ditulis saat pertama kali
    if not os.path.isfile(log_file_path):
        # Jika file tidak ada, buat file baru dan tulis header
        log_df.to_csv(log_file_path, mode='w', index=False)
    else:
        # Jika file ada, tambahkan data baru tanpa menulis header
        log_df.to_csv(log_file_path, mode='a', index=False, header=False)

# 5. Tangkap semua request yang terjadi
@app.route('/', methods=['GET', 'POST'])
def handle_request():
    print(f"Received request from {request.remote_addr} with method {request.method}")
    
    if request.method == 'POST':
        # Ambil data dari body request
        data = request.get_data(as_text=True)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote_addr

        # Log data yang diterima
        print(f"Data received: {data}")
        
        # Deteksi apakah ada serangan yang terdeteksi di dalam body request
        attack_types = detect_attack_type(data)

        # Log request
        log_request(ip_address, user_agent, data, attack_types)

        # Respon jika ada serangan terdeteksi
        if attack_types:
            return jsonify({"message": "Attack detected", "attacks": attack_types}), 403
        else:
            return jsonify({"message": "No attack detected"}), 200

    return jsonify({"message": "Send a POST request to log data"}), 200

# 6. Jalankan aplikasi Flask
if __name__ == '__main__':
    app.run(host='localhost', port=8000,  debug=True)
