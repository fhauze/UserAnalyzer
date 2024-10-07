import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys

file_path = sys.argv[1]

# 1. Memuat data hasil deteksi serangan
# data = pd.read_csv('malicious_files_detected.csv')
data = pd.read_csv(file_path)
slash = file_path.rfind("\\")

# Menentukan path penyimpanan
if slash != -1:
    vizpath = file_path[:slash + 1]
else:
    print("no data found")

# 2. Fungsi untuk menyimpan grafik aktivitas pengguna sebagai gambar
def plot_user_activity(data, output_file=vizpath + 'user_activity.png'):
    plt.figure(figsize=(10, 6))
    sns.countplot(data=data, x='user_agent', order=data['user_agent'].value_counts().index)
    plt.xticks(rotation=90)
    plt.title('User Activity by User Agent')
    plt.xlabel('User Agent')
    plt.ylabel('Number of Activities')
    plt.tight_layout()
    # Menyimpan grafik ke file
    plt.savefig(output_file)
    plt.close()

# 3. Fungsi untuk menyimpan grafik distribusi serangan sebagai gambar
def plot_attack_distribution(data, output_file=vizpath +'attack_distribution.png'):
    data_exploded = data.explode('detected_attack')
    plt.figure(figsize=(10, 6))
    sns.countplot(data=data_exploded, x='detected_attack', order=data_exploded['detected_attack'].value_counts().index)
    plt.title('Detected Attack Types')
    plt.xlabel('Attack Type')
    plt.ylabel('Count')
    plt.tight_layout()
    # Menyimpan grafik ke file
    plt.savefig(output_file)
    plt.close()

# 4. Menyimpan grafik ke file yang bisa diakses oleh CodeIgniter
plot_user_activity(data, vizpath +'user_activity.png')
plot_attack_distribution(data, vizpath +'attack_distribution.png')
