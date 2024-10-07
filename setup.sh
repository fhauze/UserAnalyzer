#!/bin/bash

#medefimisikan root path
CI_PATH="$(pwd)"
req_path="$CI_PATH/vendor/src/python/requirements.txt"
IMAGE_PATH="$CI_PATH/writable/images"
CSV_PATH="$CI_PATH/writable/results"
PATH_FILE="$CI_PATH/app/Config/Paths.php"
echo "dir : $CI_PATH"
# Cek apakah pip sudah terinstal
if ! command -v pip &> /dev/null
then
    echo "pip tidak ditemukan. Silakan instal pip terlebih dahulu."
    exit 1
fi

# Install dependencies
if [ -f "$req_path" ]; then
    pip install -r "$req_path"
    echo "Semua dependensi Python telah diinstal."
    # Menjalankan install_requirements.sh
    #./install_requirements.sh
else
    echo "No file found"
fi

if [ ! -d "$IMAGE_PATH" ]; then
    mkdir -p "$IMAGE_PATH"

    chmod -R 755 "$IMAGE_PATH"
else
    echo "Folder sudah ada"
fi

if [ ! -d "$CSV_PATH" ]; then
    mkdir -p "$CSV_PATH"

    chmod -R 755 "$CSV_PATH"
else
    echo "Folder CSV sudah ada"
fi


#menulis file
#cmd="/^.*public .*\$.*; /a public \$wim= ROOTPATH . 'writable/images';"
if [ -f "$PATH_FILE" ]; then
    sed -i "/^.*public .*\$.*; /a public \$wim= ROOTPATH . 'writable/images';" "$PATH_FILE"
else
    echo "$PATH_FILE : File tdak dtmukan."
fi

