#!/bin/bash

echo "[*] Installing Python requirements..."
pip install -r requirements.txt

echo "[*] Installing system tools (optional)..."
sudo apt update
sudo apt install -y curl

# Optional: Go-based tools
if command -v go &> /dev/null; then
    echo "[*] Installing gau and hakrawler..."
    go install github.com/lc/gau/v2/cmd/gau@latest
    go install github.com/hakluke/hakrawler@latest
else
    echo "[!] Skipping gau/hakrawler (Go not installed)"
fi

mkdir -p output
echo "[✔] Environment setup complete."
