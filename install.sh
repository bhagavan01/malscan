#!/bin/bash

echo "[+] Installing malscan..."
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install flask psutil requests

echo "[+] Setup complete!"
echo "[*] Run with: python3 malscan.py"
