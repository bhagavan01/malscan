#!/usr/bin/env python3

import os
import hashlib
import psutil
import time

SIGNATURE_FILE = "signatures.txt"
SUSPICIOUS_KEYWORDS = ["keylogger", "trojan", "reverse shell", "botnet", "persistence", "exploit"]

def load_signatures():
    if not os.path.exists(SIGNATURE_FILE):
        print("[!] Warning: No malware signatures loaded. Add SHA256 hashes to 'signatures.txt' to detect malware.")
        return set()
    with open(SIGNATURE_FILE, "r") as f:
        return set(line.strip().lower() for line in f if line.strip())

def hash_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def scan_directory(directory, signatures):
    print(f"\n[*] Scanning directory: {directory}")
    infected_files = 0
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = hash_file(filepath)
            if file_hash and file_hash in signatures:
                print(f"[!] Infected file found: {filepath}")
                infected_files += 1
    print(f"[*] Scan complete. {infected_files} infected files found.\n")

def scan_processes(signatures):
    print("[*] Scanning running processes...")
    infected = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info['exe']
            if exe:
                file_hash = hash_file(exe)
                if file_hash and file_hash in signatures:
                    print(f"[!] Malicious process detected: PID={proc.pid}, Name={proc.info['name']}")
                    infected += 1
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    print(f"[*] Process scan complete. {infected} infected processes found.\n")

def scan_logs(log_paths):
    print("[*] Performing behavioral analysis (log pattern scan)...")
    found = 0
    for path in log_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword in content:
                        print(f"[!] Suspicious pattern '{keyword}' found in {path}")
                        found += 1
        except Exception as e:
            print(f"[!] Could not read file {path}: {e}")
    if found == 0:
        print("[*] No suspicious patterns found in logs.\n")

def main():
    print("=== malscan - Simple Malware Scanner ===")

    signatures = load_signatures()

    scan_path = input("Enter directory to scan: ").strip()
    if not os.path.exists(scan_path):
        print("[!] Invalid path.")
        return

    start_time = time.time()

    scan_directory(scan_path, signatures)
    scan_processes(signatures)

    # Scan logs for suspicious keywords (behavioral analysis)
    log_files = [
        "/var/log/syslog", "/var/log/auth.log", "/var/log/messages",
        os.path.expanduser("~/Library/Logs/system.log"),  # macOS
        os.path.expanduser("~\\AppData\\Roaming\\logs.txt")  # Windows placeholder
    ]
    scan_logs(log_files)

    end_time = time.time()
    print(f"=== Scan finished in {end_time - start_time:.2f} seconds ===")

if __name__ == "__main__":
    main()

