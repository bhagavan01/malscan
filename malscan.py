#!/usr/bin/env python3
import os
import hashlib
import psutil
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk

SIGNATURE_FILE = "signatures.txt"

class MalScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("malscan - Malware Scanner")

        # Load and display malware image
        try:
            image = Image.open("malware.png")
            image = image.resize((100, 100))
            self.photo = ImageTk.PhotoImage(image)
            img_label = tk.Label(root, image=self.photo)
            img_label.pack(pady=10)
        except Exception as e:
            print(f"[!] Could not load malware image: {e}")

        # Scan directory selection
        btn_browse = tk.Button(root, text="Select Directory to Scan", command=self.browse_directory)
        btn_browse.pack(pady=5)

        # Text box for showing logs/output
        self.output_text = scrolledtext.ScrolledText(root, width=80, height=20)
        self.output_text.pack(padx=10, pady=10)

        # Scan button
        btn_scan = tk.Button(root, text="Start Scan", command=self.start_scan)
        btn_scan.pack(pady=5)

        self.signatures = self.load_signatures()
        self.target_dir = None

    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update()

    def load_signatures(self):
        if not os.path.exists(SIGNATURE_FILE):
            self.log(f"[!] Warning: Signature file '{SIGNATURE_FILE}' not found. No malware detection via hashes.")
            return set()
        with open(SIGNATURE_FILE, 'r') as f:
            sigs = set(line.strip() for line in f if line.strip())
            self.log(f"[*] Loaded {len(sigs)} malware signatures.")
            return sigs

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.target_dir = directory
            self.log(f"[*] Selected directory: {directory}")

    def sha256sum(self, filename):
        h = hashlib.sha256()
        try:
            with open(filename, 'rb') as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.log(f"[!] Error reading {filename}: {e}")
            return None

    def scan_directory(self, path):
        infected_files = []
        for root_dir, _, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root_dir, file)
                file_hash = self.sha256sum(filepath)
                if file_hash and file_hash in self.signatures:
                    infected_files.append(filepath)
                    self.log(f"[!] Malware detected: {filepath}")
        return infected_files

    def behavioral_analysis(self):
        suspicious_keywords = ["unauthorized", "malware", "rootkit", "exploit", "failed login"]
        self.log("[*] Performing behavioral analysis (running process scan)...")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(s in name for s in ['keylogger', 'rat', 'stealer']):
                    self.log(f"[!] Suspicious process found: {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def start_scan(self):
        self.output_text.delete('1.0', tk.END)
        if not self.target_dir:
            messagebox.showerror("Error", "Please select a directory to scan first.")
            return

        self.log("[*] Starting scan...")
        infected = self.scan_directory(self.target_dir)
        self.log("[*] File scan complete.\n")

        self.behavioral_analysis()

        self.log("[*] Scan complete.")
        self.log(f"[*] {len(infected)} infected file(s) found.")

def main():
    root = tk.Tk()
    app = MalScanApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
