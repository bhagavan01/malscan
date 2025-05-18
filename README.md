# 🛡️ malscan

**malscan** is a cross-platform malware detection tool that combines static (hash-based) and behavioral analysis to identify malicious software. It works on **Linux**, **macOS**, and **Windows**, with both CLI and GUI interfaces, and includes an optional web dashboard for centralized analysis.

---

## 🔍 Features

- ✅ Static analysis using SHA256 signature matching
- ✅ Behavioral analysis of:
  - Running processes
  - Suspicious file names or paths
  - System log files
- ✅ Command-line interface (CLI)
- ✅ GUI using Tkinter (Python)
- ✅ Web dashboard using Flask (optional)
- ✅ Lightweight, fast, and open source
- ✅ Designed for educational, research, and cybersecurity awareness purposes

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Git
- pip (Python package manager)

### Steps

```bash
# Clone the repository
git clone https://github.com/bhagavan01/malscan.git

# Change into the directory
cd malscan

# Install required dependencies
pip install -r requirements.txt
```
For web dashboard:
```bash
pip install flask
```
For GUI:
```bash
sudo apt install python3-tk

```
🚀 Usage
CLI Mode
```bash

python3 malscan.py
```
You will be prompted to:

Enter a directory to scan

Review process and system behavior

GUI Mode
```bash

python3 gui_malscan.py
```
Tkinter GUI will launch with buttons to start scanning and display results.

Web Dashboard (optional)
```bash

python3 app.py
```
Visit http://127.0.0.1:5000 in your browser to view the dashboard.

📸 Screenshot (optional)


(Replace these links with your actual images)

🧪 Signature Matching
To add malware signatures, add SHA256 hashes to signatures.txt, one per line:

eicar-test-file-sha256-here
another-malware-sha256-here

📄 License
This project is licensed under the MIT License.

👨‍💻 Author
Bhagavan

GitHub: @bhagavan01

💡 Disclaimer
This tool is intended only for educational and awareness purposes. It does not replace enterprise-grade antivirus solutions. Use it responsibly 
