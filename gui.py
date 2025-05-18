import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess

def scan():
    path = filedialog.askdirectory()
    if not path:
        return
    output = subprocess.getoutput(f"python3 malscan.py <<< '{path}'")
    messagebox.showinfo("Scan Complete", output[-500:])

root = tk.Tk()
root.title("Malscan GUI")
root.geometry("300x200")

btn = tk.Button(root, text="Scan Directory", command=scan)
btn.pack(pady=40)

root.mainloop()
