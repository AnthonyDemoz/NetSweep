
import ipaddress
import subprocess
import threading
import logging
import socket
import platform
import bcrypt
import sqlite3
import requests
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import scrolledtext, messagebox
from mac_vendor_lookup import MacLookup

# ─────── ASCII Banner ───────
def show_banner():
    banner = [
        "   ███╗   ██╗███████╗████████╗███████╗██╗    ██╗███████╗██████╗ ",
        "   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║    ██║██╔════╝██╔══██╗",
        "   ██╔██╗ ██║█████╗     ██║   █████╗  ██║ █╗ ██║█████╗  ██████╔╝",
        "   ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║███╗██║██╔══╝  ██╔═══╝ ",
        "   ██║ ╚████║███████╗   ██║   ███████╗╚███╔███╔╝███████╗██║     ",
        "   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝     ",
        ""
    ]
    for line in banner:
        print(line)

# ─────── Logging ───────
logging.basicConfig(
    filename="netsweep_gui.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

stop_scan_flag = False

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3389: "RDP"
}

# ─────── Authentication ───────
def verify_user(username, password):
    conn = sqlite3.connect("netsweep_users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode('utf-8'), row[0]):
        return True
    return False

# ─────── Geo IP Lookup ───────
def geo_lookup(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = res.json()
        if data["status"] == "success":
            return f"🌍 {ip} ➜ {data['country']}, {data['city']} ({data['isp']}) [Lat: {data['lat']} | Lon: {data['lon']}]"
        else:
            return f"❌ Could not locate {ip}."
    except Exception as e:
        return f"⚠️ Error: {e}"

# Cache the vendor lookup database
try:
    MacLookup().update_vendors()  # Only run once or when needed
except Exception as e:
    print(f"⚠️ Couldn't update MAC vendors: {e}")

def get_mac_vendor(mac):
    try:
        vendor = MacLookup().lookup(mac)
        return vendor
    except Exception:
        return "Unknown Vendor"

# ─────── Ping Hosts ───────
def ping_ip(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(["ping", param, "1", str(ip)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return str(ip) if result.returncode == 0 else None

# ─────── Scan Ports ───────
def scan_ports(ip, output_widget):
    for port, service in COMMON_PORTS.items():
        if stop_scan_flag:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    try:
                        sock.send(b"\n")
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                        info = f"{ip}:{port} ({service})"
                        info += f" → {banner}" if banner else ""
                    except:
                        info = f"{ip}:{port} ({service}) open"
                    output_widget.insert(tk.END, f"🔓 {info}\n")
                    output_widget.see(tk.END)
        except Exception as e:
            logging.error(f"Error scanning {ip}:{port} → {e}")

# ─────── Main Scan Routine ───────
def start_scan(ip_range, output_widget, scan_btn, stop_btn):
    global stop_scan_flag
    stop_scan_flag = False

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        messagebox.showerror("Invalid Input", "Enter CIDR like 192.168.1.0/24")
        return

    output_widget.delete(1.0, tk.END)
    output_widget.insert(tk.END, f"🔍 Scanning {len(list(network.hosts()))} hosts...\n")
    scan_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    def scan():
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in network.hosts()]
            live_hosts = [f.result() for f in futures if f.result()]

        output_widget.insert(tk.END, f"📡 Found {len(live_hosts)} live hosts\n\n")
        for ip, mac in live_hosts:
            output_widget.insert(tk.END, f"🔎 Scanning {ip}...\n")
            scan_ports(ip, output_widget)

        output_widget.insert(tk.END, "\n✅ Scan complete.\n")
        scan_btn.config(state=tk.NORMAL)
        stop_btn.config(state=tk.DISABLED)

    threading.Thread(target=scan).start()

def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True

# ─────── GUI ───────
def launch_gui():
    root = tk.Tk()
    root.title("NetSweep - Network Scanner")
    root.configure(bg="#1e1e1e")

    # IP Range Entry
    tk.Label(root, text="Enter IP range (CIDR):", bg="#1e1e1e", fg="white").pack(pady=5)
    ip_entry = tk.Entry(root, width=30)
    ip_entry.pack(pady=5)
    ip_entry.insert(0, "192.168.1.0/24")

    # Output Box
    output_box = scrolledtext.ScrolledText(root, width=75, height=20, bg="#111", fg="#0f0", insertbackground="white")
    output_box.pack(padx=10, pady=10)

    # Geo IP Lookup
    geo_frame = tk.Frame(root, bg="#1e1e1e")
    geo_frame.pack(pady=5)
    tk.Label(geo_frame, text="IP Geolocation:", bg="#1e1e1e", fg="white").pack(side=tk.LEFT)
    geo_entry = tk.Entry(geo_frame, width=20)
    geo_entry.pack(side=tk.LEFT, padx=5)

    def lookup_geo():
        ip = geo_entry.get().strip()
        if ip:
            result = geo_lookup(ip)
            output_box.insert(tk.END, f"{result}\n")
            output_box.see(tk.END)

    tk.Button(geo_frame, text="🌍 Lookup", command=lookup_geo, bg="#007acc", fg="white").pack(side=tk.LEFT)

    # Buttons
    button_frame = tk.Frame(root, bg="#1e1e1e")
    button_frame.pack(pady=5)
    scan_btn = tk.Button(button_frame, text="Start Scan", bg="#2e8b57", fg="white")
    stop_btn = tk.Button(button_frame, text="Stop", bg="#8b0000", fg="white", command=stop_scan, state=tk.DISABLED)

    scan_btn.config(command=lambda: start_scan(ip_entry.get(), output_box, scan_btn, stop_btn))
    scan_btn.grid(row=0, column=0, padx=5)
    stop_btn.grid(row=0, column=1, padx=5)

    root.mainloop()

# ─────── Login ───────
def login_window():
    login = tk.Tk()
    login.title("NetSweep Login")
    login.geometry("300x200")
    login.configure(bg="#1e1e1e")

    tk.Label(login, text="Username", bg="#1e1e1e", fg="white").pack(pady=5)
    username_entry = tk.Entry(login)
    username_entry.pack()

    tk.Label(login, text="Password", bg="#1e1e1e", fg="white").pack(pady=5)
    password_entry = tk.Entry(login, show="*")
    password_entry.pack()

    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()
        if verify_user(username, password):
            login.destroy()
            launch_gui()
        else:
            messagebox.showerror("Login Failed", "Wrong credentials.")

    tk.Button(login, text="Login", command=attempt_login, bg="#2e8b57", fg="white").pack(pady=10)
    login.mainloop()

# ─────── Entry Point ───────
if __name__ == "__main__":
    show_banner()
    login_window()
