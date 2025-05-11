import ipaddress
import subprocess
import threading
import logging
import socket
import platform
import requests
import webbrowser
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import scrolledtext, messagebox
from valid_auth import verify_user

# ─────── ASCII Banner ───────

def show_banner():
    banner = [
        "        ┌────────────────────────────┐",
        "        │  NetSweep - LAN Scanner  │",
        "        └────────────────────────────┘",
        "                ║     ",
        "           ┌────▼────┐",
        "           │  Router │───📶─── Internet",
        "           └─────────┘",
        "        (ARP & TCP scanner + Geo IP)",
        ""
    ]
    for line in banner:
        print(line)


# ─────── Config & Globals ───────

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

logging.basicConfig(
    filename="netsweep_gui.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

stop_scan_flag = False


# ─────── Helper Functions ───────

def arp_discover(ip_range):
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]
        return [(rcv.psrc, rcv.hwsrc) for _, rcv in result]
    except Exception as e:
        logging.error(f"ARP scan error: {e}")
        return []


def geo_lookup(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data["status"] == "success":
            return {
                "summary": f"{data['country']} - {data['city']} ({data['isp']})",
                "lat": data["lat"],
                "lon": data["lon"]
            }
    except Exception as e:
        logging.error(f"Geo IP lookup failed for {ip}: {e}")
    return None


def scan_ports(ip, output_widget):
    if stop_scan_flag:
        return

    is_private = ipaddress.ip_address(ip).is_private
    if not is_private:
        geo = geo_lookup(ip)
        if geo:
            summary = geo["summary"]
            lat, lon = geo["lat"], geo["lon"]
            output_widget.insert(tk.END, f"🌍 {ip} ➜ {summary} (📍 {lat}, {lon})\n")

            def open_map():
                webbrowser.open(f"https://www.google.com/maps?q={lat},{lon}")
            output_widget.after(0, lambda: tk.Button(output_widget, text="🗺️ View on Map", command=open_map).pack())
        else:
            output_widget.insert(tk.END, f"🌍 {ip} ➜ Geo Info N/A\n")
        output_widget.see(tk.END)

    for port, service in COMMON_PORTS.items():
        if stop_scan_flag:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                result = sock.connect_ex((str(ip), port))
                if result == 0:
                    try:
                        sock.sendall(b"\n")
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                        if banner:
                            msg = f"    🔓 {ip}:{port} ({service}) ➜ {banner}\n"
                        else:
                            msg = f"    🔓 {ip}:{port} ({service}) is open\n"
                    except:
                        msg = f"    🔓 {ip}:{port} ({service}) is open (no banner)\n"
                    logging.info(msg.strip())
                    output_widget.insert(tk.END, msg)
                    output_widget.see(tk.END)
        except Exception as e:
            logging.error(f"Error on {ip}:{port} - {e}")


def start_scan(ip_range, output_widget, scan_btn, stop_btn, remote_mode=False):
    global stop_scan_flag
    stop_scan_flag = False

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid CIDR like 192.168.1.0/24")
        return

    output_widget.delete(1.0, tk.END)
    scan_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    def scan():
        if remote_mode:
            output_widget.insert(tk.END, "🌐 Remote mode: using ICMP ping...\n")
            def ping_host(ip):
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                result = subprocess.run(
                    ['ping', param, '1', str(ip)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return ip if result.returncode == 0 else None

            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
                hosts = [(ip, 'N/A') for ip in [f.result() for f in futures] if ip]
        else:
            output_widget.insert(tk.END, f"🔍 Performing ARP discovery on {ip_range}...\n\n")
            hosts = arp_discover(str(network))

        output_widget.insert(tk.END, f"📡 Found {len(hosts)} active hosts\n\n")

        with ThreadPoolExecutor(max_workers=50) as executor:
            for ip, mac in hosts:
                output_widget.insert(tk.END, f"🔎 Scanning {ip} ({mac})...\n")
                executor.submit(scan_ports, ip, output_widget)

        output_widget.insert(tk.END, "\n✅ Scan complete.\n")
        scan_btn.config(state=tk.NORMAL)
        stop_btn.config(state=tk.DISABLED)

    threading.Thread(target=scan).start()


def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True


# ─────── GUI Functions ───────

def launch_gui():
    root = tk.Tk()
    root.title("NetSweep - LAN Scanner")
    root.configure(bg="#1e1e1e")

    tk.Label(root, text="Enter IP range (e.g. 192.168.1.0/24):", bg="#1e1e1e", fg="white").pack(pady=5)
    ip_entry = tk.Entry(root, width=30)
    ip_entry.pack(pady=5)
    ip_entry.insert(0, "192.168.1.0/24")

    output_box = scrolledtext.ScrolledText(root, width=70, height=20, bg="#111", fg="#00ff00", insertbackground="white")
    output_box.pack(padx=10, pady=10)

    button_frame = tk.Frame(root, bg="#1e1e1e")
    button_frame.pack(pady=5)

    scan_btn = tk.Button(button_frame, text="Start Scan", bg="#2e8b57", fg="white")
    stop_btn = tk.Button(button_frame, text="Stop Scan", bg="#8b0000", fg="white", command=stop_scan, state=tk.DISABLED)

    is_remote = tk.BooleanVar()
    remote_check = tk.Checkbutton(
        root,
        text="Remote Scan Mode (No ARP)",
        variable=is_remote,
        bg="#1e1e1e",
        fg="white",
        activebackground="#1e1e1e",
        activeforeground="white",
        selectcolor="#1e1e1e"
    )
    remote_check.pack(pady=5)

    scan_btn.config(command=lambda: start_scan(ip_entry.get(), output_box, scan_btn, stop_btn, is_remote.get()))
    scan_btn.grid(row=0, column=0, padx=5)
    stop_btn.grid(row=0, column=1, padx=5)

    root.mainloop()


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
            messagebox.showerror("Login Failed", "Invalid username or password.")

    tk.Button(login, text="Login", command=attempt_login, bg="#2e8b57", fg="white").pack(pady=10)
    login.mainloop()


# ─────── Entry Point ───────

if __name__ == "__main__":
    show_banner()
    login_window()
