import ipaddress
import subprocess
import threading
import logging
import socket
import platform
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import scrolledtext, messagebox
from valid_auth import verify_user

# Configuration

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

stop_scan_flag = False  # Global flag to stop scanning


# Network Functions

def ping_ip(ip, output_widget):
    global stop_scan_flag
    if stop_scan_flag:
        return

    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(
            ['ping', param, '1', str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            status = f"{ip} is active\n"
            logging.info(f"{ip} is active")
            output_widget.insert(tk.END, status)
            output_widget.see(tk.END)
            return ip
        else:
            logging.info(f"{ip} is offline")
    except Exception as e:
        logging.error(f"Error pinging {ip}: {e}")
        output_widget.insert(tk.END, f"Error pinging {ip}: {e}\n")
        output_widget.see(tk.END)


def scan_ports(ip, output_widget):
    for port, service in COMMON_PORTS.items():
        if stop_scan_flag:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((str(ip), port))
                if result == 0:
                    msg = f"{ip}:{port} ({service}) is open\n"
                    logging.info(msg.strip())
                    output_widget.insert(tk.END, msg)
                    output_widget.see(tk.END)
        except Exception as e:
            logging.error(f"Error on {ip}:{port} - {e}")


def start_scan(ip_range, output_widget, scan_btn, stop_btn):
    global stop_scan_flag
    stop_scan_flag = False

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid CIDR like 192.168.1.0/24")
        return

    output_widget.delete(1.0, tk.END)
    output_widget.insert(tk.END, f"🔍 Scanning {len(list(network.hosts()))} hosts...\n\n")
    scan_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    def scan():
        active_ips = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(ping_ip, ip, output_widget) for ip in network.hosts()]
            for future in futures:
                result = future.result()
                if result:
                    active_ips.append(result)

        output_widget.insert(tk.END, f"\n📡 {len(active_ips)} active hosts found. Starting port scan...\n\n")

        with ThreadPoolExecutor(max_workers=50) as executor:
            for ip in active_ips:
                executor.submit(scan_ports, ip, output_widget)

        output_widget.insert(tk.END, "\n✅ Scan complete.\n")
        scan_btn.config(state=tk.NORMAL)
        stop_btn.config(state=tk.DISABLED)

    threading.Thread(target=scan).start()


def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True


# GUI Functions

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

    scan_btn.config(command=lambda: start_scan(ip_entry.get(), output_box, scan_btn, stop_btn))

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


if __name__ == "__main__":
    login_window()