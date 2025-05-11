# ⚡ NetSweep – Python LAN & Remote Scanner

**NetSweep** is a powerful, GUI-based network scanner built with Python. It helps you discover devices on your local network or remote subnet, detect open ports, extract service banners, and optionally secure access with a login screen.

Designed to be fast, clean, and beginner-friendly — with a professional touch.

![NetSweep Banner](docs/banner.png) <!-- Optional visual -->

---

## 🚀 Features

- 🔐 **Login-protected access** (with bcrypt-secured user system)
- 📡 **Host discovery** using **ARP** (LAN) or **ICMP ping** (remote)
- 🔍 **Open port detection** on common TCP ports
- 🧠 **Service & version detection** via banner grabbing
- 🧰 **Multithreaded scanning** for performance
- 💾 Optional export & logging (CSV support coming!)
- 🧪 Responsive **Tkinter GUI** with dark mode
- 📁 **Log file output**: `netsweep_gui.log`

---

## 🎯 How it Works

You can choose between:

- ✅ **Local Scan (default)** → uses ARP to discover all devices on your LAN and scan their ports  
- 🌐 **Remote Scan Mode** → uses ping to find devices on any reachable IP range (e.g. VPN, cloud subnet)

---

## 🧩 Installation

```bash
# 1. Clone the repo
git clone https://github.com/AnthonyDemoz/NetSweep.git
cd NetSweep
---
# 2. Install dependencies
pip install -r requirements.txt
---
# 3. Create your first user
python setup_users.py
---
# 4. Run the scanner
python netsweep.py
