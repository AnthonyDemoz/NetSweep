<div align="center">

# 🖥️ NetSweep  
**A modern Python-based LAN & Remote network scanner with login security, port detection, banner grabbing, and Geo IP mapping.**

![netsweep-banner](docs/banner-netsweep.png)

</div>

---

### 🔍 About

NetSweep is a Python-powered network scanning tool that makes it easy to detect devices on your LAN or remote subnets. It supports both ARP discovery and ICMP ping modes, login authentication, TCP port scanning, banner grabbing, and even public IP geolocation with a one-click Google Maps preview.

Whether you're a cybersecurity student, system admin, or enthusiast, NetSweep provides powerful recon features in a clean and intuitive GUI.

---

### 🛠️ Install & Run

```bash
# Clone the repository
git clone https://github.com/AnthonyDemoz/NetSweep.git
cd NetSweep

# Install dependencies
pip install -r requirements.txt

# Set up your login user
python setup_users.py

# Start scanning
python netsweep.py
