<div align="center">

# NetSweep  
**A Python-based network scanner with ping-based discovery, port detection, and Geo IP mapping.**

![netsweep-banner](docs/netsweeplgo.jpg)

</div>

---

### About

**NetSweep** is a user-friendly and powerful network scanning toolkit built in Python with a graphical interface. It supports:

- LAN scanning using Ping and Remote scanning using ARP
- TCP port discovery with service banner grabbing
- Public IP geolocation
- Password-protected access using bcrypt hashing

NetSweep is ideal for cybersecurity students, ethical hackers, and sysadmins who want a fast, GUI-based alternative to CLI tools.

---

### Project Versions

| Version              | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **`Netsweep`** | Combines ARP scanning and Ping scanning    |
| **`geo_netsweep`**       | Adds Geo IP lookup and Google Maps integration for public IPs (no ARP)     |

Both versions share the same login system, core scanning engine, and multithreaded performance — choose based on your scanning focus.

---

### Install & Run

# 1. Clone the repository
```
git clone https://github.com/AnthonyDemoz/NetSweep.git
```
# 2. Navigate to Netsweep
```
cd NetSweep
```
# 3. Make sure venv is installed (Linux)
```
sudo apt install python3-venv
```
# 4. Create a virtual environment (Linux)
```
python3 -m venv netsweep-env
```
# 5. Activate it (Linux)
```
source netsweep-env/bin/activate
```
# 4. Install required Python packages
```
pip install -r requirements.txt
```
# 5. Create a secure login user
```
python setup_users.py
```
# 6. Run one of the versions:
```
python netsweep.py   # For LAN scan and remote scan
python geo_netsweep.py         # For IP Geolocation
```
# 7. Use chmod +x to make the file executable
---
### License

This project is licensed under the MIT License.

