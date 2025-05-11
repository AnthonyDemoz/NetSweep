<div align="center">

# NetSweep  
**A Python-based network scanner with ARP & Remote discovery, port detection, and Geo IP mapping.**

![netsweep-banner](docs/netsweeplgo.jpg)

</div>

---

### About

**NetSweep** is a user-friendly and powerful network scanning toolkit built in Python with a graphical interface. It supports:

- LAN scanning using ARP packets
- Remote subnet scanning using ICMP ping
- TCP port discovery with service banner grabbing
- Public IP geolocation with a Google Maps preview
- Password-protected access using bcrypt hashing

NetSweep is ideal for cybersecurity students, ethical hackers, and sysadmins who want a fast, GUI-based alternative to CLI tools.

---

### Project Versions

| Version              | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **`NetSweep_arpremote`** | Combines ARP scanning for LAN with ICMP ping for remote subnets              |
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
# 3. Install required Python packages
```
pip install -r requirements.txt
```
# 4. Create a secure login user
```
python setup_users.py
```
# 5. Run one of the versions:
```
python netsweep_arpremote.py   # For LAN & remote scan
python geo_netsweep.py         # For Geo IP scanning
```
---
### License

This project is licensed under the MIT License.

