# 🔌 NetMan – Network Management CLI Tool

**NetMan** is a Python-based CLI tool for **network scanning**, **device disconnection (via ARP spoofing)**, and **network restoration** on local networks. Built using **Scapy**, this tool helps you ethically test and manage local network devices for educational and research purposes.

> ⚠️ DISCLAIMER:  
> This tool is for **educational and ethical purposes only**.  
> Do **not use** it on any network you don’t own or have explicit permission to test.  
> The author is not responsible for any misuse or illegal activities involving this code.

---

## 🧰 Features

| Feature                    | Description                                                  |
|---------------------------|--------------------------------------------------------------|
| 🔍 Network Scanning        | Discover all active devices on your LAN with IP/MAC info     |
| ✂️ Disconnect Devices      | ARP spoof selected devices to block their access to internet |
| ♻️ Restore Devices         | Send correct ARP packets to restore a disconnected device     |
| 🔒 Whitelist Support       | Prevent specific MAC addresses from being targeted           |
| 📄 Save Scan Results       | Export device list to CSV                                    |
| 👥 Multi-Device Control     | Disconnect or restore multiple devices at once               |
| 🛡️ Restore All            | Restore the entire network with one command                  |

---

## 📦 Requirements

- Python 3.x
- Root privileges (Linux/macOS)

### ✅ Installation and Usage

<pre>
git clone https://github.com/PULSAR-002/netman.git
cd netman/netman
pip install -r requirements.txt
sudo python3 netman.py
</pre>


---

## 🖼️ Demo Screenshot
<img width="1913" height="960" alt="Screenshot 2025-08-03 032038" src="https://github.com/user-attachments/assets/a26230de-c5e9-4a39-85fe-01390ccb818c" />
