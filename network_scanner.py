import argparse
import socket
import sys

def get_default_ip():
    """Attempt to get the default IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"

def get_default_subnet():
    """Guess the subnet based on the default IP."""
    ip = get_default_ip()
    parts = ip.split('.')
    parts[3] = '0/24'
    return '.'.join(parts)

def get_arguments():
    parser = argparse.ArgumentParser(description="A network scanner supporting ARP and Socket fallback.")
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range (e.g., 192.168.1.0/24 or domain).")
    options = parser.parse_args()
    
    if not options.target:
        options.target = get_default_subnet()
        print(f"[*] No target specified. Defaulting to local subnet: {options.target}")
        
    return options

def socket_recon(target):
    """Fallback scanner for Cloud/Render (No Admin/Root required)."""
    clients_list = []
    ports = [21, 22, 80, 443, 8080]
    open_ports = []

    # Clean target if subnet passed
    clean_target = target.split('/')[0] if '/' in target else target

    try:
        resolved_ip = socket.gethostbyname(clean_target)
    except socket.gaierror:
        resolved_ip = clean_target

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((resolved_ip, port))
        if result == 0:
            open_ports.append(str(port))
        s.close()

    port_info = f"Open Ports: {', '.join(open_ports)}" if open_ports else "Reachable (No standard web ports open)"
    clients_list.append({
        "ip": f"{resolved_ip} ({clean_target})" if resolved_ip != clean_target else resolved_ip,
        "mac": f"Cloud Mode - {port_info}"
    })
    return clients_list

def scan(ip):
    """Scan the network via ARP requests, with fallback to socket scanning on permission restriction."""
    try:
        import scapy.all as scapy
        
        # ARP request setup
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
        
        return clients_list

    except (PermissionError, OSError):
        # Fallback executes automatically when run on Render/Non-Root cloud environments
        return socket_recon(ip)

def print_result(results_list):
    """Print the list of discovered devices nicely."""
    print("\nIP Address\t\tMAC / Recon Status")
    print("-" * 55)
    for client in results_list:
        print(f"{client['ip']:<20}{client['mac']}")

if __name__ == "__main__":
    options = get_arguments()
    print(f"[*] Scanning {options.target}...")
    
    try:
        scan_result = scan(options.target)
        if not scan_result:
            print("[-] No devices found.")
        else:
            print_result(scan_result)
    except Exception as e:
        print(f"\n[-] An error occurred: {e}")
        sys.exit(1)