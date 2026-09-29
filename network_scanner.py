import scapy.all as scapy
import argparse
import socket
import sys

def get_default_ip():
    """Attempt to get the default IP address of the machine."""
    try:
        # Create a dummy socket to determine the default route
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1" # Fallback

def get_default_subnet():
    """Guess the subnet based on the default IP."""
    ip = get_default_ip()
    parts = ip.split('.')
    parts[3] = '0/24'
    return '.'.join(parts)

def get_arguments():
    parser = argparse.ArgumentParser(description="A local network scanner using Scapy.")
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range (e.g., 192.168.1.0/24). Default is your local subnet.")
    options = parser.parse_args()
    
    if not options.target:
        options.target = get_default_subnet()
        print(f"[*] No target specified. Defaulting to local subnet: {options.target}")
        
    return options

def scan(ip):
    """Scan the network via ARP requests."""
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip)
    # Create an Ethernet frame directed to broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the Ethernet frame and ARP request
    arp_request_broadcast = broadcast/arp_request
    
    # Send the packet and capture the responses (srp = send/receive at layer 2)
    # timeout ensures the script doesn't hang waiting
    # verbose=False stops scapy from printing extra info
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        # element[0] is the request sent, element[1] is the response received
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def print_result(results_list):
    """Print the list of discovered devices nicely."""
    print("\nIP Address\t\tMAC Address")
    print("-" * 41)
    for client in results_list:
        # Align columns
        print(f"{client['ip']:<20}{client['mac']}")

if __name__ == "__main__":
    options = get_arguments()
    print(f"[*] Scanning {options.target}...")
    
    try:
        scan_result = scan(options.target)
        if not scan_result:
            print("[-] No devices found. (Or you might need administrator privileges/Npcap installed)")
        else:
            print_result(scan_result)
    except PermissionError:
        print("\n[-] Permission Error: Scapy requires administrative privileges to send raw packets.")
        print("    Please run your command prompt or terminal as an Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An error occurred: {e}")
        print("    Note: On Windows, Scapy requires Npcap to be installed to capture packets.")
        print("    You can download it from: https://npcap.com/")
        sys.exit(1)
