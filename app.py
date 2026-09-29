from flask import Flask, render_template, request, jsonify
import scapy.all as scapy
import socket
import sys
import os
import requests
import subprocess
import re
import concurrent.futures
from mac_vendor_lookup import MacLookup, VendorNotFoundError

app = Flask(__name__)
mac_lookup = MacLookup()

# Try to update the mac-vendor-lookup cache on startup
try:
    mac_lookup.update_vendors()
except Exception:
    pass # Ignore if it fails due to network or permissions

def get_default_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"

def get_default_subnet():
    ip = get_default_ip()
    parts = ip.split('.')
    parts[3] = '0/24'
    return '.'.join(parts)

def get_vendor(mac):
    # Method 1: use the local library
    try:
        return mac_lookup.lookup(mac)
    except VendorNotFoundError:
        pass
    except Exception:
        pass
    
    # Method 2: fallback to an API
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
        
    return "Unknown"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def get_arp_cache():
    devices = []
    try:
        # Run arp -a to get devices already known to the OS
        output = subprocess.check_output("arp -a", shell=True).decode()
        for line in output.splitlines():
            # Match dynamic ARP entries (IP and MAC)
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+dynamic", line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').lower()
                # Ignore broadcast/multicast IPs
                if not ip.endswith('.255') and not ip.startswith('224.') and not ip.startswith('239.'):
                    devices.append({"ip": ip, "mac": mac})
    except Exception:
        pass
    return devices

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/subnet", methods=["GET"])
def api_subnet():
    return jsonify({"subnet": get_default_subnet()})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json
    target_ip = data.get("subnet", get_default_subnet())
    
    try:
        # Create ARP request
        arp_request = scapy.ARP(pdst=target_ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Increase timeout to 5 seconds and add retry=1 for better discovery
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, retry=1, verbose=False)[0]

        discovered_dict = {} # Use dict to prevent duplicates by MAC
        
        # 1. Parse Scapy results
        for element in answered_list:
            ip_addr = element[1].psrc
            mac_addr = element[1].hwsrc.lower()
            discovered_dict[mac_addr] = {"ip": ip_addr, "mac": mac_addr}
            
        # 2. Merge with system ARP cache (finds sleeping/firewalled devices)
        arp_cache = get_arp_cache()
        for dev in arp_cache:
            if dev["mac"] not in discovered_dict:
                discovered_dict[dev["mac"]] = {"ip": dev["ip"], "mac": dev["mac"]}

        clients_list = []
        
        # Helper function to enrich device info in parallel
        def enrich_device(device_info):
            mac = device_info["mac"]
            ip = device_info["ip"]
            return {
                "ip": ip,
                "mac": mac,
                "vendor": get_vendor(mac),
                "hostname": get_hostname(ip)
            }
            
        # 3. Enrich devices with vendor and hostname (using threads to speed up DNS lookups)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            clients_list = list(executor.map(enrich_device, discovered_dict.values()))
            
        # Sort by IP address
        try:
            clients_list.sort(key=lambda x: [int(p) for p in x["ip"].split('.')])
        except Exception:
            pass
            
        return jsonify({"status": "success", "devices": clients_list})
    except PermissionError:
        return jsonify({"status": "error", "message": "Permission Error: Administrator privileges required to run Scapy."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
