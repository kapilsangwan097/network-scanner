from flask import Flask, render_template, request, jsonify
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

try:
    mac_lookup.update_vendors()
except Exception:
    pass

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
    try:
        return mac_lookup.lookup(mac)
    except VendorNotFoundError:
        pass
    except Exception:
        pass
    
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
        output = subprocess.check_output("arp -a", shell=True).decode()
        for line in output.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+dynamic", line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').lower()
                if not ip.endswith('.255') and not ip.startswith('224.') and not ip.startswith('239.'):
                    devices.append({"ip": ip, "mac": mac})
    except Exception:
        pass
    return devices

def cloud_socket_scan(target):
    """Fallback scanner for Cloud/Render (bypasses Scapy root restrictions)"""
    devices = []
    clean_target = target.split('/')[0] if '/' in target else target
    
    try:
        resolved_ip = socket.gethostbyname(clean_target)
    except socket.gaierror:
        resolved_ip = clean_target

    common_ports = [21, 22, 80, 443, 8080]
    open_ports = []
    
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((resolved_ip, port)) == 0:
            open_ports.append(str(port))
        s.close()
        
    port_text = f"Open Ports: {', '.join(open_ports)}" if open_ports else "Host Up (No common web ports open)"
    
    devices.append({
        "ip": resolved_ip,
        "mac": "Cloud/Recon Mode",
        "vendor": port_text,
        "hostname": clean_target if clean_target != resolved_ip else get_hostname(resolved_ip)
    })
    return devices

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/subnet", methods=["GET"])
def api_subnet():
    return jsonify({"subnet": get_default_subnet()})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    target_ip = data.get("subnet", get_default_subnet())
    
    try:
        import scapy.all as scapy
        
        # Scapy ARP Scan (Chalega jab root/admin rights hon)
        arp_request = scapy.ARP(pdst=target_ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, retry=1, verbose=False)[0]

        discovered_dict = {}
        for element in answered_list:
            ip_addr = element[1].psrc
            mac_addr = element[1].hwsrc.lower()
            discovered_dict[mac_addr] = {"ip": ip_addr, "mac": mac_addr}
            
        arp_cache = get_arp_cache()
        for dev in arp_cache:
            if dev["mac"] not in discovered_dict:
                discovered_dict[dev["mac"]] = {"ip": dev["ip"], "mac": dev["mac"]}

        def enrich_device(device_info):
            mac = device_info["mac"]
            ip = device_info["ip"]
            return {
                "ip": ip,
                "mac": mac,
                "vendor": get_vendor(mac),
                "hostname": get_hostname(ip)
            }
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            clients_list = list(executor.map(enrich_device, discovered_dict.values()))
            
        try:
            clients_list.sort(key=lambda x: [int(p) for p in x["ip"].split('.')])
        except Exception:
            pass
            
        if not clients_list:
            clients_list = cloud_socket_scan(target_ip)
            
        return jsonify({"status": "success", "devices": clients_list})

    except (PermissionError, OSError, Exception):
        # Render cloud ya restricted environment me fallback execute hoga
        fallback_devices = cloud_socket_scan(target_ip)
        return jsonify({"status": "success", "devices": fallback_devices})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)