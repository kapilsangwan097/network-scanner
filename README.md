# Network Explorer (Web Scanner)

A beautiful, web-based local network scanner built with Python, Flask, and Scapy.

## Features
- **ARP Scanning**: Uses low-level ARP requests (via Scapy) to discover devices on your network.
- **Enhanced Discovery**: Uses longer timeouts and retries to find devices that might be slow to respond.
- **MAC Vendor Resolution**: Automatically looks up the manufacturer/vendor of the device based on its MAC address.
- **Beautiful UI**: Features a modern, dark-themed, glassmorphism design.
- **CSV Export**: Easily export your scan results to a CSV file.

## Requirements
- Python 3.x
- Administrative/Root privileges (required by Scapy to send raw packets)
- **Windows Users**: You must have [Npcap](https://npcap.com/) installed (comes with Wireshark/Nmap).

## Installation

Install the required Python dependencies:
```bash
pip install flask scapy mac-vendor-lookup requests
```

## Running the Application

1. Open your command prompt or terminal **as an Administrator**.
2. Navigate to this directory.
3. Start the Flask server:
   ```bash
   python app.py
   ```
4. Open your web browser and go to: `http://localhost:5000`

## How to Use
1. The app will automatically try to guess your local subnet (e.g., `192.168.1.0/24`). 
2. If the guess is wrong or you want to scan a different range, edit the input field.
3. Click **Start Scan**. The scan may take up to 10 seconds.
4. Once complete, the table will populate with the IP, MAC, and Vendor of discovered devices.
5. Click **Export CSV** to save the results.
