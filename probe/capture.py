#!/usr/bin/env python3

from scapy.all import *
from datetime import datetime
import csv
import os
from dotenv import load_dotenv

# Load interface from .env if available
load_dotenv()
iface = os.getenv("IFACE")

# Fallback: prompt user if IFACE not set
if not iface:
    iface = input(" No interface found in .env. Please enter interface name (e.g., wlan0mon): ").strip()
    if not iface:
        print(" No interface provided. Exiting.")
        exit(1)

output_file = "probe_requests_log.csv"

def is_randomized_mac(mac):
    """Returns True if MAC address is likely randomized (locally administered)."""
    return bool(mac and int(mac[1], 16) & 2)

def handle_packet(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.getlayer(Dot11Elt).info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "<hidden>"
        mac = pkt.addr2
        if not mac:
            return

        timestamp = datetime.now().isoformat()
        strength = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
        randomized = is_randomized_mac(mac)

        row = [timestamp, mac, ssid, strength, randomized]
        print(f"[] {timestamp} | {mac} | SSID: {ssid} | Signal: {strength} | Random: {randomized}")

        with open(output_file, "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(row)

def setup_csv():
    if not os.path.exists(output_file):
        with open(output_file, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "mac", "ssid", "signal_strength", "randomized"])

if __name__ == "__main__":
    print(f" Starting capture on interface: {iface}")
    setup_csv()
    sniff(iface=iface, prn=handle_packet, store=0, monitor=True)
