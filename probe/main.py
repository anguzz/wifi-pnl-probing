import threading
import subprocess
import time
import os
import sys
from scapy.all import sniff, Dot11, Dot11ProbeReq, RadioTap

# Constants
IFACE = "wlan0mon"
CHANNELS = list(range(1, 14))
LOG_FILE = "probe_requests_log.csv"
VENDOR_FILE = "mac-vendor.txt"

# Shared state
run_event = threading.Event()
current_channel = 1
vendor_dict = {}

# Load MAC vendor prefixes (optional)
def load_mac_vendors():
    vendors = {}
    if os.path.exists(VENDOR_FILE):
        with open(VENDOR_FILE) as f:
            for line in f:
                if "#" in line or "," not in line:
                    continue
                prefix, vendor = line.strip().split(",", 1)
                vendors[prefix.lower()] = vendor.strip()
    return vendors

def lookup_vendor(mac):
    prefix = mac.lower().replace(":", "")[:6]
    return vendor_dict.get(prefix, "Unknown")

# CSV setup
def setup_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("timestamp,mac,ssid,signal_strength,vendor\n")

def append_to_csv(row):
    with open(LOG_FILE, "a") as f:
        f.write(",".join(map(str, row)) + "\n")

# Channel Hopper Thread
def channel_hopper():
    global current_channel
    while run_event.is_set():
        for ch in CHANNELS:
            if not run_event.is_set():
                break
            current_channel = ch
            subprocess.run(["iwconfig", IFACE, "channel", str(ch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

# Packet Handler
def handle_packet(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.info.decode(errors="ignore") if pkt.info else "<hidden>"
        mac = pkt.addr2
        rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal') else "N/A"
        vendor = lookup_vendor(mac)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        append_to_csv([timestamp, mac, ssid, rssi, vendor])
        print(f"{timestamp} | MAC: {mac} | SSID: {ssid} | RSSI: {rssi} | Channel: {current_channel}")

# UI Menu
def menu():
    while True:
        print("\n==============================")
        print("""
┌─┐┬─┐┌─┐┌┐ ┌─┐┌─┐┬┬  ┬  ┌─┐
├─┘├┬┘│ │├┴┐├┤ ┌─┘││  │  ├─┤
┴  ┴└─└─┘└─┘└─┘└─┘┴┴─┘┴─┘┴ ┴
""")
        print("==============================")
        print("1) Start Scan")
        print("2) Stop Scan")
        print("3) Show Last 10 Entries")
        print("q) Quit")
        opt = input("Select an option: ").strip()

        if opt == "1":
            start_scan()
        elif opt == "2":
            stop_scan()
        elif opt == "3":
            show_log()
        elif opt.lower() == "q":
            stop_scan()
            break
        else:
            print("Invalid option.")

# Start/Stop logic
def start_scan():
    if run_event.is_set():
        print("[INFO] Scan already running.")
        return

    run_event.set()
    setup_csv()
    print("[INFO] Starting scan...")
    
    threading.Thread(target=channel_hopper, daemon=True).start()
    threading.Thread(target=lambda: sniff(iface=IFACE, prn=handle_packet, store=0), daemon=True).start()

def stop_scan():
    if run_event.is_set():
        run_event.clear()
        print("[INFO] Scan stopped.")
    else:
        print("[INFO] No scan running.")

def show_log():
    if not os.path.exists(LOG_FILE):
        print("[INFO] No log file found.")
        return
    with open(LOG_FILE) as f:
        lines = f.readlines()
        print("\n--- Last 10 Captures ---")
        for line in lines[-10:]:
            print(line.strip())

# Entry point
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Run this script with sudo.")
        sys.exit(1)

    vendor_dict = load_mac_vendors()
    menu()
