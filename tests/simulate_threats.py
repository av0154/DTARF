import os
import time
import socket
import random
import requests
import string
import math
import argparse
from datetime import datetime

class DTARFSimulator:
    def __init__(self, target_host="127.0.0.1", dashboard_port=8080):
        self.target_host = target_host
        self.dashboard_port = dashboard_port
        self.dashboard_url = f"http://{target_host}:{dashboard_port}"

    def simulate_ransomware(self):
        """Creates a file with high entropy to trigger ransomware detection."""
        print("[*] Simulating Ransomware (High Entropy File)...")
        test_file = "test_ransomware_payload.dat"
        # Generate random high entropy data
        data = os.urandom(1024 * 10) # 10KB of random data
        with open(test_file, "wb") as f:
            f.write(data)
        print(f"  ✓ High entropy file created: {test_file}")
        print("  ! Check dashboard for 'high_entropy_data' or ransomware alerts.")

    def simulate_port_scan(self):
        """Performs a quick port scan on localhost."""
        print("[*] Simulating Port Scan...")
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
        random.shuffle(ports)
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((self.target_host, port))
                s.close()
            except:
                pass
        print(f"  ✓ Scanned {len(ports)} ports.")
        print("  ! Check dashboard for 'port_scan_detected' alerts.")

    def simulate_malicious_connection(self):
        """Attempts to connect to a known malicious IP from our IOC list."""
        print("[*] Simulating Malicious IOC Connection...")
        # 185.220.101.1 is in our default ioc_database.json
        malicious_ip = "185.220.101.1"
        print(f"  → Attempting connection to {malicious_ip}...")
        try:
            # We don't actually need to succeed, the sniffer will catch the attempt
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex((malicious_ip, 80))
            s.close()
        except:
            pass
        print("  ✓ Connection attempt finished.")
        print("  ! Check dashboard for 'threat_intel_match' alerts.")

    def simulate_http_flood(self):
        """Sends a burst of HTTP requests to trigger rate limiting."""
        print("[*] Simulating HTTP Flood...")
        count = 50
        for i in range(count):
            try:
                requests.get(self.dashboard_url, timeout=0.5)
            except:
                pass
        print(f"  ✓ Sent {count} HTTP requests.")
        print("  ! Check dashboard for 'http_flood_detected' or rate limit actions.")

def main():
    parser = argparse.ArgumentParser(description="DTARF Threat Simulator")
    parser.add_argument("--type", choices=["all", "ransomware", "portscan", "ioc", "flood"], default="all")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    
    args = parser.parse_args()
    sim = DTARFSimulator(args.host, args.port)

    print("="*50)
    print("  DTARF Threat Simulation Tool")
    print("="*50)

    if args.type in ["all", "ransomware"]:
        sim.simulate_ransomware()
        time.sleep(2)
    
    if args.type in ["all", "portscan"]:
        sim.simulate_port_scan()
        time.sleep(2)

    if args.type in ["all", "ioc"]:
        sim.simulate_malicious_connection()
        time.sleep(2)

    if args.type in ["all", "flood"]:
        sim.simulate_http_flood()

    print("\n[!] Simulation Complete. Monitor the DTARF dashboard for results.")

if __name__ == "__main__":
    main()
