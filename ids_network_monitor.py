from scapy.all import *
import logging
import numpy as np
import subprocess

# Configure logging
logging.basicConfig(filename='ids_logs.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables for statistical analysis
packet_sizes = []
packet_count = 0

def block_ip(ip_address):
    # Block IP using Windows firewall (requires administrative privileges)
    command = f"netsh advfirewall firewall add rule name='Blocked IP' dir=in action=block remoteip={ip_address}"
    subprocess.run(command, shell=True, check=True)

def packet_callback(packet):
    global packet_sizes, packet_count
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        
        # Update packet statistics
        packet_sizes.append(packet_size)
        packet_count += 1
        
        # Detect large packets
        if packet_size > 1500:
            logging.warning(f"Suspiciously large packet ({packet_size} bytes) detected from {ip_src} to {ip_dst}")
        
        # Detect frequent requests from a single source
        if packet_count > 100 and len(set(packet_sizes[-100:])) == 1:
            logging.warning(f"Suspiciously repetitive traffic detected from {ip_src}")
            
            block_ip(ip_src)

# Main function to start packet sniffing
def main():
    # Start sniffing network traffic and invoke callback for each packet
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()