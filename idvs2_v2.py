from scapy.all import sniff, IP, TCP, UDP, show_interfaces
from collections import defaultdict
import threading
import datetime, time
import logging
import re
from difflib import SequenceMatcher



# Setting up logging
logging.basicConfig(filename='ids_log.txt', level=logging.INFO, format='%(asctime)s %(message)s')

# Define some global thresholds
SYN_COUNT_THRESHOLD = 100  # Threshold for SYN packets from the same IP to consider it a SYN flood
PORT_SCAN_THRESHOLD = 50  # Threshold for port hits from the same IP to consider it port scanning
DNS_RESPONSE_THRESHOLD = 100
THRESHOLD = 100
TIME_WINDOW = 60

# Initialize dictionaries to keep track of packet counts
syn_flood_tracking = {}
port_scan_tracking = {}
dns_response_tracking = {}
ip_counts = {}

# def reset_counts(): #This code monitors network traffic and flags potential DoS attacks by tracking and evaluating packet counts from individual IP addresses within a specified time window.
#     global ip_counts
#     while True:
#         time.sleep(TIME_WINDOW)
#         ip_counts = defaultdict(int)




def detect_intrusion(packet):
    """
    Analyze packets for suspicious behavior.
    """
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst


        # Detect SYN Flood
        if packet[TCP].flags == 'S':
            syn_flood_tracking[src_ip] = syn_flood_tracking.get(src_ip, 0) + 1
            if syn_flood_tracking[src_ip] > SYN_COUNT_THRESHOLD:
                logging.info(f"SYN Flood attempt detected from {src_ip}")
                syn_flood_tracking[src_ip] = 0  # Reset counter after logging

        # Detect Port Scanning
        dst_port = packet[TCP].dport
        if src_ip not in port_scan_tracking:
            port_scan_tracking[src_ip] = set()
        port_scan_tracking[src_ip].add(dst_port)
        if len(port_scan_tracking[src_ip]) > PORT_SCAN_THRESHOLD:
            logging.info(f"Port scan detected from {src_ip} targeting {dst_ip}")
            port_scan_tracking[src_ip] = set()  # Reset after logging

    if packet.haslayer(UDP):
        # Detect potential DNS Amplification attack
        if packet[UDP].sport == 53 and len(packet) > 500:  # Large DNS response packet
            logging.info(f"Potential DNS Amplification attack from {packet[IP].src}")

        # Detect DOS attack
    ip_counts = defaultdict(int)
    if IP in packet:
        ip_src = packet[IP].src
        ip_counts[ip_src] += 1
        if ip_counts[ip_src] > THRESHOLD:
            logging.info(f"Potential DoS attack detected from IP: {src_ip}")
            sniff(prn=detect_intrusion, filter="ip", store=0)

        
        # Detect domain spoofing

# Define a list of known legitimate domains
known_domains = [
    'https://www.sif.org.sg/en',
    'https://www.sustainablelivinglab.org/',
    'https://www.sustainablelivinglab.org/singapore/',
    'https://www.sustainablelivinglab.org/india/',
]

# Function to calculate Levenshtein distance
def levenshtein_ratio(s1, s2):
    return SequenceMatcher(None, s1, s2).ratio()

# Heuristic rules for detecting domain spoofing
def is_spoofed_domain(domain):
    for known_domain in known_domains:
        if domain == known_domain:
            return False
        if domain.endswith(f'.{known_domain}'):
            return True
        if levenshtein_ratio(domain, known_domain) > 0.8:
            return True
    return False

# Function to extract domain from URL
def extract_domain(url):
    match = re.search(r'https?://([A-Za-z_0-9.-]+).*', url)
    if match:
        return match.group(1)
    return None

# Test function for external usage
#The test_domain_spoofing function can be used to test a list of URLs for spoofing.

def test_domain_spoofing(urls):
    results = {}
    for url in urls:
        domain = extract_domain(url)
        if domain:
            results[url] = 'spoofed' if is_spoofed_domain(domain) else 'legitimate'
        else:
            results[url] = 'invalid'
    return results








    # if packet.haslayer(UDP):
    #     if packet[UDP].sport == 53:  # Check if the source port is 53 (DNS response)
    #         src_ip = packet[IP].src
    #         if src_ip not in dns_response_tracking:
    #             dns_response_tracking[src_ip] = 0
    #         dns_response_tracking[src_ip] += 1
            
    #         if dns_response_tracking[src_ip] > DNS_RESPONSE_THRESHOLD:
    #             logging.info(f"DNS Amplification attack detected from {src_ip}")
    #             dns_response_tracking[src_ip] = 0  # Reset counter after logging



def list_interfaces():
    """
    List all available network interfaces.
    """
    print("Available network interfaces:")
    show_interfaces()

def monitor_network(interface):
    """
    Monitor network traffic on a given interface for intrusion detection.
    """
    print(f"Monitoring network traffic on {interface}. Press CTRL+C to stop.")
    sniff(iface=interface, prn=detect_intrusion, store=False)


if __name__ == "__main__":
    list_interfaces()  # Uncomment this line to list all interfaces
    try:
        # Replace 'Ethernet' with the correct interface name from the list_interfaces output
        network_interface = "en0"
        monitor_network(network_interface)
    except KeyboardInterrupt:
        print("Stopped monitoring.")
    except Exception as e:
        print(f"An error occurred: {e}")