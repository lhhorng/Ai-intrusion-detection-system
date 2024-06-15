from scapy.all import send, IP, TCP

def port_scan(target_ip, start_port, end_port):
    packets = []
    for port in range(start_port, end_port + 1):
        packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
        packets.append(packet)
    send(packets, verbose=0)

if __name__ == "__main__":
    target_ip = "192.168.1.10"  # Change to the IP your IDS is monitoring
    port_scan(target_ip, 1, 100)  # Scan ports 1 to 100
