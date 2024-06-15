from scapy.all import send, IP, TCP

def syn_flood(target_ip, target_port, count):
    packets = []
    for _ in range(count):
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
        packets.append(packet)
    send(packets, verbose=0)

if __name__ == "__main__":
    target_ip = "192.168.1.10"  # Change to the IP your IDS is monitoring
    target_port = 80  # Commonly monitored port
    syn_flood(target_ip, target_port, 100)  # Adjust count as needed for your threshold
