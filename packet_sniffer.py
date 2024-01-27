import os
import sys
from scapy.all import *

# Defines a function to display and save the captured packets
def packet_sniff(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto
        payload = str(packet[TCP].payload)

        output_string = f"Source IP: {src_ip}\n"
        output_string += f"Destination IP: {dst_ip}\n"
        output_string += f"Source Port: {src_port}\n"
        output_string += f"Destination Port: {dst_port}\n"
        output_string += f"Protocol: {protocol}\n"
        output_string += f"Payload: {payload[:50]}...\n"

        print(output_string, end='')
        with open('packet_sniffer_results.txt', 'a') as f:
            f.write(output_string)

# Sets the path and filename for the output text file
output_path = "/packet_sniffer_results.txt"
output_file = os.path.join(output_path, "packet_sniffer_results.txt")

# Calls the sniff() function from the Scapy library to capture and analyze network packets
sniff(filter="tcp", prn=packet_sniff, store=0, count=10)

# Displays the output file's name and location after successful sniffing
print(f"\nResults saved to: {output_file}")
