from scapy.all import ARP, Ether, srp, conf

# Set the target IP address (default gateway)
target_ip = "192.168.1.1"  # Replace with your gateway IP

# Create an ARP request
arp_request = ARP(pdst=target_ip)
# Create an Ethernet frame
ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address

# Combine them
packet = ether / arp_request

# Send the packet and capture the response
result = srp(packet, timeout=2, verbose=False)[0]

# Process the response
for sent, received in result:
    print(f"IP: {received.psrc}, MAC: {received.hwsrc}")