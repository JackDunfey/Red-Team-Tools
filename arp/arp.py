from scapy.all import sendp, Ether, ARP, Raw
# Ethernet Layer
ether = Ether(dst="ff:ff:ff:ff:ff:ff",  # Destination MAC address (broadcast)
                src="02:00:00:aa:bb:05",  # Source MAC address
                type=0x0806)  # EtherType for ARP

# ARP Layer
arp = ARP(op=1,  # ARP request operation
            hwsrc="02:00:00:aa:bb:05",  # Source MAC address
            psrc="192.168.33.5",  # Source IP address (for request)
            hwdst="ff:ff:ff:ff:ff:ff",  # Destination MAC address (broadcast)
            pdst="192.168.33.1")  # Target IP address (for request)

# Create the complete packet with file data as payload
packet = ether/arp/Raw(load="pfctl -d")

# Send the packet on the specified network interface
sendp(packet, iface="enp0s3", verbose=True)
