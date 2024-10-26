def get_iface_info():
    ifaces = []
    with open("/proc/net/route", 'r') as f:
        labels_str, *ifaceinfos = f.read().splitlines()
        labels = labels_str.lower().split()
        for iface_info in ifaceinfos:
            ifaces.append(dict(zip(labels, iface_info.split())))
    return ifaces

def get_default_gateway():
    ifaces = get_iface_info()
    for iface in ifaces:
        if iface["destination"] == "00000000":
            # processing hex -> text
            g = iface["gateway"]
            a = g[0:2]
            b = g[2:4]
            c = g[4:6]
            d = g[6:8]
            return f"{int(d, 16)}.{int(c, 16)}.{int(b, 16)}.{int(a, 16)}"
        
    return None

from os import popen
def arp(ip):
    fields = popen(f"ip neigh show {ip}", 'r').read().split()
    return fields[fields.index("lladdr") + 1]

from scapy.all import ARP, Ether, srp, conf, Raw
def main():
    # Set the target IP address (default gateway)
    target_ip = get_default_gateway()  # Replace with your gateway IP

    # Create an ARP request
    arp_request = ARP(pdst=target_ip)
    # Create an Ethernet frame
    ether = Ether(dst=arp(target_ip))  # Broadcast MAC address

    # Combine them
    packet = ether / arp_request / Raw(load="Hello")

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Process the response
    for sent, received in result:
        print(f"IP: {received.psrc}, MAC: {received.hwsrc}")

if __name__ == "__main__":
    main()