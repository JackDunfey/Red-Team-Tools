def get_my_mac(IF_NAME):
    with open(f"/sys/class/net/{IF_NAME}/address", 'r') as f:
        return f.read()

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
            return iface["iface"], f"{int(d, 16)}.{int(c, 16)}.{int(b, 16)}.{int(a, 16)}"
        
    return None

from os import popen
def arp(ip):
    fields = popen(f"ip neigh show {ip}", 'r').read().split()
    return fields[fields.index("lladdr") + 1]

from scapy.all import ARP, Ether, send, srp, conf, Raw
def send_arp_data(data):
    IF_NAME, gateway = get_default_gateway()
    gateway_mac = arp(gateway)
    
    my_mac = get_my_mac(IF_NAME)
    my_ip = popen("hostname -I", 'r').read().strip()

    # 2 = reply
    arp_reply = ARP(op=2, psrc=my_ip, hwsrc=my_mac, pdst=gateway)

    ether = Ether(dst=gateway_mac)

    packet = ether / arp_reply # / Raw(load=data)

    print(f"Gateway:\nIP: {gateway}\nMAC: {gateway_mac}\nMe:\nIP: {my_ip}\nMAC: {my_mac}")

    send(packet)

# srp!!
def main():
    send_arp_data("709505")

if __name__ == "__main__":
    main()