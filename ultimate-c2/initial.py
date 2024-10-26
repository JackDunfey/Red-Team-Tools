def get_my_mac(IF_NAME):
    with open("/sys/class/net/{IF_NAME}/address", 'r') as f:
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

def send_arp_data(data):
    IF_NAME, gateway = get_default_gateway()
    gateway_mac = arp(gateway)
    
    my_mac = get_my_mac()
    my_ip = popen("hostname -I", 'r').read().strip()

    arp_reply = ARP(op=ARP.is_at, psrc=my_ip, hwsrc=my_mac, pdst=gateway)

    ether = Ether(dst=gateway_mac)

    packet = ether / arp_reply / Raw(load=data)

from scapy.all import ARP, Ether, srp, conf, Raw
# srp!!
def main():
    send_arp_data("709505")

if __name__ == "__main__":
    main()