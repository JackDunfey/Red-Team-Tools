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
def get_gateway_mac(ip):
    fields = popen(f"ip neigh show {ip}", 'r').read().split()
    print(fields[fields.index("lladdr") + 1])

get_gateway_mac(get_default_gateway())