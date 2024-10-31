from scapy.all import ARP, Ether, Raw, sendp, conf
from time import sleep
import threading
from random import randint

ROUTER_IP = "10.9.0.1"
ROUTER_MAC = "10.9.0.1"

with open("interface", "r") as f:
    conf.iface = f.read().strip()

def get_mac_address():
    return "02:00:00:%02x:%02x:%02x" % (randint(0, 255), randint(0, 255), randint(0, 255))

def main():
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src="de:ad:be:ef:ca:fe") / ARP(op=2, psrc="10.9.0.7", hwsrc="de:ad:be:ef:ca:fe", pdst="10.9.0.7", hwdst="de:ad:be:ef:ca:fe"))

if __name__ == "__main__":
    main()