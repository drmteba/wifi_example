import logging

from scapy.layers.dot11 import Dot11WEP, Dot11

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = "wlan0"
verbose = 1
workdir = "./capture"
filename = workdir + "/" + "wepcap.cap"
max_pkts = 50000
pkts = []


# This function will be called for every sniffed packet
def PacketHandler(pkt):
    if pkt.haslayer(Dot11WEP):  # Got WEP packet?
        pkts.append(pkt)
        if verbose:
            print(f'Pkt-{len(pkts)}: {pkt[Dot11].addr2} IV:{str(pkt.iv)} '
                  f'Keyid:{str(pkt.keyid)} ICV:{str(pkt.icv)}')
        if len(pkts) == max_pkts:  # Got enough packets to crack WEP key? Save to pcap
            print(f'Got {max_pkts} packets, saving to PCAP file:{filename} and exiting!')
            wrpcap(filename, pkts)
            sys.exit(0)


# Scapy sniffer function
print(f'Starting sniff on interface {intfmon}')
sniff(iface=intfmon, prn=PacketHandler)
