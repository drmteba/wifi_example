import logging

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, \
    Dot11EltRates, Dot11EltDSSSet

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = 'wlan0'
broadcast = 'ff:ff:ff:ff:ff:fff'

for ssid in open(sys.argv[1], 'r').readlines():
    pkt = RadioTap() / \
          Dot11(type=0, subtype=4, addr1=broadcast, addr2=RandMAC(), addr3=broadcast) / \
          Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid.strip()) / Dot11EltRates() / \
          Dot11EltDSSSet()
    print('Trying SSID %s' % ssid)
    ans = srp1(pkt, iface=intfmon, timeout=5)
    print(ans)
    if ans:
        print('Discovered ESSID: %s with BSSID: %s' % (ans.info().decode(), ans.addr3()))
        exit()
