import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11Deauth, Dot11, RadioTap, \
    Dot11AssoReq, Dot11Elt, Dot11FCS, Dot11ProbeReq, Dot11Auth

intfmon = 'wlan0'
station = client = '00:01:00:01:00:01'
bssid = '34:DA:B7:BA:2F:DB'
apssid = 'Mohamed'
broadcast = 'ff:ff:ff:ff:ff:ff'

# probe request
pkt = RadioTap() / Dot11FCS(addr1=broadcast, addr2=station, addr3=station)
pkt /= Dot11ProbeReq() / Dot11Elt(ID='SSID', info=apssid, len=len(apssid))
print(f"\nSending Probe request to AP with name: {apssid}")
res = srp1(pkt, iface=intfmon, timeout=2)
if res:
    res.summary()
    print("Got answer from " + res.addr2)
else:
    print("Got no answer from " + apssid)

# authentication with open system
pkt = RadioTap() / Dot11FCS(subtype=0xb, addr1=bssid, addr2=station, addr3=bssid)
pkt /= Dot11Auth(algo=0, seqnum=0x01, status=0)
print("\nSending authentication request to AP with BSSID: " + bssid)
res = srp1(pkt, iface=intfmon, timeout=2)
if res:
    res.summary()
    print("Got answer from " + res.addr2)
else:
    print("Got no answer from " + bssid)

# association request
pkt = RadioTap() / Dot11(type=0, subtype=0, addr1=bssid, addr2=station, addr3=bssid)
pkt /= Dot11AssoReq() / Dot11Elt(ID='SSID', info=apssid) / Dot11Elt(ID="Rates",
                                                                    info="x82x84x0bx16")
print("\nSending Association request to AP with SSID: " + apssid)
res = srp1(pkt, iface=intfmon, timeout=2)
if res:
    res.summary()
    print("Got answer from " + res.addr2)
else:
    print("Got no answer from " + apssid)

# Deauthentication request
# AP to STA deauth
pkt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
# STA to AP deauth
pkt2 = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
print("\nSending both Deauth requests to AP and STA")
res = srp1(pkt, iface=intfmon, retry=3, timeout=2)
if res:
    res.summary()
else:
    print("Got no answer from Station: " + str(station))
res = srp1(pkt2, iface=intfmon, retry=3, timeout=2)
if res:
    res.summary()
else:
    print("Got no answer from AP: " + apssid)
