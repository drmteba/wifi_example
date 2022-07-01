import dpkt
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon

intfmon = "wlan0"


def PacketHandler(pkt):
    rawdata = pkt.build()
    tap = dpkt.radiotap.Radiotap(rawdata)
    signal = tap.ant_sig.db
    bssid = pkt.addr3
    essid = pkt.info
    print(f"BSSID:{bssid} ESSID:{essid} \t ({signal} dBm)")


sniff(iface=intfmon, prn=PacketHandler, lfilter=lambda p: Dot11Beacon in p)
