import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeResp, Dot11, Dot11Elt

intfmon = 'wlan0'
workdir = '/tmp'
filename = workdir + '/' + 'example10.cap'


# Scapy packet handler function
def PacketHandler(pkt):
    bssid = pkt[Dot11].addr3
    essid = pkt[Dot11Elt].info.decode()
    print(f'Saving Probe Response of {essid} ({bssid}) to file: {filename}')
    writer = PcapWriter(filename, append=True)
    writer.write(pkt)
    writer.close()


# We begin to sniff and capture
sniff(iface=intfmon, prn=PacketHandler, count=4,
      lfilter=lambda pkt: (Dot11ProbeResp in pkt))
