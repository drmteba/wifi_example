import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, RadioTap, Dot11, Dot11ProbeReq, Dot11EltRates


intfmon = 'wlan0'
verbose = 0
count = 30
dst = bssid = 'ff:ff:ff:ff:ff:ff'
apssid = 'DrmtebaAP'
src = '00:01:02:03:04:05'
sc = -1
bootime = time.time()


def next_sc():
    global sc
    sc = (sc + 1) % 4096
    return sc * 16  # Fragment number -> right 4 bits


def current_timestamp():
    global bootime
    return (time.time() - bootime) * 1000000


def ProbeReq(source, counts, apssids, dsts, bssids):
    essid = Dot11Elt(ID='SSID', info=apssids, len=len(apssids))
    wps_id = "\x00\x50\xF2\x04"
    wps_elt = Dot11Elt(ID=221, len=9, info="%s\x10\x4a\x00\x01\x10" % wps_id)
    dsset = Dot11Elt(ID='DSset', info='\x01')
    pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=dsts, addr2=source, addr3=bssids) \
          / Dot11ProbeReq() / essid / wps_elt / Dot11EltRates() / dsset
    i = 0
    while i < counts:
        # Update timestamp
        pkt.timestamp = current_timestamp()
        pkt.SC = next_sc()  # Update sequence number
        if verbose:
            pkt.show()
        try:
            sendp(pkt, iface=intfmon, count=1, inter=0.1, verbose=verbose)
            i += 1
        except:
            raise


print(f'Sending {count} 802.11 Probe Request: ESSID=[{apssid}], BSSID={bssid}')
ProbeReq(src, count, apssid, dst, bssid)
