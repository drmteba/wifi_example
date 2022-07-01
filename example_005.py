from scapy.all import *
from scapy.layers.dot11 import Dot11

intfmon = 'wlan0'  # Just monitor VAP interface (mon0)


def PacketHandler(pkt):
    global destination, sta
    if pkt.type == 0:  # Management frame
        destination = '01(MGT)-sub:' + str(pkt.subtype)
        return
    elif pkt.type == 1:  # Control frames
        destination = '01(CTRL)-sub:' + str(pkt.subtype)
        return
    elif pkt.type == 2:  # Data frames
        ds = pkt.FCfield & 0x3
        to_ds = int(ds & 0x1 != 0)
        from_ds = int(ds & 0x2 != 0)
        destination = '02(DATA)-sub:' + str(pkt.subtype) + ' - ds:' + str(ds) + '-FromDS:' \
                      + str(from_ds) + '-ToDS:' + str(to_ds)
        if pkt.FCfield & 3 == 0:  # direct
            # from_ds=0, to_ds=0 is a pkt from sta to sta
            # smac,dmac = pkt.addr2 , pkt.addr1
            destination = destination + ' sta-sta'
            sta = pkt.addr2
        elif pkt.FCfield & 3 == 1:  # to ds
            # from_ds=1, to_ds=0 is a pkt sent by a station for an AP (destined to the ds)
            # smac,dmac = pkt.addr3 , pkt.addr1
            destination = destination + ' sta-ds'
            sta = pkt.addr2
        elif pkt.FCfield & 3 == 2:  # from ds
            # from_ds=0, to_ds=1 is a pkt exiting the ds for a station
            # smac,dmac = pkt.addr2 , pkt.addr3
            destination = destination + ' ds-sta'
            sta = pkt.addr1
        elif pkt.FCfield & 3 == 3:  # WDS
            # from_ds=1, to_ds=1 is a pkt from AP to AP (WDS)
            # smac,dmac = pkt.addr4 , pkt.addr3
            destination = destination + ' ds-ds'
            sta = pkt.addr1
        else:
            destination = pkt.type
    # print(pkt.command())
    print(f"Packet destination: {destination}, \t station address {sta}")


# We begin to sniff and capture
sniff(iface=intfmon, prn=PacketHandler, store=False, lfilter=lambda pkt: (Dot11 in pkt))
