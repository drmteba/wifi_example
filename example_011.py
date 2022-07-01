import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon, Dot11ProbeReq, Dot11
from scapy.all import *
from netaddr import *
from netaddr.core import NotRegisteredError

intfmon = 'wlan0'
workdir = './'  # directory where the captures pcap are stored
verbose = 0
pcounter = 0


# Parse information inside beacon frame
def ParsePacket(packets):
    global packet_type
    crypto = channel = uptime = interval = ''
    if packets.haslayer(Dot11Beacon):
        packet_type = 'Beacon'
        interval = float(packets.beacon_interval) / 1000  # Get beacon interval value
        uptime = str(timedelta(microseconds=packets[Dot11Beacon].timestamp))  # AP uptime
    elif packets.haslayer(Dot11ProbeReq):
        packet_type = 'Probe Request'

    # Get date of captured beacon frame
    capturetime = datetime.fromtimestamp(float(packets.time)).strftime('%d-%m-%Y %H:%M:%S')
    bssid = packets[Dot11].addr2
    essid = packets[Dot11Elt].info.decode()
    try:
        stats = packets[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
    except:
        pass

    #  calculate manufacturer
    mac = EUI(bssid)
    try:
        manuf = mac.oui.registration().org
    except NotRegisteredError:
        manuf = "Not available"
    print(f'\n {packet_type}: BSSID: {bssid}({manuf}) SSID:{essid} ENC:{crypto} in '
          f'Channel:{channel} captured:[{capturetime}] uptime:[{uptime}] '
          f'Interval:{interval}')


# Select AP to use
caplist = []
i = 0
for file in os.listdir(workdir):
    if file.endswith(".cap"):
        caplist.append(file)
        print(f"{i}. {file}")
        i += 1
selected = int(input("\nSelect file number to use: "))
if not selected in range(0, i):
    print("Sorry wrong index number...")
    exit()

pcapfile = workdir + caplist[selected]
pktreader = PcapReader(pcapfile)
print(pcapfile)

# Walk through the PCAP file packets
for pkt in pktreader:
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq):
        ParsePacket(pkt)
        if verbose >= 1:
            print("Packet structured:\n" + pkt.command())
    pcounter += 1
print(f"Total packets in PCAP file: {pcounter}\n")
