import logging.handlers

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from netaddr import *
from netaddr.core import NotRegisteredError
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, \
    Dot11, Dot11ProbeResp

# define variables
intfmon = 'wlan0'
workdir = './capture'  # directory where cap files are stored
number2send = 1000  # number of packets to send after selecting AP
verbose = 0  # verbosity level (0-5)
modify_header = False  # Insert a new RadioTap header or use original
boottime = time.time()  # to generate uptime or timestamp
sc = -1  # first frame sequence counter
channel = '1'  # default channel to use
interval = 0.1
pcounter = 0
bssid = ''
essid = ''
capability = ''
crypto = []
capturetime = ''
uptime = ''
manuf = ''


def SetChannel(channel):
    cmd = 'iwconfig %s channel %s >/dev/null 2>&1' % (intfmon, channel)
    try:
        os.system(cmd)
    except:
        raise


def current_timestamp():
    global boottime
    return (time.time() - boottime) * 1000000


def next_sc():
    global sc
    sc = (sc + 1) % 4096
    temp = sc
    return temp * 16  # Fragment number -> right 4 bits


def get_radiotap_header():
    global channel
    radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
                               notdecoded='\x00\x6c' + chr(channel) +
                                          '\xc0\x00\xc0\x01\x00\x00')
    return radiotap_packet


# Parse information inside beacon frame
def ParseBeacon(p):
    global capability, crypto, essid, channel, interval, capturetime, uptime, bssid, manuf
    # Get packet encryption and RSN
    essid = p[Dot11Elt].info.decode()
    stats = p[Dot11Beacon].network_stats()
    channel = stats.get("channel")
    crypto = stats.get("crypto")
    # Get beacon interval value
    interval = float(p.beacon_interval) / 1000
    # Get date of captured beacon frame and AP uptime
    capturetime = datetime.fromtimestamp(float(p.time)).strftime('%d-%m-%Y %H:%M:%S')
    uptime = str(timedelta(microseconds=p[Dot11Beacon].timestamp))
    # Get packet BSSID and calculate manufacturer
    bssid = p[Dot11].addr2
    manuf = get_oui(bssid)


def get_oui(mac):
    global manuf
    maco = EUI(mac)
    try:
        manuf = maco.oui.registration().org.replace(',', ' ')
    except NotRegisteredError:
        manuf = "Not available"
    return manuf


# Show information inside beacon


def ShowBeacon(p):
    global capability, crypto, essid, channel, interval, capturetime, uptime, bssid, manuf
    if verbose >= 1:
        print("\n Scapy command to gen packet:")
        print(p.command())
    if verbose >= 2:
        print("\n Packet structure:")
        p.show()
    if verbose >= 3:
        print("\nFields parsed in the frame:")
        ls(p)
    if verbose >= 4:
        print("\nHexdump of frame:")
        hexdump(p)
    if verbose >= 5:
        print("\nOpening Wireshark...")
        wireshark(p)
    print(f'\nGoing to send {number2send} beacons for BSSID: {bssid} '
          f'({manuf}) SSID: {essid} ENC: {crypto} in Channel: {channel}'
          f' [{capturetime}][{uptime}] Interval: {interval}')
    input("\nPress enter to start\n")


# Send beacon frame n times
def SendBeacon(p):
    global intfmon, interval, number2send
    SetChannel(channel)
    sendp(p, iface=intfmon, inter=interval, count=number2send)


# Update beacon fields with new generated ones
def ModifyBeacon(p):
    # Update sequence number
    p.SC = next_sc()
    # Update timestamp
    p.timestamp = current_timestamp()
    # Insert new RadioTap header?
    if modify_header:
        p = get_radiotap_header() / p.payload
        if verbose >= 2:
            print("\nmodified header:")
            print(p.command())
    return p


def InitMon():
    # Check if monitor device exists
    if not os.path.isdir("/sys/class/net/" + intfmon):
        print('WiFi interface {intfparent} does not exist! Cannot continue!')
        exit()
    else:
        output = subprocess.run(["iw", intfmon, "info"],
                                capture_output=True, text=True)
        p = re.search(r'type (\w+)', output.stdout).group(1)
        if p != "monitor":
            try:
                # create monitor interface using iw
                subprocess.run(["ifconfig", intfmon, "down"])
                subprocess.run(["iw", "dev", intfmon, "set", "monitor", "none"])
                time.sleep(0.5)
                subprocess.run(["ifconfig", intfmon, "up"])
            except:
                raise
        else:
            print("Monitor %s exists! Nothing to do, just continuing..." % intfmon)


# Main loop
# Select AP to use
caplist = []
i = 0
try:
    for file in os.listdir(workdir):
        if file.endswith(".cap"):
            caplist.append(file)
            print(f'{i}. {file}')
            i += 1
except:
    print("No files or directory found, exiting!")
    exit()
selected = int(input("\nSelect file number to use: "))
pcapfile = workdir + '/' + caplist[selected]
pktreader = PcapReader(pcapfile)
print("Reading capture file: %s" % pcapfile)
InitMon()       # Init monitor mode (if necessary)
# Walk through the PCAP file packets
for p in pktreader:
    if p.haslayer(Dot11Beacon):
        ParseBeacon(p)
        if modify_header and verbose >= 2:
            print("\noriginal packet:")
            print(p.command())
        ModifyBeacon(p)
        ShowBeacon(p)
        SendBeacon(p)
        quit()
    elif p.haslayer(Dot11ProbeResp):
        # ParseProbeResp(p)
        break
    pcounter += 1
# No result of packet parsing
print(f'\nNo valid packets in capture file: {pcapfile}')
