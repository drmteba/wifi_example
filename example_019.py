import csv
from signal import SIGINT, signal
import logging.handlers

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from netaddr import *
from netaddr.core import NotRegisteredError
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt, \
    Dot11ProbeResp, Dot11Beacon, RadioTap, Dot11EltDSSSet, \
    Dot11EltRates

# define variables
intfparent = intfmon = 'wlan0'
workdir = './capture'
csvsummary = workdir + '/' + 'ap_summary.csv'
channel = ''
clients = []
uni = 0
mach = []
manuf = ''
ap_list = []
ap_plist = []
sysloglevel = 4  # (debug)7------0(not syslog)
lock = Lock()
DN = open(os.devnull, 'w')


# Scapy packet handler function
def PacketHandler(pkt):
    global ap_plist, ap_list, csvwriter
    if pkt.haslayer(Dot11):
        if pkt.haslayer(Dot11ProbeReq):  # probe request
            mac = pkt.addr2.lower()
            if pkt.haslayer(Dot11Elt):
                ssid = pkt.info.decode()
                if ssid and ssid not in clients:
                    manuf = get_oui(mac)
                    clients.append([mac, manuf, ssid])
                    print(f'CLIENT MAC: {mac} ({manuf}) PROBING FOR AP: {ssid}')
        elif pkt.haslayer(Dot11ProbeResp):  # probe response
            bssid = pkt.addr3.lower()
            if bssid not in ap_plist:
                ap_plist.append(bssid)
                manuf = get_oui(bssid)
                essid = pkt[Dot11Elt].info.decode()
                channel = int(ord(pkt[Dot11Elt:3].info))
                p = pkt[Dot11Elt]
                cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                  "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
                crypto = set()
                while isinstance(p, Dot11Elt):
                    if p.ID == 48:
                        crypto.add("WPA2")
                    elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                        crypto.add("WPA")
                    p = p.payload
                if not crypto:
                    if 'privacy' in cap:
                        crypto.add("WEP")
                    else:
                        crypto.add("OPN")
                print(f"AP ESSID: {essid} BSSID: {bssid} ({manuf}) ENC: "
                      f"{'/'.join(crypto)} CHANNEL: {channel} - PROBE RESPONSE SAVED!")
                filename = workdir + '/' + pkt.info.decode() + '_' + bssid.replace(':', '') + '.cap'
                writer = PcapWriter(filename, append=True)
                writer.write(pkt)
                writer.close()
        elif pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr3.lower()
            if bssid not in ap_list:
                ap_list.append(bssid)
                manuf = get_oui(bssid)
                essid = pkt.info.decode()
                essid = essid.replace("\0", "")
                stats = pkt[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                if not essid: essid = 'HiddenEssid!'
                print(f'AP ESSID: {essid} BSSID: {bssid} ({manuf}) ENC: '
                      f'{crypto} CHANNEL: {channel} - BEACON SAVED!')
                filename = workdir + '/' + essid + '_' + bssid.replace(':', '') + '.cap'
                writer = PcapWriter(filename, append=True)
                csvwriter.writerow([essid, bssid, manuf, crypto, channel])
                writer.write(pkt)
                writer.close()


def endsniff(d=False):
    return d


def get_oui(mac):
    global manuf
    maco = EUI(mac)
    try:
        manuf = maco.oui.registration().org.replace(',', ' ')
    except NotRegisteredError:
        manuf = "Not available"
    return manuf


def ProbeReqBroadcast():
    sendp(RadioTap() /
          Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3="ff:ff:ff:ff:ff:ff") /
          Dot11ProbeReq() / Dot11Elt(ID="SSID", info=""), iface=intfmon, count=10)


def ProbeReq(probessid):
    src = '00:00:de:ad:be:ef'  # source ip from packets
    dst = 'ff:ff:ff:ff:ff:ff'  # Destination address for beacons and probes
    bssid = '00:11:22:33:44:55'  # BSSID MAC address for fake AP
    count = 10
    essid = Dot11Elt(ID='SSID', info=probessid, len=len(probessid))
    dsset = Dot11EltDSSSet()
    pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=dst, addr2=src, addr3=bssid) / \
          Dot11ProbeReq() / essid / Dot11EltRates() / dsset
    print(f'[*] 802.11 Probe Request: SSID=[{probessid}], count={count}')
    try:
        sendp(pkt, count=count, inter=0.1, verbose=0)
    except:
        raise


def InitMon():
    # Check if monitor device exists
    if not os.path.isdir("/sys/class/net/" + intfparent):
        print('WiFi interface {intfparent} does not exist! Cannot continue!')
        exit()
    else:
        output = subprocess.run(["iw", intfparent, "info"],
                                capture_output=True, text=True)
        p = re.search(r'type (\w+)', output.stdout).group(1)
        if p != "monitor":
            try:
                # create monitor interface using iw
                subprocess.run(["ifconfig", intfparent, "down"])
                subprocess.run(["iw", "dev", intfparent, "set", "monitor", "none"])
                time.sleep(0.5)
                subprocess.run(["ifconfig", intfparent, "up"])
            except:
                raise
        else:
            print("Monitor %s exists! Nothing to do, just continuing..." % intfmon)


def stop():
    print('CTRL+C pressed, exiting...')
    endsniff(True)
    sys.exit('Closing')


def LoadAPlist():
    try:
        ifile = open(csvsummary, "r")
        csvreader = csv.reader(ifile, delimiter=',', quotechar='"',
                               quoting=csv.QUOTE_NONE, escapechar='\\')
        for row in csvreader:
            ap_list.append(row[1])
        ifile.close()
    except Exception:
        return


def channel_hop(channel=''):
    global intfmon
    channelNum = 1
    while 1:
        if channel:
            with lock:
                monchannel = channel
        else:
            # switch channel from 1 to 14 each 0.5s
            channelNum = channelNum % 14 + 1
            with lock:
                monchannel = str(channelNum)
            try:
                proc = subprocess.run(['iw', 'dev', intfmon, 'set', 'channel', monchannel])
            except OSError:
                print("Could not execute 'iw'")
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
            if proc.stderr:
                print('Channel hopping failed:')
            time.sleep(.05)


def checkdir(dirs):
    try:
        os.makedirs(dirs)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


# Main loop
# Init monitor mode device
InitMon()
# Check if workdir exists and create it
checkdir(workdir)
# Start channel hopping
hop = Thread(target=channel_hop, args=channel, daemon=True)
hop.start()
# Signal handler init
signal(SIGINT, stop)
# We need a CSV file to save the summary of captured files
LoadAPlist()
ofile = open(csvsummary, "a")
csvwriter = csv.writer(ofile, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONE, escapechar='\\')
# We begin to sniff and capture
try:
    sniff(iface=intfmon, prn=PacketHandler, stop_filter=endsniff())
except:
    print("Some error avoid sniffing with %s device!" % intfmon)
ofile.close()
