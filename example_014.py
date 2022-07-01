from sys import argv, stderr, exit
from getopt import GetoptError, getopt as getoptions
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11Beacon, \
        Dot11ProbeResp, Dot11, Dot11Elt, Dot11ProbeReq
except Exception as err:
    print('Failed to import scapy:', err)
    exit(1)


class WPSQuery(object):
    bssid = None
    essid = None
    pfile = None
    rprobe = False
    verbose = False
    probedNets = {}
    WPS_ID = b'\x00\x50\xF2\x04'
    wps_attributes = {
        0x104A: {'name': 'Version                          ', 'type': 'hex'},
        0x1044: {'name': 'WPS State                        ', 'type': 'hex'},
        0x1057: {'name': 'AP Setup Locked                  ', 'type': 'hex'},
        0x1041: {'name': 'Selected Registrar               ', 'type': 'hex'},
        0x1012: {'name': 'Device Password ID               ', 'type': 'hex'},
        0x1053: {'name': 'Selected Registrar Config Methods', 'type': 'hex'},
        0x103B: {'name': 'Response Type                    ', 'type': 'hex'},
        0x1047: {'name': 'UUID-E                           ', 'type': 'hex'},
        0x1021: {'name': 'Manufacturer                     ', 'type': 'str'},
        0x1023: {'name': 'Model Name                       ', 'type': 'str'},
        0x1024: {'name': 'Model Number                     ', 'type': 'str'},
        0x1042: {'name': 'Serial Number                    ', 'type': 'str'},
        0x1054: {'name': 'Primary Device Type              ', 'type': 'hex'},
        0x1011: {'name': 'Device Name                      ', 'type': 'str'},
        0x1008: {'name': 'Config Methods                   ', 'type': 'hex'},
        0x103C: {'name': 'RF Bands                         ', 'type': 'hex'},
        0x1045: {'name': 'SSID                             ', 'type': 'str'},
        0x102D: {'name': 'OS Version                       ', 'type': 'str'}
    }

    def __init__(self, iface, pfile):
        if iface:
            conf.iface = iface
        if pfile:
            self.pfile = pfile

    def run(self):
        if self.verbose:
            if self.pfile:
                stderr.write("Reading packets from %s\n\n" % self.pfile)
            else:
                stderr.write("Listening on interface %s\n\n" % conf.iface)

        try:
            sniff(prn=self.pcap, offline=self.pfile)
        except Exception as error:
            print('Caught exception while running sniff():', error)

    # Handles captured packets
    def pcap(self, packets):
        if packets.haslayer(Dot11Beacon):
            self.beaconh(packets)
        elif packets.haslayer(Dot11ProbeResp):
            self.responseh(packets)

    # Beacon packet handler
    def beaconh(self, pkt):
        elt = None
        eltcount = 1
        doprobe = False
        essid = None
        bssid = pkt[Dot11].addr3.upper()

        # If a specific BSSID and ESSID combination was supplied
        # skip everything else and just probe it
        if self.bssid and self.essid:
            self.probereq(self.essid, self.bssid)
            return

        # If we've already probed it, processing its beacon frames
        # won't do us any more good
        if bssid in self.probedNets.keys():
            return

        # Is this the BSSID we're looking for?
        if self.bssid and self.bssid != bssid:
            return

        # Loop through all information elements
        while elt != pkt.lastlayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt, nb=eltcount)
            eltcount += 1

            # Get the SSID
            if elt.ID == 0:
                essid = elt.info.decode()
                # Skip if this is not the SSID we're looking for
                if self.essid and essid != self.essid:
                    return

            # Check for a WPS information element
            else:
                doprobe = self.iswpselt(elt)
                if doprobe:
                    if self.verbose:
                        stderr.write("WPS support detected for %s (%s)\n"
                                     % (bssid, essid))
                    break

        # Should we actively probe this AP?
        if doprobe or self.rprobe:
            self.probereq(essid, bssid)
        return

    # Probe response packet handler
    def responseh(self, pkt):
        wpsdata = []
        eltcount = 1
        elt = None
        essid = None
        bssid = pkt[Dot11].addr3.upper()

        # Is this the BSSID we're looking for?
        if self.bssid and self.bssid != bssid:
            return

        # Loop through all information elements
        while elt != pkt.lastlayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt, nb=eltcount)
            eltcount += 1

            # Get the SSID
            if elt.ID == 0:
                essid = elt.info.decode()
                # Don't probe a network if we've already gotten a probe response for it
                if essid and bssid in self.probedNets.keys() \
                        and self.probedNets[bssid] == essid:
                    return
                # Skip if this is not the SSID we're looking for
                if self.essid and essid != self.essid:
                    return
                if self.verbose:
                    stderr.write("Received probe response from %s (%s)\n" % (bssid, essid))
            elif self.iswpselt(elt):
                wpsdata = self.parsewpselt(elt)

        # Display WPS information
        if wpsdata:
            self.printwpsinfo(wpsdata, bssid, essid)
        elif self.verbose:
            stderr.write("No WPS element supplied by %s (%s)!\n" % (bssid, essid))

        # Mark this BSSID as complete
        self.probedNets[bssid] = essid

        return

    # Display collected WPS data
    @staticmethod
    def printwpsinfo(wpsdata, bssid, essid):
        textlen = 33
        filler = ' '

        if wpsdata:
            print('')
            print('BSSID:', bssid)
            print('ESSID:', essid)
            print('----------------------------------------------------------')

            for (header, data, datatype) in wpsdata:
                if datatype != 'str':
                    tdata = data
                    data = '0x'
                    for i in tdata:
                        byte = str(hex(i))[2:]
                        if len(byte) == 1:
                            byte = '0' + byte
                        data += byte
                header = header + (filler * (textlen - len(header)))
                print(f'{header}: {data}')
            print('')

    # Send a probe request to the specified AP
    def probereq(self, essid, bssid):
        if not essid or not bssid:
            return
        if bssid in self.probedNets.keys() and self.probedNets[bssid] is not None:
            return
        if self.pfile:
            return

        if self.verbose:
            stderr.write("Probing network '%s (%s)'\n" % (bssid, essid))

        try:
            # Build a probe request packet with a SSID and a WPS information element
            dst = mac2str(bssid)
            src = mac2str("ff:ff:ff:ff:ff:ff")
            packets = Dot11(addr1=dst, addr2=src, addr3=dst) / Dot11ProbeReq()
            packets = packets / Dot11Elt(ID=0, len=len(essid), info=essid) / \
                      Dot11Elt(ID=221, len=9, info="%s\x10\x4a\x00\x01\x10"
                                                   % self.WPS_ID)

            # Send it!
            send(packets, verbose=0)
            self.probedNets[bssid] = None
        except Exception as error:
            print('Failure sending probe request to', essid, ':', error)

    # Check if an element is a WPS element
    def iswpselt(self, elt):
        if elt.ID == 221:
            if elt.info.startswith(self.WPS_ID):
                return True
        return False

    # Parse a WPS element
    def parsewpselt(self, elt):
        data = []
        i = len(self.WPS_ID)

        try:
            if self.iswpselt(elt):
                while i < elt.len:
                    # Get tag number and length
                    tag = int(elt.info[i] * 0x100 + elt.info[i + 1])
                    i += 2
                    tlen = int(elt.info[i] * 0x100 + elt.info[i + 1])
                    i += 2

                    # Get the tag data
                    tagdata = elt.info[i:i + tlen]
                    i += tlen

                    # Lookup the tag name and type
                    try:
                        tagname = self.wps_attributes[tag]['name']
                        datatype = self.wps_attributes[tag]['type']
                    except Exception:
                        tagname = 'Unknown'
                        datatype = 'hex'

                    # Append to array
                    data.append((tagname, tagdata, datatype))
        except Exception as error:
            print('Exception processing WPS element:', error)

        return data


def about():
    print('''
WPScan actively scans access points that support WiFi Protected Setup by sending
802.11 probe requests to them. It then examines the WPS information element in the
resulting 802.11 probe response and displays the information contained in that IE.

This is useful for fingerprinting WPS-capable access points, as many of them will
include their vendor, model number, and firmware versions in the WPS IE of the
probe response.
''')
    exit(0)


def usage():
    print('''
Usage: %s [OPTIONS]

    -i <iface>  Specify the interface to listen on
    -p <file>   Specify pcap file to read from
    -b <bssid>  Specify a bssid filter
    -e <essid>  Specify an essid filter
    -n          Probe all networks
    -v          Enable verbose mode
    -a          Show about information
    -h          Show help
''' % argv[0])
    exit(1)


def main():
    global opts
    bssid = None
    essid = None
    iface = 'wlan0'
    pfile = None
    probeall = False
    verbose = False

    try:
        opts, args = getoptions(argv[1:], "b:e:i:p:ainvh")
    except GetoptError as error:
        print('Usage Error:', error)
        usage()

    for opt, optarg in opts:
        if opt == '-b':
            bssid = optarg.upper()
        elif opt == '-e':
            essid = optarg
        elif opt == '-i':
            iface = optarg
        elif opt == '-p':
            pfile = optarg
        elif opt == '-v':
            verbose = True
        elif opt == '-n':
            probeall = True
        elif opt == '-a':
            about()
        else:
            usage()

    wps = WPSQuery(iface, pfile)
    wps.bssid = bssid
    wps.essid = essid
    wps.rprobe = probeall
    wps.verbose = verbose
    wps.run()


if __name__ == "__main__":
    main()
