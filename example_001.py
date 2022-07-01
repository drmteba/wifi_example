import fcntl
import os
import re
import socket
import struct
import subprocess
import sys
import time
from platform import system
from signal import SIGINT

# define variables
iface = 'wlan0'


# Check if OS is linux:
def OScheck():
    osversion = system()
    print("Operating System: %s" % osversion)
    if osversion != 'Linux':
        print("This script only works on Linux OS! Exiting!")
        exit(1)


'''another way OScheck():
import sys
def OScheck():
    osversion = sys.platform()
    print("Operating System: %s" %osversion)
    if osversion != 'linux':
        print("This script only works on Linux OS! Exiting!")
        exit(1)
'''


def Monitor_mode():
    if not os.path.isdir("/sys/class/net/" + iface):
        print("WiFi interface %s does not exist! Cannot continue!" % iface)
        exit(1)
    else:
        output = subprocess.run(["iw", iface, "info"],
                                capture_output=True, text=True)
        p = re.search(r"type (\w+)", output.stdout).group(1)
        if not p == "monitor":
            try:
                # create monitor interface using iw
                subprocess.run(["ifconfig", iface, "down"])
                subprocess.run(["iw", "dev", iface, "set", "monitor", "none"])
                time.sleep(0.5)
                subprocess.run(["ifconfig", iface, "up"])
                print("Creating monitor mode for %s" % iface)
            except OSError:
                print("Could not create monitor %s" % iface)
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
        else:
            print("Monitor %s exists! Nothing to do, just continuing..." % iface)


def Get_mac_address(intface):  # hard way
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', intface[:15].encode("utf-8")))
    macaddress = ':'.join([f'{b:02x}' for b in info[18:24]])
    return macaddress


# Check if OS is linux:
OScheck()

# Check for root privileges
if os.geteuid() != 0:
    exit("You need to be root to run this script!")
else:
    print("You are running this script as root!")

# Check if monitor device exists
Monitor_mode()
# Get intfmon actual MAC address
macaddr = Get_mac_address(iface).upper()
print(f"Actual {iface} MAC Address: {macaddr}")
