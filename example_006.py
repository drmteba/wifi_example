from netaddr import *
from netaddr.core import NotRegisteredError


def get_oui(macaddress):
    maco = EUI(macaddress)
    try:
        manuf = maco.oui.registration().org
    except NotRegisteredError:
        manuf = "Not available"
    return manuf


mac = 'bc:ae:c5:dd:dd:5e'
print(get_oui(mac))

