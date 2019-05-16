from scapy.all import *
from scapy.layers.dot11 import *


def handle(pk):
    beacon = pk[Dot11Beacon]
    if beacon:
        hexdump(beacon)
    else:
        print("a")


class BeaconSniffer:
    def __init__(self, iface):
        self.iface = iface

    def sniff(self):
        sniff(iface=self.iface, filter="type mgt subtype beacon", prn=handle, count=0)
