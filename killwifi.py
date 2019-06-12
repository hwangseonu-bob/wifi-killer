from scapy.all import *
from scapy.layers.dot11 import *
import click
import threading


class ApSniffer(threading.Thread):
    def __init__(self, iface, ssid):
        super().__init__()
        self.bssid = set()
        self.ssid = ssid
        self.iface = iface
        self.stop = False

    def stop_thread(self):
        self.stop = True

    def stop_filter(self, pk):
        return self.stop

    def handle_packet(self, pk):
        dot11 = pk[Dot11]
        ds = dot11.FCfield & 0x3
        to_ds = ds & 0x1 != 0
        from_ds = ds & 0x2 != 0
        if not to_ds and not from_ds:
            ssid = dot11.info.decode()
            if ssid == self.ssid:
                self.bssid.add(dot11.addr2)

    def run(self):
        sniff(count=0, prn=self.handle_packet, filter='type mgt subtype beacon', stop_filter=self.stop_filter, iface=self.iface)


@click.command()
@click.option('--iface', '-i', help='network interface', type=str)
@click.option('--target', '-t', help='target ssid', type=str)
def main(iface, target):
    try:
        set_iface_monitor(iface, monitor=True)
        apSniff = ApSniffer(iface, target)
        apSniff.start()
        apSniff.join()
    except KeyboardInterrupt:
        apSniff.stop_thread()
        exit(0)


if __name__ == '__main__':
    main()
