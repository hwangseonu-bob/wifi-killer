from beacon_sniff import BeaconSniffer

if __name__ == '__main__':
    sniffer = BeaconSniffer("en0")
    sniffer.sniff()
