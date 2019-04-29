//
//  APSniffer.cpp
//  wifi-killer
//
//  Created by hwangseonu on 29/04/2019.
//  Copyright © 2019 hwangseonu. All rights reserved.
//

#include "APSniffer.hpp"

void APSniffer::upLinePrompt(int cnt) {
    while (cnt--) {
        cout << "\33[2K";
        cout << "\x1b[A";
    }
}

void APSniffer::showApList() {
    cout << "***** Detected AP List *****" << endl;
    ApListMap::iterator it;
    int cnt = 0;
    for (it = this->apList.begin(); it != this->apList.end(); it++) {
        cnt++;
        cout << cnt << " BSSID : " << it->first << "    SSID : " << it->second << endl;
    }
    this->upLinePrompt(cnt+1);
}

bool APSniffer::handle(PDU &pdu) {
    const Dot11Beacon &beacon = pdu.rfind_pdu<Dot11Beacon>();
    if (!beacon.from_ds() && !beacon.to_ds()) {
        Bssid addr = beacon.addr2();
        ApListMap::iterator it = this->apList.find(addr);
        if (it == this->apList.end()) {
            try {
                string ssid = beacon.ssid();
                this->apList.insert(pair<Bssid, string>(addr, ssid));
                this->showApList();
            } catch (runtime_error&) {}
        }
    }
    return true;
}

void APSniffer::sniff() {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(this->iface, config);
    sniffer.sniff_loop(make_sniffer_handler(this, &APSniffer::handle));
}

APSniffer::APSniffer(string iface) {
    this->iface = iface;
}
