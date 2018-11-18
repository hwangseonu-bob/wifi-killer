#ifndef __BEACON_SNIFFER__
#define __BEACON_SNIFFER__

#include <iostream>
#include <map>
#include <set>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

class BeaconSniffer {
private:
    string iface_name;
    Sniffer *sniffer;
    map<string, set<HWAddress<6>>> *address_map;
    bool endflag = false;
public:
    explicit BeaconSniffer(const string &iface) {
        this->iface_name = iface;
        this->address_map = new map<string, set<HWAddress<6>>>();

        SnifferConfiguration config;

        config.set_promisc_mode(true);
        config.set_rfmon(true);
        config.set_filter("type mgt subtype beacon");

        this->sniffer = new Sniffer(this->iface_name, config);
    }

    void chHopping() {
        static int ch = 1;
        cout << ch << endl;
        string cmd = "iwconfig " + this->iface_name + " channel " + to_string(ch++);
        system(cmd.c_str());
        if (ch == 13) ch = 1;
    }

    void beaconSniff() {
        while (!this->endflag) {
            Packet pk = this->sniffer->next_packet();

            if (!pk.pdu()) continue;
            auto *dot11 = pk.pdu()->find_pdu<Dot11>();
            if (!dot11) continue;
            auto *beacon = dot11->find_pdu<Dot11Beacon>();
            if (!beacon) continue;

            auto iter = address_map->find(beacon->ssid());

            if(iter == address_map->end()){
                set<HWAddress<6>> temp;
                temp.emplace(beacon->addr2());
                (*address_map)[beacon->ssid()] = temp;
            }else{
                set<HWAddress<6>> temp = (*address_map)[beacon->ssid()];
                temp.emplace(beacon->addr2());
                (*address_map)[beacon->ssid()] = temp;
            }
        }
    }

    map<string, set<HWAddress<6>>>* getMap() {
        return this->address_map;
    }
};

#endif