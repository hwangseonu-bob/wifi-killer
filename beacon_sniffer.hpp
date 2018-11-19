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
    string target;
    int ch;
    Sniffer *sniffer;
    set<HWAddress<6>> *address_set;
    bool endflag = false;
    bool chflag = true;

public:
    explicit BeaconSniffer(const string &iface, const string &target) {
        this->target = target;
        this->iface_name = iface;
        this->address_set = new set<HWAddress<6>>();

        SnifferConfiguration config;

        config.set_promisc_mode(true);
        config.set_rfmon(true);
        config.set_filter("type mgt subtype beacon");

        this->sniffer = new Sniffer(this->iface_name, config);
    }

    void chHopping() {
        static int ch = 1;
        string cmd = "sudo iwconfig " + this->iface_name + " channel " + to_string(ch++);
        system(cmd.c_str());
        if (ch >= 14) ch = 1;
    }

    void beaconSniff() {
        while (!this->endflag) {
            if (this->chflag) this->chHopping();
            Packet pk = this->sniffer->next_packet();

            if (!pk.pdu()) continue;
            auto *dot11 = pk.pdu()->find_pdu<Dot11>();
            if (!dot11) continue;
            auto *beacon = dot11->find_pdu<Dot11Beacon>();
            if (!beacon) continue;

            if (beacon->ssid() == this->target) {
                this->address_set->emplace(beacon->addr2());
                this->chflag = false;
            }
        }
    }

    set<HWAddress<6>>* getAddressSet() {
        return this->address_set;
    }

    int getCh() {
        return this->ch;
    }
};

#endif