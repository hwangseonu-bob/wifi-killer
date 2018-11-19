#ifndef __DATA_SNIFFER__
#define __DATA_SNIFFER__

#include <iostream>
#include <map>
#include <set>
#include <thread>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

class DataSniffer {
private:
    string iface_name;
    HWAddress<6> myMac;
    Sniffer *sniffer;
    set<HWAddress<6>> *address_set;
    set<HWAddress<6>> *target_set;
    bool endflag = false;
    enum FRAME_DRIECTION {
        TO_AP = 1,
        FROM_AP = 2,
        OTHER = 3
    };
public:
    DataSniffer(set<HWAddress<6>> *target, const string &iface, const string &my) {
        this->iface_name = iface;
        this->myMac = NetworkInterface(my).hw_address();
        this->target_set = target;
        this->address_set = new set<HWAddress<6>>;

        SnifferConfiguration config;

        config.set_rfmon(true);
        config.set_promisc_mode(true);
        config.set_filter("type data subtype data");

        this->sniffer = new Sniffer(this->iface_name, config);
    }

    FRAME_DRIECTION getFrameDirection(Dot11 *dot11) {
        if (dot11->to_ds() && !dot11->from_ds()) {
            return TO_AP;
        } else if (!dot11->to_ds() && dot11->from_ds()){
            return FROM_AP;
        }
        return OTHER;
    }

    bool isTargetAssociated(FRAME_DRIECTION fd, Dot11 *dot11) {
        if (fd == TO_AP) {
            return this->target_set->find(dot11->addr1()) != this->target_set->end();
        } else if (fd == FROM_AP){
            return this->target_set->find(dot11->find_pdu<Dot11Data>()->addr2()) != this->target_set->end();
        }
        return false;
    }

    void dataSniff() {
        while (!this->endflag) {
            Packet pk = this->sniffer->next_packet();

            if (!pk.pdu()) continue;
            auto *dot11 = pk.pdu()->find_pdu<Dot11>();
            if (!dot11) continue;
            auto *data = dot11->find_pdu<Dot11Data>();
            if (!data) continue;
            FRAME_DRIECTION fd = this->getFrameDirection(dot11);

            if (!isTargetAssociated(fd, dot11)) continue;

            if (fd == TO_AP) {
                if (data->addr2() != this->myMac) this->address_set->insert(data->addr2());
                if (data->addr3() != this->myMac) this->address_set->insert(data->addr3());
            } else if (fd == FROM_AP) {
                if (data->addr1() != this->myMac) this->address_set->insert(data->addr1());
                if (data->addr3() != this->myMac) this->address_set->insert(data->addr3());
            }
        }
    }

    set<HWAddress<6>>* getSet() {
        return this->address_set;
    }

    bool isEnd() {
        return this->endflag;
    }

    void end() {
        this->endflag = true;
    }
};


#endif