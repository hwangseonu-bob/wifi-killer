#include <iostream>
#include "DataSniffer.h"

DataSniffer::DataSniffer(NetworkInterface interface, HWAddress<6> myMac, HWAddress<6> target)  {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_rfmon(true);
    config.set_filter("type data subtype data");
    this->sniffer = new Sniffer(interface.name(), config);
    this->targetSet = new set<HWAddress<6>>;
    this->myMac = myMac;
    this->target = target;
}

FRAME_DIRECTION DataSniffer::getFrameDirection(Dot11 *dot11) {
    if (dot11->to_ds() && !dot11->from_ds()) return TO_AP;
    else if (!dot11->to_ds() && dot11->from_ds()) return FROM_AP;
    else return OTHER;
}

bool DataSniffer::isTargetAssociated(FRAME_DIRECTION direction, Dot11 *dot11) {
    if (direction == TO_AP) return dot11->addr1() == this->target;
    else if (direction == FROM_AP) return dot11->find_pdu<Dot11Data>()->addr2() == this->target;
    else return false;
}

void DataSniffer::sniff() {
    while (true) {
        Packet pk = this->sniffer->next_packet();

        if (!pk.pdu()) continue;
        auto *dot11 = pk.pdu()->find_pdu<Dot11>();
        if (!dot11) continue;
        auto *data = dot11->find_pdu<Dot11Data>();
        if (!data) continue;
        FRAME_DIRECTION  direction = this->getFrameDirection(dot11);

        if (!this->isTargetAssociated(direction, dot11)) continue;

        if (direction == TO_AP) {
            if (data->addr2() != this->myMac) this->targetSet->insert(data->addr2());
            if (data->addr3() != this->myMac) this->targetSet->insert(data->addr3());
        } else if (direction == FROM_AP) {
            if (data->addr1() != this->myMac) this->targetSet->insert(data->addr1());
            if (data->addr3() != this->myMac) this->targetSet->insert(data->addr3());
        }
    }
}

set<HWAddress<6>>* DataSniffer::getTargetSet() {
    return this->targetSet;
}