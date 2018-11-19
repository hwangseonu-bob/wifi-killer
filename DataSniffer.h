#ifndef WIFI_KILLER_DATASNIFFER_H
#define WIFI_KILLER_DATASNIFFER_H

#include <set>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

enum FRAME_DIRECTION {
    TO_AP = 1,
    FROM_AP = 2,
    OTHER = 3
};

class DataSniffer {
private:
    Sniffer *sniffer;
    HWAddress<6> myMac;
    HWAddress<6> target;
    set<HWAddress<6>> *targetSet;
public:
    explicit DataSniffer(NetworkInterface interface, HWAddress<6> myMac, HWAddress<6> target);
    FRAME_DIRECTION getFrameDirection(Dot11 *dot11);
    bool isTargetAssociated(FRAME_DIRECTION direction, Dot11 *dot11);
    void sniff();
    set<HWAddress<6>>* getTargetSet();
};


#endif //WIFI_KILLER_DATASNIFFER_H
