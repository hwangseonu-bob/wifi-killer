#ifndef WIFI_KILLER_DEAUTHSENDER_H
#define WIFI_KILLER_DEAUTHSENDER_H

#include <iostream>
#include <set>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

class DeauthSender {
private:
    NetworkInterface interface;
    HWAddress<6> target;
    set<HWAddress<6>> *addressSet;
public:
    explicit DeauthSender(NetworkInterface interface, HWAddress<6> target, set<HWAddress<6>> *addressSet);
    void sendPacket();
};

#endif //WIFI_KILLER_DEAUTHSENDER_H
