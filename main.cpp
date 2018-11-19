#include <iostream>
#include <thread>
#include <tins/tins.h>

#include "DataSniffer.h"

using namespace std;
using namespace Tins;

NetworkInterface selectInterfaces(const string& msg) {
    int i = 1;
    for (auto iter : NetworkInterface::all()) cout << i++ << ". " << iter.name() << endl;
    cout << msg;
    cin >> i;
    return NetworkInterface::from_index(static_cast<NetworkInterface::id_type>(i));
}

void selectChannel(const string& interface) {
    int ch;
    cout << "select network channel > ";
    cin >> ch;
    string cmd = "sudo iwconfig " + interface + " channel " + to_string(ch);
    system(cmd.c_str());
}

string input(const string& msg) {
    string input;
    cout << msg;
    cin >> input;
    return input;
}

int main() {
    auto sendInterface = selectInterfaces("select network interface to send > ");
    auto inetInterface = selectInterfaces("select network interface you wifi > ");
    selectChannel(sendInterface.name());

    string bssid = input("input target bssid > ");

    DataSniffer *sniffer = new DataSniffer(sendInterface, inetInterface.hw_address(), bssid);

    thread snifferThread = thread(&DataSniffer::sniff, sniffer);

    snifferThread.join();
}