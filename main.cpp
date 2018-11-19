#include <iostream>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

NetworkInterface selectInterfaces() {
    int i = 1;
    for (auto iter : NetworkInterface::all()) cout << i++ << ". " << iter.name() << endl;
    cout << "select network interface > ";
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
    auto interface = selectInterfaces();
    selectChannel(interface.name());
    string ssid = input("input target ssid > ");

}