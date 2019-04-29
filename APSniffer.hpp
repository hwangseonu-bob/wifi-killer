//
//  APSniffer.hpp
//  wifi-killer
//
//  Created by hwangseonu on 29/04/2019.
//  Copyright © 2019 hwangseonu. All rights reserved.
//

#ifndef APSniffer_hpp
#define APSniffer_hpp

#include <iostream>
#include <string>
#include <map>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

typedef Dot11::address_type Bssid;
typedef map<Bssid, string> ApListMap;

class APSniffer {
private:
    string iface;
    ApListMap apList;
public:
    APSniffer(string iface);
    void upLinePrompt(int);
    void showApList();
    bool handle(PDU&);
    void sniff();
};

#endif /* APSniffer_hpp */
