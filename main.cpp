//
//  main.cpp
//  wifi-killer
//
//  Created by hwangseonu on 28/04/2019.
//  Copyright © 2019 hwangseonu. All rights reserved.
//

#include <iostream>
#include "APSniffer.hpp"

int main() {
    APSniffer apSniffer("en0");
    apSniffer.sniff();
    return 0;
}
