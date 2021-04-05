#include "netutils.hpp"
#include "inttypes.h"
#include <stdio.h>
#include <string>

void resolve_unit_test(std::string hosthint, int64_t expected, bool mode, bool any) {
    sockaddr_in outsock = GetRecipient(const_cast<char*>(hosthint.c_str()));
    int64_t address = outsock.sin_addr.s_addr;
    if (mode) {
        if (address == expected) {
            printf("[passed] %s\n", hosthint.c_str());
        } else {
            if (any) {
                printf("[flake] %s has been resolved to %X instead of %X\n", hosthint.c_str(), address, expected);
            } else {
                printf("[failed] %s has been resolved to %X instead of %X\n", hosthint.c_str(), address, expected);
            }
        }
    } else {
        if (address != -1)
            printf("[failed] resolved %s to %X while it's an invalid address\n", hosthint.c_str(), address);
        else
            printf("[passed] rejected %s\n", hosthint.c_str());
    }
}

void test_resolver() {
    resolve_unit_test("1.1.1.1", 0x01010101, true, false);
    resolve_unit_test("8.8.8.8", 0x08080808, true, false);
    resolve_unit_test("142.250.186.174", 0x8EFABAAE, true, true);
    resolve_unit_test("185.60.216.35", 0xB93CD823, true, true);
    resolve_unit_test("2137.2137.2137.2137", 0x01010101, false, false);
    resolve_unit_test("8.8.8.8.8.8.8.8", 0x08080808, false, false);
    resolve_unit_test("www.google.com", 0x01010101, true, true);
    resolve_unit_test("www.facebook.com", 0x01010101, true, true);
    resolve_unit_test("www.youtube.com", 0x01010101, true, true);
    resolve_unit_test("www.amazon.com", 0x01010101, true, true);
    resolve_unit_test("www.rozrzutniki-gnojownicy.pl", 0x01010101, false, true);
    resolve_unit_test("www.polskie_okna.com", 0x01010101, false, true);
    resolve_unit_test("www.skamieliny.net", 0x01010101, false, true);
}

int main() {
    test_resolver();
}