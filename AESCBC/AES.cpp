#include "AES.hpp"
#include <iomanip>
#include <cstring>
#include <iostream>
using namespace std;
//reminder index = row + 4 * c
static const uint8_t sbox[256] = {/**/ };
static const uint8_t inv_sbox[256] = {/**/ };

static const uint8_t Rcon[11] = {
	0x00, 0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

AES128::AES128