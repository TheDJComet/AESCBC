#include "AES.hpp"
#include <iomanip>
#include <cstring>
#include <iostream>
using namespace std;
//reminder index = row + 4 * c
//for sboxes row + 15 * c
static const uint8_t sbox[256] = { 
	0x63, 0x7c,0x77,0x7b,0xf2
};
static const uint8_t inv_sbox[256] = {/**/ };

static const uint8_t Rcon[11] = {
	0x00, 0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

AES128::AES128(const array<uint8_t, 16>& key){}

void AES128::printState(const uint8_t state[16], const std::string& label = " ") const {
	cout << "\n" << label << endl;
	int index = 0;
	for (int row = 0; row < 4; row++) {
		for (int col = 0; col < 4; col++) {
			index = row + (4 * col);
			cout << "Row " << row << ": " << state[index] << " ";

		}
		cout << endl;
	}
}


