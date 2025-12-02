#include <iostream>
#include <iomanip>
#include <cstdint>
#include <array>
#include "AES.hpp"
using namespace std;
/*
int main() {

    // Example 128-bit key (you can change this)
    array<uint8_t, 16> key = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    // Example plaintext block (16 bytes)
    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t ciphertext[16] = {};

    AES128 aes(key);

    aes.encryptBlock(plaintext, ciphertext);

    aes.printBlock(plaintext, "Plaintext");
    aes.printBlock(ciphertext, "Ciphertext");



	return 0;
}
*/