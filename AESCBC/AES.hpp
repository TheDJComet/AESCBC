#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <string>

class AES128 {
public:
	AES128(const std::array<uint8_t, 16>& key); //constructor
	void encryptBlock(uint8_t in[16], uint8_t out[16]) const;
	void decryptBlock(uint8_t in[16], uint8_t out[16]) const;
private:
	
	std::array<uint8_t, 176> roundKeys; // initial addKey K0. then the keys for all 10 rounds K1 - K10. 11 K's in total each needs 16 bytes 11 * 16 = 176

	void keyExpansion(const uint8_t key[16]);
	void addRoundKey(uint8_t state[16], int round) const;
	void substituteBytes(uint8_t state[16]) const;
	void shiftRows(uint8_t state[16]) const;
	void mixColumns(uint8_t state[16]) const;
	void inverseSubstituteBytes(uint8_t state[16]) const;
	void inverseShiftRows(uint8_t state[16]) const;
	void inverseMixColumns(uint8_t state[16]) const;

	//GF(2^8) math
	static uint8_t xtime(uint8_t x);
	static uint8_t mul(uint8_t x, uint8_t by);

	//debugging
	void printState(const uint8_t state[16], const std::string& label = " ") const;
};