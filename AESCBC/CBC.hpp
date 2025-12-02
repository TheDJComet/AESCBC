#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <string>
#include "AES.hpp"

class AESCBC {
public:
	AESCBC(const std::array<uint8_t, 16>& key);
	std::vector<uint8_t> encryptStream(const std::string& plainText);
	void printBlocks(const std::array<uint8_t,16> block, const std::string& label) const;
	void printBlocks(const uint8_t block[16], const std::string& label) const;
	//std::string decryptStream(const std::vector<uint8_t>& cipherText);
private:
	std::array<uint8_t, 16>  initializationVector = { 
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f 
	};
	AES128 aes;
	void textToBlocks(const std::string& text, std::vector<std::array<uint8_t,16>>& blocks);
};