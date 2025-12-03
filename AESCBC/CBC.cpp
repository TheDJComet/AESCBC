#include "CBC.hpp"
#include <iomanip>
#include <cstring>
#include <iostream>
using namespace std;

AESCBC::AESCBC(const std::array<uint8_t, 16>& key) :aes(key) {};

void AESCBC::printBlocks(const std::array<uint8_t, 16> block, const std::string& label) const {
	cout << endl << label << ": ";
	for (int i = 0; i < 16; ++i) {
		cout << hex << setw(2) << setfill('0') << (int)block[i] << " ";
	}
	cout << dec << endl;
}

void AESCBC::printBlocks(const uint8_t block[16], const std::string& label) const {
	cout << endl << label << ": ";
	for (int i = 0; i < 16; ++i) {
		cout << hex << setw(2) << setfill('0') << (int)block[i] << " ";
	}
	cout << dec << endl;
}

void AESCBC::textToBlocks(const std::string& text, std::vector<std::array<uint8_t, 16>>& blocks) {
	auto length = text.size();
	auto n = length / 16;
	auto remainingBytes = length % 16;
	auto padding = 16 - remainingBytes;
	
	for (int b = 0; b < n; ++b) {
		array<uint8_t, 16> temp;
		for (int j = 0; j < 16; ++j) {
			temp[j] = (uint8_t)text[16 * b + j];
		}
		printBlocks(temp,"PT Block");
		blocks.push_back(temp);
	}
	//padding according to PKCS7
	array<uint8_t, 16> paddingBlock = {};
	if (remainingBytes == 0) {
		for (int i = 0; i < 16; ++i) {
			paddingBlock[i] = 0x10;
		}
	}
	else if (remainingBytes > 0) {
		int start = n * 16;
		for (int i = 0; i < remainingBytes; ++i) {
			paddingBlock[i] = (uint8_t)text[start + i];
		}
		uint8_t padFill = (uint8_t)(16 - remainingBytes);
		for (int i = remainingBytes; i < 16; ++i) {
			paddingBlock[i] = padFill;
		}
	}
	printBlocks(paddingBlock, "Padding Block");
	blocks.push_back(paddingBlock);
}
vector<uint8_t> AESCBC::encryptStream(const std::string& plainText) {
	vector<array<uint8_t, 16>> blocks;
	vector<uint8_t> ciphertext;
	textToBlocks(plainText, blocks);
	uint8_t X[16], out[16],prevCipher[16];
	for (size_t i = 0; i < blocks.size(); ++i) {
		if (i == 0) {
			for (size_t j = 0; j < 16; ++j) {
				cout << blocks[i][j] << " ";
				
				X[j] = blocks[i][j] ^ initializationVector[j];
				

				
			}
			printBlocks(X, "XOR Block (P[i] ^ IV/C[i-1])");
			aes.encryptBlock(X, out);
			for (size_t j = 0; j < 16; ++j) {
				ciphertext.push_back(out[j]);
			}
			memcpy(prevCipher, out, 16);
			printBlocks(out, "Ciphertext Block C[" + std::to_string(i) + "]");
		}
		else {
			for (size_t j = 0; j < 16; ++j) {
				cout << blocks[i][j] << " ";
				X[j] = blocks[i][j] ^ prevCipher[j];
			}
			printBlocks(X, "XOR Block (P[i] ^ IV/C[i-1])");
			aes.encryptBlock(X, out);
			for (size_t j = 0; j < 16; ++j) {
				ciphertext.push_back(out[j]);
			}
			memcpy(prevCipher, out, 16);
			printBlocks(out, "Ciphertext Block C[" + std::to_string(i) + "]");
		}
	}
	return ciphertext;
}

std::string AESCBC::decryptStream(const std::vector<uint8_t>& cipherText) {
	//Cipher text must be a multiple of 16 byte block size
	if (cipherText.empty() || cipherText.size() % 16 != 0) {
		cerr << "Invalid ciphertext length for CBC decryption. " << endl;
		return " ";
	}

	const size_t blocks = cipherText.size() / 16;

	std::string plainText;
	plainText.reserve(cipherText.size()); //can't be bigger than this

	uint8_t in[16]; //current ciphertext block
	uint8_t decrypt[16]; //previous
	uint8_t xored[16]; //P[i]

	for(size_t i = 0; i < blocks; i++){

		//load cipherblock into current
		for(int j = 0; j < 16; j++){
			in[j] = cipherText[i * 16 + j];
		}

		printBlocks(in, "CiphertextBlock C[" + std::to_string(i) + "] ");

		//Block decryption
		aes.decryptBlock(in, decrypt);
		printBlocks(decrypt, "After block decryption C[" + std::to_string(i) + "]");

		//XOR with IV or previous block 

		if(i == 0){
			for(int j = 0; j < 16; j++) {
				xored[j] = decrypt[j] ^ initializationVector[j];
			}
		}else {
			for(int j = 0; j < 16; j++) {
				xored[j] = decrypt[j] ^ cipherText[(i - 1) * 16 + j];
			}
		}

		printBlocks(xored, "Recovered plaintext block P[" + std::to_string(i) + "]");

		//append to plaintext
		for(int j = 0; j < 16; j++){
			plainText.push_back(static_cast<char>(xored[j]));
		}
	}

	//string pkcs#7 padding
	if(!plainText.empty()){
		uint8_t pad = static_cast<uint8_t>(plainText.back());

		//assume encryption stream is correct
		if(pad > 0 && pad <= 16 && plainText.size() >= pad){
			plainText.resize(plainText.size() - pad);
		}
		else{
			cerr << "Warning: invalid padding value (" << (int)pad << 
			"), returning plaintext." << endl;

			return plainText;
		}
	}

	return plainText;
}