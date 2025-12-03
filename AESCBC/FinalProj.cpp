#include "AES.hpp"
#include "CBC.hpp"
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <array>
#include <fstream>
using namespace std;

int main() {
    array<uint8_t, 16> key = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };
    string textFromFile,fileString;
    cout << "File to encrypt: ";
    cin >> fileString;
    ifstream inFile(fileString);
    if (inFile.is_open()) {
        string line;
        while (getline(inFile, line)) {
            textFromFile.append(line);
            textFromFile.push_back('\n');
        }
        inFile.close();
    }
    else {
        cerr << "Unable to open file" << endl;
    }
    

    AESCBC test(key);

    vector<uint8_t> ciphertext = test.encryptStream(textFromFile);
    cout << endl << "Ciphertext: \n";
    for (int i = 0; i < ciphertext.size(); ++i) {

        cout << hex << setw(2) << setfill('0') << (int)ciphertext[i] << " ";

    }
    ofstream outFile("output.txt");
    if (outFile.is_open()) {
        for (int i = 0; i < ciphertext.size(); ++i) {
            outFile << hex << setw(2) << setfill('0') << (int)ciphertext[i] << " ";
        }
        outFile.close();
    }
    else {
        cerr << "Unable to open file" << endl;
    }

    //CBC decryption

    string ptxt = test.decryptStream(ciphertext);
    cout << "\n\nRecovered Plaintext: \n";
    cout << ptxt << "\n";

    ofstream recovered("recoveredPlainText.txt");
    if(recovered.is_open()) {
        recovered << ptxt;
        recovered.close();
    } else {
        cerr << "Unable to open recovered.txt for writing. :( " << endl;
    }

	return 0;
}
