#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "aes.h"

void printVector(const std::vector<uint8_t> &vec)
{
    std::stringstream sstr;
    std::string str = "";
    for (auto &v : vec)
    {
        sstr << std::setw(2) << std::setfill ('0') << std::hex << (int)v;
    }
    str = sstr.str();
    std::cout << str << "\n";
}

int main()
{
    std::cout << "Aplikacja pokazowa modułu AES\n\n";

    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    
    AES aes128(AES_128);
    std::vector<uint8_t> key128 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    std::vector<uint8_t> out = aes128.cipher(inp, key128);
    std::cout << "AES 128 Encryption\n";
    std::cout << "Input:\t\t"; printVector(inp);
    std::cout << "Key:\t\t"; printVector(key128);
    std::cout << "Encrypted:\t"; printVector(out);
    std::cout << "(Expected):\t" << "69c4e0d86a7b0430d8cdb78070b4c55a\n";

    AES aes192(AES_192);
    std::vector<uint8_t> key192 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    out = aes192.cipher(inp, key192);
    std::cout << "\nAES 192 Encryption\n";
    std::cout << "Input:\t\t"; printVector(inp);
    std::cout << "Key:\t\t"; printVector(key192);
    std::cout << "Encrypted:\t"; printVector(out);
    std::cout << "(Expected):\t" << "dda97ca4864cdfe06eaf70a0ec0d7191\n";

    AES aes256(AES_256);
    std::vector<uint8_t> key256 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    out = aes256.cipher(inp, key256);
    std::cout << "\nAES 256 Encryption\n";
    std::cout << "Input:\t\t"; printVector(inp);
    std::cout << "Key:\t\t"; printVector(key256);
    std::cout << "Encrypted:\t"; printVector(out);
    std::cout << "(Expected):\t" << "8ea2b7ca516745bfeafc49904b496089\n";
    
    inp = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
    key128 = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    out = aes128.invCipher(inp, key128);
    std::cout << "\nAES 128 Decryption\n";
    std::cout << "Input:\t\t"; printVector(inp);
    std::cout << "Key:\t\t"; printVector(key128);
    std::cout << "Decrypted:\t"; printVector(out);
    std::cout << "(Expected):\t" << "3243f6a8885a308d313198a2e0370734\n";

    inp = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
    out = aes192.invCipher(inp, key192);
    std::cout << "\nAES 192 Decryption\n";
    std::cout << "Input:\t\t"; printVector(inp);
    std::cout << "Key:\t\t"; printVector(key192);
    std::cout << "Decrypted:\t"; printVector(out);
    std::cout << "(Expected):\t" << "00112233445566778899aabbccddeeff\n";

    inp = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
    out = aes256.invCipher(inp, key256);
    std::cout << "\nAES 256 Decryption\n";
    std::cout << "Input:\t\t"; printVector(inp);
    std::cout << "Key:\t\t"; printVector(key256);
    std::cout << "Decrypted:\t"; printVector(out);
    std::cout << "(Expected):\t" << "00112233445566778899aabbccddeeff\n";

    return 0;
}
