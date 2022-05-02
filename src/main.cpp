#include <iomanip>
#include <iostream>
#include <sstream>

#include "aes.h"

void printVector(std::vector<uint8_t> vec)
{
    std::stringstream sstr;
    std::string str = "";
    for (std::size_t i = 0; i < vec.size(); ++i)
    {
        sstr << std::setw(2) << std::setfill ('0') << std::hex << (int)vec[i];
    }
    str = sstr.str();
    std::cout << str;
}

int main()
{
    std::cout << "Aplikacja pokazowa modułu AES" << std::endl;

    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    
    AES aes128(AES_128);
    std::vector<uint8_t> key128 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    std::vector<uint8_t> out = aes128.cipher(inp, key128);
    std::cout << "\nAES 128";
    std::cout << "\nInput:\t\t"; printVector(inp);
    std::cout << "\nKey:\t\t"; printVector(key128);
    std::cout << "\nCiphered:\t"; printVector(out); std::cout << std::endl;

    AES aes192(AES_192);
    std::vector<uint8_t> key192 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    out = aes192.cipher(inp, key192);
    std::cout << "\nAES 192";
    std::cout << "\nInput:\t\t"; printVector(inp);
    std::cout << "\nKey:\t\t"; printVector(key192);
    std::cout << "\nCiphered:\t"; printVector(out); std::cout << std::endl;

    AES aes256(AES_256);
    std::vector<uint8_t> key256 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    out = aes256.cipher(inp, key256);
    std::cout << "\nAES 256";
    std::cout << "\nInput:\t\t"; printVector(inp);
    std::cout << "\nKey:\t\t"; printVector(key256);
    std::cout << "\nCiphered:\t"; printVector(out); std::cout << std::endl;
    
    return 0;
}
