#include "aesmode.h"

#include <iostream>

AESMode::AESMode(AES_Mode_t am)
{
    setMode(am);
}

std::vector<uint8_t> AESMode::encrypt(const std::vector<uint8_t> &inp, const std::vector<uint8_t> &key)
{
    switch(mode)
    {
        case ECB: return ECBEncrypt_(inp, key);
        // case CBC: return CBCEncrypt_(inp, key);
        // case OFB: return OFBEncrypt_(inp, key);
        // case CFB: return CFBEncrypt_(inp, key);
        default:
            std::cerr << "Mode unknown!\n";
            return inp;
    }
}

// std::vector<uint8_t> AESMode::decrypt(const std::vector<uint8_t> &inp, const std::vector<uint8_t> &key)
// {
//     switch(mode)
//     {
//         case ECB: return ECBDecrypt_(inp, key);
//         case CBC: return CBCDecrypt_(inp, key);
//         case OFB: return OFBDecrypt_(inp, key);
//         case CFB: return CFBDecrypt_(inp, key);
//         default:
//             std::cerr << "Mode unknown!\n";
//             return inp;
//     }
// }

void AESMode::setMode(AES_Mode_t am)
{
    mode = am;
}

CipherKey_t AESMode::recognize_key_length_(const std::vector<uint8_t> &key)
{
    switch(key.size())
    {
        case 16: return AES_128;
        case 24: return AES_192;
        case 32: return AES_256;
        default: throw std::length_error("Key length is not valid.");
    }
}

std::vector<uint8_t> AESMode::ECBEncrypt_(const std::vector<uint8_t> &inp, const std::vector<uint8_t> &key)
{
    std::vector<uint8_t> encrypted = {};
    
    try
    {
        AES aes(recognize_key_length_(key));

        size_t i = 0;
        for (; i < inp.size()/16; ++i)
        {
            std::vector<uint8_t> sub_inp = { inp.begin()+(i*16), inp.begin()+(i*16)+16 };
            std::vector<uint8_t> temp = aes.cipher(sub_inp, key);
            encrypted.insert(end(encrypted), begin(temp), end(temp));
        }
        if (inp.size() > i*16)
        {
            std::vector<uint8_t> sub_inp = { inp.begin()+(i*16), inp.end() };
            sub_inp.push_back(0x80); // b10000000
            while (sub_inp.size() <= 16)
            {
                sub_inp.push_back(0x00);
            }
            std::vector<uint8_t> temp = aes.cipher(sub_inp, key);
            encrypted.insert(end(encrypted), begin(temp), end(temp));
        }
    }
    catch(const std::length_error& le)
    {
        std::cerr << "Exception: " << le.what() << '\n';
    }

    return encrypted;
}
