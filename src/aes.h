#pragma once

#include <cstdint> // uintX_t
#include <vector>

enum CipherKey_t { AES_128 = 4, AES_192 = 6, AES_256 = 8 };

class AES
{
public:
    AES(CipherKey_t ck);
    std::vector<uint8_t> cipher(std::vector<uint8_t> in, std::vector<uint8_t> key);
    std::vector<uint8_t> invCipher(std::vector<uint8_t> in, std::vector<uint8_t> key);
private:
    const uint32_t Nb = 4;  // Number of columns
    uint32_t Nk;            // Number of 32-bit words comprising the Cipher Key
    uint32_t Nr;            // Number of rounds
};
