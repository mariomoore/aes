#pragma once

#include "aes.h"

class AESTest : public AES
{
public:
    AESTest(CipherKey_t ck);
// Tested
    void addRoundKey(std::vector<uint8_t> key);
// Help
    void setState(std::vector<uint8_t> inp);
    std::vector<uint8_t> state2vec();
};