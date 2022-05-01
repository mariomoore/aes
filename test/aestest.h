#pragma once

#include "aes.h"

class AESTest : public AES
{
public:
    AESTest(CipherKey_t ck);
// Tested
    void rotWord(uint8_t *w);
    void subWord(uint8_t *w);
    void keyExpansion(std::vector<uint8_t> key);
    void addRoundKey(uint8_t *key);
    void subBytes();
    void shiftRows();
    void mixColumns();
// Help
    void setState(std::vector<uint8_t> inp);
    std::vector<uint8_t> state2vec();
    std::vector<uint8_t> keySchedule2vec();
};
