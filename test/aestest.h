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
    void invSubBytes();
    void shiftRows();
    void invShiftRows();
    void mixColumns();
    void invMixColumns();
// Help
    void setState(std::vector<uint8_t> inp);
    std::vector<uint8_t> state2vec();
    std::vector<uint8_t> keySchedule2vec();

private:
    const uint32_t Nb = 4;  // Number of columns
    uint32_t Nk;            // Number of 32-bit words comprising the Cipher Key
    uint32_t Nr;            // Number of rounds
};
