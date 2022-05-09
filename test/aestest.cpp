#include "aestest.h"

#include <cstddef> // size_t

AESTest::AESTest(CipherKey_t ck) : AES(ck)
{
    Nk = ck;
    Nr = 6 + ck;
}

void AESTest::rotWord(uint8_t *w)
{
    rotWord_(w);
}

void AESTest::subWord(uint8_t *w)
{
    subWord_(w);
}

void AESTest::keyExpansion(std::vector<uint8_t> key)
{
    keyExpansion_(key);
}

void AESTest::addRoundKey(uint8_t *key)
{
    addRoundKey_(key);
}

void AESTest::subBytes()
{
    subBytes_();
}

void AESTest::invSubBytes()
{
    invSubBytes_();
}

void AESTest::shiftRows()
{
    shiftRows_();
}

void AESTest::invShiftRows()
{
    invShiftRows_();
}

void AESTest::mixColumns()
{
    mixColumns_();
}

void AESTest::invMixColumns()
{
    invMixColumns_();
}

void AESTest::setState(std::vector<uint8_t> inp)
{
    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < Nb; ++c)
        {
            state[r][c] = inp[r + 4 * c];
        }
    }
}

std::vector<uint8_t> AESTest::state2vec()
{
    return state2vec_();
}

std::vector<uint8_t> AESTest::keySchedule2vec()
{
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i < (4 * Nb * (Nr + 1)); ++i)
    {
        out.push_back(keySchedule[i]);
    }

    return out;
}
