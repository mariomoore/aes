#include "aestest.h"

#include <cstddef> // size_t

AESTest::AESTest(CipherKey_t ck) : AES(ck)
{

}

void AESTest::addRoundKey(std::vector<uint8_t> key)
{
    addRoundKey_(key);
}

void AESTest::subBytes()
{
    subBytes_();
}

void AESTest::shiftRows()
{
    shiftRows_();
}

void AESTest::mixColumns()
{
    mixColumns_();
}

void AESTest::setState(std::vector<uint8_t> inp)
{
    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < 4; ++c) // c < Nb
        {
            state[r][c] = inp[r + 4 * c];
        }
    }
}

std::vector<uint8_t> AESTest::state2vec()
{
    return state2vec_();
}
