#include "aes.h"

#include <cstddef> // size_t

AES::AES(CipherKey_t ck)
{
    Nk = ck;
    Nr = 6 + ck;
    state = new uint8_t*[4];
    for (std::size_t i = 0; i < 4; ++i)
    {
        state[i] = new uint8_t[Nb];
    }
}

AES::~AES()
{
    for (std::size_t i = 0; i < 4; ++i)
    {
        delete [] state[i];
    }
    delete [] state;
}

std::vector<uint8_t> AES::cipher(std::vector<uint8_t> in, std::vector<uint8_t> key)
{
    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < Nb; ++c)
        {
            state[r][c] = in[r + 4 * c];
        }
    }

    addRoundKey_(key);

    return state2vec_();
}

void AES::addRoundKey_(std::vector<uint8_t> key)
{
    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < Nb; ++c)
        {
            state[r][c] ^= key[r + 4 * c];
        }
    }
}

void AES::subBytes_()
{
    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < Nb; ++c)
        {
            state[r][c] = sbox[state[r][c]];
        }
    }
}

std::vector<uint8_t> AES::state2vec_()
{
    std::vector<uint8_t> out;
    for (std::size_t c = 0; c < Nb; ++c)
    {
        for (std::size_t r = 0; r < 4; ++r)
        {
            out.push_back(state[r][c]);
        }
    }

    return out;
}
