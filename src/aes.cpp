#include "aes.h"

#include <cstddef> // size_t

AES::AES(CipherKey_t ck)
{
    Nk = ck;
    Nr = 6 + ck;
}

std::vector<uint8_t> AES::cipher(std::vector<uint8_t> in, std::vector<uint8_t> key)
{
    uint8_t **state = new uint8_t*[4];
    for (std::size_t i = 0; i < 4; ++i)
    {
        state[i] = new uint8_t[Nb];
    }

    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < Nb; ++c)
        {
            state[r][c] = in[r + 4 * c];
        }
    }

    addRoundKey_(state, key);

    std::vector<uint8_t> out = state2vec_(state);

    for (std::size_t i = 0; i < 4; ++i)
    {
        delete [] state[i];
    }
    delete [] state;

    return out;
}

void AES::addRoundKey_(uint8_t **state, std::vector<uint8_t> key)
{
    for (std::size_t r = 0; r < 4; ++r)
    {
        for (std::size_t c = 0; c < Nb; ++c)
        {
            state[r][c] ^= key[r + 4 * c];
        }
    }
}

std::vector<uint8_t> AES::state2vec_(uint8_t **state)
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
