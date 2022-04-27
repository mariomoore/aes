#include "aes.h"

#include <cstddef> // size_t
#include <iomanip> // hex, setw, setfill
#include <iostream>
#include <sstream>
#include <string>

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

void AES::printState() const
{
    std::stringstream sstr;
    std::string str = "";
    for (std::size_t c = 0; c < Nb; ++c)
    {
        for (std::size_t r = 0; r < 4; ++r)
        {
            sstr << std::setw(2) << std::setfill ('0') << std::hex << (int)state[r][c];
        }
    }
    str = sstr.str();
    std::cout << str << std::endl;
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

void AES::shiftRows_()
{
    for (std::size_t r = 1; r < 4; ++r)
    {
        for (std::size_t sshf = 1; sshf <= r; ++sshf)
        {
            uint8_t tmp = state[r][0];
            for ( std::size_t c = 0; c < Nb - 1; ++c)
            {
                state[r][c] = state[r][c + 1];
            }
            state[r][Nb - 1] = tmp;
        }
    }
}

void AES::mixColumns_()
{
    for (std::size_t c = 0; c < Nb; ++c)
    {
        uint8_t tmp_col[4] = {};
        for (std::size_t r = 0; r < 4; ++r)
        {
            for (std::size_t i = 0; i < 4; ++i)
            {
                switch(mixcoeff[r][i])
                {
                    case 1: tmp_col[r] ^= state[i][c]; break;
                    case 2: tmp_col[r] ^= multiply2[state[i][c]]; break;
                    case 3: tmp_col[r] ^= multiply3[state[i][c]]; break;
                }
            }
        }
        for (std::size_t r = 0; r < 4; ++r)
        {
            state[r][c] = tmp_col[r];
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
