#include "aes.h"

#include <cstddef> // size_t
#include <iomanip> // hex, setw, setfill
#include <iostream>
#include <sstream>
#include <string>

void printKey4debug(uint8_t *key)
{
    const uint32_t Nb = 4;  // Number of columns
    std::stringstream sstr;
    std::string str = "";
    for (std::size_t i = 0; i < 4 * Nb; ++i)
    {
        sstr << std::setw(2) << std::setfill ('0') << std::hex << (int)key[i];
    }
    str = sstr.str();
    std::cout << str << std::endl;
}

AES::AES(CipherKey_t ck)
{
    Nk = ck;
    Nr = 6 + ck;
    state = new uint8_t*[4];
    for (std::size_t i = 0; i < 4; ++i)
    {
        state[i] = new uint8_t[Nb];
    }
    keySchedule = new uint8_t[4 * Nb * (Nr + 1)];
}

AES::~AES()
{
    for (std::size_t i = 0; i < 4; ++i)
    {
        delete [] state[i];
    }
    delete [] state;
    delete [] keySchedule;
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

    keyExpansion_(key);

    std::size_t round = 0;
    addRoundKey_(keySchedule);
    round++;
    for (; round < Nr; ++round)
    {
        subBytes_();
        shiftRows_();
        mixColumns_();
        addRoundKey_(keySchedule + 4 * round * Nb);
    }
    subBytes_();
    shiftRows_();
    addRoundKey_(keySchedule + 4 * round * Nb);

    return state2vec_();
}

void AES::printState4debug() const
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

void AES::keyExpansion_(std::vector<uint8_t> key)
{
    std::size_t i = 0;
    for (; i < key.size(); ++i)
    {
        keySchedule[i] = key[i];
    }

    uint8_t temp[4];
    while (i < (4 * Nb * (Nr + 1)))
    {
        temp[0] = keySchedule[i - 4];
        temp[1] = keySchedule[i - 3];
        temp[2] = keySchedule[i - 2];
        temp[3] = keySchedule[i - 1];
        
        if (i % (Nk * 4) == 0)
        {
            rotWord_(temp);
            subWord_(temp);
            temp[0] ^= rcon[i/(Nk * 4) - 1];
        }
        else if ((Nk > 6) && (i % (Nk * 4) == 16))
        {
            subWord_(temp);
        }
        keySchedule[i] = keySchedule[i - (Nk * 4)] ^ temp[0];
        keySchedule[i + 1] = keySchedule[i - (Nk * 4) + 1] ^ temp[1];
        keySchedule[i + 2] = keySchedule[i - (Nk * 4) + 2] ^ temp[2];
        keySchedule[i + 3] = keySchedule[i - (Nk * 4) + 3] ^ temp[3];
        i += 4;
    }
}

void AES::rotWord_(uint8_t *w)
{
    uint8_t tmp = w[0];
    for (std::size_t i = 0; i < 3; ++i)
    {
        w[i] = w[i+1];
    }
    w[3] = tmp;
}

void AES::subWord_(uint8_t *w)
{
    for (std::size_t i = 0; i < 4; ++i)
    {
        w[i] = sbox[w[i]];
    }
}

void AES::addRoundKey_(uint8_t *key)
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

void AES::invShiftRows_()
{
    for (std::size_t r = 1; r < 4; ++r)
    {
        for (std::size_t sshf = 1; sshf <= r; ++sshf)
        {
            uint8_t tmp = state[r][Nb - 1];
            for (std::size_t c = Nb - 1; c > 0; --c)
            {
                state[r][c] = state[r][c - 1];
            }
            state[r][0] = tmp;
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
