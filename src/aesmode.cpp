#include "aesmode.h"

#include <algorithm>   // transform
#include <functional>  // bit_xor
#include <iostream>

AESMode::AESMode(AES_Mode_t am)
{
    setMode(am);
}

std::vector<uint8_t> AESMode::encrypt(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    switch (mode)
    {
        case ECB: return ECBEncrypt_(inp, key);
        case CBC: return CBCEncrypt_(inp, key);
        case OFB: return OFBEncrypt_(inp, key);
        // case CFB: return CFBEncrypt_(inp, key);
        default:
            std::cerr << "Mode unimplemented!\n";
            return inp;
    }
}

std::vector<uint8_t> AESMode::decrypt(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    switch (mode)
    {
        case ECB: return ECBDecrypt_(inp, key);
        case CBC: return CBCDecrypt_(inp, key);
        case OFB: return OFBDecrypt_(inp, key);
        // case CFB: return CFBDecrypt_(inp, key);
        default:
            std::cerr << "Mode unimplemented!\n";
            return inp;
    }
}

void AESMode::setMode(AES_Mode_t am)
{
    mode = am;
    if (mode == CBC || mode == OFB)
    {
        setIV(std::vector<uint8_t>(16, 0));
    }
}

void AESMode::setIV(const std::vector<uint8_t>& iv)
{
    if (iv.size() == 16)
    {
        initializationVector.clear();
        initializationVector = iv;
        return;
    }
    std::cerr << "Size of IV is not 16. IV has not been changed.\n";
}

CipherKey_t AESMode::recognize_key_length_(const std::vector<uint8_t>& key)
{
    switch (key.size())
    {
        case 16: return AES_128;
        case 24: return AES_192;
        case 32: return AES_256;
        default: throw std::length_error("Key length is not valid.");
    }
}

std::vector<uint8_t> AESMode::ECBEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> encrypted = {};

    try
    {
        AES aes(recognize_key_length_(key));

        size_t i = 0;
        for (; i < inp.size() / 16; ++i)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.begin() + (i * 16) + 16 };
            std::vector<uint8_t> temp = aes.cipher(sub_inp, key);
            encrypted.insert(end(encrypted), begin(temp), end(temp));
        }
        if (inp.size() > i * 16) {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.end() };
            sub_inp.push_back(0x80);  // b10000000
            while (sub_inp.size() <= 16)
            {
                sub_inp.push_back(0x00);
            }
            std::vector<uint8_t> temp = aes.cipher(sub_inp, key);
            encrypted.insert(end(encrypted), begin(temp), end(temp));
        }
    }
    catch (const std::length_error& le)
    {
        std::cerr << "Exception: " << le.what() << '\n';
    }

    return encrypted;
}

std::vector<uint8_t> AESMode::ECBDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> decrypted = {};

    try
    {
        AES aes(recognize_key_length_(key));

        size_t i = 0;
        for (; i < inp.size() / 16; ++i)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.begin() + (i * 16) + 16 };
            std::vector<uint8_t> temp = aes.invCipher(sub_inp, key);
            decrypted.insert(end(decrypted), begin(temp), end(temp));
        }
        if (inp.size() > i * 16)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.end() };
            sub_inp.push_back(0x80);  // b10000000
            while (sub_inp.size() <= 16)
            {
                sub_inp.push_back(0x00);
            }
            std::vector<uint8_t> temp = aes.invCipher(sub_inp, key);
            decrypted.insert(end(decrypted), begin(temp), end(temp));
        }
    }
    catch (const std::length_error& le)
    {
        std::cerr << "Exception: " << le.what() << '\n';
    }

    return decrypted;
}

std::vector<uint8_t> AESMode::CBCEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> encrypted = {};

    try
    {
        AES aes(recognize_key_length_(key));
        std::vector<uint8_t> output_block = initializationVector;

        size_t i = 0;
        for (; i < inp.size() / 16; ++i)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.begin() + (i * 16) + 16 };
            std::transform(sub_inp.begin(), sub_inp.end(), output_block.begin(), sub_inp.begin(), std::bit_xor<uint8_t>());
            std::vector<uint8_t> temp = aes.cipher(sub_inp, key);
            encrypted.insert(end(encrypted), begin(temp), end(temp));
            output_block = temp;
        }
        if (inp.size() > i * 16)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.end() };
            sub_inp.push_back(0x80);  // b10000000
            while (sub_inp.size() <= 16)
            {
                sub_inp.push_back(0x00);
            }
            std::transform(sub_inp.begin(), sub_inp.end(), output_block.begin(), sub_inp.begin(), std::bit_xor<uint8_t>());
            std::vector<uint8_t> temp = aes.cipher(sub_inp, key);
            encrypted.insert(end(encrypted), begin(temp), end(temp));
        }
    }
    catch (const std::length_error& le)
    {
        std::cerr << "Exception: " << le.what() << '\n';
    }

    return encrypted;
}

std::vector<uint8_t> AESMode::CBCDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> decrypted = {};

    try
    {
        AES aes(recognize_key_length_(key));
        std::vector<uint8_t> iv_temp = initializationVector;

        size_t i = 0;
        for (; i < inp.size() / 16; ++i)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.begin() + (i * 16) + 16 };
            std::vector<uint8_t> ciphered_block = sub_inp;
            std::vector<uint8_t> temp = aes.invCipher(sub_inp, key);
            std::transform(temp.begin(), temp.end(), iv_temp.begin(), temp.begin(), std::bit_xor<uint8_t>());
            decrypted.insert(end(decrypted), begin(temp), end(temp));
            iv_temp = ciphered_block;
        }
        if (inp.size() > i * 16)
        {
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.end() };
            sub_inp.push_back(0x80);  // b10000000
            std::vector<uint8_t> temp = aes.invCipher(sub_inp, key);
            std::transform(temp.begin(), temp.end(), iv_temp.begin(), temp.begin(), std::bit_xor<uint8_t>());
            decrypted.insert(end(decrypted), begin(temp), end(temp));
        }
    }
    catch (const std::length_error& le)
    {
        std::cerr << "Exception: " << le.what() << '\n';
    }

    return decrypted;
}

std::vector<uint8_t> AESMode::OFBEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> encrypted = {};

    try
    {
        AES aes(recognize_key_length_(key));
        std::vector<uint8_t> input_block = initializationVector;

        size_t i = 0;
        for (; i < inp.size() / 16; ++i)
        {
            std::vector<uint8_t> temp = aes.cipher(input_block, key);
            input_block = temp;
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.begin() + (i * 16) + 16 };
            std::transform(sub_inp.begin(), sub_inp.end(), input_block.begin(), sub_inp.begin(), std::bit_xor<uint8_t>());
            encrypted.insert(end(encrypted), begin(sub_inp), end(sub_inp));
        }
        if (inp.size() > i * 16)
        {
            std::vector<uint8_t> input_block = aes.cipher(input_block, key);
            std::vector<uint8_t> sub_inp = { inp.begin() + (i * 16), inp.end() };
            sub_inp.push_back(0x80);  // b10000000
            while (sub_inp.size() <= 16)
            {
                sub_inp.push_back(0x00);
            }
            std::transform(sub_inp.begin(), sub_inp.end(), input_block.begin(), sub_inp.begin(), std::bit_xor<uint8_t>());
            encrypted.insert(end(encrypted), begin(sub_inp), end(sub_inp));
        }
    }
    catch (const std::length_error& le)
    {
        std::cerr << "Exception: " << le.what() << '\n';
    }

    return encrypted;
}

std::vector<uint8_t> AESMode::OFBDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key)
{
    return OFBEncrypt_(inp, key);
}
