#pragma once

#include "aes.h"

#include <cstdint> // uintX_t
#include <vector>

enum AES_Mode_t { ECB, CBC, OFB, CFB };

class AESMode
{
public:
    AESMode(AES_Mode_t am);
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    void setMode(AES_Mode_t am);
    void setIV(const std::vector<uint8_t>& iv);

private:
    AES_Mode_t mode = ECB;
    std::vector<uint8_t> initializationVector;
    CipherKey_t recognize_key_length_(const std::vector<uint8_t>& key);
    std::vector<uint8_t> ECBEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> ECBDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> CBCEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> CBCDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> OFBEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> OFBDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> CFBEncrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
    std::vector<uint8_t> CFBDecrypt_(const std::vector<uint8_t>& inp, const std::vector<uint8_t>& key);
};
