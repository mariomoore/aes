#include "unity.h"
#include "aesmode.h"

void setUp(void)
{

}

void tearDown(void)
{

}

void test_aesmodeECB128_encrypt_should_encryptMessage(void)
{
    AESMode aesmode(ECB);

    std::vector<uint8_t> inp = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    std::vector<uint8_t>key128 = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    std::vector<uint8_t> exp = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
    };

    std::vector<uint8_t> out = aesmode.encrypt(inp, key128);

    TEST_ASSERT_EQUAL_HEX8(exp[0], out[0]);
    TEST_ASSERT_EQUAL_HEX8(exp[1], out[1]);
    TEST_ASSERT_EQUAL_HEX8(exp[2], out[2]);
    TEST_ASSERT_EQUAL_HEX8(exp[3], out[3]);
    TEST_ASSERT_EQUAL_HEX8(exp[4], out[4]);
    TEST_ASSERT_EQUAL_HEX8(exp[5], out[5]);
    TEST_ASSERT_EQUAL_HEX8(exp[6], out[6]);
    TEST_ASSERT_EQUAL_HEX8(exp[7], out[7]);
    TEST_ASSERT_EQUAL_HEX8(exp[8], out[8]);
    TEST_ASSERT_EQUAL_HEX8(exp[9], out[9]);
    TEST_ASSERT_EQUAL_HEX8(exp[10], out[10]);
    TEST_ASSERT_EQUAL_HEX8(exp[11], out[11]);
    TEST_ASSERT_EQUAL_HEX8(exp[12], out[12]);
    TEST_ASSERT_EQUAL_HEX8(exp[13], out[13]);
    TEST_ASSERT_EQUAL_HEX8(exp[14], out[14]);
    TEST_ASSERT_EQUAL_HEX8(exp[15], out[15]);
    TEST_ASSERT_EQUAL_HEX8(exp[16], out[16]);
    TEST_ASSERT_EQUAL_HEX8(exp[17], out[17]);
    TEST_ASSERT_EQUAL_HEX8(exp[18], out[18]);
    TEST_ASSERT_EQUAL_HEX8(exp[19], out[19]);
    TEST_ASSERT_EQUAL_HEX8(exp[20], out[20]);
    TEST_ASSERT_EQUAL_HEX8(exp[21], out[21]);
    TEST_ASSERT_EQUAL_HEX8(exp[22], out[22]);
    TEST_ASSERT_EQUAL_HEX8(exp[23], out[23]);
    TEST_ASSERT_EQUAL_HEX8(exp[24], out[24]);
    TEST_ASSERT_EQUAL_HEX8(exp[25], out[25]);
    TEST_ASSERT_EQUAL_HEX8(exp[26], out[26]);
    TEST_ASSERT_EQUAL_HEX8(exp[27], out[27]);
    TEST_ASSERT_EQUAL_HEX8(exp[28], out[28]);
    TEST_ASSERT_EQUAL_HEX8(exp[29], out[29]);
    TEST_ASSERT_EQUAL_HEX8(exp[30], out[30]);
    TEST_ASSERT_EQUAL_HEX8(exp[31], out[31]);
    TEST_ASSERT_EQUAL_HEX8(exp[32], out[32]);
    TEST_ASSERT_EQUAL_HEX8(exp[33], out[33]);
    TEST_ASSERT_EQUAL_HEX8(exp[34], out[34]);
    TEST_ASSERT_EQUAL_HEX8(exp[35], out[35]);
    TEST_ASSERT_EQUAL_HEX8(exp[36], out[36]);
    TEST_ASSERT_EQUAL_HEX8(exp[37], out[37]);
    TEST_ASSERT_EQUAL_HEX8(exp[38], out[38]);
    TEST_ASSERT_EQUAL_HEX8(exp[39], out[39]);
    TEST_ASSERT_EQUAL_HEX8(exp[40], out[40]);
    TEST_ASSERT_EQUAL_HEX8(exp[41], out[41]);
    TEST_ASSERT_EQUAL_HEX8(exp[42], out[42]);
    TEST_ASSERT_EQUAL_HEX8(exp[43], out[43]);
    TEST_ASSERT_EQUAL_HEX8(exp[44], out[44]);
    TEST_ASSERT_EQUAL_HEX8(exp[45], out[45]);
    TEST_ASSERT_EQUAL_HEX8(exp[46], out[46]);
    TEST_ASSERT_EQUAL_HEX8(exp[47], out[47]);
    TEST_ASSERT_EQUAL_HEX8(exp[48], out[48]);
    TEST_ASSERT_EQUAL_HEX8(exp[49], out[49]);
    TEST_ASSERT_EQUAL_HEX8(exp[50], out[50]);
    TEST_ASSERT_EQUAL_HEX8(exp[51], out[51]);
    TEST_ASSERT_EQUAL_HEX8(exp[52], out[52]);
    TEST_ASSERT_EQUAL_HEX8(exp[53], out[53]);
    TEST_ASSERT_EQUAL_HEX8(exp[54], out[54]);
    TEST_ASSERT_EQUAL_HEX8(exp[55], out[55]);
    TEST_ASSERT_EQUAL_HEX8(exp[56], out[56]);
    TEST_ASSERT_EQUAL_HEX8(exp[57], out[57]);
    TEST_ASSERT_EQUAL_HEX8(exp[58], out[58]);
    TEST_ASSERT_EQUAL_HEX8(exp[59], out[59]);
    TEST_ASSERT_EQUAL_HEX8(exp[60], out[60]);
    TEST_ASSERT_EQUAL_HEX8(exp[61], out[61]);
    TEST_ASSERT_EQUAL_HEX8(exp[62], out[62]);
    TEST_ASSERT_EQUAL_HEX8(exp[63], out[63]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aesmodeECB128_encrypt_should_encryptMessage);
    return UNITY_END();
}
