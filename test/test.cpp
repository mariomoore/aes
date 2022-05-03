#include "unity.h"
#include "aestest.h"

void setUp(void)
{

}

void tearDown(void)
{

}

void test_aes_state2vec_should_returnInput(void)
{
    AESTest aestest(AES_128);

    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; // round[ 0].input
    aestest.setState(inp);
    
    std::vector<uint8_t> out = aestest.state2vec();
    
    TEST_ASSERT_EQUAL_HEX8(inp[0], out[0]);
    TEST_ASSERT_EQUAL_HEX8(inp[1], out[1]);
    TEST_ASSERT_EQUAL_HEX8(inp[2], out[2]);
    TEST_ASSERT_EQUAL_HEX8(inp[3], out[3]);
    TEST_ASSERT_EQUAL_HEX8(inp[4], out[4]);
    TEST_ASSERT_EQUAL_HEX8(inp[5], out[5]);
    TEST_ASSERT_EQUAL_HEX8(inp[6], out[6]);
    TEST_ASSERT_EQUAL_HEX8(inp[7], out[7]);
    TEST_ASSERT_EQUAL_HEX8(inp[8], out[8]);
    TEST_ASSERT_EQUAL_HEX8(inp[9], out[9]);
    TEST_ASSERT_EQUAL_HEX8(inp[10], out[10]);
    TEST_ASSERT_EQUAL_HEX8(inp[11], out[11]);
    TEST_ASSERT_EQUAL_HEX8(inp[12], out[12]);
    TEST_ASSERT_EQUAL_HEX8(inp[13], out[13]);
    TEST_ASSERT_EQUAL_HEX8(inp[14], out[14]);
    TEST_ASSERT_EQUAL_HEX8(inp[15], out[15]);
}

void test_aes_rotWord_should_rotateWord(void)
{
    AESTest aestest(AES_128);

    uint8_t inp[] = { 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t exp[] = { 0xcf, 0x4f, 0x3c, 0x09 };
    
    aestest.rotWord(inp);

    TEST_ASSERT_EQUAL_HEX8(exp[0], inp[0]);
    TEST_ASSERT_EQUAL_HEX8(exp[1], inp[1]);
    TEST_ASSERT_EQUAL_HEX8(exp[2], inp[2]);
    TEST_ASSERT_EQUAL_HEX8(exp[3], inp[3]);
}

void test_aes_subWord_should_transformWord(void)
{
    AESTest aestest(AES_128);

    uint8_t inp[] = { 0x6c, 0x76, 0x05, 0x2a };
    uint8_t exp[] = { 0x50, 0x38, 0x6b, 0xe5 };
    
    aestest.subWord(inp);

    TEST_ASSERT_EQUAL_HEX8(exp[0], inp[0]);
    TEST_ASSERT_EQUAL_HEX8(exp[1], inp[1]);
    TEST_ASSERT_EQUAL_HEX8(exp[2], inp[2]);
    TEST_ASSERT_EQUAL_HEX8(exp[3], inp[3]);
}

void test_aes128_keyExpansion_should_prepareKeySchedule(void)
{
    AESTest aestest(AES_128);

    std::vector<uint8_t> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t xbg[] = { 0xa0, 0xfa, 0xfe, 0x17 };
    uint8_t xen[] = { 0xb6, 0x63, 0x0c, 0xa6 };

    aestest.keyExpansion(key);
    std::vector<uint8_t> out = aestest.keySchedule2vec();

    TEST_ASSERT_EQUAL_HEX8(xbg[0], out[16]);
    TEST_ASSERT_EQUAL_HEX8(xbg[1], out[17]);
    TEST_ASSERT_EQUAL_HEX8(xbg[2], out[18]);
    TEST_ASSERT_EQUAL_HEX8(xbg[3], out[19]);
    TEST_ASSERT_EQUAL_HEX8(xen[0], out[172]);
    TEST_ASSERT_EQUAL_HEX8(xen[1], out[173]);
    TEST_ASSERT_EQUAL_HEX8(xen[2], out[174]);
    TEST_ASSERT_EQUAL_HEX8(xen[3], out[175]); // 4 * Nb * (Nr + 1) -1
}

void test_aes192_keyExpansion_should_prepareKeySchedule(void)
{
    AESTest aestest(AES_192);

    std::vector<uint8_t> key = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                                 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t xbg[] = { 0xfe, 0x0c, 0x91, 0xf7 };
    uint8_t xen[] = { 0x01, 0x00, 0x22, 0x02 };

    aestest.keyExpansion(key);
    std::vector<uint8_t> out = aestest.keySchedule2vec();

    TEST_ASSERT_EQUAL_HEX8(xbg[0], out[24]);
    TEST_ASSERT_EQUAL_HEX8(xbg[1], out[25]);
    TEST_ASSERT_EQUAL_HEX8(xbg[2], out[26]);
    TEST_ASSERT_EQUAL_HEX8(xbg[3], out[27]);
    TEST_ASSERT_EQUAL_HEX8(xen[0], out[204]);
    TEST_ASSERT_EQUAL_HEX8(xen[1], out[205]);
    TEST_ASSERT_EQUAL_HEX8(xen[2], out[206]);
    TEST_ASSERT_EQUAL_HEX8(xen[3], out[207]); // 4 * Nb * (Nr + 1) -1
}

void test_aes256_keyExpansion_should_prepareKeySchedule(void)
{
    AESTest aestest(AES_256);

    std::vector<uint8_t> key = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t xbg[] = { 0x9b, 0xa3, 0x54, 0x11 };
    uint8_t xen[] = { 0x70, 0x6c, 0x63, 0x1e };

    aestest.keyExpansion(key);
    std::vector<uint8_t> out = aestest.keySchedule2vec();

    TEST_ASSERT_EQUAL_HEX8(xbg[0], out[32]);
    TEST_ASSERT_EQUAL_HEX8(xbg[1], out[33]);
    TEST_ASSERT_EQUAL_HEX8(xbg[2], out[34]);
    TEST_ASSERT_EQUAL_HEX8(xbg[3], out[35]);
    TEST_ASSERT_EQUAL_HEX8(xen[0], out[236]);
    TEST_ASSERT_EQUAL_HEX8(xen[1], out[237]);
    TEST_ASSERT_EQUAL_HEX8(xen[2], out[238]);
    TEST_ASSERT_EQUAL_HEX8(xen[3], out[239]); // 4 * Nb * (Nr + 1) -1
}

void test_aes_addRoundKey_should_addKeyToState(void)
{
    AESTest aestest(AES_128);

    std::vector<uint8_t> inp = { 0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92, 0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9, 0xf9, 0x1a }; // round[ 1].m_col
    uint8_t key[] = { 0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe }; // round[ 1].k_sch
    std::vector<uint8_t> exp = { 0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68, 0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12, 0x8f, 0xe4 }; // round[ 2].start
    aestest.setState(inp);
    
    aestest.addRoundKey(key);
    std::vector<uint8_t> out = aestest.state2vec();
    
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
}

void test_aes_subBytes_should_transformState(void)
{
    AESTest aestest(AES_128);

    std::vector<uint8_t> inp = { 0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68, 0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12, 0x8f, 0xe4 }; // round[ 2].start
    std::vector<uint8_t> exp = { 0xa7, 0x61, 0xca, 0x9b, 0x97, 0xbe, 0x8b, 0x45, 0xd8, 0xad, 0x1a, 0x61, 0x1f, 0xc9, 0x73, 0x69 }; // round[ 2].s_box
    aestest.setState(inp);

    aestest.subBytes();
    std::vector<uint8_t> out = aestest.state2vec();

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
}

void test_aes_invSubBytes_should_transformState(void)
{
    AESTest aestest(AES_128);

    std::vector<uint8_t> inp = { 0x54, 0x11, 0xf4, 0xb5, 0x6b, 0xd9, 0x70, 0x0e, 0x96, 0xa0, 0x90, 0x2f, 0xa1, 0xbb, 0x9a, 0xa1 }; // round[ 2].is_row
    std::vector<uint8_t> exp = { 0xfd, 0xe3, 0xba, 0xd2, 0x05, 0xe5, 0xd0, 0xd7, 0x35, 0x47, 0x96, 0x4e, 0xf1, 0xfe, 0x37, 0xf1 }; // round[ 2].is_box
    aestest.setState(inp);

    aestest.invSubBytes();
    std::vector<uint8_t> out = aestest.state2vec();

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
}

void test_aes_shiftRows_should_shiftRows(void)
{
    AESTest aestest(AES_128);
    std::vector<uint8_t> inp = { 0x3b, 0x59, 0xcb, 0x73, 0xfc, 0xd9, 0x0e, 0xe0, 0x57, 0x74, 0x22, 0x2d, 0xc0, 0x67, 0xfb, 0x68 }; // round[ 3].s_box
    std::vector<uint8_t> exp = { 0x3b, 0xd9, 0x22, 0x68, 0xfc, 0x74, 0xfb, 0x73, 0x57, 0x67, 0xcb, 0xe0, 0xc0, 0x59, 0x0e, 0x2d }; // round[ 3].s_row
    aestest.setState(inp);

    aestest.shiftRows();
    std::vector<uint8_t> out = aestest.state2vec();

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
}

void test_aes_invShiftRows_should_shiftRows(void)
{
    AESTest aestest(AES_128);
    std::vector<uint8_t> inp = { 0x3e, 0x1c, 0x22, 0xc0, 0xb6, 0xfc, 0xbf, 0x76, 0x8d, 0xa8, 0x50, 0x67, 0xf6, 0x17, 0x04, 0x95 }; // round[ 3].istart
    std::vector<uint8_t> exp = { 0x3e, 0x17, 0x50, 0x76, 0xb6, 0x1c, 0x04, 0x67, 0x8d, 0xfc, 0x22, 0x95, 0xf6, 0xa8, 0xbf, 0xc0 }; // round[ 3].is_row
    aestest.setState(inp);

    aestest.invShiftRows();
    std::vector<uint8_t> out = aestest.state2vec();

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
}

void test_aes_mixColumns_should_mixColumns(void)
{
    AESTest aestest(AES_128);

    std::vector<uint8_t> inp = { 0x2d, 0x6d, 0x7e, 0xf0, 0x3f, 0x33, 0xe3, 0x34, 0x09, 0x36, 0x02, 0xdd, 0x5b, 0xfb, 0x12, 0xc7 }; // round[ 4].s_row
    std::vector<uint8_t> exp = { 0x63, 0x85, 0xb7, 0x9f, 0xfc, 0x53, 0x8d, 0xf9, 0x97, 0xbe, 0x47, 0x8e, 0x75, 0x47, 0xd6, 0x91 }; // round[ 4].m_col
    aestest.setState(inp);

    aestest.mixColumns();
    std::vector<uint8_t> out = aestest.state2vec();

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
}

void test_aes128_cipher_should_cipherMessage(void)
{
    AES aes(AES_128);

    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; // round[ 0].input
    std::vector<uint8_t> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; // round[ 0].k_sch
    std::vector<uint8_t> exp = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }; // round[10].output
    
    std::vector<uint8_t> out = aes.cipher(inp, key);

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
}

void test_aes192_cipher_should_cipherMessage(void)
{
    AES aes(AES_192);

    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; // round[ 0].input
    std::vector<uint8_t> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    std::vector<uint8_t> exp = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }; // round[12].output
    
    std::vector<uint8_t> out = aes.cipher(inp, key);

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
}

void test_aes256_cipher_should_cipherMessage(void)
{
    AES aes(AES_256);

    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; // round[ 0].input
    std::vector<uint8_t> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    std::vector<uint8_t> exp = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }; // round[14].output
    
    std::vector<uint8_t> out = aes.cipher(inp, key);

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
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aes_state2vec_should_returnInput);
    RUN_TEST(test_aes_rotWord_should_rotateWord);
    RUN_TEST(test_aes_subWord_should_transformWord);
    RUN_TEST(test_aes128_keyExpansion_should_prepareKeySchedule);
    RUN_TEST(test_aes192_keyExpansion_should_prepareKeySchedule);
    RUN_TEST(test_aes256_keyExpansion_should_prepareKeySchedule);
    RUN_TEST(test_aes_addRoundKey_should_addKeyToState);
    RUN_TEST(test_aes_subBytes_should_transformState);
    RUN_TEST(test_aes_invSubBytes_should_transformState);
    RUN_TEST(test_aes_shiftRows_should_shiftRows);
    RUN_TEST(test_aes_invShiftRows_should_shiftRows);
    RUN_TEST(test_aes_mixColumns_should_mixColumns);
    RUN_TEST(test_aes128_cipher_should_cipherMessage);
    RUN_TEST(test_aes192_cipher_should_cipherMessage);
    RUN_TEST(test_aes256_cipher_should_cipherMessage);
    return UNITY_END();
}
