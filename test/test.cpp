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

void test_aes_addRoundKey_should_addKeyToState(void)
{
    AESTest aestest(AES_128);
// TEST 1
    std::vector<uint8_t> inp1 = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; // round[ 0].input
    std::vector<uint8_t> key1 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; // round[ 0].k_sch
    std::vector<uint8_t> exp1 = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 }; // round[ 1].start
    aestest.setState(inp1);
    
    aestest.addRoundKey(key1);
    std::vector<uint8_t> out = aestest.state2vec();
    
    TEST_ASSERT_EQUAL_HEX8(exp1[0], out[0]);
    TEST_ASSERT_EQUAL_HEX8(exp1[1], out[1]);
    TEST_ASSERT_EQUAL_HEX8(exp1[2], out[2]);
    TEST_ASSERT_EQUAL_HEX8(exp1[3], out[3]);
    TEST_ASSERT_EQUAL_HEX8(exp1[4], out[4]);
    TEST_ASSERT_EQUAL_HEX8(exp1[5], out[5]);
    TEST_ASSERT_EQUAL_HEX8(exp1[6], out[6]);
    TEST_ASSERT_EQUAL_HEX8(exp1[7], out[7]);
    TEST_ASSERT_EQUAL_HEX8(exp1[8], out[8]);
    TEST_ASSERT_EQUAL_HEX8(exp1[9], out[9]);
    TEST_ASSERT_EQUAL_HEX8(exp1[10], out[10]);
    TEST_ASSERT_EQUAL_HEX8(exp1[11], out[11]);
    TEST_ASSERT_EQUAL_HEX8(exp1[12], out[12]);
    TEST_ASSERT_EQUAL_HEX8(exp1[13], out[13]);
    TEST_ASSERT_EQUAL_HEX8(exp1[14], out[14]);
    TEST_ASSERT_EQUAL_HEX8(exp1[15], out[15]);

// TEST 2
    std::vector<uint8_t> inp2 = { 0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92, 0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9, 0xf9, 0x1a }; // round[ 1].m_col
    std::vector<uint8_t> key2 = { 0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe }; // round[ 1].k_sch
    std::vector<uint8_t> exp2 = { 0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68, 0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12, 0x8f, 0xe4 }; // round[ 2].start
    aestest.setState(inp2);
    
    aestest.addRoundKey(key2);
    out = aestest.state2vec();
    
    TEST_ASSERT_EQUAL_HEX8(exp2[0], out[0]);
    TEST_ASSERT_EQUAL_HEX8(exp2[1], out[1]);
    TEST_ASSERT_EQUAL_HEX8(exp2[2], out[2]);
    TEST_ASSERT_EQUAL_HEX8(exp2[3], out[3]);
    TEST_ASSERT_EQUAL_HEX8(exp2[4], out[4]);
    TEST_ASSERT_EQUAL_HEX8(exp2[5], out[5]);
    TEST_ASSERT_EQUAL_HEX8(exp2[6], out[6]);
    TEST_ASSERT_EQUAL_HEX8(exp2[7], out[7]);
    TEST_ASSERT_EQUAL_HEX8(exp2[8], out[8]);
    TEST_ASSERT_EQUAL_HEX8(exp2[9], out[9]);
    TEST_ASSERT_EQUAL_HEX8(exp2[10], out[10]);
    TEST_ASSERT_EQUAL_HEX8(exp2[11], out[11]);
    TEST_ASSERT_EQUAL_HEX8(exp2[12], out[12]);
    TEST_ASSERT_EQUAL_HEX8(exp2[13], out[13]);
    TEST_ASSERT_EQUAL_HEX8(exp2[14], out[14]);
    TEST_ASSERT_EQUAL_HEX8(exp2[15], out[15]);
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

void test_aes_cipher_should_cipherMessage(void)
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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aes_state2vec_should_returnInput);
    RUN_TEST(test_aes_addRoundKey_should_addKeyToState);
    RUN_TEST(test_aes_subBytes_should_transformState);
    RUN_TEST(test_aes_cipher_should_cipherMessage);
    return UNITY_END();
}
