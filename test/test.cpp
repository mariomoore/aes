#include "unity.h"
#include "aes.h"

void setUp(void)
{

}

void tearDown(void)
{

}

void test_cipherReturnsCurrentState(void)
{
    AES aes(AES_128);
    std::vector<uint8_t> inp = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    std::vector<uint8_t> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    std::vector<uint8_t> out = aes.cipher(inp, key);
    
    std::vector<uint8_t> exp = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 };
    
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
    RUN_TEST(test_cipherReturnsCurrentState);
    return UNITY_END();
}
