#include "unity.h"
#include "aes.h"

void setUp(void)
{

}

void tearDown(void)
{

}

void test_FakeTest(void)
{
    TEST_ASSERT_EQUAL_HEX8(69, 69);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_FakeTest);
    return UNITY_END();
}
