#ifndef OPENTLV_TEST_FRAMEWORK_H
#define OPENTLV_TEST_FRAMEWORK_H

#include <stdio.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define TLV_TEST(name) static void name(void)

#define RUN_TEST(name) do { \
    g_tests_run++; \
    printf("  RUN  %s\n", #name); \
    name(); \
    printf("  OK   %s\n", #name); \
} while (0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        g_tests_failed++; \
        fprintf(stderr, "    ASSERT_TRUE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        return; \
    } \
} while (0)

#define ASSERT_EQ(expected, actual) do { \
    long long _e = (long long)(expected); \
    long long _a = (long long)(actual); \
    if (_e != _a) { \
        g_tests_failed++; \
        fprintf(stderr, "    ASSERT_EQ failed: expected %lld, got %lld (%s:%d)\n", \
                _e, _a, __FILE__, __LINE__); \
        return; \
    } \
} while (0)

#define ASSERT_MEM_EQ(expected, actual, len) do { \
    if (memcmp((expected), (actual), (len)) != 0) { \
        g_tests_failed++; \
        fprintf(stderr, "    ASSERT_MEM_EQ failed (%s:%d)\n", __FILE__, __LINE__); \
        return; \
    } \
} while (0)

#define TEST_SUMMARY() \
    (printf("\n%d test(s), %d failed\n", g_tests_run, g_tests_failed), \
     g_tests_failed == 0 ? 0 : 1)

#endif /* OPENTLV_TEST_FRAMEWORK_H */
