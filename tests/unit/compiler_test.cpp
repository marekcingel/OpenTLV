#include "tlv/compiler.h"

#include <gtest/gtest.h>

extern "C" int tlv_test_c_compiler(void);

TEST(Unit_Tlv_Compiler, PublicCContract) {
    EXPECT_EQ(1, tlv_test_c_compiler());
}

TEST(Unit_Tlv_Compiler, VersionMacrosAreOrdered) {
    EXPECT_LT(TLV_C99, TLV_C11);
    EXPECT_LT(TLV_C11, TLV_C17);
    EXPECT_LT(TLV_C17, TLV_C23);
}

TEST(Unit_Tlv_Compiler, HasChecksRejectUnknownNames) {
    EXPECT_EQ(0, TLV_HAS_ATTRIBUTE(this_attribute_does_not_exist_1234));
    EXPECT_EQ(0, TLV_HAS_BUILTIN(this_builtin_does_not_exist_1234));
    EXPECT_EQ(0, TLV_HAS_DECLSPEC_ATTRIBUTE(this_declspec_attribute_does_not_exist_1234));
}

TEST(Unit_Tlv_Compiler, HasC17ImpliesHasC11AndHasC23ImpliesHasC17) {
    EXPECT_TRUE(!TLV_HAS_C17 || TLV_HAS_C11);
    EXPECT_TRUE(!TLV_HAS_C23 || TLV_HAS_C17);
}
