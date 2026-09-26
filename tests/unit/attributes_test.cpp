#include "tlv/attributes.h"

#include <gtest/gtest.h>

extern "C" int tlv_test_c_attributes(void);

TEST(Unit_Tlv_Attributes, PublicCContract) {
    EXPECT_EQ(1, tlv_test_c_attributes());
}

namespace {
TLV_NODISCARD int nodiscard_answer() {
    return 42;
}
} // namespace

TEST(Unit_Tlv_Attributes, NodiscardDeclarationCompilesAndReturnsUnchanged) {
    EXPECT_EQ(42, nodiscard_answer());
}
