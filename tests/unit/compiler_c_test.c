#include "tlv/compiler.h"

#if TLV_C_VERSION < TLV_C99
#error "TLV_C_VERSION must be at least TLV_C99"
#endif
#if TLV_HAS_C17 && !TLV_HAS_C11
#error "TLV_HAS_C17 must imply TLV_HAS_C11"
#endif
#if TLV_HAS_C23 && !TLV_HAS_C17
#error "TLV_HAS_C23 must imply TLV_HAS_C17"
#endif
#if TLV_HAS_ATTRIBUTE(this_attribute_does_not_exist_1234)
#error "TLV_HAS_ATTRIBUTE must reject an unknown attribute"
#endif
#if TLV_HAS_BUILTIN(this_builtin_does_not_exist_1234)
#error "TLV_HAS_BUILTIN must reject an unknown builtin"
#endif
#if TLV_HAS_DECLSPEC_ATTRIBUTE(this_declspec_attribute_does_not_exist_1234)
#error "TLV_HAS_DECLSPEC_ATTRIBUTE must reject an unknown attribute"
#endif

/* Standalone public header and its capability macros compiled as C. */
int tlv_test_c_compiler(void) {
    return TLV_C_VERSION >= TLV_C99 && (!TLV_HAS_C17 || TLV_HAS_C11) &&
           (!TLV_HAS_C23 || TLV_HAS_C17) &&
           TLV_HAS_ATTRIBUTE(this_attribute_does_not_exist_1234) == 0 &&
           TLV_HAS_BUILTIN(this_builtin_does_not_exist_1234) == 0 &&
           TLV_HAS_DECLSPEC_ATTRIBUTE(this_declspec_attribute_does_not_exist_1234) == 0;
}
