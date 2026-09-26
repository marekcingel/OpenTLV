#include "tlv/attributes.h"

TLV_NODISCARD static int nodiscard_answer(void) {
    return 42;
}

TLV_DEPRECATED_MSG("use nodiscard_answer instead")
TLV_MAYBE_UNUSED static int deprecated_answer(void) {
    return 42;
}

static int fallthrough_sum(int selector) {
    int sum = 0;
    switch (selector) {
        case 0: sum += 1; TLV_FALLTHROUGH;
        case 1: sum += 2; break;
        default: sum += 100; break;
    }
    return sum;
}

/* Standalone public header compiled as C; attributes stay additive under the C99 baseline. */
int tlv_test_c_attributes(void) {
    TLV_MAYBE_UNUSED int unused_value = 7;
    return nodiscard_answer() == 42 && fallthrough_sum(0) == 3 && fallthrough_sum(1) == 2 &&
           fallthrough_sum(2) == 100;
}
