#include "tlv/tag.h"
#include "tlv/profiles/emv.h"

/* Compiled as C: enum constants must be valid integer constant expressions. */
int tlv_test_c_tag_switch(void) {
    const tlv_tag_t tag = {{0x82}, 1};
    uint64_t value = 0;
    int equal = 0;
    tlv_tag_t constructed;
    if (tlv_tag_from_u8(0x82, 1, TLV_BYTE_ORDER_BIG_ENDIAN, &constructed) != TLV_OK ||
        tlv_tag_equal(&tag, &constructed, &equal) != TLV_OK || !equal) return 0;
    if (tlv_tag_to_u64(&tag, TLV_BYTE_ORDER_BIG_ENDIAN, &value) != TLV_OK) return 0;
    switch (value) {
    case tlv_emv_tag_aip_u64: return tlv_tag_equal_u64(&tag, value, TLV_BYTE_ORDER_BIG_ENDIAN, &equal) == TLV_OK && equal;
    default: return 0;
    }
}
