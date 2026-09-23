#include "tlv/tag.h"
#include "tlv/builtins/emv/emv.h"

/* Compiled as C: enum constants must be valid integer constant expressions. */
int tlv_test_c_tag_switch(void) {
    const tlv_tag_t tag = TLV_TAG(0x82);
    if (!tlv_tag_equal(tag, tlv_emv_tag_aip)) return 0;
    switch (tag.data[0]) {
        case tlv_emv_tag_aip_u64: return 1;
        default: return 0;
    }
}
