#include "tlv/endian.h"

/* Standalone public header and exact function types compiled as C. */
int tlv_test_c_endian(void) {
    tlv_result_t (*read_uint)(const uint8_t*, size_t, tlv_byte_order_t, uint64_t*) = tlv_read_uint;
    tlv_result_t (*write_uint)(uint8_t*, size_t, tlv_byte_order_t, uint64_t) = tlv_write_uint;
    uint8_t  bytes[3] = {0};
    uint64_t value = 0;
    return write_uint(bytes, 3, TLV_BYTE_ORDER_BIG_ENDIAN, 0x123456) == TLV_OK &&
           bytes[0] == 0x12 && bytes[1] == 0x34 && bytes[2] == 0x56 &&
           read_uint(bytes, 3, TLV_BYTE_ORDER_LITTLE_ENDIAN, &value) == TLV_OK && value == 0x563412;
}
