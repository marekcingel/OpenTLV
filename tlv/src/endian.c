#include "tlv/endian.h"

tlv_byte_order_t tlv_endian_native(void) {
    const uint32_t value = UINT32_C(0x01020304);
    const unsigned char* bytes = (const unsigned char*)&value;
    if (bytes[0] == 1 && bytes[1] == 2 && bytes[2] == 3 && bytes[3] == 4)
        return TLV_BYTE_ORDER_BIG_ENDIAN;
    if (bytes[0] == 4 && bytes[1] == 3 && bytes[2] == 2 && bytes[3] == 1)
        return TLV_BYTE_ORDER_LITTLE_ENDIAN;
    return TLV_BYTE_ORDER_UNKNOWN;
}

uint16_t tlv_read_u16_be(const uint8_t* data) {
    return (uint16_t)(((uint32_t)data[0] << 8) | ((uint32_t)data[1] << 0));
}

uint16_t tlv_read_u16_le(const uint8_t* data) {
    return (uint16_t)(((uint32_t)data[0] << 0) | ((uint32_t)data[1] << 8));
}

uint32_t tlv_read_u32_be(const uint8_t* data) {
    return (uint32_t)(((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                      ((uint32_t)data[2] << 8) | ((uint32_t)data[3] << 0));
}

uint32_t tlv_read_u32_le(const uint8_t* data) {
    return (uint32_t)(((uint32_t)data[0] << 0) | ((uint32_t)data[1] << 8) |
                      ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));
}

void tlv_write_u16_be(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value >> 0);
}

void tlv_write_u16_le(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 0);
    data[1] = (uint8_t)(value >> 8);
}

void tlv_write_u32_be(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)(value >> 0);
}

void tlv_write_u32_le(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value >> 0);
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

tlv_result_t tlv_read_uint(const uint8_t* data, size_t width, tlv_byte_order_t order,
                           uint64_t* value) {
    uint64_t result = 0;
    size_t i;
    if (!data || !value) return TLV_ERR_NULL_ARG;
    if (!width || width > sizeof(uint64_t)) return TLV_ERR_INVALID_LENGTH;
    if (order != TLV_BYTE_ORDER_BIG_ENDIAN && order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    for (i = 0; i < width; ++i) {
        size_t index = order == TLV_BYTE_ORDER_BIG_ENDIAN ? i : width - 1 - i;
        result = (result << 8) | data[index];
    }
    *value = result;
    return TLV_OK;
}

tlv_result_t tlv_write_uint(uint8_t* data, size_t width, tlv_byte_order_t order, uint64_t value) {
    size_t i;
    if (!data) return TLV_ERR_NULL_ARG;
    if (!width || width > sizeof(uint64_t)) return TLV_ERR_INVALID_LENGTH;
    if (order != TLV_BYTE_ORDER_BIG_ENDIAN && order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    if (width < sizeof(uint64_t) && (value >> (width * 8)) != 0) return TLV_ERR_OVERFLOW;
    for (i = 0; i < width; ++i) {
        size_t index = order == TLV_BYTE_ORDER_LITTLE_ENDIAN ? i : width - 1 - i;
        data[index] = (uint8_t)value;
        value >>= 8;
    }
    return TLV_OK;
}

uint64_t tlv_read_u64_be(const uint8_t* data) {
    uint64_t value = 0;
    tlv_read_uint(data, sizeof(uint64_t), TLV_BYTE_ORDER_BIG_ENDIAN, &value);
    return value;
}
uint64_t tlv_read_u64_le(const uint8_t* data) {
    uint64_t value = 0;
    tlv_read_uint(data, sizeof(uint64_t), TLV_BYTE_ORDER_LITTLE_ENDIAN, &value);
    return value;
}
void tlv_write_u64_be(uint8_t* data, uint64_t value) {
    tlv_write_uint(data, sizeof(uint64_t), TLV_BYTE_ORDER_BIG_ENDIAN, value);
}
void tlv_write_u64_le(uint8_t* data, uint64_t value) {
    tlv_write_uint(data, sizeof(uint64_t), TLV_BYTE_ORDER_LITTLE_ENDIAN, value);
}
