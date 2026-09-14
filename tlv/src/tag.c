#include "tlv/tag.h"
#include <stddef.h>
#include <string.h>

int tlv_tag_equal(const tlv_tag_t* a, const tlv_tag_t* b) {
    if (b == NULL) return 0;
    return tlv_tag_equal_bytes(a, b->data, b->size);
}

int tlv_tag_equal_bytes(const tlv_tag_t* tag, const uint8_t* data, size_t size) {
    if (tag == NULL || (data == NULL && size != 0)) return 0;
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    if (tag->size > TLV_TAG_CAPACITY) return 0;
#endif
    if (size > TLV_TAG_CAPACITY) return 0;
    return tag->size == size && (size == 0 || memcmp(tag->data, data, size) == 0);
}

int tlv_tag_equal_u8(const tlv_tag_t* tag, uint8_t value, tlv_byte_order_t order) {
    return tlv_tag_equal_u64(tag, value, order);
}

int tlv_tag_equal_u16(const tlv_tag_t* tag, uint16_t value, tlv_byte_order_t order) {
    return tlv_tag_equal_u64(tag, value, order);
}

int tlv_tag_equal_u32(const tlv_tag_t* tag, uint32_t value, tlv_byte_order_t order) {
    return tlv_tag_equal_u64(tag, value, order);
}

int tlv_tag_equal_u64(const tlv_tag_t* tag, uint64_t value, tlv_byte_order_t order) {
    uint64_t number;
    return tlv_tag_to_u64(tag, order, &number) == TLV_OK && number == value;
}

tlv_result_t tlv_tag_to_u8(const tlv_tag_t* tag, tlv_byte_order_t order, uint8_t* value) {
    uint64_t number;
    tlv_result_t result;
    if (value == NULL) return TLV_ERR_NULL_ARG;
    result = tlv_tag_to_u64(tag, order, &number);
    if (result != TLV_OK) return result;
    if (number > UINT8_MAX) return TLV_ERR_INVALID_TAG;
    *value = (uint8_t)number;
    return TLV_OK;
}

tlv_result_t tlv_tag_to_u16(const tlv_tag_t* tag, tlv_byte_order_t order, uint16_t* value) {
    uint64_t number;
    tlv_result_t result;
    if (value == NULL) return TLV_ERR_NULL_ARG;
    result = tlv_tag_to_u64(tag, order, &number);
    if (result != TLV_OK) return result;
    if (number > UINT16_MAX) return TLV_ERR_INVALID_TAG;
    *value = (uint16_t)number;
    return TLV_OK;
}

tlv_result_t tlv_tag_to_u32(const tlv_tag_t* tag, tlv_byte_order_t order, uint32_t* value) {
    uint64_t number;
    tlv_result_t result;
    if (value == NULL) return TLV_ERR_NULL_ARG;
    result = tlv_tag_to_u64(tag, order, &number);
    if (result != TLV_OK) return result;
    if (number > UINT32_MAX) return TLV_ERR_INVALID_TAG;
    *value = (uint32_t)number;
    return TLV_OK;
}

tlv_result_t tlv_tag_to_u64(const tlv_tag_t* tag, tlv_byte_order_t order, uint64_t* value) {
    uint64_t result = 0;
    size_t i;
    if (tag == NULL || value == NULL) return TLV_ERR_NULL_ARG;
#if TLV_TAG_CAPACITY < TLV_TAG_MAX_SUPPORTED_SIZE
    if (tag->size > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_TAG_SIZE;
#endif
    if (tag->size == 0 || tag->size > 8) return TLV_ERR_INVALID_TAG_SIZE;
    if (order != TLV_BYTE_ORDER_BIG_ENDIAN && order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_ARG;
    for (i = 0; i < tag->size; ++i) {
        size_t index = order == TLV_BYTE_ORDER_BIG_ENDIAN ? i : tag->size - 1u - i;
        result = (result << 8) | tag->data[index];
    }
    *value = result;
    return TLV_OK;
}

tlv_result_t tlv_tag_from_bytes(const uint8_t* data, size_t size, tlv_tag_t* tag) {
    if (tag == NULL || (data == NULL && size != 0)) return TLV_ERR_NULL_ARG;
    if (size > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_TAG_SIZE;
    if (size != 0) memmove(tag->data, data, size);
    memset(tag->data + size, 0, TLV_TAG_CAPACITY - size);
    tag->size = (uint8_t)size;
    return TLV_OK;
}

tlv_result_t tlv_tag_from_u8(uint8_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag) {
    return tlv_tag_from_u64(value, size, order, tag);
}

tlv_result_t tlv_tag_from_u16(uint16_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag) {
    return tlv_tag_from_u64(value, size, order, tag);
}

tlv_result_t tlv_tag_from_u32(uint32_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag) {
    return tlv_tag_from_u64(value, size, order, tag);
}

tlv_result_t tlv_tag_from_u64(uint64_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag) {
    size_t i;
    if (tag == NULL) return TLV_ERR_NULL_ARG;
    if (size == 0 || size > 8 || size > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_TAG_SIZE;
    if (order != TLV_BYTE_ORDER_BIG_ENDIAN && order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_ARG;
    if (size < 8 && (value >> (size * 8)) != 0) return TLV_ERR_INVALID_TAG;
    for (i = 0; i < size; ++i) {
        size_t index = order == TLV_BYTE_ORDER_LITTLE_ENDIAN ? i : size - 1 - i;
        tag->data[index] = (uint8_t)value;
        value >>= 8;
    }
    memset(tag->data + size, 0, TLV_TAG_CAPACITY - size);
    tag->size = (uint8_t)size;
    return TLV_OK;
}
