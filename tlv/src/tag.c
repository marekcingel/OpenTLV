#include "tlv/tag.h"
#include <string.h>

bool tlv_tag_equal(tlv_tag_t lhs, tlv_tag_t rhs) {
    if (lhs.size != rhs.size) return false;
    if (lhs.size == 0) return true;
    return memcmp(lhs.data, rhs.data, lhs.size) == 0;
}

int tlv_tag_compare(tlv_tag_t lhs, tlv_tag_t rhs) {
    size_t common;
    int order;
    common = lhs.size < rhs.size ? lhs.size : rhs.size;
    order = common == 0 ? 0 : memcmp(lhs.data, rhs.data, common);
    if (order != 0) return order < 0 ? -1 : 1;
    if (lhs.size == rhs.size) return 0;
    return lhs.size < rhs.size ? -1 : 1;
}

bool tlv_tag_is_empty(tlv_tag_t tag) {
    return tag.size == 0;
}

size_t tlv_tag_hash(tlv_tag_t tag) {
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t i;
    for (i = 0; i < tag.size; ++i) {
        hash ^= tag.data[i];
        hash *= UINT64_C(1099511628211);
    }
    return (size_t)hash;
}

tlv_result_t tlv_tag_copy(tlv_tag_t tag, uint8_t* data, size_t capacity, size_t* written) {
    if (!written) return TLV_ERR_NULL_ARG;
    if (!data && capacity) return TLV_ERR_NULL_ARG;
    if (!tag.data && tag.size) return TLV_ERR_NULL_ARG;
    if (!data) {
        *written = tag.size;
        return TLV_OK;
    }
    if (capacity < tag.size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (tag.size) memmove(data, tag.data, tag.size);
    *written = tag.size;
    return TLV_OK;
}
