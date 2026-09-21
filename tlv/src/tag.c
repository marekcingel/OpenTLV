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
