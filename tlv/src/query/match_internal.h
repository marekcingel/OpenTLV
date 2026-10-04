// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_MATCH_INTERNAL_H
#define OPENTLV_QUERY_MATCH_INTERNAL_H
#include "tlv/tag.h"

/* V1 uses decoded exact bytes; programs use copied hexadecimal spelling. */
static inline int query_hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static inline int query_tag_test(tlv_tag_t tag, const uint8_t* pattern, size_t size, int encoded) {
    if (encoded && size == 1 && pattern[0] == '*') return 1;
    size_t width = encoded ? size / 2 : size;
    if ((encoded && size % 2) || width != tag.size || (tag.size && !tag.data)) return 0;
    for (size_t i = 0; i < width; ++i) {
        unsigned byte = pattern[i];
        if (encoded) {
            const uint8_t* pair = pattern + 2 * i;
            if (pair[0] == '?' && pair[1] == '?') continue;
            int high = query_hex(pair[0]), low = query_hex(pair[1]);
            if (high < 0 || low < 0) return 0;
            byte = (unsigned)(high * 16 + low);
        }
        if (tag.data[i] != byte) return 0;
    }
    return 1;
}
#endif
