// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/query.h"
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!size) return 0;
    size_t text_size = data[0];
    if (text_size > size - 1) text_size = size - 1;
    tlv_query_t query;
    if (tlv_query_parse_n((const char*)data + 1, text_size, &query, NULL) != TLV_OK) return 0;
    tlv_query_matcher_t matcher;
    if (tlv_query_matcher_init(&matcher, &query) != TLV_OK) return 0;
    for (size_t i = text_size + 1; i + 1 < size; i += 2) {
        tlv_tag_t tag = tlv_tag(data + i, 1);
        (void)tlv_query_matcher_visit(&matcher, &tag, data[i + 1]);
    }
    return 0;
}
