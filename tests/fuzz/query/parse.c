// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/query.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    tlv_query_t query = {0};
    if (tlv_query_parse_n((const char*)data, size, &query, NULL) == TLV_OK) {
        char   text[2 * TLV_QUERY_MAX_BYTES + TLV_QUERY_MAX_STEPS];
        size_t required;
        if (tlv_query_format(&query, text, sizeof text, &required) != TLV_OK) abort();
        tlv_query_t copy;
        if (tlv_query_parse_n(text, required - 1, &copy, NULL) != TLV_OK) abort();
        if (tlv_query_count(&copy) != tlv_query_count(&query)) abort();
        for (size_t i = 0; i < tlv_query_count(&query); ++i)
            if (!tlv_tag_equal(tlv_query_step(&query, i), tlv_query_step(&copy, i))) abort();
    }
    /* Accessors must also handle arbitrary corrupted storage safely. */
    memset(&query, 0, sizeof query);
    memcpy(&query, data, size < sizeof query ? size : sizeof query);
    for (size_t i = 0; i <= TLV_QUERY_MAX_STEPS; ++i) {
        tlv_tag_t tag = tlv_query_step(&query, i);
        if (tag.size && (!tag.data || tag.size > TLV_QUERY_MAX_BYTES)) abort();
    }
    return 0;
}
