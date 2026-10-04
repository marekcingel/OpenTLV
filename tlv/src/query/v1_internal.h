// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_V1_INTERNAL_H
#define OPENTLV_QUERY_V1_INTERNAL_H
#include "tlv/query/query.h"
#include <string.h>
typedef struct query_v1_data {
    uint8_t bytes[TLV_QUERY_MAX_BYTES];
    uint16_t ends[TLV_QUERY_MAX_STEPS];
    uint16_t count;
} query_v1_data_t;
typedef struct query_v1_matcher {
    const tlv_query_t* query;
    size_t matched;
} query_v1_matcher_t;
/* C99-compatible compile-time storage invariants; keep public ABI sizes fixed. */
typedef char query_v1_storage_fits[(sizeof(query_v1_data_t) <= sizeof(tlv_query_t)) ? 1 : -1];
typedef char
    query_v1_matcher_fits[(sizeof(query_v1_matcher_t) <= sizeof(tlv_query_matcher_t)) ? 1 : -1];
static inline query_v1_data_t query_v1_load(const tlv_query_t* query) {
    query_v1_data_t data;
    memcpy(&data, query, sizeof data);
    return data;
}
static inline query_v1_matcher_t query_v1_matcher_load(const tlv_query_matcher_t* matcher) {
    query_v1_matcher_t data;
    memcpy(&data, matcher, sizeof data);
    return data;
}
#endif
