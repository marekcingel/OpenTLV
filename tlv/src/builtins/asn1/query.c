// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/builtins/asn1/query.h"
#include "tlv/builtins/asn1/identifier.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/builtins/asn1/asn1_codec.h"
#include <string.h>
static tlv_result_t tag_class(const void* context, const tlv_tag_t* tag, int64_t* result) {
    (void)context;
    if (!tag || !result) return TLV_ERR_NULL_ARG;
    uint64_t number;
    tlv_result_t rc = tlv_ber_tag_number(tag, &number);
    if (rc != TLV_OK) return rc;
    *result = tlv_asn1_tag_class(tag);
    return TLV_OK;
}
static tlv_result_t tag_number(const void* context, const tlv_tag_t* tag, int64_t* result) {
    (void)context;
    if (!tag || !result) return TLV_ERR_NULL_ARG;
    uint64_t number;
    tlv_result_t rc = tlv_ber_tag_number(tag, &number);
    if (rc != TLV_OK) return rc;
    if (number > INT64_MAX) return TLV_ERR_OVERFLOW;
    *result = (int64_t)number;
    return TLV_OK;
}
const tlv_query_tag_adapter_t tlv_asn1_query_tags = {1, NULL, tag_class, tag_number};
static tlv_codec_result_t date_decode(const void* context, const tlv_tree_event_t* event,
                                      const uint8_t* data, size_t size, void* scratch,
                                      size_t capacity, tlv_query_result_t* result) {
    (void)context;
    (void)event;
    if (!scratch || !result) return TLV_CODEC_ERR_NULL_ARG;
    tlv_codec_result_t rc =
        tlv_codec_decode(&tlv_asn1_codec_generalized_time, data, size, scratch, capacity);
    if (rc != TLV_CODEC_OK) return rc;
    tlv_asn1_generalized_time_t t;
    memcpy(&t, scratch, sizeof t);
    if (t.fraction_digits_length) return TLV_CODEC_ERR_INVALID_VALUE;
    static const unsigned days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int leap = t.year % 4 == 0 && (t.year % 100 != 0 || t.year % 400 == 0);
    if (!t.month || t.month > 12 || !t.day ||
        t.day > days[t.month - 1] + (unsigned)(t.month == 2 && leap))
        return TLV_CODEC_ERR_INVALID_VALUE;
    /* Count whole Gregorian days from year zero, then shift to 1970-01-01. */
    int64_t year = t.year,
            total = 365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400;
    for (unsigned month = 1; month < t.month; ++month)
        total += days[month - 1] + (unsigned)(month == 2 && leap);
    total += t.day - 1;
    const int64_t epoch =
        365 * INT64_C(1970) + (1970 + 3) / 4 - (1970 + 99) / 100 + (1970 + 399) / 400;
    tlv_query_result_t out = {0};
    out.kind = TLV_QUERY_RESULT_INTEGER;
    out.integer = (total - epoch) * 86400 + t.hour * 3600 + t.minute * 60 + t.second;
    *result = out;
    return TLV_CODEC_OK;
}
const tlv_query_hook_t tlv_asn1_query_date = {
    4, TLV_QUERY_DATE, sizeof(tlv_asn1_generalized_time_t), 8, NULL, date_decode};
