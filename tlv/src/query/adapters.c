// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/adapters.h"
#include "tlv/codec/values.h"
#include "tlv/codec/number.h"
#include "../utf8_internal.h"
#include <string.h>
static int same_name(const char* text, size_t size, const char* name) {
    return name && strlen(name) == size && (!size || !memcmp(text, name, size));
}
tlv_result_t tlv_query_definition_resolve(const void* context, const char* ns, size_t ns_size,
                                          const char* name, size_t name_size, tlv_tag_t* tag) {
    if (!context || !name || !tag || (!ns && ns_size)) return TLV_ERR_NULL_ARG;
    const tlv_query_definition_resolver_t* resolver = context;
    if (resolver->count && !resolver->scopes) return TLV_ERR_NULL_ARG;
    tlv_tag_t found = {0};
    size_t matches = 0;
    for (size_t i = 0; i < resolver->count; ++i) {
        const tlv_query_definition_scope_t* scope = &resolver->scopes[i];
        if (ns_size && !same_name(ns, ns_size, scope->namespace_name)) continue;
        if (!scope->definitions || (scope->definitions->count && !scope->definitions->entries))
            return TLV_ERR_INVALID_ARG;
        for (size_t j = 0; j < scope->definitions->count; ++j) {
            const tlv_definition_t* definition = &scope->definitions->entries[j];
            if (same_name(name, name_size, definition->name)) {
                if (!definition->tag.size || !definition->tag.data) return TLV_ERR_INVALID_TAG;
                found = definition->tag;
                ++matches;
            }
        }
    }
    if (matches != 1) return matches ? TLV_ERR_INVALID_ARG : TLV_ERR_INVALID_TAG;
    *tag = found;
    return TLV_OK;
}
#if OPENTLV_CODEC
tlv_codec_result_t tlv_query_codec_decode(const void* context, const tlv_tree_event_t* event,
                                          const uint8_t* data, size_t size, void* scratch,
                                          size_t capacity, tlv_query_result_t* result) {
    (void)event;
    if (!context || !scratch || !result) return TLV_CODEC_ERR_NULL_ARG;
    const tlv_query_codec_adapter_t* adapter = context;
    if (adapter->representation > TLV_QUERY_CODEC_UTF8) return TLV_CODEC_ERR_INVALID_VALUE;
    size_t needed =
        adapter->representation == TLV_QUERY_CODEC_UTF8 ? sizeof(tlv_value_t) : sizeof(uint64_t);
    if (capacity < needed) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_codec_result_t rc = tlv_codec_decode(adapter->codec, data, size, scratch, capacity);
    if (rc != TLV_CODEC_OK) return rc;
    tlv_query_result_t out = {0};
    out.kind = TLV_QUERY_RESULT_INTEGER;
    if (adapter->representation == TLV_QUERY_CODEC_SIGNED)
        memcpy(&out.integer, scratch, sizeof out.integer);
    else if (adapter->representation == TLV_QUERY_CODEC_UNSIGNED) {
        uint64_t n;
        memcpy(&n, scratch, sizeof n);
        if (n > INT64_MAX) return TLV_CODEC_ERR_INVALID_VALUE;
        out.integer = (int64_t)n;
    } else {
        tlv_value_t span;
        memcpy(&span, scratch, sizeof span);
        if (span.size > SIZE_MAX || tlv_utf8_validate(span.data, (size_t)span.size) != TLV_OK)
            return TLV_CODEC_ERR_INVALID_VALUE;
        out.kind = TLV_QUERY_RESULT_STRING;
        out.data = span.data;
        out.size = (size_t)span.size;
    }
    *result = out;
    return TLV_CODEC_OK;
}
static const tlv_number_codec_config_t bcd_config = {TLV_NUMBER_BCD, 0, 18};
static const tlv_codec_t bcd_codec = {&bcd_config, tlv_number_decode, tlv_number_encode};
static const tlv_query_codec_adapter_t integer_adapter = {&tlv_codec_int64_minimal_be,
                                                          TLV_QUERY_CODEC_SIGNED};
static const tlv_query_codec_adapter_t bcd_adapter = {&bcd_codec, TLV_QUERY_CODEC_UNSIGNED};
static const tlv_query_codec_adapter_t text_adapter = {&tlv_codec_bytes, TLV_QUERY_CODEC_UTF8};
static const tlv_query_hook_t builtin_hooks[] = {
    {1, TLV_QUERY_NUM, sizeof(int64_t), 8, &integer_adapter, tlv_query_codec_decode},
    {2, TLV_QUERY_BCD, sizeof(uint64_t), 8, &bcd_adapter, tlv_query_codec_decode},
    {3, TLV_QUERY_TEXT, sizeof(tlv_value_t), 8, &text_adapter, tlv_query_codec_decode}};
const tlv_query_hook_t* tlv_query_builtin_hooks(size_t* count) {
    if (count) *count = 3;
    return builtin_hooks;
}

#endif
