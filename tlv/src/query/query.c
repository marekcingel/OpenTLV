// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/query/query.h"
#include "v1_internal.h"
#include "match_internal.h"

static int hex_digit(char c) {
    return query_hex((unsigned char)c);
}

static void set_offset(size_t* out, size_t offset) {
    if (out) *out = offset;
}

tlv_result_t tlv_query_parse_n(const char* text, size_t size, tlv_query_t* query,
                               size_t* error_offset) {
    query_v1_data_t parsed;
    size_t pos = 0, used = 0;
    if (!text || !query) return TLV_ERR_NULL_ARG;
    memset(&parsed, 0, sizeof parsed);
    for (;;) {
        size_t start = pos, digits;
        while (pos < size && text[pos] != '/') {
            if (hex_digit(text[pos]) < 0) {
                set_offset(error_offset, pos);
                return TLV_ERR_INVALID_ARG;
            }
            ++pos;
        }
        digits = pos - start;
        if (!digits || digits % 2) {
            set_offset(error_offset, digits ? start : pos);
            return TLV_ERR_INVALID_ARG;
        }
        if (parsed.count == TLV_QUERY_MAX_STEPS) {
            set_offset(error_offset, start);
            return TLV_ERR_LIMIT;
        }
        if (digits / 2 > TLV_QUERY_MAX_BYTES - used) {
            set_offset(error_offset, start);
            return TLV_ERR_LIMIT;
        }
        for (size_t i = 0; i < digits / 2; ++i)
            parsed.bytes[used + i] =
                (uint8_t)(hex_digit(text[start + 2 * i]) << 4 | hex_digit(text[start + 2 * i + 1]));
        used += digits / 2;
        parsed.ends[parsed.count++] = (uint16_t)used;
        if (pos == size) break;
        ++pos; /* The separator; another tag must follow. */
    }
    memset(query, 0, sizeof *query);
    memcpy(query, &parsed, sizeof parsed);
    return TLV_OK;
}

tlv_result_t tlv_query_parse(const char* text, tlv_query_t* query, size_t* error_offset) {
    if (!text || !query) return TLV_ERR_NULL_ARG;
    return tlv_query_parse_n(text, strlen(text), query, error_offset);
}

static int valid_query(const query_v1_data_t* data) {
    size_t begin = 0;
    if (!data->count || data->count > TLV_QUERY_MAX_STEPS) return 0;
    for (size_t i = 0; i < data->count; ++i) {
        if (data->ends[i] <= begin || data->ends[i] > TLV_QUERY_MAX_BYTES) return 0;
        begin = data->ends[i];
    }
    return 1;
}

size_t tlv_query_count(const tlv_query_t* query) {
    if (!query) return 0;
    query_v1_data_t data = query_v1_load(query);
    return valid_query(&data) ? data.count : 0;
}

tlv_tag_t tlv_query_step(const tlv_query_t* query, size_t index) {
    if (!query) return tlv_tag(NULL, 0);
    query_v1_data_t data = query_v1_load(query);
    if (!valid_query(&data) || index >= data.count) return tlv_tag(NULL, 0);
    size_t begin = index ? data.ends[index - 1] : 0;
    return tlv_tag(query->opaque + begin, data.ends[index] - begin);
}

tlv_result_t tlv_query_format(const tlv_query_t* query, char* output, size_t capacity,
                              size_t* required) {
    static const char hex[] = "0123456789ABCDEF";
    if (!query || !required) return TLV_ERR_NULL_ARG;
    if (!output && capacity) return TLV_ERR_NULL_ARG;
    query_v1_data_t data = query_v1_load(query);
    if (!valid_query(&data)) return TLV_ERR_INVALID_ARG;
    size_t length = 2 * data.ends[data.count - 1] + data.count - 1;
    *required = length + 1;
    if (!output) return TLV_OK;
    if (capacity <= length) return TLV_ERR_BUFFER_TOO_SHORT;
    /* Stage output so overlapping Query/output cannot corrupt bytes being read. */
    size_t pos = 0, begin = 0;
    for (size_t step = 0; step < data.count; ++step) {
        if (step) output[pos++] = '/';
        for (size_t i = begin; i < data.ends[step]; ++i) {
            output[pos++] = hex[data.bytes[i] >> 4];
            output[pos++] = hex[data.bytes[i] & 15];
        }
        begin = data.ends[step];
    }
    output[pos] = 0;
    return TLV_OK;
}

tlv_result_t tlv_query_matcher_init(tlv_query_matcher_t* matcher, const tlv_query_t* query) {
    if (!matcher || !query) return TLV_ERR_NULL_ARG;
    query_v1_data_t data = query_v1_load(query);
    if (!data.count || data.count > TLV_QUERY_MAX_STEPS) return TLV_ERR_INVALID_ARG;
    if (!valid_query(&data)) return TLV_ERR_INVALID_TAG_SIZE;
    query_v1_matcher_t state = {query, 0};
    memset(matcher, 0, sizeof *matcher);
    memcpy(matcher, &state, sizeof state);
    return TLV_OK;
}

tlv_result_t tlv_query_matcher_rebind(tlv_query_matcher_t* matcher, const tlv_query_t* query) {
    if (!matcher || !query) return TLV_ERR_NULL_ARG;
    query_v1_matcher_t state = query_v1_matcher_load(matcher);
    if (!state.query) return TLV_ERR_INVALID_ARG;
    query_v1_data_t old = query_v1_load(state.query), replacement = query_v1_load(query);
    if (!valid_query(&old) || !valid_query(&replacement) || old.count != replacement.count ||
        memcmp(old.ends, replacement.ends, old.count * sizeof old.ends[0]) ||
        memcmp(old.bytes, replacement.bytes, old.ends[old.count - 1]))
        return TLV_ERR_INVALID_ARG;
    state.query = query;
    memcpy(matcher, &state, sizeof state);
    return TLV_OK;
}

int tlv_query_matcher_visit(tlv_query_matcher_t* matcher, const tlv_tag_t* tag, size_t depth) {
    if (!matcher || !tag || (tag->size && !tag->data)) return 0;
    query_v1_matcher_t state = query_v1_matcher_load(matcher);
    if (!state.query) return 0;
    const uint8_t* storage = (const uint8_t*)state.query;
    uint16_t count;
    memcpy(&count, storage + offsetof(query_v1_data_t, count), sizeof count);
    if (!count || count > TLV_QUERY_MAX_STEPS || state.matched > count || depth > state.matched)
        return 0;
    state.matched = depth;
    int match = 0;
    if (depth < count) {
        uint16_t begin = 0, end;
        const uint8_t* ends = storage + offsetof(query_v1_data_t, ends);
        if (depth) memcpy(&begin, ends + (depth - 1) * sizeof begin, sizeof begin);
        memcpy(&end, ends + depth * sizeof end, sizeof end);
        if (begin >= end || end > TLV_QUERY_MAX_BYTES) return 0;
        if (query_tag_test(*tag, storage + begin, end - begin, 0)) {
            state.matched = depth + 1;
            match = state.matched == count;
        }
    }
    memcpy(matcher, &state, sizeof state);
    return match;
}

typedef struct query_visitor {
    tlv_query_matcher_t* matcher;
    tlv_tree_visitor_t visitor;
    void* context;
} query_visitor_t;

static tlv_visit_result_t on_element(const tlv_element_t* element, size_t depth, size_t offset,
                                     void* context) {
    query_visitor_t* state = (query_visitor_t*)context;
    if (!tlv_query_matcher_visit(state->matcher, &element->tag, depth)) return TLV_VISIT_CONTINUE;
    return state->visitor(element, depth, offset, state->context);
}

tlv_result_t tlv_query_visit(tlv_tree_reader_t* reader, tlv_query_matcher_t* matcher,
                             tlv_tree_visitor_t visitor, void* context, size_t* error_offset) {
    query_visitor_t state;
    if (!reader || !matcher || !visitor) return TLV_ERR_NULL_ARG;
    if (!query_v1_matcher_load(matcher).query) return TLV_ERR_NULL_ARG;
    state.matcher = matcher;
    state.visitor = visitor;
    state.context = context;
    return tlv_tree_reader_visit(reader, on_element, &state, error_offset);
}

tlv_result_t tlv_query_visit_buffer(const uint8_t* data, size_t size, const tlv_format_t* format,
                                    const tlv_query_t* query, size_t max_depth, size_t max_elements,
                                    tlv_tree_visitor_t visitor, void* context,
                                    size_t* error_offset) {
    tlv_query_matcher_t matcher;
    tlv_result_t rc;
    if (!visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_query_matcher_init(&matcher, query);
    if (rc != TLV_OK) return rc;
    tlv_tree_frame_t frames[TLV_QUERY_MAX_STEPS];
    tlv_tree_reader_t reader;
    rc = tlv_tree_reader_init(&reader, data, size, format, frames, TLV_QUERY_MAX_STEPS, max_depth,
                              max_elements);
    if (rc != TLV_OK) {
        if (error_offset) *error_offset = 0;
        return rc;
    }
    return tlv_query_visit(&reader, &matcher, visitor, context, error_offset);
}
