#include "tlv/query/query.h"
#include <string.h>

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void set_offset(size_t* out, size_t offset) {
    if (out) *out = offset;
}

tlv_result_t tlv_query_parse(const char* text, tlv_query_t* query, size_t* error_offset) {
    tlv_query_t parsed;
    size_t pos = 0, used = 0;
    if (!text || !query) return TLV_ERR_NULL_ARG;
    memset(&parsed, 0, sizeof parsed);
    for (;;) {
        size_t start = pos, digits;
        while (text[pos] && text[pos] != '/') {
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
        if (!text[pos]) break;
        ++pos; /* The separator; another tag must follow. */
    }
    *query = parsed;
    return TLV_OK;
}

tlv_tag_t tlv_query_step(const tlv_query_t* query, size_t index) {
    size_t begin;
    if (!query || index >= query->count || index >= TLV_QUERY_MAX_STEPS) return tlv_tag(NULL, 0);
    begin = index == 0 ? 0 : query->ends[index - 1];
    return tlv_tag(query->bytes + begin, query->ends[index] - begin);
}

tlv_result_t tlv_query_matcher_init(tlv_query_matcher_t* matcher, const tlv_query_t* query) {
    if (!matcher || !query) return TLV_ERR_NULL_ARG;
    if (!query->count || query->count > TLV_QUERY_MAX_STEPS) return TLV_ERR_INVALID_ARG;
    for (size_t i = 0, begin = 0; i < query->count; begin = query->ends[i++])
        if (query->ends[i] <= begin || query->ends[i] > TLV_QUERY_MAX_BYTES)
            return TLV_ERR_INVALID_TAG_SIZE;
    matcher->query = query;
    matcher->matched = 0;
    return TLV_OK;
}

int tlv_query_matcher_visit(tlv_query_matcher_t* matcher, const tlv_tag_t* tag, size_t depth) {
    const tlv_query_t* query;
    if (!matcher || !matcher->query || !tag) return 0;
    query = matcher->query;
    /* An element whose parent did not match is outside every path. */
    if (depth > matcher->matched) return 0;
    matcher->matched = depth;
    if (depth >= query->count) return 0;
    if (!tlv_tag_equal(tlv_query_step(query, depth), *tag)) return 0;
    matcher->matched = depth + 1;
    return depth + 1 == query->count;
}

typedef struct query_walk {
    tlv_query_matcher_t matcher;
    tlv_tree_visitor_t visitor;
    void* context;
} query_walk_t;

static tlv_visit_result_t on_element(const tlv_view_t* view, size_t depth, size_t offset,
                                     void* context) {
    query_walk_t* walk = (query_walk_t*)context;
    if (!tlv_query_matcher_visit(&walk->matcher, &view->tag, depth)) return TLV_VISIT_CONTINUE;
    return walk->visitor(view, depth, offset, walk->context);
}

tlv_result_t tlv_query_walk(const uint8_t* data, size_t size, const tlv_reader_format_t* format,
                            tlv_is_constructed_fn is_constructed, const tlv_query_t* query,
                            size_t max_depth, size_t max_elements, tlv_tree_visitor_t visitor,
                            void* context, size_t* error_offset) {
    query_walk_t walk;
    tlv_result_t rc;
    if (!visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_query_matcher_init(&walk.matcher, query);
    if (rc != TLV_OK) return rc;
    walk.visitor = visitor;
    walk.context = context;
    return tlv_walk_tree(data, size, format, is_constructed, max_depth, max_elements, on_element,
                         &walk, error_offset);
}
