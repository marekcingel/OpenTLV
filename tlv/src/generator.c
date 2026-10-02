// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/generator.h"
#include "tlv/writer/writer.h"
#include <string.h>

typedef struct generator {
    const tlv_format_t* format;
    const tlv_generator_options_t* options;
    uint8_t* workspace;
    uint64_t random;
    size_t remaining;
    size_t attempts;
} generator_t;

/* SplitMix64: fixed-width arithmetic makes the sequence platform independent. */
static uint64_t next(generator_t* g) {
    uint64_t z = (g->random += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static size_t value_size(generator_t* g, size_t lo, size_t hi) {
    static const size_t boundaries[] = {0, 1, 127, 128, 255, 256};
    uint64_t r = next(g);
    size_t n;
    if (r % 4 == 0) return lo;
    if (r % 4 == 1) return hi;
    n = boundaries[(r >> 2) % 6];
    if (r % 4 == 2 && n >= lo && n <= hi) return n;
    /* hi is bounded by positive max_case_size, leaving room for +1. */
    return lo + (size_t)(next(g) % (hi - lo + 1));
}

tlv_result_t tlv_generator_workspace_size(const tlv_generator_options_t* o, size_t* size) {
    size_t i;
    if (!o || !size) return TLV_ERR_NULL_ARG;
    if (!o->max_elements || !o->max_case_size || o->max_depth > 64 || !o->candidates ||
        !o->candidate_count)
        return TLV_ERR_INVALID_ARG;
    if (o->max_case_size > SIZE_MAX / (o->max_depth + 1) || o->max_case_size == SIZE_MAX ||
        o->max_elements > SIZE_MAX / 64)
        return TLV_ERR_OVERFLOW;
    for (i = 0; i < o->candidate_count; ++i) {
        const tlv_generator_candidate_t* c = &o->candidates[i];
        if (c->min_value_size > c->max_value_size || (!c->tag.data && c->tag.size))
            return TLV_ERR_INVALID_ARG;
    }
    *size = (o->max_depth + 1) * o->max_case_size;
    return TLV_OK;
}

static size_t stream(generator_t* g, uint8_t* out, size_t capacity, size_t depth) {
    size_t pos = 0;
    size_t target = 1 + (size_t)(next(g) % g->remaining);
    size_t accepted = 0;
    while (accepted < target && g->remaining && g->attempts && pos < capacity) {
        const tlv_generator_candidate_t* c;
        uint8_t* value = g->workspace + depth * g->options->max_case_size;
        size_t hi, length, n = 0, check = 0, saved = g->remaining, i;
        tlv_decoded_t decoded;
        int constructed;
        --g->attempts;
        c = &g->options->candidates[next(g) % g->options->candidate_count];
        hi = c->max_value_size;
        if (hi > g->options->max_value_size) hi = g->options->max_value_size;
        if (hi > capacity - pos) hi = capacity - pos;
        if (c->min_value_size > hi) continue;
        constructed =
            g->format->is_constructed && g->format->is_constructed(g->format->context, &c->tag);
        --g->remaining;
        if (constructed) {
            length = depth < g->options->max_depth && g->remaining && hi
                         ? stream(g, value, hi, depth + 1)
                         : 0;
            if (length < c->min_value_size) {
                g->remaining = saved;
                continue;
            }
        } else {
            length = value_size(g, c->min_value_size, hi);
            for (i = 0; i < length; ++i) value[i] = (uint8_t)next(g);
        }
        if (tlv_write(out + pos, capacity - pos, g->format, c->tag, value, length, &n) != TLV_OK ||
            !n || tlv_format_decode(g->format, out + pos, n, &decoded, NULL) != TLV_OK ||
            decoded.source.size != n || !tlv_tag_equal(c->tag, decoded.element.tag) ||
            ((c->tag.data == NULL) != (decoded.element.tag.data == NULL)) ||
            decoded.element.value.size != length ||
            (length && memcmp(decoded.element.value.data, value, length)) ||
            tlv_write_element(value, g->options->max_case_size, g->format, &decoded.element,
                              &check) != TLV_OK ||
            check != n || memcmp(value, out + pos, n)) {
            g->remaining = saved;
            continue;
        }
        pos += n;
        ++accepted;
    }
    return pos;
}

tlv_result_t tlv_generate(const tlv_format_t* format, const tlv_generator_options_t* o,
                          uint8_t* data, size_t capacity, uint8_t* workspace, size_t workspace_size,
                          size_t* written) {
    generator_t g;
    size_t required, n;
    tlv_result_t rc;
    if (!format || !data || !workspace || !written || !tlv_format_can_read(format) ||
        !tlv_format_can_write(format))
        return TLV_ERR_NULL_ARG;
    rc = tlv_generator_workspace_size(o, &required);
    if (rc != TLV_OK) return rc;
    if (capacity < o->max_case_size || workspace_size < required) return TLV_ERR_BUFFER_TOO_SHORT;
    g.format = format;
    g.options = o;
    g.workspace = workspace;
    g.random = o->seed ^ UINT64_C(0xd1b54a32d192ed03);
    g.random ^= o->case_index * UINT64_C(0x9e3779b97f4a7c15);
    g.remaining = o->max_elements;
    g.attempts = o->max_elements * 64;
    n = stream(&g, data, o->max_case_size, 0);
    if (!n) return TLV_ERR_LIMIT;
    *written = n;
    return TLV_OK;
}
