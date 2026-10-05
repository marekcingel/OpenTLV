// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_PROGRAM_INTERNAL_H
#define OPENTLV_QUERY_PROGRAM_INTERNAL_H
#include "tlv/query/program.h"
#include "match_internal.h"
#include <stdint.h>
#include <string.h>

#define QUERY_MAGIC UINT32_C(0x51525932)
#define QUERY_NONE UINT32_MAX
enum query_op {
    Q_TEST,
    Q_ROOT,
    Q_SELF,
    Q_META,
    Q_LITERAL,
    Q_BYTES,
    Q_STRING,
    Q_VARIABLE,
    Q_CHILD,
    Q_DESC,
    Q_FILTER,
    Q_UNION,
    Q_INTERSECT,
    Q_EXCEPT,
    Q_EQ,
    Q_NE,
    Q_LT,
    Q_LE,
    Q_GT,
    Q_GE,
    Q_AND,
    Q_OR,
    Q_CALL,
    Q_ARGS,
    Q_BOOL
};
enum query_token_kind {
    T_WORD,
    T_BYTES,
    T_STRING,
    T_META,
    T_VARIABLE,
    T_SLASH,
    T_DESC,
    T_OPEN,
    T_CLOSE,
    T_POPEN,
    T_PCLOSE,
    T_COMMA,
    T_UNION,
    T_INTERSECT,
    T_EXCEPT,
    T_EQ,
    T_NE,
    T_LT,
    T_LE,
    T_GT,
    T_GE,
    T_AND,
    T_OR,
    T_DOT,
    T_DDOT,
    T_AXIS,
    T_END
};
enum query_axis { A_CHILD, A_SELF, A_DESC, A_ANCESTOR, A_OTHER };
typedef struct query_token {
    uint32_t kind, begin, end;
} query_token_t;
typedef struct query_node {
    uint32_t op, left, right, begin, end, axis, anchor, scalar, type;
    uint32_t low, predicate_guard, path_guard, path_kind;
    uint32_t variable_slot;
    uint32_t data_offset, data_size, resolved, hook_id, scratch_size, reuse, folded;
} query_node_t;
typedef struct query_operator {
    uint32_t kind, token, base, function;
} query_operator_t;
struct tlv_query_program {
    uint32_t magic, version, count, root, text_size, text_offset, level, reserved;
    uint32_t variable_count, payload_size, pattern_capacity, codec_stride, tag_id;
};
enum query_value_kind { V_NODE, V_BOOL, V_NUMBER, V_BYTES, V_STRING };
static inline unsigned query_private_type(tlv_query_result_kind_t type) {
    switch (type) {
        case TLV_QUERY_RESULT_NODES: return V_NODE;
        case TLV_QUERY_RESULT_BOOL: return V_BOOL;
        case TLV_QUERY_RESULT_INTEGER: return V_NUMBER;
        case TLV_QUERY_RESULT_BYTES: return V_BYTES;
        case TLV_QUERY_RESULT_STRING: return V_STRING;
        default: return UINT32_MAX;
    }
}
static inline tlv_query_result_kind_t query_public_type(unsigned type) {
    switch (type) {
        case V_BOOL: return TLV_QUERY_RESULT_BOOL;
        case V_NUMBER: return TLV_QUERY_RESULT_INTEGER;
        case V_BYTES: return TLV_QUERY_RESULT_BYTES;
        case V_STRING: return TLV_QUERY_RESULT_STRING;
        default: return TLV_QUERY_RESULT_NODES;
    }
}
typedef struct query_value {
    uint64_t number;
    const uint8_t* data;
    size_t size;
    unsigned kind;
    int negative;
} query_value_t;
struct tlv_query_exec {
    const tlv_query_program_t* program;
    size_t depth_capacity, open, elements, max_elements, work, max_work, pattern_capacity;
    size_t context_ordinal, context_depth;
    int has_context, context_found, context_active;
    size_t pruned, prune_depth;
    int pruning, prune_allowed;
    int any_match;
    int invalid, finished;
    int retained;
    size_t node_capacity, result_cursor;
    const tlv_query_environment_t* environment;
    tlv_query_result_t result;
};
static inline const query_node_t* query_nodes(const tlv_query_program_t* p) {
    return (const query_node_t*)(p + 1);
}
static inline const char* query_text(const tlv_query_program_t* p) {
    return (const char*)p + p->text_offset;
}
enum query_function {
    F_VALUE,
    F_LEN,
    F_NOT,
    F_STARTS,
    F_ENDS,
    F_CONTAINS,
    F_SUBSTR,
    F_MASK,
    F_RANGE,
    F_COUNT,
    F_EXISTS,
    F_EMPTY,
    F_POSITION,
    F_LAST,
    F_NUM,
    F_BCD,
    F_TEXT,
    F_DATE,
    F_TAG,
    F_CLASS,
    F_CONSTRUCTED,
    F_NUMBER,
    F_NAME,
    F_UNKNOWN
};
static inline unsigned query_function_kind(const char* text, const query_node_t* n) {
    static const char* names[] = {"value",       "len",    "not",      "starts-with", "ends-with",
                                  "contains",    "substr", "tag-mask", "tag-range",   "count",
                                  "exists",      "empty",  "position", "last",        "num",
                                  "bcd",         "text",   "date",     "tag",         "class",
                                  "constructed", "number", "name"};
    for (unsigned i = 0; i < F_UNKNOWN; ++i)
        if (strlen(names[i]) == n->end - n->begin &&
            !memcmp(text + n->begin, names[i], n->end - n->begin))
            return i;
    return F_UNKNOWN;
}
/* Structural check of a readable compiler-owned image, not an external loader.
   The redundant extent rejects inconsistent single-field header corruption.
   Storage must remain unchanged after execution initialization. */
static inline int query_program_valid(const tlv_query_program_t* p) {
    if ((uintptr_t)p % sizeof(uint32_t)) return 0;
    if (p->magic != QUERY_MAGIC || p->version != 3 || !p->count || p->root >= p->count ||
        p->level > TLV_QUERY_D || !p->text_size)
        return 0;
    if (p->count > (UINT32_MAX - sizeof *p) / sizeof(query_node_t)) return 0;
    size_t offset = sizeof *p + (size_t)p->count * sizeof(query_node_t);
    if (p->text_offset != offset || p->text_size >= UINT32_MAX - offset ||
        p->payload_size > UINT32_MAX - offset - p->text_size - 1 ||
        p->reserved != offset + p->text_size + 1 + p->payload_size)
        return 0;
    const query_node_t* nodes = query_nodes(p);
    uint32_t variables = 0;
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op > Q_BOOL || n->axis > A_OTHER || n->anchor > 2 || n->scalar > 1 ||
            n->type > V_STRING || n->begin > n->end || n->end > p->text_size || n->low > i)
            return 0;
        if ((n->left != QUERY_NONE && n->left >= i) || (n->right != QUERY_NONE && n->right >= i) ||
            (n->predicate_guard != QUERY_NONE && n->predicate_guard >= i) ||
            (n->path_guard != QUERY_NONE && n->path_guard >= i))
            return 0;
        if (n->path_guard != QUERY_NONE && n->path_kind != Q_CHILD && n->path_kind != Q_DESC &&
            n->path_kind != Q_SELF)
            return 0;
        if ((n->op >= Q_CHILD && n->op <= Q_OR) || n->op == Q_ARGS) {
            if (n->left == QUERY_NONE || n->right == QUERY_NONE) return 0;
        } else if (n->op != Q_CALL && (n->left != QUERY_NONE || n->right != QUERY_NONE))
            return 0;
        if (n->op == Q_CALL && n->right != QUERY_NONE) return 0;
        if (n->op == Q_CALL) {
            unsigned fn = query_function_kind(query_text(p), n);
            uint32_t cursor = n->left;
            size_t argc = 0;
            while (cursor != QUERY_NONE && nodes[cursor].op == Q_ARGS) {
                if (++argc > 2) return 0;
                cursor = nodes[cursor].left;
            }
            if (cursor != QUERY_NONE) ++argc;
            if (fn >= F_NAME || ((fn == F_POSITION || fn == F_LAST) && argc != 0) ||
                ((fn == F_VALUE || fn == F_LEN || (fn >= F_TAG && fn <= F_NUMBER)) && argc > 1) ||
                ((fn == F_NOT || (fn >= F_COUNT && fn <= F_EMPTY) ||
                  (fn >= F_NUM && fn <= F_DATE)) &&
                 argc != 1) ||
                ((fn >= F_STARTS && fn <= F_CONTAINS) && argc != 2) ||
                ((fn == F_MASK || fn == F_RANGE) && argc != 2) ||
                (fn == F_SUBSTR && argc != 2 && argc != 3))
                return 0;
            unsigned type = fn == F_VALUE || fn == F_TAG || fn == F_SUBSTR ? V_BYTES
                            : fn == F_TEXT                                 ? V_STRING
                            : fn == F_MASK || fn == F_RANGE                ? V_NODE
                            : fn == F_LEN || fn == F_COUNT || fn == F_POSITION || fn == F_LAST ||
                                    fn == F_NUM || fn == F_BCD || fn == F_DATE || fn == F_CLASS ||
                                    fn == F_NUMBER
                                ? V_NUMBER
                                : V_BOOL;
            if (n->type != type || ((fn >= F_NUM && fn <= F_DATE) && !n->hook_id)) return 0;
        }

        if (((n->op <= Q_SELF || (n->op >= Q_CHILD && n->op <= Q_EXCEPT)) && n->type != V_NODE) ||
            ((n->op == Q_META || n->op == Q_LITERAL) && n->type != V_NUMBER) ||
            (n->op == Q_BYTES && n->type != V_BYTES) ||
            (n->op == Q_STRING && n->type != V_STRING) ||
            ((n->op == Q_BOOL || (n->op >= Q_EQ && n->op <= Q_OR)) && n->type != V_BOOL) ||
            (n->op == Q_BOOL && n->folded > 1) || n->resolved > 1 ||
            (n->scratch_size && (!n->hook_id || n->scratch_size > p->codec_stride)) ||
            p->codec_stride % 16)
            return 0;

        if (n->op == Q_BYTES && (n->end - n->begin < 3 || (n->end - n->begin - 3) % 2)) return 0;
        if (n->data_offset > p->payload_size || n->data_size > p->payload_size - n->data_offset ||
            (n->reuse != QUERY_NONE && n->reuse >= i))
            return 0;
        if (n->op == Q_VARIABLE) {
            if ((n->type != V_NUMBER && n->type != V_BYTES && n->type != V_STRING) ||
                n->variable_slot > variables || n->end - n->begin < 2)
                return 0;
            if (n->variable_slot == variables)
                ++variables;
            else {
                const query_node_t* first = NULL;
                for (size_t j = 0; j < i; ++j)
                    if (nodes[j].op == Q_VARIABLE && nodes[j].variable_slot == n->variable_slot) {
                        first = &nodes[j];
                        break;
                    }
                if (!first || first->type != n->type ||
                    first->end - first->begin != n->end - n->begin ||
                    memcmp(query_text(p) + first->begin, query_text(p) + n->begin,
                           n->end - n->begin))
                    return 0;
            }
        }
    }
    return variables == p->variable_count && query_text(p)[p->text_size] == 0;
}
static inline const uint8_t* query_payload(const tlv_query_program_t* p) {
    return (const uint8_t*)query_text(p) + p->text_size + 1;
}
/* Shared scalar VM operations used by both execution profiles. */
tlv_result_t query_function_eval(tlv_query_exec_t*, const tlv_tree_event_t*, const query_node_t*,
                                 query_value_t*, tlv_query_diagnostic_t*);
tlv_result_t query_retained_finish(tlv_query_exec_t*, tlv_query_diagnostic_t*);
tlv_result_t query_retained_feed(tlv_query_exec_t*, const tlv_tree_event_t*,
                                 tlv_query_diagnostic_t*);
static inline void query_diag_init(tlv_query_diagnostic_t* d) {
    if (d) memset(d, 0, sizeof *d);
}
static inline tlv_result_t query_error(tlv_query_diagnostic_t* d, tlv_result_t code,
                                       tlv_query_error_kind_t kind, size_t begin, size_t end,
                                       const char* expected) {
    if (d) {
        d->kind = kind;
        d->begin = begin;
        d->end = end;
        d->expected = expected;
    }
    return code;
}
static inline tlv_result_t query_limit(tlv_query_diagnostic_t* d, const char* name,
                                       size_t configured, size_t begin, size_t end) {
    if (d) {
        d->limit = name;
        d->configured = configured;
    }
    return query_error(d, TLV_ERR_LIMIT, TLV_QUERY_ERROR_LIMIT, begin, end, NULL);
}
static inline int query_word(const char* text, size_t begin, size_t end, const char* word) {
    size_t n = strlen(word);
    return end - begin == n && !memcmp(text + begin, word, n);
}
#endif
