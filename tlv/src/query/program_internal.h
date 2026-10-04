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
    Q_ARGS
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
} query_node_t;
typedef struct query_operator {
    uint32_t kind, token, base, function;
} query_operator_t;
struct tlv_query_program {
    uint32_t magic, version, count, root, text_size, text_offset, level, reserved;
};
enum query_value_kind { V_NODE, V_BOOL, V_NUMBER, V_BYTES, V_STRING };
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
};
static inline const query_node_t* query_nodes(const tlv_query_program_t* p) {
    return (const query_node_t*)(p + 1);
}
static inline const char* query_text(const tlv_query_program_t* p) {
    return (const char*)p + p->text_offset;
}
/* Structural check of a readable compiler-owned image, not an external loader.
   The redundant extent rejects inconsistent single-field header corruption.
   Storage must remain unchanged after execution initialization. */
static inline int query_program_valid(const tlv_query_program_t* p) {
    if ((uintptr_t)p % sizeof(uint32_t)) return 0;
    if (p->magic != QUERY_MAGIC || p->version != 1 || !p->count || p->root >= p->count ||
        p->level > TLV_QUERY_D || !p->text_size)
        return 0;
    if (p->count > (UINT32_MAX - sizeof *p) / sizeof(query_node_t)) return 0;
    size_t offset = sizeof *p + (size_t)p->count * sizeof(query_node_t);
    if (p->text_offset != offset || p->text_size >= UINT32_MAX - offset ||
        p->reserved != offset + p->text_size + 1)
        return 0;
    const query_node_t* nodes = query_nodes(p);
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op > Q_ARGS || n->axis > A_OTHER || n->anchor > 2 || n->scalar > 1 ||
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
        if (n->op == Q_BYTES && (n->end - n->begin < 3 || (n->end - n->begin - 3) % 2)) return 0;
    }
    return nodes[p->root].type == V_NODE && query_text(p)[p->text_size] == 0;
}
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
