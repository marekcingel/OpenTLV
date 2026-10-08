// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_PROGRAM_INTERNAL_H
#define OPENTLV_QUERY_PROGRAM_INTERNAL_H
#include "../callback_internal.h"
#include "tlv/query/plan.h"
#include "tlv/config.h"
#include <stdint.h>
#include <string.h>

#define QUERY_MAGIC UINT32_C(0x51525932)
#define QUERY_IMAGE_VERSION TLV_QUERY_PLAN_VERSION
#define QUERY_NONE TLV_QUERY_PLAN_NONE
#define Q_TEST TLV_QUERY_OP_TEST
#define Q_ROOT TLV_QUERY_OP_ROOT
#define Q_SELF TLV_QUERY_OP_SELF
#define Q_META TLV_QUERY_OP_META
#define Q_LITERAL TLV_QUERY_OP_LITERAL
#define Q_BYTES TLV_QUERY_OP_BYTES
#define Q_STRING TLV_QUERY_OP_STRING
#define Q_VARIABLE TLV_QUERY_OP_VARIABLE
#define Q_CHILD TLV_QUERY_OP_CHILD
#define Q_DESC TLV_QUERY_OP_DESC
#define Q_FILTER TLV_QUERY_OP_FILTER
#define Q_UNION TLV_QUERY_OP_UNION
#define Q_INTERSECT TLV_QUERY_OP_INTERSECT
#define Q_EXCEPT TLV_QUERY_OP_EXCEPT
#define Q_EQ TLV_QUERY_OP_EQ
#define Q_NE TLV_QUERY_OP_NE
#define Q_LT TLV_QUERY_OP_LT
#define Q_LE TLV_QUERY_OP_LE
#define Q_GT TLV_QUERY_OP_GT
#define Q_GE TLV_QUERY_OP_GE
#define Q_AND TLV_QUERY_OP_AND
#define Q_OR TLV_QUERY_OP_OR
#define Q_CALL TLV_QUERY_OP_CALL
#define Q_ARGS TLV_QUERY_OP_ARGS
#define Q_BOOL TLV_QUERY_OP_BOOL
#define A_CHILD TLV_QUERY_AXIS_CHILD
#define A_SELF TLV_QUERY_AXIS_SELF
#define A_DESC TLV_QUERY_AXIS_DESC
#define A_ANCESTOR TLV_QUERY_AXIS_ANCESTOR
#define A_DESC_SELF TLV_QUERY_AXIS_DESC_SELF
#define A_PARENT TLV_QUERY_AXIS_PARENT
#define A_ANCESTOR_SELF TLV_QUERY_AXIS_ANCESTOR_SELF
#define A_FOLLOW_SIBLING TLV_QUERY_AXIS_FOLLOW_SIBLING
#define A_PRECEDE_SIBLING TLV_QUERY_AXIS_PRECEDE_SIBLING
#define A_FOLLOW TLV_QUERY_AXIS_FOLLOW
#define A_PRECEDE TLV_QUERY_AXIS_PRECEDE
#define F_VALUE TLV_QUERY_FN_VALUE
#define F_LEN TLV_QUERY_FN_LEN
#define F_NOT TLV_QUERY_FN_NOT
#define F_STARTS TLV_QUERY_FN_STARTS
#define F_ENDS TLV_QUERY_FN_ENDS
#define F_CONTAINS TLV_QUERY_FN_CONTAINS
#define F_SUBSTR TLV_QUERY_FN_SUBSTR
#define F_MASK TLV_QUERY_FN_MASK
#define F_RANGE TLV_QUERY_FN_RANGE
#define F_COUNT TLV_QUERY_FN_COUNT
#define F_EXISTS TLV_QUERY_FN_EXISTS
#define F_EMPTY TLV_QUERY_FN_EMPTY
#define F_POSITION TLV_QUERY_FN_POSITION
#define F_LAST TLV_QUERY_FN_LAST
#define F_NUM TLV_QUERY_FN_NUM
#define F_BCD TLV_QUERY_FN_BCD
#define F_TEXT TLV_QUERY_FN_TEXT
#define F_DATE TLV_QUERY_FN_DATE
#define F_TAG TLV_QUERY_FN_TAG
#define F_CLASS TLV_QUERY_FN_CLASS
#define F_CONSTRUCTED TLV_QUERY_FN_CONSTRUCTED
#define F_NUMBER TLV_QUERY_FN_NUMBER
#define F_NAME TLV_QUERY_FN_NAME
#define F_UNKNOWN TLV_QUERY_FN_UNKNOWN

static inline int query_format_compatible(const tlv_format_t* a, const tlv_format_t* b) {
    return a && b && a->context == b->context && a->decode == b->decode &&
           a->measure == b->measure && a->encode == b->encode &&
           a->is_constructed == b->is_constructed;
}

static inline int query_reverse_axis(unsigned axis) {
    return axis == A_ANCESTOR || axis == A_ANCESTOR_SELF || axis == A_PRECEDE_SIBLING ||
           axis == A_PRECEDE;
}
typedef tlv_query_instruction_t query_node_t;

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
    size_t workspace_size;
    uintptr_t borrowed_low, borrowed_high;
    int busy;
    size_t depth_capacity, open, elements, max_elements, work, max_work, pattern_capacity;
    size_t context_ordinal, context_depth;
    int has_context, context_found, context_active;
    size_t pruned, prune_depth;
    int pruning, prune_allowed;
    int any_match;
    int invalid, finished;
    int retained;
    size_t node_capacity, result_cursor;
    int document_backend;
    const void* document_owner;
    uint64_t document_revision;
    int (*document_current)(const void*, uint64_t);
    tlv_result_t (*document_metadata)(const void*, int, size_t*);
    tlv_tree_event_t delayed;
    int delayed_selected, published_match;
    const tlv_query_environment_t* environment;
    tlv_query_result_t result;
};
/* Subtraction avoids wrapping either caller-supplied interval endpoint. */
static inline int query_overlap(const void* a, size_t an, const void* b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return a && b && an && bn && (x <= y ? y - x < an : x - y < bn);
}
static inline int query_event_overlap(const tlv_tree_event_t* event, const void* p, size_t n) {
    return query_overlap(event->element.tag.data, event->element.tag.size, p, n) ||
           query_overlap(event->element.value.data, (size_t)event->element.value.size, p, n) ||
           query_overlap(event->source.data, event->source.size, p, n);
}
static inline void query_track_borrow(tlv_query_exec_t* e, const void* p, size_t n) {
    if (!p || !n) return;
    uintptr_t begin = (uintptr_t)p;
    uintptr_t end = n > UINTPTR_MAX - begin ? UINTPTR_MAX : begin + n;
    if (!e->borrowed_high || begin < e->borrowed_low) e->borrowed_low = begin;
    if (end > e->borrowed_high) e->borrowed_high = end;
}
int query_retained_overlap(const tlv_query_exec_t*, const void*, size_t);
int query_live_overlap(const tlv_query_exec_t*, const void*, size_t);
/* Per-event/cursor checks must not scan the accumulated candidate set. */
static inline int query_output_overlap_live(const tlv_query_exec_t* e, const void* p, size_t n) {
    return query_overlap(e, e->workspace_size, p, n) ||
           query_overlap(e->program, e->program->reserved, p, n) ||
           query_overlap(e->environment, e->environment ? sizeof *e->environment : 0, p, n) ||
           query_live_overlap(e, p, n) ||
           (e->environment &&
            (query_overlap(e->environment->hooks,
                           e->environment->hook_count * sizeof(tlv_query_hook_t), p, n) ||
             query_overlap(e->environment->tags,
                           e->environment->tags ? sizeof(tlv_query_tag_adapter_t) : 0, p, n) ||
             query_overlap(e->environment->format,
                           e->environment->format ? sizeof(tlv_format_t) : 0, p, n)));
}
static inline int query_output_overlap(const tlv_query_exec_t* e, const void* p, size_t n) {
    return query_output_overlap_live(e, p, n) || query_retained_overlap(e, p, n);
}
static inline int query_borrow_overlap(const tlv_query_exec_t* e, const void* p, size_t n) {
    return query_overlap(e, e->workspace_size, p, n);
}
/* Location availability is independent of borrowed Source bytes on Document.
 * Reader events still validate the actual Source header envelope. */
static inline tlv_result_t query_source_metadata(const tlv_tree_event_t* event, int header,
                                                 size_t* value) {
    if (!event->source.data || (header && !event->source.header.present))
        return TLV_ERR_INVALID_VALUE;
    if (header && (event->source.header.offset > event->source.size ||
                   event->source.header.size > event->source.size - event->source.header.offset))
        return TLV_ERR_INVALID_ARG;
    *value = header ? event->source.header.size : event->offset;
    return TLV_OK;
}
static inline const query_node_t* query_nodes(const tlv_query_program_t* p) {
    return (const query_node_t*)(p + 1);
}
static inline const char* query_text(const tlv_query_program_t* p) {
    return (const char*)p + p->text_offset;
}

static inline int query_nodes_need_values(const query_node_t* nodes, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op == Q_META && n->selector == TLV_QUERY_META_LEN) return 1;
        if (n->op != Q_CALL) continue;
        unsigned fn = n->selector;
        if (fn == F_VALUE || fn == F_LEN || (fn >= F_NUM && fn <= F_DATE) ||
            (fn >= F_STARTS && fn <= F_SUBSTR && n->left == QUERY_NONE))
            return 1;
    }
    return 0;
}
static inline int query_program_needs_values(const tlv_query_program_t* p) {
    return query_nodes_need_values(query_nodes(p), p->count);
}
static inline const uint8_t* query_payload(const tlv_query_program_t* p) {
    return (const uint8_t*)query_text(p) + p->text_size + 1;
}
static inline uint64_t query_immediate(const query_node_t* n) {
    return ((uint64_t)n->immediate_high << 32) | n->immediate_low;
}
static inline int query_plan_tag(const tlv_query_program_t* p, const query_node_t* n,
                                 tlv_tag_t tag) {
    if (!n->resolved) return 1;
    if (tag.size != n->data_size || (tag.size && !tag.data)) return 0;
    const uint8_t* bytes = query_payload(p) + n->data_offset;
    const uint8_t* mask = query_payload(p) + (n->resolved == 2 ? n->mask_offset : 0);
    for (size_t i = 0; i < tag.size; ++i) {
        unsigned m = n->resolved == 2 ? mask[i] : 255;
        if ((tag.data[i] & m) != (bytes[i] & m)) return 0;
    }
    return 1;
}
static inline int query_variable_name(const tlv_query_program_t* p, const query_node_t* n,
                                      const char* name) {
    return strlen(name) == n->data_size &&
           !memcmp(query_payload(p) + n->data_offset, name, n->data_size);
}
static inline int query_plan_supported(const tlv_query_program_t* p) {
#if !OPENTLV_QUERY_SET_OPERATIONS
    for (size_t i = 0; i < p->count; ++i)
        if (query_nodes(p)[i].op >= Q_UNION && query_nodes(p)[i].op <= Q_EXCEPT) return 0;
#endif
#if !OPENTLV_DOCUMENT
    if (p->level == TLV_QUERY_D) return 0;
#endif
    (void)p;
    return 1;
}
/* Structural check of a readable compiler-owned image, not an external loader.
   The redundant extent rejects inconsistent single-field header corruption.
   Storage must remain unchanged after execution initialization. */
static inline int query_program_valid(const tlv_query_program_t* p) {
    if ((uintptr_t)p % sizeof(uint32_t)) return 0;
    if (p->magic != QUERY_MAGIC || p->version != QUERY_IMAGE_VERSION || !p->count ||
        p->root >= p->count || p->level > TLV_QUERY_D)
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
        if (n->op > Q_BOOL || n->axis > A_PRECEDE || n->anchor > 2 || n->scalar > 1 ||
            n->grouped > 1 || n->nested > 1 || n->type > V_STRING || n->begin > n->end ||
            (p->text_size && n->end > p->text_size) || n->low > i)
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
            unsigned fn = n->selector;
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
            (n->op == Q_BOOL && n->folded > 1) || n->resolved > 2 ||
            (n->scratch_size && (!n->hook_id || n->scratch_size > p->codec_stride)) ||
            p->codec_stride % 16)
            return 0;

        if (n->context > 1 || n->negative > 1 ||
            (n->op == Q_META && n->selector > TLV_QUERY_META_HLEN) ||
            (n->op == Q_LITERAL && (query_immediate(n) > (uint64_t)INT64_MAX + n->negative ||
                                    (!query_immediate(n) && n->negative))))
            return 0;
        if (n->resolved == 2 &&
            (n->mask_offset > p->payload_size || n->data_size > p->payload_size - n->mask_offset))
            return 0;
        if (n->data_offset > p->payload_size || n->data_size > p->payload_size - n->data_offset ||
            (n->reuse != QUERY_NONE && n->reuse >= i))
            return 0;
        if (n->op == Q_VARIABLE) {
            if ((n->type != V_NUMBER && n->type != V_BYTES && n->type != V_STRING) ||
                n->variable_slot > variables || !n->data_size)
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
                if (!first || first->type != n->type || first->data_size != n->data_size ||
                    memcmp(query_payload(p) + first->data_offset, query_payload(p) + n->data_offset,
                           n->data_size))
                    return 0;
            }
        }
    }
    return variables == p->variable_count && query_text(p)[p->text_size] == 0;
}
/* Shared scalar VM operations used by both execution profiles. */
tlv_result_t query_function_eval(tlv_query_exec_t*, const tlv_tree_event_t*, const query_node_t*,
                                 query_value_t*, tlv_query_diagnostic_t*);
tlv_result_t query_retained_finish(tlv_query_exec_t*, tlv_query_diagnostic_t*);
tlv_result_t query_retained_feed(tlv_query_exec_t*, const tlv_tree_event_t*,
                                 tlv_query_diagnostic_t*);
void query_document_handle(tlv_query_exec_t*, void*, const uint8_t*);
const uint8_t* query_document_end(tlv_query_exec_t*);
tlv_result_t query_document_next(tlv_query_exec_t*, void**);
tlv_result_t query_document_result_count(const tlv_query_exec_t*, size_t*);
size_t query_candidate_size(void);
size_t query_candidate_alignment(void);
uint32_t query_s1_filter(const query_node_t*, size_t, uint32_t);
static inline void query_diag_init(tlv_query_diagnostic_t* d) {
    if (d) memset(d, 0, sizeof *d);
}
static inline tlv_result_t query_error(tlv_query_diagnostic_t* d, tlv_result_t code,
                                       tlv_query_error_kind_t kind, size_t begin, size_t end,
                                       const char* expected) {
    if (d) {
        d->kind = code == TLV_ERR_INVALID_STATE ? TLV_QUERY_ERROR_STATE
                  : code == TLV_ERR_CALLBACK    ? TLV_QUERY_ERROR_CALLBACK
                                                : kind;
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

/* Preserve callee detail; state results always have their own top-level kind. */
static inline tlv_result_t query_failure(tlv_query_diagnostic_t* d, tlv_result_t rc,
                                         tlv_query_error_kind_t kind, const char* expected) {
    if (rc != TLV_OK && d && d->kind == TLV_QUERY_ERROR_NONE)
        query_error(d, rc, kind, 0, 0, expected);
    if (rc == TLV_ERR_INVALID_STATE && d) d->kind = TLV_QUERY_ERROR_STATE;
    return rc;
}
#endif
