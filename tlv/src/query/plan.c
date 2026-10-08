// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "program_internal.h"

size_t tlv_query_program_variable_count(const tlv_query_program_t* p) {
    return p && query_program_valid(p) ? p->variable_count : 0;
}

tlv_result_t tlv_query_program_variable(const tlv_query_program_t* p, size_t index,
                                        tlv_query_variable_info_t* info) {
    if (!p || !info) return TLV_ERR_NULL_ARG;
    if ((uintptr_t)p % sizeof(uint32_t)) return TLV_ERR_INVALID_ARG;
    if (query_overlap(p, p->reserved, info, sizeof *info)) return TLV_ERR_INVALID_ARG;
    if (!query_program_valid(p)) return TLV_ERR_INVALID_VALUE;
    if (index >= p->variable_count) return TLV_ERR_INVALID_ARG;
    const query_node_t* nodes = query_nodes(p);
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op == Q_VARIABLE && n->variable_slot == index) {
            tlv_query_variable_info_t result = {(const char*)query_payload(p) + n->data_offset,
                                                n->data_size, query_public_type(n->type)};
            *info = result;
            return TLV_OK;
        }
    }
    return TLV_ERR_INVALID_ARG;
}

/* All references have already passed the bounded, backward-reference check. */
static int plan_types(const tlv_query_program_t* p) {
    const query_node_t* nodes = query_nodes(p);
    if (nodes[p->root].op == Q_ARGS) return 0;
    int immediate = nodes[p->root].type == V_NODE;
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &nodes[i];
        if ((n->predicate_guard != QUERY_NONE && nodes[n->predicate_guard].type != V_NODE) ||
            (n->path_guard != QUERY_NONE && nodes[n->path_guard].type != V_NODE))
            return 0;
        if (n->left != QUERY_NONE && nodes[n->left].op == Q_ARGS && n->op != Q_CALL &&
            n->op != Q_ARGS)
            return 0;
        if (n->right != QUERY_NONE && nodes[n->right].op == Q_ARGS) return 0;
        unsigned a = n->left == QUERY_NONE ? V_NODE : nodes[n->left].type;
        unsigned b = n->right == QUERY_NONE ? V_NODE : nodes[n->right].type;
        if ((n->op == Q_CHILD || n->op == Q_DESC || (n->op >= Q_UNION && n->op <= Q_EXCEPT)) &&
            (a != V_NODE || b != V_NODE))
            return 0;
        if (n->op == Q_FILTER && (a != V_NODE || b > V_NUMBER)) return 0;
        if (n->op >= Q_EQ && n->op <= Q_GE && (a != b || a == V_NODE)) return 0;
        if ((n->op == Q_AND || n->op == Q_OR) && (a > V_BOOL || b > V_BOOL)) return 0;
        if (n->op == Q_ARGS && n->type != V_NODE) return 0;
        if (n->op == Q_ROOT && n->nested) immediate = 0;
        if (n->op == Q_LITERAL && n->anchor == 2) immediate = 0;
        if (n->op == Q_TEST) {
            if ((n->axis >= A_DESC_SELF && !(n->axis == A_PRECEDE_SIBLING && n->scalar)) ||
                (n->axis == A_DESC && n->scalar) || (n->axis == A_ANCESTOR && !n->scalar) ||
                (n->axis == A_CHILD && n->scalar))
                immediate = 0;
            if ((n->axis == A_FOLLOW || n->axis == A_PRECEDE) && p->level != TLV_QUERY_D) return 0;
            if (n->context && (n->axis != A_PARENT || n->resolved)) return 0;
            if (n->reuse != QUERY_NONE) {
                const query_node_t* other = &nodes[n->reuse];
                if (other->op != Q_TEST || other->axis != n->axis || other->anchor != n->anchor ||
                    other->scalar != n->scalar || other->predicate_guard != n->predicate_guard ||
                    other->path_guard != n->path_guard || other->path_kind != n->path_kind ||
                    other->resolved != n->resolved || other->data_size != n->data_size ||
                    memcmp(query_payload(p) + other->data_offset, query_payload(p) + n->data_offset,
                           n->data_size) ||
                    (n->resolved == 2 && memcmp(query_payload(p) + other->mask_offset,
                                                query_payload(p) + n->mask_offset, n->data_size)))
                    return 0;
            }
        }
        if (n->op == Q_FILTER && query_reverse_axis(nodes[n->left].axis)) immediate = 0;
        if (n->op != Q_CALL) continue;
        uint32_t args[3], cursor = n->left;
        size_t count = 0;
        while (cursor != QUERY_NONE && nodes[cursor].op == Q_ARGS) {
            args[count++] = nodes[cursor].right;
            cursor = nodes[cursor].left;
        }
        if (cursor != QUERY_NONE) args[count++] = cursor;
        for (size_t j = 0; j < count / 2; ++j) {
            uint32_t tmp = args[j];
            args[j] = args[count - j - 1];
            args[count - j - 1] = tmp;
        }
        unsigned f = n->selector;
        a = count ? nodes[args[0]].type : V_NODE;
        b = count > 1 ? nodes[args[1]].type : V_NODE;
        if (f == F_VALUE || (f >= F_TAG && f <= F_NUMBER)) {
            if (count && a != V_NODE) return 0;
            if (count || f >= F_TAG) immediate = 0;
        } else if (f == F_LEN) {
            if (count && a != V_BYTES && a != V_STRING) return 0;
        } else if (f == F_NOT) {
            if (a != V_BOOL && a != V_NODE) return 0;
        } else if (f >= F_COUNT && f <= F_LAST) {
            if (count && a != V_NODE) return 0;
            immediate = 0;
        } else if (f >= F_NUM && f <= F_DATE) {
            if (a != V_NODE && a != V_BYTES) return 0;
            immediate = 0;
        } else if (f == F_SUBSTR) {
            if (a != V_BYTES || b != V_NUMBER || (count == 3 && nodes[args[2]].type != V_NUMBER))
                return 0;
        } else if (f >= F_STARTS && f <= F_RANGE) {
            if (a != V_BYTES || b != V_BYTES) return 0;
            if (f == F_CONTAINS && nodes[args[1]].op == Q_BYTES &&
                nodes[args[1]].data_size > p->pattern_capacity)
                return 0;
            if (f == F_MASK || f == F_RANGE) {
                const query_node_t *x = &nodes[args[0]], *y = &nodes[args[1]];
                if (x->op != Q_BYTES || y->op != Q_BYTES) return 0;
                if (f == F_MASK && x->data_size != y->data_size) return 0;
                if (f == F_RANGE) {
                    size_t size = x->data_size < y->data_size ? x->data_size : y->data_size;
                    int order = memcmp(query_payload(p) + x->data_offset,
                                       query_payload(p) + y->data_offset, size);
                    if (order > 0 || (!order && x->data_size > y->data_size)) return 0;
                }
                if (n->predicate_guard != QUERY_NONE) immediate = 0;
            }
        }
        if ((f == F_CLASS || f == F_NUMBER) && !p->tag_id) return 0;
    }
    if (p->level == TLV_QUERY_S0 && !immediate) return 0;
    if (p->level == TLV_QUERY_S1 && query_s1_filter(nodes, p->count, p->root) == QUERY_NONE)
        return 0;
    return 1;
}

tlv_result_t tlv_query_plan_open(const void* image, size_t size,
                                 const tlv_query_program_t** program,
                                 tlv_query_diagnostic_t* diagnostic) {
    if (query_overlap(image, size, program, program ? sizeof *program : 0) ||
        query_overlap(image, size, diagnostic, diagnostic ? sizeof *diagnostic : 0) ||
        query_overlap(program, program ? sizeof *program : 0, diagnostic,
                      diagnostic ? sizeof *diagnostic : 0))
        return TLV_ERR_INVALID_ARG;
    query_diag_init(diagnostic);
    if (!image || !program)
        return query_error(diagnostic, TLV_ERR_NULL_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "required plan arguments");
    if ((uintptr_t)image % sizeof(uint32_t))
        return query_error(diagnostic, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "aligned bounded plan");
    if (size < sizeof(tlv_query_program_t))
        return query_error(diagnostic, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_IMAGE, 0, 0,
                           "complete plan header");
    const tlv_query_program_t* p = image;
    if (p->magic != QUERY_MAGIC) goto invalid;
    if (p->version != QUERY_IMAGE_VERSION)
        return query_error(diagnostic, TLV_ERR_UNSUPPORTED, TLV_QUERY_ERROR_IMAGE_VERSION, 0, 0,
                           "compatible native plan version and byte order");
    /* Establish the complete extent before any instruction/payload dereference. */
    if (size > UINT32_MAX || p->reserved != size || !p->count ||
        p->count > (size - sizeof *p) / sizeof(query_node_t))
        goto invalid;
    size_t offset = sizeof *p + (size_t)p->count * sizeof(query_node_t);
    if (p->text_offset != offset || p->text_size >= size - offset ||
        p->payload_size != size - offset - p->text_size - 1)
        goto invalid;
    if (!query_program_valid(p) || !plan_types(p)) goto invalid;
    if (!query_plan_supported(p))
        return query_error(diagnostic, TLV_ERR_UNSUPPORTED, TLV_QUERY_ERROR_CAPABILITY, 0, 0,
                           "available plan operation families");
    *program = p;
    return TLV_OK;
invalid:
    return query_error(diagnostic, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_IMAGE, 0, 0,
                       "valid execution plan");
}

tlv_result_t tlv_query_plan_info(const tlv_query_program_t* p, tlv_query_program_info_t* info) {
    if (!p || !info) return TLV_ERR_NULL_ARG;
    if ((uintptr_t)p % sizeof(uint32_t)) return TLV_ERR_INVALID_ARG;
    if (query_overlap(p, p->reserved, info, sizeof *info)) return TLV_ERR_INVALID_ARG;
    if (!query_program_valid(p)) return TLV_ERR_INVALID_VALUE;
    if (info->struct_size < offsetof(tlv_query_program_info_t, expression_values))
        return TLV_ERR_INVALID_ARG;
    tlv_query_program_info_t result = {0};
    result.struct_size = info->struct_size;
    result.program_size = p->reserved;
    result.program_alignment = sizeof(uint32_t);
    result.states = p->count;
    result.language_version = 1;
    result.level = (tlv_query_level_t)p->level;
    result.result_kind = query_public_type(query_nodes(p)[p->root].type);
    result.expression_values = p->count;
    result.instructions = p->count;
    result.variable_slots = p->variable_count;
    result.codec_scratch = p->codec_stride;
    result.pattern_bytes = p->pattern_capacity;
    result.expression_stack = (size_t)p->count + 1;
    result.candidate_size = p->level >= TLV_QUERY_S2 ? query_candidate_size() : 0;
    result.candidate_alignment = p->level >= TLV_QUERY_S2 ? query_candidate_alignment() : 0;
    result.frame_states = p->count;
    result.decision_timing = p->level == TLV_QUERY_S0   ? TLV_QUERY_DECISION_NODE
                             : p->level == TLV_QUERY_S1 ? TLV_QUERY_DECISION_SCOPE
                                                        : TLV_QUERY_DECISION_EOF;
    result.stable_input_required = p->level != TLV_QUERY_S0;
    result.constructed_values_required = query_program_needs_values(p);
    memcpy(info, &result, info->struct_size < sizeof result ? info->struct_size : sizeof result);
    return TLV_OK;
}
