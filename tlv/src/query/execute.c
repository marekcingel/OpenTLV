// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "program_internal.h"
#include "../utf8_internal.h"

static unsigned byte_at(query_value_t v, size_t i) {
    return v.data[i];
}
static int bytes_kind(query_value_t v) {
    return v.kind == V_BYTES;
}
static int truth(query_value_t v) {
    return v.number != 0;
}

static tlv_result_t charge(tlv_query_exec_t* e, size_t amount, const query_node_t* n,
                           tlv_query_diagnostic_t* d) {
    if (amount > e->max_work - e->work)
        return query_limit(d, "work", e->max_work, n->begin, n->end);
    e->work += amount;
    return TLV_OK;
}
static int tag_test(const tlv_query_program_t* p, const query_node_t* n, tlv_tag_t tag) {
    return query_plan_tag(p, n, tag);
}
static query_value_t* execution_values(tlv_query_exec_t* e) {
    return (query_value_t*)(e + 1);
}
static query_value_t* execution_bindings(tlv_query_exec_t* e) {
    return execution_values(e) + e->program->count;
}
static tlv_result_t bindings_ready(tlv_query_exec_t* e, tlv_query_diagnostic_t* d) {
    const query_node_t* nodes = query_nodes(e->program);
    for (size_t i = 0; i < e->program->count; ++i)
        if (nodes[i].op == Q_VARIABLE && !execution_bindings(e)[nodes[i].variable_slot].kind) {
            e->invalid = 1;
            return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_BINDING, nodes[i].begin,
                               nodes[i].end, "bound variable");
        }
    return TLV_OK;
}
static size_t* execution_indexes(tlv_query_exec_t* e) {
    return (size_t*)(execution_bindings(e) + e->program->variable_count);
}
static uint8_t* execution_states(tlv_query_exec_t* e) {
    return (uint8_t*)(execution_indexes(e) + e->depth_capacity + e->pattern_capacity);
}
static size_t pattern_capacity(const tlv_query_program_t* p) {
    size_t result = 0;
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &query_nodes(p)[i];
        if (n->op == Q_CALL && n->selector == F_CONTAINS && n->left != QUERY_NONE) {
            const query_node_t* arg = &query_nodes(p)[n->left];
            if (arg->op == Q_ARGS) arg = &query_nodes(p)[arg->right];
            size_t capacity = arg->op == Q_BYTES ? arg->data_size : p->pattern_capacity;
            if (capacity > result) result = capacity;
        }
    }
    return result;
}

tlv_result_t tlv_query_exec_size(const tlv_query_program_t* p, size_t depth, size_t* bytes,
                                 size_t* alignment) {
    if (!p || !bytes || !alignment) return TLV_ERR_NULL_ARG;
    if ((uintptr_t)p % sizeof(uint32_t)) return TLV_ERR_INVALID_ARG;
    if (!query_program_valid(p)) return TLV_ERR_INVALID_VALUE;
    if (query_overlap(p, p->reserved, bytes, sizeof *bytes) ||
        query_overlap(p, p->reserved, alignment, sizeof *alignment) ||
        query_overlap(bytes, sizeof *bytes, alignment, sizeof *alignment))
        return TLV_ERR_INVALID_ARG;
    if (!query_plan_supported(p)) return TLV_ERR_UNSUPPORTED;
    if (p->level > TLV_QUERY_S1) return TLV_ERR_UNSUPPORTED;
    size_t count = (size_t)p->count + p->variable_count;
    if (depth == SIZE_MAX || count > (SIZE_MAX - sizeof(tlv_query_exec_t)) / sizeof(query_value_t))
        return TLV_ERR_OVERFLOW;
    size_t base = sizeof(tlv_query_exec_t) + count * sizeof(query_value_t);
    size_t pattern = pattern_capacity(p);
    if (pattern > (SIZE_MAX - base) / sizeof(size_t)) return TLV_ERR_OVERFLOW;
    base += pattern * sizeof(size_t);
    size_t per_depth = sizeof(size_t) + p->count;
    if (depth + 1 > (SIZE_MAX - base) / per_depth) return TLV_ERR_OVERFLOW;
    *bytes = base + (depth + 1) * per_depth;
    *alignment = sizeof(uint64_t) > sizeof(void*) ? sizeof(uint64_t) : sizeof(void*);
    return TLV_OK;
}

tlv_result_t tlv_query_exec_bind(tlv_query_exec_t* e, const char* name,
                                 tlv_query_result_kind_t type, int64_t integer, const uint8_t* data,
                                 size_t size, tlv_query_diagnostic_t* d) {
    if (e && (e->busy || e->invalid)) return TLV_ERR_INVALID_STATE;
    if (e && (query_output_overlap(e, d, d ? sizeof *d : 0) ||
              query_borrow_overlap(e, name, name ? strlen(name) + 1 : 0) ||
              (type != TLV_QUERY_RESULT_INTEGER && query_borrow_overlap(e, data, size))))
        return TLV_ERR_INVALID_ARG;
    if (query_overlap(name, name ? strlen(name) + 1 : 0, d, d ? sizeof *d : 0) ||
        (type != TLV_QUERY_RESULT_INTEGER && query_overlap(data, size, d, d ? sizeof *d : 0)))
        return TLV_ERR_INVALID_ARG;
    query_diag_init(d);
    if (!e || !name || (!data && size && type != TLV_QUERY_RESULT_INTEGER))
        return query_error_unlocated(d, TLV_ERR_NULL_ARG, TLV_QUERY_ERROR_BINDING,
                                     "required execution arguments");
    if (e->elements || e->open || e->invalid || e->finished)
        return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                     "fresh execution before binding");
    if (query_private_type(type) != V_NUMBER && query_private_type(type) != V_BYTES &&
        query_private_type(type) != V_STRING)
        return query_error_unlocated(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_BINDING,
                                     "integer, bytes or string binding");
    const query_node_t* nodes = query_nodes(e->program);
    query_value_t* bindings = execution_bindings(e);
    int found = 0;
    for (size_t i = 0; i < e->program->count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op != Q_VARIABLE || !query_variable_name(e->program, n, name)) continue;
        found = 1;
        if (n->type != query_private_type(type) || bindings[n->variable_slot].kind)
            return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_BINDING, n->begin, n->end,
                               "unbound variable of declared type");
    }
    if (!found)
        return query_error_unlocated(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_BINDING,
                                     "variable referenced by program");
#if SIZE_MAX > INT64_MAX
    if (type != TLV_QUERY_RESULT_INTEGER && size > INT64_MAX)
        return query_error_unlocated(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_BINDING,
                                     "span length representable as int64");
#endif
    if (type == TLV_QUERY_RESULT_STRING && tlv_utf8_validate(data, size) != TLV_OK)
        return query_error_unlocated(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_BINDING,
                                     "valid UTF-8 string binding");
    query_value_t value = {0};
    value.kind = query_private_type(type);
    if (type == TLV_QUERY_RESULT_INTEGER) {
        value.negative = integer < 0;
        value.number = integer < 0 ? (uint64_t)(-(integer + 1)) + 1 : (uint64_t)integer;
    } else {
        value.data = data;
        value.size = size;
    }
    for (size_t i = 0; i < e->program->count; ++i)
        if (nodes[i].op == Q_VARIABLE && query_variable_name(e->program, &nodes[i], name))
            bindings[nodes[i].variable_slot] = value;
    query_track_borrow(e, value.data, value.size);
    return TLV_OK;
}

tlv_result_t tlv_query_exec_init(const tlv_query_program_t* p, void* storage, size_t capacity,
                                 size_t depth, size_t max_elements, size_t max_work,
                                 tlv_query_exec_t** result) {
    if (!storage || !result) return TLV_ERR_NULL_ARG;
    size_t bytes, alignment;
    tlv_result_t rc = tlv_query_exec_size(p, depth, &bytes, &alignment);
    if (rc != TLV_OK) return rc;
    if ((uintptr_t)storage % alignment || !max_elements || !max_work) return TLV_ERR_INVALID_ARG;
    if (query_overlap(p, p->reserved, storage, capacity) ||
        query_overlap(p, p->reserved, result, sizeof *result) ||
        query_overlap(storage, capacity, result, sizeof *result))
        return TLV_ERR_INVALID_ARG;
    if (capacity < bytes) return TLV_ERR_BUFFER_TOO_SHORT;
    memset(storage, 0, bytes);
    tlv_query_exec_t* e = storage;
    e->program = p;
    e->workspace_size = bytes;
    e->depth_capacity = depth + 1;
    e->max_elements = max_elements;
    e->max_work = max_work;
    e->pattern_capacity = pattern_capacity(p);
    *result = e;
    return TLV_OK;
}

tlv_result_t tlv_query_exec_reset(tlv_query_exec_t* e) {
    if (!e) return TLV_ERR_NULL_ARG;
    if (e->busy) return TLV_ERR_INVALID_STATE;
    tlv_query_exec_t* result;
    return e->retained
               ? tlv_query_eval_init(e->program, e->environment, e, e->workspace_size,
                                     e->depth_capacity - 1, e->node_capacity, e->max_work, &result)
               : tlv_query_exec_init(e->program, e, e->workspace_size, e->depth_capacity - 1,
                                     e->max_elements, e->max_work, &result);
}

static tlv_result_t compare(tlv_query_exec_t* e, query_value_t a, query_value_t b,
                            const query_node_t* n, int* order, tlv_query_diagnostic_t* d) {
    if ((bytes_kind(a) && bytes_kind(b)) || (a.kind == V_STRING && b.kind == V_STRING)) {
        size_t limit = a.size < b.size ? a.size : b.size;
        tlv_result_t rc = charge(e, limit, n, d);
        if (rc != TLV_OK) return rc;
        for (size_t i = 0; i < limit; ++i) {
            unsigned x = byte_at(a, i), y = byte_at(b, i);
            if (x != y) {
                *order = x < y ? -1 : 1;
                return TLV_OK;
            }
        }
        *order = a.size < b.size ? -1 : a.size > b.size;
        return TLV_OK;
    }
    if (a.kind == V_BOOL && b.kind == V_BOOL) {
        *order = a.number < b.number ? -1 : a.number > b.number;
        return TLV_OK;
    }
    if (a.kind == V_NUMBER && b.kind == V_NUMBER) {
        if (a.negative != b.negative)
            *order = a.negative ? -1 : 1;
        else {
            *order = a.number < b.number ? -1 : a.number > b.number;
            if (a.negative) *order = -*order;
        }
        return TLV_OK;
    }
    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_CAPABILITY, n->begin, n->end,
                       "compatible comparison types");
}

tlv_result_t tlv_query_exec_context(tlv_query_exec_t* e, size_t ordinal) {
    if (!e) return TLV_ERR_NULL_ARG;
    if (e->busy) return TLV_ERR_INVALID_STATE;
    if (!e->retained && e->program->level == TLV_QUERY_S1) return TLV_ERR_UNSUPPORTED;
    if (e->elements || e->open || e->invalid || e->finished) return TLV_ERR_INVALID_STATE;
    if (ordinal >= e->max_elements) return TLV_ERR_INVALID_ARG;
    e->has_context = 1;
    e->context_ordinal = ordinal;
    return TLV_OK;
}

tlv_result_t tlv_query_exec_pruning(tlv_query_exec_t* e, int enabled) {
    if (!e) return TLV_ERR_NULL_ARG;
    if (e->busy || e->elements || e->open || e->invalid || e->finished)
        return TLV_ERR_INVALID_STATE;
    if (e->retained) return TLV_ERR_INVALID_ARG;
    e->pruning = enabled != 0;
    return TLV_OK;
}

tlv_result_t tlv_query_exec_info(const tlv_query_exec_t* e, tlv_query_exec_info_t* info) {
    if (!e || !info) return TLV_ERR_NULL_ARG;
    if (query_output_overlap_live(e, info, sizeof info->struct_size) ||
        query_output_overlap_live(
            e, info, info->struct_size < sizeof *info ? info->struct_size : sizeof *info))
        return TLV_ERR_INVALID_ARG;
    if (info->struct_size < offsetof(tlv_query_exec_info_t, work)) return TLV_ERR_INVALID_ARG;
    tlv_query_exec_info_t result = {info->struct_size, e->elements,
                                    e->work,           e->pruned,
                                    e->finished,       e->finished && !e->pruned && !e->invalid,
                                    e->invalid};
    memcpy(info, &result, info->struct_size < sizeof result ? info->struct_size : sizeof result);
    return TLV_OK;
}

static int can_prune(tlv_query_exec_t* e, size_t depth) {
    if (!e->pruning || e->has_context) return 0;
    const query_node_t* nodes = query_nodes(e->program);
    const uint8_t* states = execution_states(e) + depth * e->program->count;
    for (size_t i = 0; i < e->program->count; ++i) {
        if (nodes[i].op == Q_DESC || (nodes[i].op == Q_TEST && nodes[i].axis == A_DESC)) return 0;
        if (nodes[i].type == V_NODE && (states[i] & 1)) return 0;
    }
    return 1;
}

static int root_prefix(tlv_query_exec_t* e, const query_node_t* root, const tlv_tree_event_t* event,
                       unsigned kind) {
    if (!root->anchor || !e->has_context) return kind == Q_DESC || !event->depth;
    return e->context_active && (kind == Q_DESC ? event->depth > e->context_depth
                                                : event->depth == e->context_depth + 1);
}

tlv_result_t query_function_eval(tlv_query_exec_t* e, const tlv_tree_event_t* event,
                                 const query_node_t* n, query_value_t* out,
                                 tlv_query_diagnostic_t* d) {
    const tlv_query_program_t* p = e->program;
    const query_node_t* nodes = query_nodes(p);
    query_value_t* values = execution_values(e);
    uint32_t args[3];
    size_t count = 0;
    uint32_t index = n->left;
    while (index != QUERY_NONE && nodes[index].op == Q_ARGS) {
        if (count == 2)
            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                               "function arity");
        args[count++] = nodes[index].right;
        index = nodes[index].left;
    }
    if (index != QUERY_NONE) args[count++] = index;
    for (size_t i = 0; i < count / 2; ++i) {
        uint32_t temp = args[i];
        args[i] = args[count - 1 - i];
        args[count - 1 - i] = temp;
    }
    query_value_t a = {0}, b = {0}, c = {0};
    if (count) a = values[args[0]];
    if (count > 1) b = values[args[1]];
    if (count > 2) c = values[args[2]];
    if ((n->selector == F_VALUE)) {
        if (count) goto arity;
        out->kind = V_BYTES;
        out->data = event->element.value.data;
        if (event->element.value.size > SIZE_MAX) return TLV_ERR_NATIVE_SIZE;
        out->size = (size_t)event->element.value.size;
        return TLV_OK;
    }
    if ((n->selector == F_LEN)) {
        if (count > 1 || (count && !bytes_kind(a) && a.kind != V_STRING)) goto arity;
        out->kind = V_NUMBER;
        out->number = count ? a.size : event->element.value.size;
        if (out->number > INT64_MAX)
            return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_CAPABILITY, n->begin, n->end,
                               "length representable as int64");
        return TLV_OK;
    }
    if ((n->selector == F_NOT)) {
        if (count != 1 || (a.kind != V_BOOL && a.kind != V_NODE)) goto arity;
        out->kind = V_BOOL;
        out->number = !truth(a);
        return TLV_OK;
    }
    if ((n->selector == F_SUBSTR)) {
        if ((count != 2 && count != 3) || !bytes_kind(a) || b.kind != V_NUMBER ||
            (count == 3 && c.kind != V_NUMBER))
            goto arity;
        if (b.negative || (count == 3 && c.negative))
            return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_CAPABILITY, n->begin,
                               n->end, "nonnegative substring start and length");
        size_t begin = b.number > a.size ? a.size : (size_t)b.number;
        size_t length = a.size - begin;
        if (count == 3 && c.number < length) length = (size_t)c.number;
        *out = a;
        out->data = a.data ? a.data + begin : NULL;
        out->size = length;
        return TLV_OK;
    }
    if ((n->selector == F_MASK) || (n->selector == F_RANGE)) {
        if (count != 2 || !bytes_kind(a) || !bytes_kind(b)) goto arity;
        out->kind = V_NODE;
        if ((n->selector == F_MASK)) {
            if (a.size != b.size) goto arity;
            if (a.size != event->element.tag.size) return TLV_OK;
            tlv_result_t rc = charge(e, a.size, n, d);
            if (rc != TLV_OK) return rc;
            out->number = 1;
            for (size_t i = 0; i < a.size; ++i)
                if ((event->element.tag.data[i] & byte_at(b, i)) != (byte_at(a, i) & byte_at(b, i)))
                    out->number = 0;
        } else {
            query_value_t tag = {0};
            tag.kind = V_BYTES;
            tag.data = event->element.tag.data;
            tag.size = event->element.tag.size;
            int low, high;
            tlv_result_t rc = compare(e, tag, a, n, &low, d);
            if (rc != TLV_OK) return rc;
            rc = compare(e, tag, b, n, &high, d);
            if (rc != TLV_OK) return rc;
            out->number = low >= 0 && high <= 0;
        }
        if (n->anchor && event->depth) out->number = 0;
        return TLV_OK;
    }
    if (count != 2 || !bytes_kind(a) || !bytes_kind(b)) goto arity;
    out->kind = V_BOOL;
    if ((n->selector == F_STARTS) || (n->selector == F_ENDS)) {
        if (b.size > a.size) return TLV_OK;
        size_t begin = (n->selector == F_ENDS) ? a.size - b.size : 0;
        tlv_result_t rc = charge(e, b.size, n, d);
        if (rc != TLV_OK) return rc;
        out->number = 1;
        for (size_t i = 0; i < b.size; ++i)
            if (byte_at(a, begin + i) != byte_at(b, i)) {
                out->number = 0;
                break;
            }
        return TLV_OK;
    }
    if (b.size > e->pattern_capacity)
        return query_limit(d, "pattern", e->pattern_capacity, n->begin, n->end);
    if (b.size > a.size) return TLV_OK;
    if (!b.size) {
        out->number = 1;
        return TLV_OK;
    }
    /* KMP prefix workspace is caller-owned and bounded by program constants.
       The input cursor only advances; fallbacks follow already computed links. */
    size_t* prefix = execution_indexes(e) + e->depth_capacity;
    prefix[0] = 0;
    size_t matched = 0;
    for (size_t i = 1; i < b.size; ++i) {
        for (;;) {
            tlv_result_t rc = charge(e, 1, n, d);
            if (rc != TLV_OK) return rc;
            if (byte_at(b, i) == byte_at(b, matched)) {
                ++matched;
                break;
            }
            if (!matched) break;
            matched = prefix[matched - 1];
        }
        prefix[i] = matched;
    }
    matched = 0;
    for (size_t i = 0; i < a.size; ++i) {
        for (;;) {
            tlv_result_t rc = charge(e, 1, n, d);
            if (rc != TLV_OK) return rc;
            if (byte_at(a, i) == byte_at(b, matched)) {
                ++matched;
                break;
            }
            if (!matched) break;
            matched = prefix[matched - 1];
        }
        if (matched == b.size) {
            out->number = 1;
            break;
        }
    }
    return TLV_OK;
arity:
    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                       "valid function argument types and arity");
}

static tlv_result_t evaluate(tlv_query_exec_t* e, const tlv_tree_event_t* event, int* match,
                             tlv_query_diagnostic_t* d) {
    const tlv_query_program_t* p = e->program;
    const query_node_t* nodes = query_nodes(p);
    query_value_t* values = execution_values(e);
    uint8_t* states = execution_states(e) + event->depth * p->count;
    const uint8_t* parent = event->depth ? states - p->count : NULL;
    memset(values, 0, p->count * sizeof *values);
    for (size_t i = 0; i < p->count; ++i) states[i] &= 8;
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &nodes[i];
        query_value_t out = {0};
        out.kind = V_NODE;
        query_value_t a = {0}, b = {0};
        if (n->left != QUERY_NONE) a = values[n->left];
        if (n->right != QUERY_NONE) b = values[n->right];
        tlv_result_t rc = charge(e, 1, n, d);
        if (rc != TLV_OK) return rc;
        int active = n->predicate_guard == QUERY_NONE || truth(values[n->predicate_guard]);
        if (n->path_guard != QUERY_NONE) {
            int prefix;
            if (n->path_kind == Q_SELF)
                prefix = truth(values[n->path_guard]);
            else if (nodes[n->path_guard].op == Q_ROOT)
                prefix = root_prefix(e, &nodes[n->path_guard], event, n->path_kind);
            else
                prefix = parent && (parent[n->path_guard] & (n->path_kind == Q_DESC ? 2 : 1));
            active = active && prefix;
        }
        if (!active && n->op != Q_TEST) goto store_value;
        switch (n->op) {
            case Q_TEST: {
                if (n->reuse != QUERY_NONE) {
                    out = values[n->reuse];
                    states[i] = states[n->reuse];
                    break;
                }
                rc = charge(e, event->element.tag.size, n, d);
                if (rc != TLV_OK) return rc;
                int raw = tag_test(p, n, event->element.tag);
                unsigned history = states[i] & 8;
                states[i] = (uint8_t)(((raw || (parent && (parent[i] & 4))) ? 4 : 0) | history |
                                      (raw ? 8 : 0));
                if (n->axis == A_PRECEDE_SIBLING)
                    out.number = history != 0;
                else if (n->axis == A_ANCESTOR)
                    out.number = parent && (parent[i] & 4);
                else if (n->axis == A_SELF && n->anchor)
                    out.number = raw && e->has_context && e->elements - 1 == e->context_ordinal;
                else if (n->axis == A_DESC)
                    out.number = raw && (!n->anchor || !e->has_context ||
                                         (e->context_active && event->depth > e->context_depth));
                else
                    out.number =
                        raw &&
                        (!n->anchor ||
                         (e->has_context ? e->context_active && event->depth == e->context_depth + 1
                                         : !event->depth));
                if (!active) out.number = 0;
                break;
            }
            case Q_ROOT:
                out.number = n->anchor && e->has_context && e->elements - 1 == e->context_ordinal;
                break;
            case Q_SELF: out.number = 1; break;
            case Q_CHILD:
            case Q_DESC:
                /* Initial node tests in the right expression are gated by the
                   left prefix. Keeping the result here also makes grouped path
                   composition associative without distributing union branches. */
                out.number = truth(b);
                break;
            case Q_FILTER: out.number = truth(a) && truth(b); break;
#if OPENTLV_QUERY_SET_OPERATIONS
            case Q_UNION: out.number = truth(a) || truth(b); break;
            case Q_INTERSECT: out.number = truth(a) && truth(b); break;
            case Q_EXCEPT: out.number = truth(a) && !truth(b); break;
#endif
            case Q_AND:
            case Q_OR:
                out.kind = V_BOOL;
                out.number = n->op == Q_AND ? truth(a) && truth(b) : truth(a) || truth(b);
                break;
            case Q_META:
                out.kind = V_NUMBER;
                if ((n->selector == TLV_QUERY_META_LEN))
                    out.number = event->element.value.size;
                else if ((n->selector == TLV_QUERY_META_DEPTH))
                    out.number = event->depth;
                else if ((n->selector == TLV_QUERY_META_INDEX))
                    out.number = execution_indexes(e)[event->depth];
                else {
                    int header = (n->selector == TLV_QUERY_META_HLEN);
                    size_t metadata;
                    tlv_result_t source_rc = query_source_metadata(event, header, &metadata);
                    if (source_rc != TLV_OK)
                        return query_error(d, source_rc,
                                           source_rc == TLV_ERR_INVALID_ARG
                                               ? TLV_QUERY_ERROR_EVENTS
                                               : TLV_QUERY_ERROR_SOURCE,
                                           n->begin, n->end, "Source metadata");
                    out.number = metadata;
                }
                if (out.number > INT64_MAX)
                    return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_CAPABILITY, n->begin,
                                       n->end, "metadata representable as int64");
                break;
            case Q_LITERAL:
                out.kind = V_NUMBER;
                out.negative = (int)n->negative;
                out.number = query_immediate(n);
                break;
            case Q_BYTES:
            case Q_STRING:
                out.kind = n->op == Q_BYTES ? V_BYTES : V_STRING;
                out.data = query_payload(p) + n->data_offset;
                out.size = n->data_size;
                break;
            case Q_BOOL:
                out.kind = V_BOOL;
                out.number = n->folded;
                break;
            case Q_VARIABLE: out = execution_bindings(e)[n->variable_slot]; break;
            case Q_EQ:
            case Q_NE:
            case Q_LT:
            case Q_LE:
            case Q_GT:
            case Q_GE: {
                int order;
                rc = compare(e, a, b, n, &order, d);
                if (rc != TLV_OK) return rc;
                out.kind = V_BOOL;
                out.number = n->op == Q_EQ   ? order == 0
                             : n->op == Q_NE ? order != 0
                             : n->op == Q_LT ? order < 0
                             : n->op == Q_LE ? order <= 0
                             : n->op == Q_GT ? order > 0
                                             : order >= 0;
                break;
            }
            case Q_ARGS: out = b; break;
            case Q_CALL:
                rc = query_function_eval(e, event, n, &out, d);
                if (rc != TLV_OK) return rc;
                break;
            default: return TLV_ERR_UNSUPPORTED;
        }
    store_value:
        values[i] = out;
        if (truth(out)) states[i] |= 1;
        if (truth(out) || (parent && (parent[i] & 2))) states[i] |= 2;
    }
    *match = truth(values[p->root]);
    return TLV_OK;
}

/* Proven S1 subset: one root selector with local child/descendant evidence.
   Selected root scopes never overlap, so END order is also result preorder.
   Composition, nested contexts and projections conservatively use S2. */
uint32_t query_s1_filter(const query_node_t* nodes, size_t count, uint32_t root) {
    uint32_t filter = root;
    if (nodes[root].op == Q_CHILD && nodes[nodes[root].left].op == Q_ROOT &&
        !nodes[nodes[root].left].anchor)
        filter = nodes[root].right;
    if (nodes[filter].op != Q_FILTER) return QUERY_NONE;
    const query_node_t* selector = &nodes[nodes[filter].left];
    if (selector->op != Q_TEST || selector->axis != A_CHILD || selector->scalar) return QUERY_NONE;
    uint32_t predicate = nodes[filter].right;
    for (size_t i = nodes[predicate].low; i <= predicate && i < count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op == Q_TEST) {
            if (n->axis != A_CHILD && n->axis != A_DESC) return QUERY_NONE;
        } else if (n->op == Q_LITERAL) {
            if (n->anchor == 2) return QUERY_NONE;
        } else if (n->op == Q_CALL) {
            unsigned fn = n->selector;
            if (fn != F_NOT && fn != F_COUNT && fn != F_EXISTS && fn != F_EMPTY) return QUERY_NONE;
            if (fn != F_NOT && nodes[n->left].op != Q_TEST) return QUERY_NONE;
        } else if (n->op != Q_BOOL && !(n->op >= Q_EQ && n->op <= Q_OR))
            return QUERY_NONE;
    }
    return filter;
}
static tlv_result_t s1_decide(tlv_query_exec_t* e, int* matched, tlv_query_diagnostic_t* d) {
    uint32_t filter = query_s1_filter(query_nodes(e->program), e->program->count, e->program->root);
    const query_node_t* nodes = query_nodes(e->program);
    uint32_t predicate = nodes[filter].right;
    query_value_t* values = execution_values(e);
    for (size_t i = nodes[predicate].low; i <= predicate; ++i) {
        const query_node_t* n = &nodes[i];
        query_value_t v = {0}, a = {0}, b = {0};
        v.kind = n->type;
        if (n->left != QUERY_NONE) a = values[n->left];
        if (n->right != QUERY_NONE) b = values[n->right];
        tlv_result_t rc = charge(e, 1, n, d);
        if (rc != TLV_OK) return rc;
        if (n->op == Q_TEST) continue; /* count collected from complete publications */
        if (n->op == Q_LITERAL) {
            v.negative = (int)n->negative;
            v.number = query_immediate(n);
        } else if (n->op == Q_BOOL)
            v.number = n->folded;
        else if (n->op == Q_CALL) {
            unsigned fn = n->selector;
            v.number = fn == F_COUNT ? a.number : fn == F_EXISTS ? truth(a) : !truth(a);
        } else if (n->op == Q_AND || n->op == Q_OR)
            v.number = n->op == Q_AND ? truth(a) && truth(b) : truth(a) || truth(b);
        else {
            if (a.kind == V_NODE) a.number = truth(a);
            if (b.kind == V_NODE) b.number = truth(b);
            int order;
            rc = compare(e, a, b, n, &order, d);
            if (rc != TLV_OK) return rc;
            v.number = n->op == Q_EQ   ? order == 0
                       : n->op == Q_NE ? order != 0
                       : n->op == Q_LT ? order < 0
                       : n->op == Q_LE ? order <= 0
                       : n->op == Q_GT ? order > 0
                                       : order >= 0;
        }
        values[i] = v;
    }
    *matched = e->delayed_selected && truth(values[predicate]);
    e->delayed_selected = 0;
    return TLV_OK;
}
static tlv_result_t s1_feed(tlv_query_exec_t* e, const tlv_tree_event_t* event, int* matched,
                            tlv_query_diagnostic_t* d) {
    const query_node_t* nodes = query_nodes(e->program);
    uint32_t filter = query_s1_filter(nodes, e->program->count, e->program->root);
    if (e->has_context) return TLV_ERR_UNSUPPORTED;
    if (event->kind == TLV_TREE_END) return event->depth == 0 ? s1_decide(e, matched, d) : TLV_OK;
    if (!event->depth) {
        memset(execution_values(e), 0, e->program->count * sizeof(query_value_t));
        const query_node_t* selector = &nodes[nodes[filter].left];
        tlv_result_t rc = charge(e, 1, selector, d);
        if (rc == TLV_OK) rc = charge(e, event->element.tag.size, selector, d);
        if (rc != TLV_OK) return rc;
        e->delayed_selected = tag_test(e->program, selector, event->element.tag);
        e->delayed = *event;
        if (event->kind == TLV_TREE_ELEMENT) return s1_decide(e, matched, d);
        return TLV_OK;
    }
    if (!e->delayed_selected) return TLV_OK;
    uint32_t predicate = nodes[filter].right;
    for (size_t i = nodes[predicate].low; i <= predicate; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op != Q_TEST || (n->axis == A_CHILD && event->depth != 1)) continue;
        tlv_result_t rc = charge(e, 1, n, d);
        if (rc == TLV_OK) rc = charge(e, event->element.tag.size, n, d);
        if (rc != TLV_OK) return rc;
        query_value_t* v = &execution_values(e)[i];
        v->kind = V_NODE;
        if (tag_test(e->program, n, event->element.tag)) {
            if (v->number == INT64_MAX)
                return query_limit(d, "counter", (size_t)INT64_MAX, n->begin, n->end);
            ++v->number;
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_query_exec_feed(tlv_query_exec_t* e, const tlv_tree_event_t* event, int* matched,
                                 tlv_query_diagnostic_t* d) {
    if (e && e->busy) return TLV_ERR_INVALID_STATE;
    if (e && (query_output_overlap_live(e, matched, matched ? sizeof *matched : 0) ||
              query_output_overlap_live(e, d, d ? sizeof *d : 0) ||
              query_borrow_overlap(e, event, event ? sizeof *event : 0)))
        return TLV_ERR_INVALID_ARG;
    if (event && (query_overlap(event, sizeof *event, matched, matched ? sizeof *matched : 0) ||
                  query_overlap(event, sizeof *event, d, d ? sizeof *d : 0) ||
                  query_overlap(matched, matched ? sizeof *matched : 0, d, d ? sizeof *d : 0)))
        return TLV_ERR_INVALID_ARG;
    if (e && event &&
        (query_borrow_overlap(e, event->element.tag.data, event->element.tag.size) ||
         query_borrow_overlap(e, event->element.value.data, (size_t)event->element.value.size) ||
         query_borrow_overlap(e, event->source.data, event->source.size) ||
         query_overlap(event->element.tag.data, event->element.tag.size, matched,
                       matched ? sizeof *matched : 0) ||
         query_overlap(event->element.value.data, (size_t)event->element.value.size, matched,
                       matched ? sizeof *matched : 0) ||
         query_overlap(event->element.tag.data, event->element.tag.size, d, d ? sizeof *d : 0) ||
         query_overlap(event->element.value.data, (size_t)event->element.value.size, d,
                       d ? sizeof *d : 0) ||
         query_overlap(event->source.data, event->source.size, matched,
                       matched ? sizeof *matched : 0) ||
         query_overlap(event->source.data, event->source.size, d, d ? sizeof *d : 0)))
        return TLV_ERR_INVALID_ARG;
    /* A rejected continuation must not replace the original failure detail. */
    if (e && event && matched && e->invalid) return TLV_ERR_INVALID_STATE;
    query_diag_init(d);
    if (!e || !event || !matched)
        return query_error_unlocated(d, TLV_ERR_NULL_ARG, TLV_QUERY_ERROR_EVENTS,
                                     "required execution arguments");
    if (e->finished)
        return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                     "execution not finished");
    tlv_result_t rc = TLV_OK;
    int match = 0;
    if (!e->elements) {
        rc = bindings_ready(e, d);
        if (rc != TLV_OK) goto failure;
    }
    if (e->program->level == TLV_QUERY_D && !e->document_backend) {
        rc = query_error_unlocated(d, TLV_ERR_UNSUPPORTED, TLV_QUERY_ERROR_CAPABILITY,
                                   "Document execution required");
        goto failure;
    }
    /* Invalid span descriptors are arguments, independently of feed structure. */
    if (event->kind != TLV_TREE_END &&
        ((event->element.tag.size && !event->element.tag.data) ||
         (event->element.value.size && !event->element.value.data))) {
        rc = query_error_unlocated(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_EVENTS,
                                   "valid event span arguments");
        goto failure;
    }
    /* Validate the common event contract before either backend can consume it. */
    if (event->kind == TLV_TREE_END) {
        if (!e->open || event->depth != e->open - 1 ||
            (event->skipped &&
             (e->retained || !e->prune_allowed || e->prune_depth != event->depth)))
            goto events;
    } else if ((event->kind != TLV_TREE_BEGIN && event->kind != TLV_TREE_ELEMENT) ||
               event->depth != e->open || event->skipped)
        goto events;
    if (e->retained) {
        rc = query_retained_feed(e, event, d);
        if (rc != TLV_OK) goto failure;
    }
    if (event->kind == TLV_TREE_END) {
        if (event->skipped) {
            ++e->pruned;
        }
        e->prune_allowed = 0;
        if (e->has_context && e->context_found && event->depth == e->context_depth)
            e->context_active = 0;
        if (!e->retained && e->program->level == TLV_QUERY_S1) {
            rc = s1_feed(e, event, &match, d);
            if (rc != TLV_OK) goto failure;
        }
        --e->open;
    } else {
        if (event->depth >= e->depth_capacity) {
            rc = query_limit(d, "depth", e->depth_capacity - 1, 0, 0);
            goto failure;
        }
        if (e->elements == e->max_elements) {
            rc = query_limit(d, "elements", e->max_elements, 0, 0);
            goto failure;
        }
        e->prune_allowed = 0;
        ++e->elements;
        if (e->has_context && e->elements - 1 == e->context_ordinal) {
            e->context_found = 1;
            e->context_depth = event->depth;
            e->context_active = event->kind == TLV_TREE_BEGIN;
        }
        rc = e->retained                         ? TLV_OK
             : e->program->level == TLV_QUERY_S1 ? s1_feed(e, event, &match, d)
                                                 : evaluate(e, event, &match, d);
        /* Only booleans/indices survive an event; discard borrowed pointers. */
        if (e->program->level != TLV_QUERY_S1 || e->retained)
            memset(execution_values(e), 0, e->program->count * sizeof(query_value_t));
        if (rc != TLV_OK) goto failure;
        ++execution_indexes(e)[event->depth];
        if (event->kind == TLV_TREE_BEGIN) {
            e->prune_allowed = e->program->level == TLV_QUERY_S0 && can_prune(e, event->depth);
            e->prune_depth = event->depth;
            ++e->open;
            if (e->open < e->depth_capacity) {
                execution_indexes(e)[e->open] = 0;
                if (!e->retained)
                    memset(execution_states(e) + e->open * e->program->count, 0, e->program->count);
            }
        }
    }
    e->published_match = match;
    if (e->retained || e->program->level == TLV_QUERY_S1) {
        query_track_borrow(e, event->element.tag.data, event->element.tag.size);
        query_track_borrow(e, event->element.value.data, (size_t)event->element.value.size);
        query_track_borrow(e, event->source.data, event->source.size);
    }
    *matched = match;
    if (match) e->any_match = 1;
    return TLV_OK;
events:
    rc = query_error_unlocated(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_EVENTS,
                               "balanced complete canonical events without pruning");
failure:
    e->invalid = 1;
    if (d && event->source.data) {
        tlv_diagnostic_set_location(&d->diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT,
                                    event->offset, event->offset);
    }
    return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
}

tlv_result_t tlv_query_exec_selected(const tlv_query_exec_t* e, tlv_tree_event_t* event) {
    if (!e || !event) return TLV_ERR_NULL_ARG;
    if (e->busy) return TLV_ERR_INVALID_STATE;
    if (query_output_overlap(e, event, sizeof *event)) return TLV_ERR_INVALID_ARG;
    if (e->invalid) return TLV_ERR_INVALID_STATE;
    if (e->retained || e->program->level != TLV_QUERY_S1) return TLV_ERR_INVALID_ARG;
    if (!e->published_match) return TLV_ERR_INVALID_STATE;
    *event = e->delayed;
    return TLV_OK;
}

tlv_result_t tlv_query_exec_finish(tlv_query_exec_t* e, tlv_query_diagnostic_t* d) {
    if (e && (e->busy || e->invalid)) return TLV_ERR_INVALID_STATE;
    if (e && query_output_overlap(e, d, d ? sizeof *d : 0)) return TLV_ERR_INVALID_ARG;
    query_diag_init(d);
    if (!e)
        return query_error_unlocated(d, TLV_ERR_NULL_ARG, TLV_QUERY_ERROR_EVENTS,
                                     "required execution arguments");
    if (e->program->level == TLV_QUERY_D && !e->document_backend) {
        e->invalid = 1;
        return query_error_unlocated(d, TLV_ERR_UNSUPPORTED, TLV_QUERY_ERROR_CAPABILITY,
                                     "Document execution required");
    }
    if (!e->elements) {
        tlv_result_t rc = bindings_ready(e, d);
        if (rc != TLV_OK)
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
    }
    if (e->open) {
        e->invalid = 1;
        return query_error_unlocated(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_EVENTS,
                                     "balanced final EOF");
    }
    if (e->has_context && !e->context_found) {
        e->invalid = 1;
        return query_error_unlocated(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_EVENTS,
                                     "context present in input");
    }
    if (e->finished) return TLV_OK;
    if (e->retained) {
        e->busy = 1;
        tlv_result_t rc = query_retained_finish(e, d);
        if (!e->busy)
            rc = query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                       "callback preserves execution workspace");
        e->busy = 0;
        if (rc != TLV_OK) {
            e->invalid = 1;
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
        }
    }
    e->finished = 1;
    return TLV_OK;
}

#if OPENTLV_READER
/* Outputs may not alias the cursor, its frames, input bytes or Format descriptor. */
static int reader_output_overlap(const tlv_tree_reader_t* reader, const void* p, size_t n) {
    return query_overlap(reader, sizeof *reader, p, n) ||
           query_overlap(reader->frames, reader->capacity * sizeof *reader->frames, p, n) ||
           query_overlap(reader->input.data, reader->input.size, p, n) ||
           query_overlap(reader->input.format, reader->input.format ? sizeof(tlv_format_t) : 0, p,
                         n);
}

tlv_result_t tlv_query_program_visit(tlv_tree_reader_t* reader, tlv_query_exec_t* e,
                                     tlv_query_event_visitor_t visitor, void* context,
                                     tlv_query_diagnostic_t* d) {
    if (e && (e->busy || e->invalid)) return TLV_ERR_INVALID_STATE;
    if (e && query_output_overlap_live(e, d, d ? sizeof *d : 0)) return TLV_ERR_INVALID_ARG;
    if (reader && reader->capacity > SIZE_MAX / sizeof *reader->frames) return TLV_ERR_INVALID_ARG;
    if (e && reader &&
        (query_output_overlap_live(e, reader, sizeof *reader) ||
         query_output_overlap_live(e, reader->frames, reader->capacity * sizeof *reader->frames) ||
         query_borrow_overlap(e, reader->input.data, reader->input.size)))
        return TLV_ERR_INVALID_ARG;
    if (reader && reader_output_overlap(reader, d, d ? sizeof *d : 0)) return TLV_ERR_INVALID_ARG;
    query_diag_init(d);
    if (!reader || !e || !visitor)
        return query_error_unlocated(d, TLV_ERR_NULL_ARG, TLV_QUERY_ERROR_EVENTS,
                                     "required execution arguments");
    if (e->invalid)
        return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                     "execution reset after failure");
    if (e->program->level == TLV_QUERY_D || e->document_backend)
        return query_error_unlocated(d, TLV_ERR_UNSUPPORTED, TLV_QUERY_ERROR_CAPABILITY,
                                     "Document execution required");
    if (e->retained && e->environment && e->environment->format &&
        !query_format_compatible(reader->input.format, e->environment->format))
        return query_error_unlocated(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_CAPABILITY,
                                     "compatible Reader format");
    if (e->finished && !e->retained) return TLV_OK;
    if (e->finished && e->retained) goto retained_results;
    if (!e->elements) {
        tlv_result_t rc = bindings_ready(e, d);
        if (rc != TLV_OK)
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
    }
    for (;;) {
        tlv_tree_event_t event;
        /* Tree argument/resource failures intentionally leave Reader detail untouched. */
        tlv_reader_diagnostic_t reader_diag = {0};
        e->busy = 1;
        tlv_result_t rc = tlv_tree_reader_next_event_diag(reader, &event, d ? &reader_diag : NULL);
        if (!e->busy) {
            e->invalid = 1;
            return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                         "callback preserves execution workspace");
        }
        e->busy = 0;
        if (rc == TLV_ERR_END_OF_BUFFER) {
            rc = tlv_query_exec_finish(e, d);
            if (rc != TLV_OK || !e->retained)
                return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
            break;
        }
        if (rc == TLV_NEED_MORE_DATA) {
            if (d) {
                d->kind = TLV_QUERY_ERROR_READER;
                d->reader = reader_diag;
                d->reader.diagnostic.code = rc;
                d->diagnostic = d->reader.diagnostic;
            }
            return rc;
        }
        if (rc != TLV_OK) {
            e->invalid = 1;
            if (d) {
                if (reader_diag.diagnostic.code == TLV_OK)
                    tlv_diagnostic_init(&reader_diag.diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
                d->kind =
                    rc == TLV_ERR_INVALID_STATE ? TLV_QUERY_ERROR_STATE : TLV_QUERY_ERROR_READER;
                d->reader = reader_diag;
            }
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
        }
        int matched;
        rc = tlv_query_exec_feed(e, &event, &matched, d);
        if (rc != TLV_OK)
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
        if (event.kind == TLV_TREE_BEGIN && event.element.value.size && e->prune_allowed) {
            rc = tlv_tree_reader_skip_subtree(reader);
            if (rc != TLV_OK) {
                e->invalid = 1;
                if (d) {
                    d->kind = rc == TLV_ERR_INVALID_STATE ? TLV_QUERY_ERROR_STATE
                                                          : TLV_QUERY_ERROR_READER;
                    tlv_reader_diagnostic_init(&d->reader);
                    tlv_diagnostic_init(&d->reader.diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
                    d->diagnostic = d->reader.diagnostic;
                }
                return rc;
            }
        }
        if (matched) {
            tlv_tree_event_t selected = e->program->level == TLV_QUERY_S1 ? e->delayed : event;
            e->busy = 1;
            tlv_visit_result_t result = visitor(&selected, context);
            if (!e->busy) {
                e->invalid = 1;
                return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                             "callback preserves execution workspace");
            }
            e->busy = 0;
            if (result == TLV_VISIT_STOP) return TLV_OK;
            if (result != TLV_VISIT_CONTINUE) {
                e->invalid = 1;
                return query_error_unlocated(
                    d, result == TLV_VISIT_ERROR ? TLV_ERR_VISITOR : TLV_ERR_CALLBACK,
                    TLV_QUERY_ERROR_CALLBACK, "visitor continue or stop");
            }
        }
    }
retained_results:
    if (e->result.kind != TLV_QUERY_RESULT_NODES) return TLV_OK;
    for (;;) {
        tlv_tree_event_t event;
        tlv_result_t rc = tlv_query_result_next(e, &event);
        if (rc == TLV_ERR_END_OF_BUFFER) return TLV_OK;
        if (rc != TLV_OK)
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
        e->any_match = 1;
        e->busy = 1;
        tlv_visit_result_t action = visitor(&event, context);
        if (!e->busy) {
            e->invalid = 1;
            return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                         "callback preserves execution workspace");
        }
        e->busy = 0;
        if (action == TLV_VISIT_STOP) return TLV_OK;
        if (action != TLV_VISIT_CONTINUE) {
            e->invalid = 1;
            return query_error_unlocated(
                d, action == TLV_VISIT_ERROR ? TLV_ERR_VISITOR : TLV_ERR_CALLBACK,
                TLV_QUERY_ERROR_CALLBACK, "visitor continue or stop");
        }
    }
}

static tlv_visit_result_t existence_match(const tlv_tree_event_t* event, void* context) {
    (void)event;
    return *(const int*)context ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
}

tlv_result_t tlv_query_program_exists(tlv_tree_reader_t* reader, tlv_query_exec_t* e, int early,
                                      int* found, tlv_query_diagnostic_t* d) {
    if (e && e->busy) return TLV_ERR_INVALID_STATE;
    if (e && (query_output_overlap_live(e, found, found ? sizeof *found : 0) ||
              query_output_overlap_live(e, d, d ? sizeof *d : 0)))
        return TLV_ERR_INVALID_ARG;
    if (query_overlap(found, found ? sizeof *found : 0, d, d ? sizeof *d : 0))
        return TLV_ERR_INVALID_ARG;
    if (reader && (reader->capacity > SIZE_MAX / sizeof *reader->frames ||
                   reader_output_overlap(reader, found, found ? sizeof *found : 0) ||
                   reader_output_overlap(reader, d, d ? sizeof *d : 0)))
        return TLV_ERR_INVALID_ARG;
    query_diag_init(d);
    if (!reader || !e || !found)
        return query_error_unlocated(d, TLV_ERR_NULL_ARG, TLV_QUERY_ERROR_EVENTS,
                                     "required execution arguments");
    if (e->invalid)
        return query_error_unlocated(d, TLV_ERR_INVALID_STATE, TLV_QUERY_ERROR_STATE,
                                     "execution reset after failure");
    if (!early || !e->any_match) {
        tlv_result_t rc = tlv_query_program_visit(reader, e, existence_match, &early, d);
        if (rc != TLV_OK)
            return query_failure(d, rc, TLV_QUERY_ERROR_EVENTS, "valid execution operation");
    }
    *found = e->any_match;
    return TLV_OK;
}
#endif
