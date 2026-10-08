// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "program_internal.h"
#include "../utf8_internal.h"
#include <stdio.h>

/* The shared retained backend indexes canonical events, never reparses wire bytes.
   Every evaluation frame has explicit bounded node sets. Child references are
   strictly backward in the immutable image; no recursion or VM back edges. */
typedef struct retained_node {
    tlv_tree_event_t event;
    size_t parent, end, sibling;
    void* handle;
    const uint8_t* document_end;
} retained_node_t;
size_t query_candidate_size(void) {
    return sizeof(retained_node_t);
}
size_t query_candidate_alignment(void) {
    struct alignment_probe {
        char prefix;
        retained_node_t node;
    };
    return offsetof(struct alignment_probe, node);
}

typedef struct eval_frame {
    uint32_t instruction, args[3];
    size_t context, position, last, stage, cursor, ordinal, length, arg_count;
    query_value_t value, a, b, c;
    size_t selected;
} eval_frame_t;

static size_t align16(size_t n) {
    return (n + 15) & ~(size_t)15;
}
static query_value_t* eval_values(tlv_query_exec_t* e) {
    return (query_value_t*)(e + 1);
}
static query_value_t* eval_bindings(tlv_query_exec_t* e) {
    return eval_values(e) + e->program->count;
}
static size_t* eval_indexes(tlv_query_exec_t* e) {
    return (size_t*)(eval_bindings(e) + e->program->variable_count);
}
static uint8_t* eval_base(tlv_query_exec_t* e) {
    return (uint8_t*)(eval_indexes(e) + e->depth_capacity + e->pattern_capacity);
}
static retained_node_t* eval_nodes(tlv_query_exec_t* e) {
    return (retained_node_t*)(((uintptr_t)(eval_base(e) +
                                           align16(e->depth_capacity *
                                                   (e->program->count + sizeof(size_t)))) +
                               15) &
                              ~(uintptr_t)15);
}
int query_live_overlap(const tlv_query_exec_t* e, const void* p, size_t size) {
    if (!p || !size) return 0;
    if (query_overlap(e->result.data, e->result.size, p, size)) return 1;
    /* This envelope is only a fast rejection; gaps between live spans are legal.
     * Never scan the retained candidate set on this per-call path. */
    if (!e->borrowed_high ||
        !query_overlap((const void*)e->borrowed_low, e->borrowed_high - e->borrowed_low, p, size))
        return 0;
    const query_value_t* bindings = (const query_value_t*)(e + 1) + e->program->count;
    for (size_t i = 0; i < e->program->variable_count; ++i)
        if (query_overlap(bindings[i].data, bindings[i].size, p, size)) return 1;
    return !e->retained && e->program->level == TLV_QUERY_S1 &&
           (query_overlap(e->delayed.element.tag.data, e->delayed.element.tag.size, p, size) ||
            query_overlap(e->delayed.element.value.data, (size_t)e->delayed.element.value.size, p,
                          size) ||
            query_overlap(e->delayed.source.data, e->delayed.source.size, p, size));
}
int query_retained_overlap(const tlv_query_exec_t* e, const void* p, size_t size) {
    if (!e->retained || !e->borrowed_high ||
        !query_overlap((const void*)e->borrowed_low, e->borrowed_high - e->borrowed_low, p, size))
        return 0;
    const retained_node_t* nodes = eval_nodes((tlv_query_exec_t*)e);
    for (size_t i = 0; i < e->elements; ++i) {
        const tlv_tree_event_t* event = &nodes[i].event;
        if (query_overlap(event->element.tag.data, event->element.tag.size, p, size) ||
            query_overlap(event->element.value.data, (size_t)event->element.value.size, p, size) ||
            query_overlap(event->source.data, event->source.size, p, size))
            return 1;
    }
    return 0;
}
static eval_frame_t* eval_frames(tlv_query_exec_t* e) {
    return (eval_frame_t*)(eval_nodes(e) + e->node_capacity + 1);
}
static uint8_t* eval_sets(tlv_query_exec_t* e) {
    return (uint8_t*)(eval_frames(e) + e->program->count + 1);
}
static uint8_t* frame_set(tlv_query_exec_t* e, size_t frame, int saved) {
    return eval_sets(e) + (2 * frame + (unsigned)saved) * (e->node_capacity + 1);
}
static uint8_t* eval_codec_scratch(tlv_query_exec_t* e) {
    uint8_t* p = eval_sets(e) + 2 * (e->program->count + 1) * (e->node_capacity + 1);
    return (uint8_t*)(((uintptr_t)p + 15) & ~(uintptr_t)15);
}
static tlv_result_t add_size(size_t* size, size_t count, size_t width) {
    if (width && count > (SIZE_MAX - *size) / width) return TLV_ERR_OVERFLOW;
    *size += count * width;
    return TLV_OK;
}
tlv_result_t tlv_query_eval_size(const tlv_query_program_t* p, size_t depth, size_t nodes,
                                 size_t* bytes, size_t* alignment) {
    if (!p || !bytes || !alignment) return TLV_ERR_NULL_ARG;
    if (!query_program_valid(p) || !nodes) return TLV_ERR_INVALID_ARG;
    if (query_overlap(p, p->reserved, bytes, sizeof *bytes) ||
        query_overlap(p, p->reserved, alignment, sizeof *alignment) ||
        query_overlap(bytes, sizeof *bytes, alignment, sizeof *alignment))
        return TLV_ERR_INVALID_ARG;
    if (!query_plan_supported(p)) return TLV_ERR_UNSUPPORTED_TYPE;
    if (depth == SIZE_MAX || nodes == SIZE_MAX) return TLV_ERR_OVERFLOW;
    size_t size = sizeof(tlv_query_exec_t), count = (size_t)p->count + p->variable_count;
    if (add_size(&size, count, sizeof(query_value_t)) != TLV_OK ||
        add_size(&size, depth + 1, sizeof(size_t)) != TLV_OK ||
        add_size(&size, p->pattern_capacity, sizeof(size_t)) != TLV_OK)
        return TLV_ERR_OVERFLOW;
    size_t states = 0;
    if (add_size(&states, depth + 1, p->count + sizeof(size_t)) != TLV_OK || states > SIZE_MAX - 15)
        return TLV_ERR_OVERFLOW;
    if (add_size(&size, 1, align16(states)) != TLV_OK || add_size(&size, 1, 15) != TLV_OK ||
        add_size(&size, nodes + 1, sizeof(retained_node_t)) != TLV_OK ||
        add_size(&size, (size_t)p->count + 1, sizeof(eval_frame_t)) != TLV_OK ||
        add_size(&size, nodes + 1, 2 * ((size_t)p->count + 1)) != TLV_OK ||
        add_size(&size, 1, 15) != TLV_OK || add_size(&size, p->count, p->codec_stride) != TLV_OK)
        return TLV_ERR_OVERFLOW;
    *bytes = size;
    *alignment = 16;
    return TLV_OK;
}
static tlv_result_t compatible(const tlv_query_program_t* p, const tlv_query_environment_t* e) {
    const query_node_t* nodes = query_nodes(p);
    if (e && e->hook_count && !e->hooks) return TLV_ERR_INVALID_ARG;
    if (e)
        for (size_t i = 0; i < e->hook_count; ++i) {
            const tlv_query_hook_t* h = &e->hooks[i];
            if (!h->id || h->function > TLV_QUERY_DATE || !h->scratch_alignment ||
                h->scratch_alignment > 16 || (h->scratch_alignment & (h->scratch_alignment - 1)))
                return TLV_ERR_INVALID_ARG;
            for (size_t j = 0; j < i; ++j)
                if (e->hooks[j].id == h->id || e->hooks[j].function == h->function)
                    return TLV_ERR_INVALID_ARG;
        }
    for (size_t i = 0; i < p->count; ++i) {
        const query_node_t* n = &nodes[i];
        if (n->op != Q_CALL) continue;
        unsigned f = n->selector;
        if (f >= F_NUM && f <= F_DATE && !n->hook_id) return TLV_ERR_INVALID_ARG;
        if (n->hook_id) {
            const tlv_query_hook_t* h = NULL;
            if (e)
                for (size_t j = 0; j < e->hook_count; ++j)
                    if (e->hooks[j].id == n->hook_id) h = &e->hooks[j];
            if (!h || !h->decode || (unsigned)h->function != f - F_NUM ||
                h->scratch_size > n->scratch_size)
                return TLV_ERR_UNSUPPORTED_TYPE;
        }
        if ((f == F_CLASS || f == F_NUMBER) &&
            (!e || !e->tags || e->tags->id != p->tag_id ||
             (f == F_CLASS ? !e->tags->class_of : !e->tags->number_of)))
            return TLV_ERR_UNSUPPORTED_TYPE;
        if (f == F_CONSTRUCTED && (!e || !e->format)) return TLV_ERR_UNSUPPORTED_TYPE;
    }
    return TLV_OK;
}
tlv_result_t tlv_query_eval_init(const tlv_query_program_t* p, const tlv_query_environment_t* env,
                                 void* storage, size_t capacity, size_t depth, size_t nodes,
                                 size_t work, tlv_query_exec_t** result) {
    if (!storage || !result) return TLV_ERR_NULL_ARG;
    size_t bytes, alignment;
    tlv_result_t rc = tlv_query_eval_size(p, depth, nodes, &bytes, &alignment);
    if (rc != TLV_OK) return rc;
    if ((uintptr_t)storage % alignment || !work) return TLV_ERR_INVALID_ARG;
    if (env && env->hook_count > SIZE_MAX / sizeof *env->hooks) return TLV_ERR_INVALID_ARG;
    if (query_overlap(p, p->reserved, storage, capacity) ||
        query_overlap(p, p->reserved, result, sizeof *result) ||
        query_overlap(storage, capacity, result, sizeof *result) ||
        query_overlap(storage, capacity, env, env ? sizeof *env : 0) ||
        query_overlap(result, sizeof *result, env, env ? sizeof *env : 0) ||
        (env &&
         (query_overlap(storage, capacity, env->hooks, env->hook_count * sizeof *env->hooks) ||
          query_overlap(storage, capacity, env->tags, env->tags ? sizeof *env->tags : 0) ||
          query_overlap(storage, capacity, env->format, env->format ? sizeof *env->format : 0) ||
          query_overlap(result, sizeof *result, env->hooks, env->hook_count * sizeof *env->hooks) ||
          query_overlap(result, sizeof *result, env->tags, env->tags ? sizeof *env->tags : 0) ||
          query_overlap(result, sizeof *result, env->format,
                        env->format ? sizeof *env->format : 0))))
        return TLV_ERR_INVALID_ARG;
    if (capacity < bytes) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = compatible(p, env);
    if (rc != TLV_OK) return rc;
    memset(storage, 0, bytes);
    tlv_query_exec_t* e = storage;
    e->program = p;
    e->workspace_size = bytes;
    e->retained = 1;
    e->environment = env;
    e->depth_capacity = depth + 1;
    e->node_capacity = nodes;
    e->max_elements = nodes;
    e->max_work = work;
    e->pattern_capacity = p->pattern_capacity;
    eval_nodes(e)[nodes].parent = nodes;
    eval_nodes(e)[nodes].end = nodes;
    *result = e;
    return TLV_OK;
}
static tlv_result_t eval_charge(tlv_query_exec_t* e, size_t count, const query_node_t* n,
                                tlv_query_diagnostic_t* d) {
    if (count > e->max_work - e->work) return query_limit(d, "work", e->max_work, n->begin, n->end);
    e->work += count;
    return TLV_OK;
}
tlv_result_t query_retained_feed(tlv_query_exec_t* e, const tlv_tree_event_t* event,
                                 tlv_query_diagnostic_t* d) {
    if (event->depth >= e->depth_capacity)
        return query_limit(d, "depth", e->depth_capacity - 1, 0, 0);
    if (event->skipped) return TLV_ERR_INVALID_ARG;
    tlv_result_t work = eval_charge(e, 1, &query_nodes(e->program)[e->program->root], d);
    if (work != TLV_OK) return work;
    retained_node_t* nodes = eval_nodes(e);
    if (event->kind == TLV_TREE_END) {
        if (!e->open || event->depth != e->open - 1) return TLV_ERR_INVALID_ARG;
        size_t index = ((size_t*)(eval_base(e)))[event->depth];
        nodes[index].end = e->elements;
        return TLV_OK;
    }
    if (event->depth != e->open ||
        (event->kind != TLV_TREE_BEGIN && event->kind != TLV_TREE_ELEMENT))
        return TLV_ERR_INVALID_ARG;
    if (e->elements == e->node_capacity)
        return query_limit(d, "candidates", e->node_capacity, 0, 0);
    retained_node_t* n = &nodes[e->elements];
    n->event = *event;
    n->parent = e->node_capacity;
    n->end = event->kind == TLV_TREE_BEGIN ? SIZE_MAX : e->elements + 1;
    n->sibling = eval_indexes(e)[event->depth];
    if (event->depth) n->parent = ((size_t*)eval_base(e))[event->depth - 1];
    if (event->kind == TLV_TREE_BEGIN) ((size_t*)eval_base(e))[event->depth] = e->elements;
    return TLV_OK;
}
static size_t set_count(tlv_query_exec_t* e, const uint8_t* set) {
    size_t count = 0;
    for (size_t i = 0; i <= e->node_capacity; ++i)
        if (set[i]) ++count;
    return count;
}
static int value_truth(query_value_t v) {
    return v.number != 0;
}
static query_value_t signed_value(int64_t x) {
    query_value_t v = {0};
    v.kind = V_NUMBER;
    v.negative = x < 0;
    v.number = x < 0 ? (uint64_t)(-(x + 1)) + 1 : (uint64_t)x;
    return v;
}
static int64_t signed_integer(query_value_t v) {
    return v.negative ? v.number == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)v.number
                      : (int64_t)v.number;
}
static tlv_result_t scalar_call(tlv_query_exec_t* e, eval_frame_t* f, const query_node_t* n,
                                size_t instruction, tlv_query_diagnostic_t* d) {
    unsigned fn = n->selector;
    retained_node_t* nodes = eval_nodes(e);
    size_t context = f->selected != SIZE_MAX ? f->selected : f->context;
    const tlv_tree_event_t* event = context < e->elements ? &nodes[context].event : NULL;
    query_value_t* values = eval_values(e);
    if (fn == F_POSITION || fn == F_LAST) {
        f->value = signed_value((int64_t)(fn == F_POSITION ? f->position : f->last));
        return TLV_OK;
    }
    if (fn == F_COUNT || fn == F_EXISTS || fn == F_EMPTY) {
        f->value = f->a;
        return TLV_OK;
    }
    if ((fn == F_VALUE || fn == F_TAG || fn == F_CONSTRUCTED || fn == F_CLASS || fn == F_NUMBER ||
         (fn == F_LEN && !f->arg_count)) &&
        !event)
        return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_CARDINALITY, n->begin, n->end,
                           "one candidate node");
    if (fn == F_VALUE || fn == F_TAG) {
        f->value.kind = V_BYTES;
        if (fn == F_VALUE) {
            if (event->element.value.size > SIZE_MAX) return TLV_ERR_NATIVE_SIZE;
            f->value.data = event->element.value.data;
            f->value.size = (size_t)event->element.value.size;
        } else {
            f->value.data = event->element.tag.data;
            f->value.size = event->element.tag.size;
        }
        return TLV_OK;
    }
    if (fn == F_CONSTRUCTED) {
        f->value.kind = V_BOOL;
        const tlv_format_t* format = e->environment->format;
        int constructed =
            format->is_constructed && format->is_constructed(format->context, &event->element.tag);
        if (!e->busy) return TLV_ERR_INVALID_STATE;
        f->value.number = constructed;
        return TLV_OK;
    }
    if (fn == F_CLASS || fn == F_NUMBER) {
        int64_t number;
        const tlv_query_tag_adapter_t* tag = e->environment->tags;
        tlv_result_t rc = fn == F_CLASS
                              ? tag->class_of(tag->context, &event->element.tag, &number)
                              : tag->number_of(tag->context, &event->element.tag, &number);
        if (!e->busy) return TLV_ERR_INVALID_STATE;
        if (rc != TLV_OK)
            return query_error(d, rc, TLV_QUERY_ERROR_CAPABILITY, n->begin, n->end,
                               "valid tag decomposition");
        f->value = signed_value(number);
        return TLV_OK;
    }
    if (fn >= F_NUM && fn <= F_DATE) {
        const tlv_query_hook_t* hook = NULL;
        for (size_t i = 0; i < e->environment->hook_count; ++i)
            if (e->environment->hooks[i].id == n->hook_id) hook = &e->environment->hooks[i];
        tlv_query_result_t result = {0};
        tlv_codec_result_t rc =
            hook->decode(hook->context, event, f->a.data, f->a.size,
                         eval_codec_scratch(e) + instruction * e->program->codec_stride,
                         hook->scratch_size, &result);
        if (!e->busy) return TLV_ERR_INVALID_STATE;
        if (rc != TLV_CODEC_OK) {
            if (d) d->codec = rc;
            return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_CODEC, n->begin, n->end,
                               "strict complete-Value decoding");
        }
        if (query_private_type(result.kind) != n->type || (result.size && !result.data)) {
            if (d) d->codec = TLV_CODEC_ERR_INVALID_VALUE;
            return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_CODEC, n->begin, n->end,
                               "declared codec result type");
        }
        if (result.kind == TLV_QUERY_RESULT_INTEGER)
            f->value = signed_value(result.integer);
        else {
            tlv_result_t work = eval_charge(e, result.size, n, d);
            if (work != TLV_OK) return work;
            if (tlv_utf8_validate(result.data, result.size) != TLV_OK) {
                if (d) d->codec = TLV_CODEC_ERR_INVALID_VALUE;
                return query_error(d, TLV_ERR_INVALID_VALUE, TLV_QUERY_ERROR_CODEC, n->begin,
                                   n->end, "UTF-8 decoded string");
            }
            f->value.kind = V_STRING;
            f->value.data = result.data;
            f->value.size = result.size;
        }
        return TLV_OK;
    }
    if (fn == F_MASK || fn == F_RANGE) {
        values[f->args[0]] = f->a;
        values[f->args[1]] = f->b;
        query_node_t step = *n;
        step.anchor = 0;
        uint8_t* out = frame_set(e, (size_t)(f - eval_frames(e)), 0);
        for (size_t i = 0; i < e->elements; ++i) {
            if (nodes[i].parent != f->context) continue;
            query_value_t selected = {0};
            tlv_result_t rc = query_function_eval(e, &nodes[i].event, &step, &selected, d);
            if (rc != TLV_OK) return rc;
            out[i] = selected.number != 0;
        }
        f->value.kind = V_NODE;
        return TLV_OK;
    }
    if (f->arg_count) values[f->args[0]] = f->a;
    if (f->arg_count > 1) values[f->args[1]] = f->b;
    if (f->arg_count > 2) values[f->args[2]] = f->c;
    tlv_tree_event_t empty = {0};
    return query_function_eval(e, event ? event : &empty, n, &f->value, d);
}
static size_t args_of(const query_node_t* nodes, const query_node_t* n, uint32_t args[3]) {
    uint32_t cursor = n->left;
    size_t count = 0;
    while (cursor != QUERY_NONE && nodes[cursor].op == Q_ARGS) {
        if (count == 2) return 4;
        args[count++] = nodes[cursor].right;
        cursor = nodes[cursor].left;
    }
    if (cursor != QUERY_NONE) args[count++] = cursor;
    for (size_t i = 0; i < count / 2; ++i) {
        uint32_t t = args[i];
        args[i] = args[count - i - 1];
        args[count - i - 1] = t;
    }
    return count;
}
static void push_frame(tlv_query_exec_t* e, size_t index, uint32_t instruction, size_t context,
                       size_t position, size_t last) {
    eval_frame_t* f = &eval_frames(e)[index];
    memset(f, 0, sizeof *f);
    f->instruction = instruction;
    f->context = context;
    f->position = position;
    f->last = last;
    f->selected = SIZE_MAX;
    memset(frame_set(e, index, 0), 0, 2 * (e->node_capacity + 1));
}
static tlv_result_t eval_failure(tlv_query_exec_t* e, const eval_frame_t* f, tlv_result_t rc,
                                 tlv_query_diagnostic_t* d) {
    size_t selected = f->selected < e->elements ? f->selected : f->context;
    if (d && selected < e->elements) {
        const retained_node_t* node = &eval_nodes(e)[selected];
        size_t offset;
        tlv_result_t location = e->document_metadata
                                    ? e->document_metadata(node->handle, 0, &offset)
                                    : query_source_metadata(&node->event, 0, &offset);
        if (location == TLV_OK) {
            d->has_source_offset = 1;
            d->source_offset = offset;
        }
    }
    return rc;
}
tlv_result_t query_retained_finish(tlv_query_exec_t* e, tlv_query_diagnostic_t* d) {
    const query_node_t* instructions = query_nodes(e->program);
    retained_node_t* nodes = eval_nodes(e);
    size_t top = 0, virtual_root = e->node_capacity;
    push_frame(e, 0, e->program->root, e->has_context ? e->context_ordinal : virtual_root, 1, 1);
    for (;;) {
        eval_frame_t* f = &eval_frames(e)[top];
        const query_node_t* n = &instructions[f->instruction];
        uint8_t* out = frame_set(e, top, 0);
        uint8_t* saved = frame_set(e, top, 1);
        tlv_result_t rc = eval_charge(e, 1 + 5 * (e->node_capacity + 1), n, d);
        if (rc != TLV_OK) return eval_failure(e, f, rc, d);
        if (!f->stage) {
            f->value.kind = n->type;
            if (n->op == Q_TEST) {
                for (size_t i = 0; i < e->elements; ++i) {
                    rc = eval_charge(e, 1 + nodes[i].event.element.tag.size, n, d);
                    if (rc != TLV_OK) return eval_failure(e, f, rc, d);
                    int candidate = 0;
                    switch (n->axis) {
                        case A_SELF: candidate = i == f->context; break;
                        case A_CHILD: candidate = nodes[i].parent == f->context; break;
                        case A_DESC:
                        case A_DESC_SELF:
                            candidate = f->context == virtual_root ||
                                        (i >= f->context + (n->axis == A_DESC) &&
                                         i < nodes[f->context].end);
                            break;
                        case A_PARENT:
                            candidate = f->context < e->elements && i == nodes[f->context].parent;
                            break;
                        case A_ANCESTOR:
                        case A_ANCESTOR_SELF:
                            candidate = f->context < e->elements &&
                                        (i < f->context ||
                                         (i == f->context && n->axis == A_ANCESTOR_SELF)) &&
                                        nodes[i].end > f->context;
                            break;
                        case A_FOLLOW_SIBLING:
                        case A_PRECEDE_SIBLING:
                            candidate =
                                f->context < e->elements &&
                                nodes[i].parent == nodes[f->context].parent &&
                                (n->axis == A_FOLLOW_SIBLING ? i > f->context : i < f->context);
                            break;
                        case A_FOLLOW:
                            candidate = f->context < e->elements && i >= nodes[f->context].end;
                            break;
                        case A_PRECEDE:
                            candidate = f->context < e->elements && i < f->context &&
                                        nodes[i].end <= f->context;
                            break;
                    }
                    int match = query_plan_tag(e->program, n, nodes[i].event.element.tag);
                    out[i] = (uint8_t)(candidate && match);
                }
                if (n->axis == A_PARENT && f->context < e->elements &&
                    nodes[f->context].parent == virtual_root && n->context)
                    out[virtual_root] = 1;
                goto complete;
            }
            if (n->op == Q_ROOT || n->op == Q_SELF) {
                size_t context =
                    n->op == Q_SELF || n->anchor || n->context ? f->context : virtual_root;
                out[context] = 1;
                goto complete;
            }
            if (n->op == Q_BYTES || n->op == Q_STRING) {
                f->value.data = query_payload(e->program) + n->data_offset;
                f->value.size = n->data_size;
                goto complete;
            }
            if (n->op == Q_BOOL) {
                f->value.number = n->folded;
                goto complete;
            }
            if (n->op == Q_VARIABLE) {
                f->value = eval_bindings(e)[n->variable_slot];
                goto complete;
            }
            if (n->op == Q_LITERAL) {
                f->value.negative = (int)n->negative;
                f->value.number = query_immediate(n);
                goto complete;
            }
            if (n->op == Q_META) {
                if (f->context == virtual_root)
                    return eval_failure(e, f,
                                        query_error(d, TLV_ERR_INVALID_VALUE,
                                                    TLV_QUERY_ERROR_CARDINALITY, n->begin, n->end,
                                                    "candidate metadata"),
                                        d);
                const tlv_tree_event_t* event = &nodes[f->context].event;
                uint64_t value;
                if ((n->selector == TLV_QUERY_META_LEN))
                    value = event->element.value.size;
                else if ((n->selector == TLV_QUERY_META_DEPTH))
                    value = event->depth;
                else if ((n->selector == TLV_QUERY_META_INDEX))
                    value = nodes[f->context].sibling;
                else {
                    int header = (n->selector == TLV_QUERY_META_HLEN);
                    size_t metadata;
                    tlv_result_t source_rc =
                        e->document_metadata
                            ? e->document_metadata(nodes[f->context].handle, header, &metadata)
                            : query_source_metadata(event, header, &metadata);
                    if (source_rc != TLV_OK)
                        return eval_failure(e, f,
                                            query_error(d, source_rc,
                                                        source_rc == TLV_ERR_INVALID_ARG
                                                            ? TLV_QUERY_ERROR_EVENTS
                                                            : TLV_QUERY_ERROR_SOURCE,
                                                        n->begin, n->end, "Source metadata"),
                                            d);
                    value = metadata;
                }
                if (value > INT64_MAX)
                    return eval_failure(e, f,
                                        query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_CAPABILITY,
                                                    n->begin, n->end, "int64 metadata"),
                                        d);
                f->value.number = value;
                goto complete;
            }
            if (n->op == Q_CALL) {
                f->arg_count = args_of(instructions, n, f->args);
                if (!f->arg_count) {
                    rc = scalar_call(e, f, n, f->instruction, d);
                    if (!e->busy) return TLV_ERR_INVALID_STATE;
                    if (rc != TLV_OK) return eval_failure(e, f, rc, d);
                    goto complete;
                }
                f->stage = 10;
                push_frame(e, ++top, f->args[0], f->context, f->position, f->last);
                continue;
            }
            f->stage = 1;
            push_frame(e, ++top, n->left, f->context, f->position, f->last);
            continue;
        }
        /* A completed child lives in frame top+1 until the next push. */
        eval_frame_t* child = &eval_frames(e)[top + 1];
        uint8_t* child_set = frame_set(e, top + 1, 0);
        if (f->stage >= 10) {
            size_t arg = f->stage - 10;
            query_value_t v = child->value;
            unsigned fn = n->selector;
            if (v.kind == V_NODE) {
                size_t count = set_count(e, child_set);
                if (fn == F_COUNT || fn == F_EXISTS || fn == F_EMPTY) {
                    v = signed_value((int64_t)count);
                    if (fn != F_COUNT) {
                        v.kind = V_BOOL;
                        v.number = fn == F_EXISTS ? count != 0 : count == 0;
                    }
                } else if (fn == F_NOT) {
                    v.kind = V_BOOL;
                    v.number = count != 0;
                } else {
                    if (count != 1)
                        return eval_failure(e, f,
                                            query_error(d, TLV_ERR_INVALID_VALUE,
                                                        TLV_QUERY_ERROR_CARDINALITY, n->begin,
                                                        n->end, "exactly one node"),
                                            d);
                    size_t selected = 0;
                    while (!child_set[selected]) ++selected;
                    if (selected == virtual_root)
                        return eval_failure(e, f,
                                            query_error(d, TLV_ERR_INVALID_VALUE,
                                                        TLV_QUERY_ERROR_CARDINALITY, n->begin,
                                                        n->end, "one concrete node"),
                                            d);
                    f->selected = selected;
                    if (fn >= F_NUM && fn <= F_DATE) {
                        v.kind = V_BYTES;
                        v.data = nodes[selected].event.element.value.data;
                        if (nodes[selected].event.element.value.size > SIZE_MAX)
                            return TLV_ERR_NATIVE_SIZE;
                        v.size = (size_t)nodes[selected].event.element.value.size;
                    }
                }
            }
            if (!arg)
                f->a = v;
            else if (arg == 1)
                f->b = v;
            else
                f->c = v;
            if (++arg < f->arg_count) {
                ++f->stage;
                push_frame(e, ++top, f->args[arg], f->context, f->position, f->last);
                continue;
            }
            rc = scalar_call(e, f, n, f->instruction, d);
            if (!e->busy) return TLV_ERR_INVALID_STATE;
            if (rc != TLV_OK) return eval_failure(e, f, rc, d);
            if (f->value.kind == V_NODE && f->value.number && f->context < e->elements)
                out[f->context] = 1;
            goto complete;
        }
        if (f->stage == 1) {
            f->a = child->value;
            memcpy(saved, child_set, e->node_capacity + 1);
            if (n->op == Q_CHILD || n->op == Q_DESC || n->op == Q_FILTER) {
                if (n->op == Q_DESC) {
                    if (saved[virtual_root]) {
                        for (size_t i = 0; i < e->elements; ++i) saved[i] = 1;
                    } else
                        for (size_t i = 0; i < e->elements; ++i)
                            if (saved[i])
                                for (size_t j = i + 1; j < nodes[i].end; ++j) {
                                    rc = eval_charge(e, 1, n, d);
                                    if (rc != TLV_OK) return eval_failure(e, f, rc, d);
                                    saved[j] = 1;
                                }
                }
                f->cursor = 0;
                f->length = set_count(e, saved);
                f->stage = 3;
            } else {
                f->stage = 2;
                push_frame(e, ++top, n->right, f->context, f->position, f->last);
                continue;
            }
        } else if (f->stage == 2) {
            f->b = child->value;
#if OPENTLV_QUERY_SET_OPERATIONS
            if (n->op == Q_UNION || n->op == Q_INTERSECT || n->op == Q_EXCEPT) {
                for (size_t i = 0; i <= e->node_capacity; ++i)
                    out[i] = (uint8_t)(n->op == Q_UNION       ? saved[i] || child_set[i]
                                       : n->op == Q_INTERSECT ? saved[i] && child_set[i]
                                                              : saved[i] && !child_set[i]);
            } else
#endif
                if (n->op == Q_AND || n->op == Q_OR)
                f->value.number = n->op == Q_AND ? value_truth(f->a) && value_truth(f->b)
                                                 : value_truth(f->a) || value_truth(f->b);
            else {
                int order;
                if (f->a.kind == V_NUMBER) {
                    int64_t a = signed_integer(f->a), b = signed_integer(f->b);
                    order = a < b ? -1 : a > b;
                } else if (f->a.kind == V_BOOL)
                    order = f->a.number < f->b.number ? -1 : f->a.number > f->b.number;
                else {
                    size_t size = f->a.size < f->b.size ? f->a.size : f->b.size;
                    rc = eval_charge(e, size, n, d);
                    if (rc != TLV_OK) return eval_failure(e, f, rc, d);
                    order = size ? memcmp(f->a.data, f->b.data, size) : 0;
                    if (!order) order = f->a.size < f->b.size ? -1 : f->a.size > f->b.size;
                }
                f->value.number = n->op == Q_EQ   ? order == 0
                                  : n->op == Q_NE ? order != 0
                                  : n->op == Q_LT ? order < 0
                                  : n->op == Q_LE ? order <= 0
                                  : n->op == Q_GT ? order > 0
                                                  : order >= 0;
            }
            goto complete;
        } else if (f->stage == 4) {
            if (n->op == Q_FILTER) {
                int yes = child->value.kind == V_NUMBER
                              ? !child->value.negative && child->value.number == f->ordinal
                              : value_truth(child->value);
                if (yes) out[f->selected] = 1;
            } else
                for (size_t i = 0; i <= e->node_capacity; ++i)
                    if (child_set[i]) out[i] = 1;
            ++f->cursor;
            f->stage = 3;
        }
        if (f->stage == 3) {
            uint32_t axis = n->left;
            while (instructions[axis].op == Q_FILTER && !instructions[axis].grouped)
                axis = instructions[axis].left;
            int reverse = n->op == Q_FILTER && !instructions[axis].grouped &&
                          instructions[axis].op == Q_TEST &&
                          query_reverse_axis(instructions[axis].axis);
            while (f->cursor <= e->node_capacity &&
                   !saved[reverse ? e->node_capacity - f->cursor : f->cursor])
                ++f->cursor;
            if (f->cursor > e->node_capacity) goto complete;
            f->selected = reverse ? e->node_capacity - f->cursor : f->cursor;
            ++f->ordinal;
            f->stage = 4;
            push_frame(e, ++top, n->right, f->selected, n->op == Q_FILTER ? f->ordinal : 1,
                       n->op == Q_FILTER ? f->length : 1);
            continue;
        }
        return TLV_ERR_INVALID_ARG;
    complete:
        if (f->value.kind == V_NODE) {
            f->value.number = set_count(e, out) != 0;
        }
        if (!top) break;
        --top;
    }
    eval_frame_t* root = &eval_frames(e)[0];
    memset(&e->result, 0, sizeof e->result);
    e->result.kind = query_public_type(root->value.kind);
    e->result.boolean = value_truth(root->value);
    if (root->value.kind == V_NUMBER) e->result.integer = signed_integer(root->value);
    e->result.data = root->value.data;
    e->result.size = root->value.size;
    return TLV_OK;
}
tlv_result_t tlv_query_exec_result(const tlv_query_exec_t* e, tlv_query_result_t* result) {
    if (!e || !result) return TLV_ERR_NULL_ARG;
    if (e->busy || e->invalid) return TLV_ERR_INVALID_STATE;
    if (query_output_overlap(e, result, sizeof *result)) return TLV_ERR_INVALID_ARG;
    if (e->document_current && !e->document_current(e->document_owner, e->document_revision))
        return TLV_ERR_INVALID_STATE;
    if (!e->finished || e->invalid) return TLV_ERR_INVALID_STATE;
    if (!e->retained) return TLV_ERR_INVALID_ARG;
    *result = e->result;
    return TLV_OK;
}
static tlv_result_t result_next(tlv_query_exec_t* e, tlv_tree_event_t* event, size_t* ordinal) {
    if (!e || !event) return TLV_ERR_NULL_ARG;
    if (e->busy || e->invalid) return TLV_ERR_INVALID_STATE;
    if (query_output_overlap_live(e, event, sizeof *event)) return TLV_ERR_INVALID_ARG;
    if (e->document_current && !e->document_current(e->document_owner, e->document_revision))
        return TLV_ERR_INVALID_STATE;
    if (!e->finished || e->invalid) return TLV_ERR_INVALID_STATE;
    if (!e->retained || e->result.kind != TLV_QUERY_RESULT_NODES) return TLV_ERR_INVALID_ARG;
    while (e->result_cursor < e->elements) {
        size_t i = e->result_cursor;
        if (frame_set(e, 0, 0)[i]) {
            const tlv_tree_event_t* selected = &eval_nodes(e)[i].event;
            if (query_event_overlap(selected, event, sizeof *event) ||
                query_event_overlap(selected, ordinal, ordinal ? sizeof *ordinal : 0))
                return TLV_ERR_INVALID_ARG;
            *event = *selected;
            if (ordinal) *ordinal = i;
            ++e->result_cursor;
            return TLV_OK;
        }
        ++e->result_cursor;
    }
    return TLV_ERR_END_OF_BUFFER;
}
tlv_result_t tlv_query_result_next(tlv_query_exec_t* e, tlv_tree_event_t* event) {
    return result_next(e, event, NULL);
}

tlv_result_t tlv_query_result_next_ordinal(tlv_query_exec_t* e, tlv_tree_event_t* event,
                                           size_t* ordinal) {
    if (!ordinal) return TLV_ERR_NULL_ARG;
    if ((e && query_output_overlap_live(e, ordinal, sizeof *ordinal)) ||
        query_overlap(ordinal, sizeof *ordinal, event, event ? sizeof *event : 0))
        return TLV_ERR_INVALID_ARG;
    return result_next(e, event, ordinal);
}
tlv_result_t tlv_query_program_explain(const tlv_query_program_t* p, char* output, size_t capacity,
                                       size_t* required) {
    if (!p || !required || (!output && capacity)) return TLV_ERR_NULL_ARG;
    if (query_overlap(p, p->reserved, output, capacity) ||
        query_overlap(p, p->reserved, required, sizeof *required) ||
        query_overlap(output, capacity, required, sizeof *required))
        return TLV_ERR_INVALID_ARG;
    if (!query_program_valid(p)) return TLV_ERR_INVALID_ARG;
    size_t total = 0;
    for (unsigned pass = 0; pass < 2; ++pass) {
        size_t pos = 0;
        for (size_t i = 0; i < p->count; ++i) {
            const query_node_t* n = &query_nodes(p)[i];
            char line[192];
            int size = snprintf(line, sizeof line, "%lu op=%u type=%u level=%u reuse=%u hook=%u\n",
                                (unsigned long)i, n->op, n->type, p->level, n->reuse, n->hook_id);
            if (size < 0 || (size_t)size >= sizeof line || (size_t)size > SIZE_MAX - pos)
                return TLV_ERR_OVERFLOW;
            if (pass && output) memcpy(output + pos, line, (size_t)size);
            pos += (size_t)size;
        }
        if (!pass) {
            total = pos;
            if (total == SIZE_MAX) return TLV_ERR_OVERFLOW;
            *required = total + 1;
            if (!output) return TLV_OK;
            if (capacity <= total) return TLV_ERR_BUFFER_TOO_SHORT;
        }
    }
    output[total] = 0;
    return TLV_OK;
}

void query_document_handle(tlv_query_exec_t* e, void* handle, const uint8_t* end) {
    if (e->elements < e->node_capacity) {
        eval_nodes(e)[e->elements].handle = handle;
        eval_nodes(e)[e->elements].document_end = end;
    }
}
const uint8_t* query_document_end(tlv_query_exec_t* e) {
    return eval_nodes(e)[((size_t*)eval_base(e))[e->open - 1]].document_end;
}
tlv_result_t query_document_next(tlv_query_exec_t* e, void** handle) {
    if (!e || !handle) return TLV_ERR_NULL_ARG;
    if (!e->finished || e->invalid) return TLV_ERR_INVALID_STATE;
    if (!e->document_backend || e->result.kind != TLV_QUERY_RESULT_NODES)
        return TLV_ERR_INVALID_ARG;
    while (e->result_cursor < e->elements) {
        size_t i = e->result_cursor++;
        if (frame_set(e, 0, 0)[i]) {
            *handle = eval_nodes(e)[i].handle;
            return TLV_OK;
        }
    }
    return TLV_ERR_END_OF_BUFFER;
}

tlv_result_t query_document_result_count(const tlv_query_exec_t* e, size_t* count) {
    if (!e || !count) return TLV_ERR_NULL_ARG;
    if (!e->finished || e->invalid) return TLV_ERR_INVALID_STATE;
    if (!e->document_backend || e->result.kind != TLV_QUERY_RESULT_NODES)
        return TLV_ERR_INVALID_ARG;
    size_t total = 0;
    for (size_t i = 0; i < e->elements; ++i)
        if (frame_set((tlv_query_exec_t*)e, 0, 0)[i]) ++total;
    *count = total;
    return TLV_OK;
}
