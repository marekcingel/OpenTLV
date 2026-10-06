// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "program_internal.h"
#include "../document/document_internal.h"
#include "../writer/tree_internal.h"
#include "tlv/reader/reader.h"

typedef struct document_source {
    const tlv_node_t* next;
    size_t depth;
    int closing;
} document_source_t;
static int document_current(const void* owner, uint64_t revision) {
    return tlv_document_revision(owner) == revision;
}
static tlv_result_t document_metadata(const void* handle, int header, size_t* value) {
    tlv_document_source_location_t location = tlv_node_source_location(handle);
    if (header ? !location.has_header_size : !location.has_offset) return TLV_ERR_INVALID_VALUE;
    *value = header ? location.header_size : location.offset;
    return TLV_OK;
}

/* Public topology provides balanced events independently of wire representation. */
static tlv_result_t document_event(void* context, tlv_tree_event_t* event) {
    document_source_t* source = context;
    const tlv_node_t* node = source->next;
    if (!node) return TLV_ERR_END_OF_BUFFER;
    memset(event, 0, sizeof *event);
    event->depth = source->depth;
    if (source->closing)
        event->kind = TLV_TREE_END;
    else {
        event->kind = tlv_node_is_constructed(node) ? TLV_TREE_BEGIN : TLV_TREE_ELEMENT;
        event->element.tag = tlv_node_tag(node);
        event->element.value.data = tlv_node_value_data(node);
        event->element.value.size = tlv_node_value_size(node);
        event->offset = tlv_node_source_location(node).offset;
        if (event->kind == TLV_TREE_BEGIN) {
            if (tlv_node_first_child(node)) {
                source->next = tlv_node_first_child(node);
                ++source->depth;
            } else
                source->closing = 1;
            return TLV_OK;
        }
    }
    source->closing = 0;
    if (tlv_node_next(node))
        source->next = tlv_node_next(node);
    else if (source->depth) {
        source->next = tlv_node_parent(node);
        --source->depth;
        source->closing = 1;
    } else
        source->next = NULL;
    return TLV_OK;
}
typedef struct document_budget {
    tlv_query_exec_t* exec;
    tlv_query_diagnostic_t* diagnostic;
} document_budget_t;
static tlv_result_t document_charge(void* context, size_t amount) {
    document_budget_t* budget = context;
    tlv_query_exec_t* e = budget->exec;
    if (amount > e->max_work - e->work)
        return query_limit(budget->diagnostic, "work", e->max_work, 0, 0);
    e->work += amount;
    return TLV_OK;
}

tlv_result_t tlv_document_query_value_size(const tlv_document_t* document,
                                           tlv_tree_writer_workspace_t* staging, size_t* bytes) {
    if (!document || !staging || !bytes) return TLV_ERR_NULL_ARG;
    document_source_t source = {tlv_document_first(document), 0, 0};
    return tlv_tree_writer_measure_events(document_format(document), document_event, &source,
                                          staging, SIZE_MAX, SIZE_MAX, bytes, NULL);
}

tlv_result_t tlv_document_query_evaluate(const tlv_document_t* document, tlv_query_exec_t* e,
                                         const tlv_node_t* context, void* storage, size_t capacity,
                                         tlv_tree_writer_workspace_t* staging,
                                         tlv_query_diagnostic_t* d) {
    if (e && (e->busy || query_output_overlap(e, d, d ? sizeof *d : 0) ||
              query_output_overlap(e, storage, capacity)))
        return TLV_ERR_INVALID_ARG;
    if (e && staging &&
        (staging->frame_capacity > SIZE_MAX / sizeof *staging->frames ||
         query_output_overlap(e, staging, sizeof *staging) ||
         query_output_overlap(e, staging->frames,
                              staging->frame_capacity * sizeof *staging->frames) ||
         query_output_overlap(e, staging->scratch, staging->scratch_capacity)))
        return TLV_ERR_INVALID_ARG;
    query_diag_init(d);
    if (!document || !e || (!storage && capacity)) return TLV_ERR_NULL_ARG;
    if (document->query_callbacks || !e->retained || e->elements || e->open || e->finished ||
        e->invalid || e->has_context || (context && !document_contains(document, context)))
        return TLV_ERR_INVALID_ARG;
    const tlv_format_t* format = document_format(document);
    if (e->environment && e->environment->format &&
        !query_format_compatible(e->environment->format, format))
        return TLV_ERR_INVALID_ARG;
    int values = query_program_needs_values(e->program);
    if (values && !staging) return TLV_ERR_NULL_ARG;
    document_query_callback((tlv_document_t*)document, 1);
    e->document_backend = 1;
    e->document_owner = document;
    e->document_revision = tlv_document_revision(document);
    e->document_current = document_current;
    e->document_metadata = document_metadata;
    document_budget_t budget = {e, d};
    tlv_result_t rc = TLV_OK;
    size_t encoded = 0;
    const uint8_t* cursor = storage;
    const uint8_t* wire_end = NULL;
    if (values) {
        document_source_t source = {tlv_document_first(document), 0, 0};
        /* Encode directly into the final snapshot: staging output is only needed
         * for discovery, and may be reused as storage here. */
        tlv_tree_writer_workspace_t output = *staging;
        output.data = storage;
        output.data_capacity = capacity;
        e->busy = 1;
        rc = tree_writer_measure_events_observed(format, document_event, &source, &output,
                                                 e->depth_capacity - 1, e->max_elements, &encoded,
                                                 NULL, document_charge, &budget);
        if (!e->busy) rc = TLV_ERR_INVALID_ARG;
        e->busy = 0;
        staging->required_data = output.required_data;
        staging->required_scratch = output.required_scratch;
        if (rc == TLV_ERR_BUFFER_TOO_SHORT && output.required_data) {
            rc = query_limit(d, "document-values", capacity, 0, 0);
            goto failed;
        }
        if (rc != TLV_OK) goto failed;
        wire_end = encoded ? cursor + encoded : cursor;
    }
    document_source_t source = {tlv_document_first(document), 0, 0};
    for (;;) {
        const tlv_node_t* node = source.next;
        tlv_tree_event_t event;
        rc = document_event(&source, &event);
        if (rc == TLV_ERR_END_OF_BUFFER) break;
        if (rc != TLV_OK) goto failed;
        rc = document_charge(&budget, 1);
        if (rc != TLV_OK) goto failed;
        const uint8_t* end = NULL;
        if (values) {
            if (event.kind == TLV_TREE_END)
                cursor = query_document_end(e);
            else {
                tlv_element_t element;
                size_t consumed;
                e->busy = 1;
                rc = tlv_read(cursor, (size_t)(wire_end - cursor), format, &element, &consumed);
                if (!e->busy) rc = TLV_ERR_INVALID_ARG;
                e->busy = 0;
                if (rc != TLV_OK) goto failed;
                rc = document_charge(&budget, consumed);
                if (rc != TLV_OK) goto failed;
                end = cursor + consumed;
                /* The wire is only a Value snapshot. Original locations come
                 * from Document provenance, never from this serialization. */
                event.element.value = element.value;
                cursor = event.kind == TLV_TREE_BEGIN ? element.value.data : end;
            }
        }
        if (event.kind != TLV_TREE_END && node == context) {
            e->has_context = 1;
            e->context_ordinal = e->elements;
        }
        int matched;
        if (event.kind != TLV_TREE_END) query_document_handle(e, (void*)node, end);
        rc = tlv_query_exec_feed(e, &event, &matched, d);
        if (rc != TLV_OK) goto failed;
    }
    rc = tlv_query_exec_finish(e, d);
failed:
    {
        int deferred = document_query_callback((tlv_document_t*)document, 0);
        if (deferred) {
            if (deferred == 2) e->document_owner = NULL;
            rc = TLV_ERR_INVALID_ARG;
        }
    }
    if (rc != TLV_OK) e->invalid = 1;
    return rc;
}
tlv_result_t tlv_document_query_next(tlv_query_exec_t* e, tlv_node_t** node) {
    if (!e || !node) return TLV_ERR_NULL_ARG;
    if (e->busy || e->invalid || query_output_overlap_live(e, node, sizeof *node))
        return TLV_ERR_INVALID_ARG;
    if (!e->document_owner || e->document_revision != tlv_document_revision(e->document_owner))
        return TLV_ERR_INVALID_ARG;
    void* handle;
    tlv_result_t rc = query_document_next(e, &handle);
    if (rc == TLV_OK) *node = handle;
    return rc;
}
tlv_result_t tlv_document_query_program_visit(tlv_query_exec_t* e,
                                              tlv_document_query_visitor_t visitor, void* context) {
    if (!e || !visitor) return TLV_ERR_NULL_ARG;
    if (e->busy || e->invalid || !e->document_owner ||
        ((const tlv_document_t*)e->document_owner)->query_callbacks)
        return TLV_ERR_INVALID_ARG;
    for (;;) {
        tlv_node_t* node;
        tlv_result_t rc = tlv_document_query_next(e, &node);
        if (rc == TLV_ERR_END_OF_BUFFER) return TLV_OK;
        if (rc != TLV_OK) return rc;
        tlv_document_t* owner = (tlv_document_t*)e->document_owner;
        document_query_callback(owner, 1);
        e->busy = 1;
        tlv_visit_result_t action = visitor(node, context);
        /* Raw reinitialization during a callback violates exclusive workspace
         * ownership, but must not strand the Document callback scope. */
        int overwritten = !e->busy || e->document_owner != owner;
        e->busy = 0;
        int deferred = document_query_callback(owner, 0);
        if (deferred || overwritten) {
            e->invalid = 1;
            if (deferred == 2) e->document_owner = NULL;
            return TLV_ERR_INVALID_ARG;
        }
        if (action == TLV_VISIT_STOP) return TLV_OK;
        if (action != TLV_VISIT_CONTINUE) {
            e->invalid = 1;
            return TLV_ERR_VISITOR;
        }
    }
}

tlv_result_t tlv_document_query_edit(tlv_document_t* document, tlv_query_exec_t* e,
                                     tlv_document_query_edit_kind_t kind, tlv_tag_t tag,
                                     const uint8_t* value, size_t size, tlv_node_t** targets,
                                     size_t capacity, size_t* applied) {
    if (!document || !e || !applied || (!targets && capacity)) return TLV_ERR_NULL_ARG;
    if (e->busy || document->query_callbacks || query_output_overlap(e, applied, sizeof *applied) ||
        capacity > SIZE_MAX / sizeof *targets ||
        query_output_overlap(e, targets, capacity * sizeof *targets) ||
        query_overlap(targets, capacity * sizeof *targets, applied, sizeof *applied) ||
        (kind != TLV_DOCUMENT_QUERY_REMOVE &&
         (query_overlap(value, size, targets, capacity * sizeof *targets) ||
          query_overlap(value, size, applied, sizeof *applied))))
        return TLV_ERR_INVALID_ARG;
    *applied = 0;
    if ((kind != TLV_DOCUMENT_QUERY_REMOVE && kind != TLV_DOCUMENT_QUERY_REPLACE &&
         kind != TLV_DOCUMENT_QUERY_INSERT_AFTER) ||
        e->document_owner != document || e->result_cursor ||
        (!value && size && kind != TLV_DOCUMENT_QUERY_REMOVE))
        return TLV_ERR_INVALID_ARG;
    if (e->document_revision != tlv_document_revision(document)) return TLV_ERR_INVALID_ARG;
    size_t required;
    tlv_result_t status = query_document_result_count(e, &required);
    if (status != TLV_OK) return status;
    if (capacity < required) return TLV_ERR_BUFFER_TOO_SHORT;
    size_t count = 0;
    for (;;) {
        tlv_node_t* node;
        tlv_result_t rc = tlv_document_query_next(e, &node);
        if (rc == TLV_ERR_END_OF_BUFFER) break;
        if (rc != TLV_OK) return rc;
        if (count == capacity) return TLV_ERR_BUFFER_TOO_SHORT;
        targets[count++] = node;
    }
    return document_edit_targets(document, targets, count, kind, tag, value, size, applied);
}
