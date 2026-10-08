// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tree_internal.h"
#include "../callback_internal.h"
#include <string.h>

static tlv_result_t tree_error(tlv_writer_diagnostic_t* diagnostic, tlv_result_t rc,
                               tlv_writer_operation_t operation, size_t offset,
                               const tlv_tag_t* tag) {
    if (diagnostic) {
        tlv_writer_diagnostic_init(diagnostic);
        tlv_diagnostic_init(&diagnostic->diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        tlv_diagnostic_set_location(&diagnostic->diagnostic, TLV_LOCATION_OUTPUT,
                                    TLV_LOCATION_POINT, offset, offset);
        diagnostic->operation = operation;
        if (tag) {
            diagnostic->has_tag = 1;
            diagnostic->tag = *tag;
        }
    }
    return rc;
}

tlv_result_t tlv_tree_writer_init(tlv_tree_writer_t* writer, uint8_t* data, size_t size,
                                  const tlv_format_t* format, tlv_tree_writer_frame_t* frames,
                                  size_t capacity, uint8_t* scratch, size_t scratch_capacity,
                                  size_t max_depth, size_t max_elements) {
    tlv_tree_writer_t result = {0};
    tlv_result_t rc;
    if (!writer || (!frames && capacity) || (!scratch && scratch_capacity)) return TLV_ERR_NULL_ARG;
    rc = tlv_writer_init(&result.output, data, size, format);
    if (rc != TLV_OK) return rc;
    result.frames = frames;
    result.capacity = capacity;
    result.max_depth = max_depth;
    result.max_elements = max_elements;
    result.scratch = scratch;
    result.scratch_capacity = scratch_capacity;
    *writer = result;
    return TLV_OK;
}

tlv_result_t tlv_tree_writer_set_tag_storage(tlv_tree_writer_t* writer, uint8_t* data,
                                             size_t capacity) {
    if (!writer || (!data && capacity)) return TLV_ERR_NULL_ARG;
    if (writer->depth) return TLV_ERR_INVALID_STATE;
    writer->tags = data;
    writer->tags_capacity = capacity;
    writer->tags_used = 0;
    return TLV_OK;
}

tlv_result_t tlv_tree_writer_write_event_diag(tlv_tree_writer_t* writer,
                                              const tlv_tree_event_t* event,
                                              tlv_writer_diagnostic_t* diagnostic) {
    tlv_writer_operation_t operation = TLV_WRITER_OP_VALUE;
    if (!writer || !event)
        return tree_error(diagnostic, TLV_ERR_NULL_ARG, operation, writer ? writer->output.pos : 0,
                          NULL);
    if (event->kind == TLV_TREE_BEGIN) operation = TLV_WRITER_OP_BEGIN;
    if (event->kind == TLV_TREE_END) operation = TLV_WRITER_OP_END;
    if (event->skipped ||
        (event->kind != TLV_TREE_BEGIN && event->kind != TLV_TREE_ELEMENT &&
         event->kind != TLV_TREE_END) ||
        (event->kind == TLV_TREE_END ? (!writer->depth || event->depth != writer->depth - 1)
                                     : event->depth != writer->depth))
        return tree_error(diagnostic, TLV_ERR_INVALID_VALUE, operation, writer->output.pos, NULL);
    if (event->kind == TLV_TREE_BEGIN)
        return tlv_tree_writer_begin_diag(writer, event->element.tag, diagnostic);
    if (event->kind == TLV_TREE_END) return tlv_tree_writer_end_diag(writer, diagnostic);
    if (event->element.tag.size && !event->element.tag.data)
        return tree_error(diagnostic, TLV_ERR_NULL_ARG, operation, writer->output.pos, NULL);
    if (writer->output.format->is_constructed &&
        writer->output.format->is_constructed(writer->output.format->context, &event->element.tag))
        return tree_error(diagnostic, TLV_ERR_INVALID_TAG, operation, writer->output.pos,
                          &event->element.tag);
    return tlv_tree_writer_write_element_diag(writer, &event->element, diagnostic);
}

tlv_result_t tlv_tree_writer_write_event(tlv_tree_writer_t* writer, const tlv_tree_event_t* event) {
    return tlv_tree_writer_write_event_diag(writer, event, NULL);
}

tlv_result_t tlv_tree_writer_begin_diag(tlv_tree_writer_t* writer, tlv_tag_t tag,
                                        tlv_writer_diagnostic_t* diagnostic) {
    tlv_result_t rc = TLV_OK;
    if (!writer || (tag.size && !tag.data))
        rc = TLV_ERR_NULL_ARG;
    else if (writer->depth > writer->max_depth || writer->count >= writer->max_elements)
        rc = TLV_ERR_LIMIT;
    else if (writer->depth >= writer->capacity)
        rc = TLV_ERR_BUFFER_TOO_SHORT;
    else if (!writer->output.format->is_constructed ||
             !writer->output.format->is_constructed(writer->output.format->context, &tag))
        rc = TLV_ERR_INVALID_TAG;
    if (rc != TLV_OK)
        return tree_error(diagnostic, rc, TLV_WRITER_OP_BEGIN, writer ? writer->output.pos : 0,
                          &tag);
    if (writer->tags && tag.data) {
        const size_t size = tag.size ? tag.size : 1;
        if (size > writer->tags_capacity - writer->tags_used)
            return tree_error(diagnostic, TLV_ERR_BUFFER_TOO_SHORT, TLV_WRITER_OP_BEGIN,
                              writer->output.pos, &tag);
        if (tag.size) memcpy(writer->tags + writer->tags_used, tag.data, tag.size);
        tag.data = writer->tags + writer->tags_used;
        writer->tags_used += size;
    }
    writer->frames[writer->depth++] = (tlv_tree_writer_frame_t){tag, writer->output.pos};
    ++writer->count;
    return TLV_OK;
}

tlv_result_t tlv_tree_writer_begin(tlv_tree_writer_t* writer, tlv_tag_t tag) {
    return tlv_tree_writer_begin_diag(writer, tag, NULL);
}

tlv_result_t tlv_tree_writer_write_element_diag(tlv_tree_writer_t* writer,
                                                const tlv_element_t* element,
                                                tlv_writer_diagnostic_t* diagnostic) {
    tlv_result_t rc = TLV_OK;
    if (!writer || !element)
        rc = TLV_ERR_NULL_ARG;
    else if (writer->depth > writer->max_depth || writer->count >= writer->max_elements)
        rc = TLV_ERR_LIMIT;
    if (rc != TLV_OK)
        return tree_error(diagnostic, rc, TLV_WRITER_OP_VALUE, writer ? writer->output.pos : 0,
                          element ? &element->tag : NULL);
    rc = tlv_writer_write_element_diag(&writer->output, element, diagnostic);
    if (rc == TLV_OK) ++writer->count;
    return rc;
}

tlv_result_t tlv_tree_writer_write_element(tlv_tree_writer_t* writer,
                                           const tlv_element_t* element) {
    return tlv_tree_writer_write_element_diag(writer, element, NULL);
}

tlv_result_t tlv_tree_writer_end_diag(tlv_tree_writer_t* writer,
                                      tlv_writer_diagnostic_t* diagnostic) {
    tlv_tree_writer_frame_t frame;
    tlv_writer_t output;
    tlv_element_t parent;
    size_t length;
    tlv_result_t rc;
    if (!writer || !writer->depth)
        return tree_error(diagnostic, writer ? TLV_ERR_INVALID_STATE : TLV_ERR_NULL_ARG,
                          TLV_WRITER_OP_END, writer ? writer->output.pos : 0, NULL);
    frame = writer->frames[writer->depth - 1];
    length = writer->output.pos - frame.start;
    if (length > writer->scratch_capacity) {
        rc = tree_error(diagnostic, TLV_ERR_BUFFER_TOO_SHORT, TLV_WRITER_OP_END, frame.start,
                        &frame.tag);
        if (diagnostic) {
            diagnostic->has_available = diagnostic->has_required = diagnostic->has_length = 1;
            diagnostic->available = writer->scratch_capacity;
            diagnostic->required = diagnostic->length = length;
        }
        return rc;
    }
    if (length) memcpy(writer->scratch, writer->output.buf + frame.start, length);
    parent = (tlv_element_t){frame.tag, {writer->scratch, length}};
    output = writer->output;
    output.pos = frame.start;
    rc = tlv_writer_write_element_diag(&output, &parent, diagnostic);
    if (rc != TLV_OK) {
        /* A failing encoder may have overwritten the active Value. Restore it,
         * so the unchanged frame/cursor can safely be used again. */
        if (length) memcpy(writer->output.buf + frame.start, writer->scratch, length);
        return rc;
    }
    writer->output = output;
    --writer->depth;
    if (writer->tags && frame.tag.data) writer->tags_used -= frame.tag.size ? frame.tag.size : 1;
    return TLV_OK;
}

tlv_result_t tlv_tree_writer_end(tlv_tree_writer_t* writer) {
    return tlv_tree_writer_end_diag(writer, NULL);
}

tlv_result_t tlv_tree_writer_finish(const tlv_tree_writer_t* writer) {
    if (!writer) return TLV_ERR_NULL_ARG;
    return writer->depth ? TLV_ERR_INVALID_STATE : TLV_OK;
}

size_t tlv_tree_writer_size(const tlv_tree_writer_t* writer) {
    if (!writer) return 0;
    return writer->depth ? writer->frames[0].start : writer->output.pos;
}

/* Preflight only our own storage checks. A callback's BUFFER_TOO_SHORT must never
 * be mistaken for an instruction to grow storage and replay that callback. */
static tlv_result_t measure_storage(tlv_tree_writer_t* writer, const tlv_element_t* element,
                                    size_t start, int closing,
                                    tlv_tree_writer_workspace_t* workspace,
                                    tlv_writer_diagnostic_t* diagnostic) {
    size_t encoded;
    tlv_result_t rc =
        tlv_element_encoded_size_diag(element, writer->output.format, &encoded, diagnostic);
    if (rc != TLV_OK) {
        if (diagnostic) tlv_location_translate(&diagnostic->diagnostic.location, start);
        return rc;
    }
    if (encoded > SIZE_MAX - start)
        return tree_error(diagnostic, TLV_ERR_OVERFLOW, TLV_WRITER_OP_VALUE, start, &element->tag);
    if (start + encoded > workspace->data_capacity) workspace->required_data = start + encoded;
    if (closing && writer->output.pos - start > workspace->scratch_capacity)
        workspace->required_scratch = writer->output.pos - start;
    if (!workspace->required_data && !workspace->required_scratch) return TLV_OK;
    rc = tree_error(diagnostic, TLV_ERR_BUFFER_TOO_SHORT,
                    workspace->required_scratch ? TLV_WRITER_OP_END : TLV_WRITER_OP_VALUE, start,
                    &element->tag);
    if (diagnostic) {
        diagnostic->has_available = diagnostic->has_required = 1;
        diagnostic->available = workspace->required_scratch ? workspace->scratch_capacity
                                                            : workspace->data_capacity - start;
        diagnostic->required = workspace->required_scratch ? workspace->required_scratch : encoded;
    }
    return rc;
}

static tlv_result_t measure_close(tlv_tree_writer_t* writer, tlv_tree_writer_workspace_t* workspace,
                                  tlv_writer_diagnostic_t* diagnostic) {
    const tlv_tree_writer_frame_t* frame = &writer->frames[writer->depth - 1];
    tlv_element_t element = {frame->tag,
                             {workspace->data ? workspace->data + frame->start : NULL,
                              writer->output.pos - frame->start}};
    tlv_result_t rc = measure_storage(writer, &element, frame->start, 1, workspace, diagnostic);
    return rc == TLV_OK ? tlv_tree_writer_end_diag(writer, diagnostic) : rc;
}

/* Node-only sources are projections: synthesize their missing structural closes
 * once here, then use the same canonical event consumer as Document and Reader. */
typedef struct preorder_source {
    tlv_tree_writer_next_fn next;
    void* context;
    tlv_tree_event_t pending;
    size_t open;
    int available;
    int done;
} preorder_source_t;

static tlv_result_t preorder_event(void* context, tlv_tree_event_t* event) {
    preorder_source_t* source = context;
    tlv_result_t rc;
    if (!source->available && !source->done) {
        int constructed = 0;
        rc = source->next(source->context, &source->pending.element, &source->pending.depth,
                          &constructed);
        rc = tlv_callback_result(rc, 1);
        if (rc == TLV_ERR_END_OF_BUFFER) {
            source->done = 1;
        } else {
            if (rc != TLV_OK) return rc;
            if (source->pending.depth > source->open) return TLV_ERR_CALLBACK;
            source->pending.kind = constructed ? TLV_TREE_BEGIN : TLV_TREE_ELEMENT;
            source->available = 1;
        }
    }
    if (source->open && (source->done || source->open > source->pending.depth)) {
        *event = (tlv_tree_event_t){0};
        event->kind = TLV_TREE_END;
        event->depth = --source->open;
        return TLV_OK;
    }
    if (source->done) return TLV_ERR_END_OF_BUFFER;
    *event = source->pending;
    source->available = 0;
    if (event->kind == TLV_TREE_BEGIN) ++source->open;
    return TLV_OK;
}

tlv_result_t tlv_tree_writer_measure(const tlv_format_t* format, tlv_tree_writer_next_fn next,
                                     void* context, tlv_tree_writer_workspace_t* workspace,
                                     size_t max_depth, size_t max_elements, size_t* size,
                                     tlv_writer_diagnostic_t* diagnostic) {
    preorder_source_t source = {0};
    source.next = next;
    source.context = context;
    return tlv_tree_writer_measure_events(format, next ? preorder_event : NULL, &source, workspace,
                                          max_depth, max_elements, size, diagnostic);
}

tlv_result_t tlv_tree_writer_measure_events(const tlv_format_t* format, tlv_tree_event_next_fn next,
                                            void* context, tlv_tree_writer_workspace_t* workspace,
                                            size_t max_depth, size_t max_elements, size_t* size,
                                            tlv_writer_diagnostic_t* diagnostic) {
    return tree_writer_measure_events_observed(format, next, context, workspace, max_depth,
                                               max_elements, size, diagnostic, NULL, NULL);
}

tlv_result_t tree_writer_measure_events_observed(
    const tlv_format_t* format, tlv_tree_event_next_fn next, void* context,
    tlv_tree_writer_workspace_t* workspace, size_t max_depth, size_t max_elements, size_t* size,
    tlv_writer_diagnostic_t* diagnostic, tree_writer_charge_fn charge, void* charge_context) {
    tlv_tree_writer_t writer;
    tlv_result_t rc;
    if (workspace) workspace->required_data = workspace->required_scratch = 0;
    if (!next || !workspace || !size)
        return tree_error(diagnostic, TLV_ERR_NULL_ARG, TLV_WRITER_OP_VALUE, 0, NULL);
    rc = tlv_tree_writer_init(&writer, workspace->data, workspace->data_capacity, format,
                              workspace->frames, workspace->frame_capacity, workspace->scratch,
                              workspace->scratch_capacity, max_depth, max_elements);
    if (rc != TLV_OK) return rc;
    for (;;) {
        tlv_tree_event_t event = {0};
        rc = tlv_callback_result(next(context, &event), 1);
        if (rc == TLV_ERR_END_OF_BUFFER) break;
        if (rc != TLV_OK)
            return tree_error(diagnostic, rc, TLV_WRITER_OP_VALUE, writer.output.pos, NULL);
        /* Validate structure before measuring, including omitted descendants. */
        if (event.skipped ||
            (event.kind != TLV_TREE_BEGIN && event.kind != TLV_TREE_ELEMENT &&
             event.kind != TLV_TREE_END) ||
            (event.kind == TLV_TREE_END ? (!writer.depth || event.depth != writer.depth - 1)
                                        : event.depth != writer.depth))
            return tree_error(diagnostic, TLV_ERR_INVALID_VALUE, TLV_WRITER_OP_VALUE,
                              writer.output.pos, NULL);
        if (charge) {
            rc = charge(charge_context, 1);
            if (rc != TLV_OK) return rc;
            if (event.kind == TLV_TREE_ELEMENT && event.element.value.size > SIZE_MAX)
                return TLV_ERR_NATIVE_SIZE;
            size_t bytes = event.kind == TLV_TREE_END
                               ? writer.output.pos - writer.frames[writer.depth - 1].start
                           : event.kind == TLV_TREE_ELEMENT ? (size_t)event.element.value.size
                                                            : 0;
            for (unsigned pass = 0; pass < 3; ++pass) {
                rc = charge(charge_context, bytes);
                if (rc != TLV_OK) return rc;
            }
        }
        if (event.kind == TLV_TREE_END) {
            rc = measure_close(&writer, workspace, diagnostic);
        } else {
            if (event.kind == TLV_TREE_ELEMENT) {
                if (writer.depth > max_depth || writer.count >= max_elements)
                    return tree_error(diagnostic, TLV_ERR_LIMIT, TLV_WRITER_OP_VALUE,
                                      writer.output.pos, &event.element.tag);
                if (event.element.tag.size && !event.element.tag.data)
                    return tree_error(diagnostic, TLV_ERR_NULL_ARG, TLV_WRITER_OP_VALUE,
                                      writer.output.pos, NULL);
                if (format->is_constructed &&
                    format->is_constructed(format->context, &event.element.tag))
                    return tree_error(diagnostic, TLV_ERR_INVALID_TAG, TLV_WRITER_OP_VALUE,
                                      writer.output.pos, &event.element.tag);
                rc = measure_storage(&writer, &event.element, writer.output.pos, 0, workspace,
                                     diagnostic);
                if (rc != TLV_OK) return rc;
            }
            rc = tlv_tree_writer_write_event_diag(&writer, &event, diagnostic);
        }
        if (rc != TLV_OK) return rc;
    }
    if (writer.depth)
        return tree_error(diagnostic, TLV_ERR_INVALID_VALUE, TLV_WRITER_OP_END, writer.output.pos,
                          NULL);
    *size = tlv_tree_writer_size(&writer);
    return TLV_OK;
}
