#include "tlv/writer/tree.h"
#include <string.h>

static tlv_result_t tree_error(tlv_writer_diagnostic_t* diagnostic, tlv_result_t rc,
                               tlv_writer_operation_t operation, size_t offset,
                               const tlv_tag_t* tag) {
    if (diagnostic) {
        tlv_writer_diagnostic_init(diagnostic);
        tlv_diagnostic_init(&diagnostic->diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        tlv_diagnostic_set_offset(&diagnostic->diagnostic, offset);
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

tlv_result_t tlv_tree_writer_begin_diag(tlv_tree_writer_t* writer, tlv_tag_t tag,
                                        tlv_writer_diagnostic_t* diagnostic) {
    tlv_result_t rc = TLV_OK;
    if (!writer || (tag.size && !tag.data))
        rc = TLV_ERR_NULL_ARG;
    else if (writer->depth > writer->max_depth || writer->count >= writer->max_elements ||
             writer->depth >= writer->capacity)
        rc = TLV_ERR_LIMIT;
    else if (!writer->output.format->is_constructed ||
             !writer->output.format->is_constructed(writer->output.format->context, &tag))
        rc = TLV_ERR_INVALID_TAG;
    if (rc != TLV_OK)
        return tree_error(diagnostic, rc, TLV_WRITER_OP_BEGIN, writer ? writer->output.pos : 0,
                          &tag);
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
        return tree_error(diagnostic, writer ? TLV_ERR_INVALID_ARG : TLV_ERR_NULL_ARG,
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
    return TLV_OK;
}

tlv_result_t tlv_tree_writer_end(tlv_tree_writer_t* writer) {
    return tlv_tree_writer_end_diag(writer, NULL);
}

tlv_result_t tlv_tree_writer_finish(const tlv_tree_writer_t* writer) {
    if (!writer) return TLV_ERR_NULL_ARG;
    return writer->depth ? TLV_ERR_INVALID_ARG : TLV_OK;
}

size_t tlv_tree_writer_size(const tlv_tree_writer_t* writer) {
    if (!writer) return 0;
    return writer->depth ? writer->frames[0].start : writer->output.pos;
}
