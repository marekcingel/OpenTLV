#ifndef OPENTLV_TEST_VISITOR_INPUT_H
#define OPENTLV_TEST_VISITOR_INPUT_H
#include "tlv/reader/visitor.h"
#include <vector>
inline tlv_result_t visit_input(const uint8_t* data, size_t size, const tlv_format_t* format,
                                tlv_visitor_t visitor, void* context) {
    tlv_reader_t reader;
    if (!visitor) return TLV_ERR_NULL_ARG;
    auto rc = tlv_reader_init(&reader, data, size, format);
    return rc == TLV_OK ? tlv_reader_visit(&reader, visitor, context) : rc;
}
inline tlv_result_t visit_tree_input_diag(const uint8_t* data, size_t size,
                                          const tlv_format_t* format, size_t depth, size_t count,
                                          tlv_tree_visitor_t visitor, void* context, size_t* offset,
                                          tlv_reader_diagnostic_t* diagnostic) {
    std::vector<tlv_tree_frame_t> frames(depth < size ? depth : size);
    tlv_tree_reader_t             reader;
    if (diagnostic) tlv_reader_diagnostic_init(diagnostic);
    auto rc = tlv_tree_reader_init(&reader, data, size, format, frames.data(), frames.size(), depth,
                                   count);
    if (rc != TLV_OK) {
        if (offset) *offset = 0;
        return rc;
    }
    return tlv_tree_reader_visit_diag(&reader, visitor, context, offset, diagnostic);
}
inline tlv_result_t visit_tree_input(const uint8_t* data, size_t size, const tlv_format_t* format,
                                     size_t depth, size_t count, tlv_tree_visitor_t visitor,
                                     void* context, size_t* offset) {
    return visit_tree_input_diag(data, size, format, depth, count, visitor, context, offset,
                                 nullptr);
}
#endif
