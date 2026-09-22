#include "diagnostic_collect.hpp"
#include "tlv/length.h"

namespace cli {

void diagnostic_scope_init(diagnostic_scope& scope, size_t size) {
    tlv_diagnostic_path_init(&scope.path);
    scope.end[0] = size;
}

void diagnostic_scope_visit(diagnostic_scope& scope, const uint8_t* base, const tlv_view_t* view,
                            size_t depth, tlv_is_constructed_fn constructed) {
    while (scope.path.length > depth) tlv_diagnostic_path_pop(&scope.path);
    if (!constructed || !constructed(NULL, &view->tag)) return;
    size_t value_length;
    if (view->value.data && depth + 1 <= TLV_WALK_MAX_DEPTH &&
        tlv_length_to_size(view->value.length, &value_length) == TLV_OK)
        scope.end[depth + 1] = (size_t)(view->value.data - base) + value_length;
    tlv_diagnostic_path_push(&scope.path, view->tag);
}

bool diagnostic_scope_derive_reader_diagnostic(const diagnostic_scope&    scope,
                                               const tlv_reader_format_t* format,
                                               const uint8_t* data, size_t size,
                                               size_t error_offset, tlv_result_t expected_code,
                                               tlv_reader_diagnostic_t* out) {
    if (error_offset > size) return false;
    size_t depth = scope.path.length;
    size_t enclosing_end = depth <= TLV_WALK_MAX_DEPTH ? scope.end[depth] : size;
    if (enclosing_end > size) enclosing_end = size;
    if (enclosing_end < error_offset) enclosing_end = error_offset;

    tlv_view_t              entry;
    size_t                  consumed;
    tlv_reader_diagnostic_t diag;
    tlv_reader_diagnostic_init(&diag);
    tlv_result_t rc = tlv_read_diag(data + error_offset, enclosing_end - error_offset, format,
                                    &entry, &consumed, &diag);
    if (rc != expected_code) return false;

    diag.diagnostic.offset += error_offset;
    if (diag.has_tag_offset) diag.tag_offset += error_offset;
    if (diag.has_length_offset) diag.length_offset += error_offset;
    if (diag.has_value_offset) diag.value_offset += error_offset;
    if (diag.has_enclosing_end) diag.enclosing_end += error_offset;
    *out = diag;
    return true;
}

} // namespace cli
