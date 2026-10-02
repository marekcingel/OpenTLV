// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "diagnostic_collect.hpp"
#include "tlv/size.h"

namespace cli {

void diagnostic_scope_init(diagnostic_scope& scope, size_t size) {
    tlv_diagnostic_path_init(&scope.path);
    scope.end.assign(1, size);
}

void diagnostic_scope_visit(diagnostic_scope& scope, const uint8_t* base,
                            const tlv_element_t* element, size_t depth,
                            tlv_is_constructed_fn constructed) {
    while (scope.path.length > depth) tlv_diagnostic_path_pop(&scope.path);
    if (!constructed || !constructed(NULL, &element->tag)) return;
    size_t value_length;
    if (element->value.data && tlv_size_to_native(element->value.size, &value_length) == TLV_OK) {
        scope.end.resize(depth + 2);
        scope.end[depth + 1] = (size_t)(element->value.data - base) + value_length;
    }
    tlv_diagnostic_path_push(&scope.path, element->tag);
}

} // namespace cli
