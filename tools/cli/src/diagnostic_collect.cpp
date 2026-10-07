// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "diagnostic_collect.hpp"

namespace cli {

void diagnostic_scope_init(diagnostic_scope& scope, size_t size) {
    scope.path = tlv::make_diagnostic_path();
    scope.end.assign(1, size);
}

void diagnostic_scope_visit(diagnostic_scope& scope, const uint8_t* base,
                            const tlv::element_view* element, size_t depth,
                            const tlv::format& format) {
    while (scope.path.length > depth) tlv::pop_path(scope.path);
    if (!format.is_constructed(element->tag())) return;
    if (element->value().data()) {
        scope.end.resize(depth + 2);
        scope.end[depth + 1] =
            static_cast<size_t>(reinterpret_cast<const uint8_t*>(element->value().data()) - base) +
            element->value().size();
    }
    (void)tlv::push_path(scope.path, element->tag());
}

} // namespace cli
