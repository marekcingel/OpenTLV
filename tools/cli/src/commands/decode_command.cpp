// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "commands/decode_command.hpp"
#include <iostream>
#include "bluetooth.hpp"
#include "commands/support.hpp"
#include "json_model.hpp"

namespace cli {

// decode's visitor: builds the versioned document (docs/cli/json-schema.md).
// A primitive carries its raw "value"; a constructed element carries its
// "children" instead, plus an explicit "length_mode" for BER.
tlv_visit_result_t decode_command::visit_element(const tlv::element_view& element,
                                                 std::size_t depth, std::size_t offset) {
    const auto native = tlv::native::descriptor(element);
    diagnostic_scope_visit(scope_, data(), &native, depth, format_->is_constructed);
    offset += base_;
    const bool indefinite = ber_ && data()[offset + element.tag().size()] == 0x80;
    cli_presentation_visit(&presentation_, &native, depth, indefinite);
    nlohmann::ordered_json object;
    object["tag"] = hex_string(element.tag().as_bytes());
    if (bluetooth_module(options_)) {
        json_bluetooth(object, &native, options_.decode != 0);
    } else if (options_.module) {
        json_emv(object, presentation_, &native, depth, options_.describe, false);
        if (options_.decode) json_decode(object, presentation_, &native, depth);
    }
    if (format_->is_constructed && format_->is_constructed(format_->context, &native.tag)) {
        if (ber_) object["length_mode"] = indefinite ? "indefinite" : "definite";
        object["children"] = nlohmann::ordered_json::array();
    } else {
        object["value"] = hex_string(element.value().as_bytes());
    }
    document_flush(depth);
    document_stack_.push_back(std::move(object));
    return TLV_VISIT_CONTINUE;
}

void decode_command::render_output() {
    // A failed export prints nothing: a partial document would look like a
    // complete one. Recovery reports what it skipped in the document.
    if (result_ != TLV_OK) return;
    document_flush(0);
    nlohmann::ordered_json document;
    document["schema"] = json_model::schema_name;
    document["version"] = (int)json_model::schema_version;
    document["format"] = options_.format;
    document["elements"] = std::move(document_root_);
    if (options_.recover) {
        document["complete"] = skipped_.empty();
        document["skipped"] = skipped_json<nlohmann::ordered_json>(skipped_);
    }
    output_ << document.dump() << "\n";
}

} // namespace cli
