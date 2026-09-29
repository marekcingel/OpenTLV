#include "commands/decode_command.hpp"
#include <iostream>
#include "bluetooth.hpp"
#include "commands/support.hpp"
#include "json_model.hpp"

namespace cli {

// decode's visitor: builds the versioned document (docs/cli/json-schema.md).
// A primitive carries its raw "value"; a constructed element carries its
// "children" instead, plus an explicit "length_mode" for BER.
tlv_visit_result_t decode_command::visit_element(const tlv_element_t* element, std::size_t depth,
                                                 std::size_t offset) {
    diagnostic_scope_visit(scope_, data(), element, depth, format_->is_constructed);
    offset += base_;
    const bool indefinite = ber_ && data()[offset + element->tag.size] == 0x80;
    cli_presentation_visit(&presentation_, element, depth, indefinite);
    nlohmann::ordered_json object;
    object["tag"] = hex_string(element->tag.data, element->tag.size);
    if (bluetooth_module(options_)) {
        json_bluetooth(object, element, options_.decode != 0);
    } else if (options_.module) {
        json_emv(object, presentation_, element, depth, options_.describe, false);
        if (options_.decode) json_decode(object, presentation_, element, depth);
    }
    if (format_->is_constructed && format_->is_constructed(format_->context, &element->tag)) {
        if (ber_) object["length_mode"] = indefinite ? "indefinite" : "definite";
        object["children"] = nlohmann::ordered_json::array();
    } else {
        object["value"] = hex_string(element->value.data, cli_element_value_size(element));
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
    std::cout << document.dump() << "\n";
}

} // namespace cli
