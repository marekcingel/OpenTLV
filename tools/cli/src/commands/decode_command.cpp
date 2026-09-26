#include "commands/decode_command.hpp"
#include <iostream>
#include "commands/support.hpp"
#include "json_model.hpp"

namespace cli {

// decode's visitor: builds the versioned document (docs/cli/json-schema.md).
// A primitive carries its raw "value"; a constructed element carries its
// "children" instead, plus an explicit "length_mode" for BER.
tlv_visit_result_t decode_command::visit_element(const tlv_view_t* view, std::size_t depth,
                                                 std::size_t offset) {
    diagnostic_scope_visit(scope_, data(), view, depth, predicate_);
    offset += base_;
    const bool indefinite = ber_ && data()[offset + view->tag.size] == 0x80;
    cli_presentation_visit(&presentation_, view, depth, indefinite);
    nlohmann::ordered_json object;
    object["tag"] = hex_string(view->tag.data, view->tag.size);
    if (options_.profile) {
        json_emv(object, presentation_, view, depth, options_.describe, false);
        if (options_.decode) json_decode(object, presentation_, view, depth);
    }
    if (constructed_ && constructed_(NULL, &view->tag)) {
        if (ber_) object["length_mode"] = indefinite ? "indefinite" : "definite";
        object["children"] = nlohmann::ordered_json::array();
    } else {
        object["value"] = hex_string(view->value.data, (size_t)view->value.length);
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
