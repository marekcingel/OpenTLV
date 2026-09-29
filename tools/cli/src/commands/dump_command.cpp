#include "commands/dump_command.hpp"
#include <iostream>
#include "commands/support.hpp"
#include "decode.hpp"

namespace cli {

tlv_visit_result_t dump_command::visit_element(const tlv_element_t* element, std::size_t depth,
                                               std::size_t offset) {
    diagnostic_scope_visit(scope_, data(), element, depth, format_->is_constructed);
    offset += base_;
    const int indefinite = ber_ && data()[offset + element->tag.size] == 0x80;
    cli_presentation_visit(&presentation_, element, depth, indefinite);
    if (!options_.tree && depth) return TLV_VISIT_CONTINUE;
    if (is_json(options_)) {
        nlohmann::json object;
        object["offset"] = offset;
        object["tag"] = hex_string(element->tag.data, element->tag.size);
        object["length"] = (uint64_t)element->value.size;
        if (indefinite) object["indefinite"] = true;
        object["value"] = hex_string(element->value.data, cli_element_value_size(element));
        if (options_.module) {
            json_emv(object, presentation_, element, depth, options_.describe);
            if (options_.decode) json_decode(object, presentation_, element, depth);
        }
        // Attach any elements deeper than this one to their parent first,
        // since their subtrees are now known to be finished.
        json_flush(depth);
        json_stack_.push_back(std::move(object));
        return TLV_VISIT_CONTINUE;
    }
    if (options_.pretty)
        cli_presentation_prefix(&presentation_, depth);
    else
        for (size_t i = 0; i < depth; ++i) std::cout << "  ";
    std::cout << "offset=" << offset << " tag=";
    print_tag(element->tag, presentation_.color != 0);
    std::cout << " length=" << element->value.size;
    if (indefinite) std::cout << " encoding=indefinite";
    std::cout << " value=";
    print_hex(element->value.data, cli_element_value_size(element));
    if (options_.module) {
        cli_presentation_emv(&presentation_, element, depth, options_.describe);
        if (options_.decode) {
            const decode_result result = decode_emv_value(presentation_.contexts[depth], element);
            if (result.status == decode_status::ok)
                std::cout << " decoded=\"" << result.text << '"';
            else if (result.status == decode_status::error)
                std::cout << " decode-error=\"" << result.text << '"';
        }
    }
    std::cout << "\n";
    return std::cout ? TLV_VISIT_CONTINUE : TLV_VISIT_ERROR;
}

void dump_command::render_output() {
    // Matches the original implementation: printed whenever --output json is
    // set, even after a failure (a partial document reflecting whatever
    // elements were visited before the error), unlike decode's and query's
    // documents, which only ever appear on success.
    if (!is_json(options_)) return;
    json_flush(0);
    nlohmann::json document;
    document["elements"] = std::move(json_root_);
    if (options_.recover) {
        document["complete"] = skipped_.empty();
        document["skipped"] = skipped_json<nlohmann::json>(skipped_);
    }
    std::cout << document.dump() << "\n";
}

bool dump_command::prints_pdol_annotations() const {
    return true;
}

bool dump_command::prints_skipped_inline() const {
    return !is_json(options_);
}

} // namespace cli
