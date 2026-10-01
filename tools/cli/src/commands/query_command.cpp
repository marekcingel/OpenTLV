#include "commands/query_command.hpp"
#include <iostream>
#include "commands/support.hpp"
#include "diagnostics.hpp"

namespace {

// The query path as text: uppercase hex tags joined by "/", however the user
// spelled it.
std::string query_path(const tlv::query& query) {
    std::string path;
    for (size_t i = 0; i < query.size(); ++i) {
        if (i) path += '/';
        const auto tag = query.step(i);
        path += cli::hex_string(tag.as_bytes());
    }
    return path;
}

} // namespace

namespace cli {

int query_command::prepare() {
    if (!options_.query) return fail(2, "invalid query");
    matcher_.reset(new tlv::query_matcher(*options_.query));
    return 0;
}

// query's visitor: prints each element the path addresses. Text output is
// the dump line without nesting, --value prints only the value bytes, and
// --output json collects the elements into one document printed at the end.
tlv_visit_result_t query_command::visit_element(const tlv::element_view& element, std::size_t depth,
                                                std::size_t offset) {
    const auto native = tlv::native::descriptor(element);
    diagnostic_scope_visit(scope_, data(), &native, depth, format_->is_constructed);
    if (!matcher_->matches(element.tag(), depth)) return TLV_VISIT_CONTINUE;
    ++matches_;
    if (is_json(options_)) {
        nlohmann::json object;
        object["path"] = query_path(*options_.query);
        object["offset"] = offset;
        object["tag"] = hex_string(element.tag().as_bytes());
        object["length"] = (uint64_t)element.value().size();
        object["value"] = hex_string(element.value().as_bytes());
        json_root_.push_back(std::move(object));
        return TLV_VISIT_CONTINUE;
    }
    if (options_.value_only) {
        print_hex(element.value().as_bytes());
    } else {
        std::cout << "offset=" << offset << " tag=";
        print_hex(element.tag().as_bytes());
        std::cout << " length=" << element.value().size() << " value=";
        print_hex(element.value().as_bytes());
    }
    std::cout << "\n";
    return std::cout ? TLV_VISIT_CONTINUE : TLV_VISIT_ERROR;
}

void query_command::render_output() {
    if (result_ != TLV_OK || !is_json(options_)) return;
    nlohmann::json document;
    document["matches"] = std::move(json_root_);
    std::cout << document.dump() << "\n";
}

int query_command::after_success() {
    if (matches_) return 0;
    std::cerr << "otlv: no match for query " << query_path(*options_.query) << "\n";
    return 5;
}

} // namespace cli
