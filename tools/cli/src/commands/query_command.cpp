#include "commands/query_command.hpp"
#include <iostream>
#include "commands/support.hpp"
#include "diagnostics.hpp"

namespace {

// The query path as text: uppercase hex tags joined by "/", however the user
// spelled it.
std::string query_path(const tlv_query_t& query) {
    std::string path;
    for (size_t i = 0; i < query.count; ++i) {
        if (i) path += '/';
        path += cli::hex_string(tlv_query_step(&query, i).data, tlv_query_step(&query, i).size);
    }
    return path;
}

} // namespace

namespace cli {

int query_command::prepare() {
    if (tlv_query_matcher_init(&matcher_, &options_.query) != TLV_OK)
        return fail(2, "invalid query");
    return 0;
}

// query's visitor: prints each element the path addresses. Text output is
// the dump line without nesting, --value prints only the value bytes, and
// --output json collects the elements into one document printed at the end.
tlv_visit_result_t query_command::visit_element(const tlv_view_t* view, std::size_t depth,
                                                std::size_t offset) {
    diagnostic_scope_visit(scope_, data(), view, depth, predicate_);
    if (!tlv_query_matcher_visit(&matcher_, &view->tag, depth)) return TLV_VISIT_CONTINUE;
    ++matches_;
    if (is_json(options_)) {
        nlohmann::json object;
        object["path"] = query_path(options_.query);
        object["offset"] = offset;
        object["tag"] = hex_string(view->tag.data, view->tag.size);
        object["length"] = (uint64_t)view->value.length;
        object["value"] = hex_string(view->value.data, (size_t)view->value.length);
        json_root_.push_back(std::move(object));
        return TLV_VISIT_CONTINUE;
    }
    if (options_.value_only) {
        print_hex(view->value.data, (size_t)view->value.length);
    } else {
        std::cout << "offset=" << offset << " tag=";
        print_hex(view->tag.data, view->tag.size);
        std::cout << " length=" << view->value.length << " value=";
        print_hex(view->value.data, (size_t)view->value.length);
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
    std::cerr << "otlv: no match for query " << query_path(options_.query) << "\n";
    return 5;
}

} // namespace cli
