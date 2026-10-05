// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_DOCUMENT_DIFF_HPP
#define OPENTLV_TLVPP_DOCUMENT_DIFF_HPP
#include "tlv++/document/document.hpp"
#include <map>
#include <set>
#include <string>
/** @file
 * @brief Minimal semantic Document diff with compiled Query filtering. */
namespace tlv {
/** @brief One direct node difference; constructed descendants are compared independently. */
enum class diff_kind {
    added,   /**< Present only on the right. */
    removed, /**< Present only on the left. */
    changed  /**< Corresponding direct semantic content differs. */
};
/** @brief Checked original input handles and stable correspondence description. */
struct diff_entry {
    diff_kind   kind;  /**< Added, removed or changed direct node content. */
    std::string path;  /**< Raw tag plus same-tag sibling occurrence at every ancestor. */
    node        left;  /**< Original left context, empty for additions. */
    node        right; /**< Original right context, empty for removals. */
};
/** @cond INTERNAL */
namespace detail {
struct diff_index {
    std::map<std::string, node>        nodes;
    std::map<tlv_node_t*, std::string> identities;
    std::vector<std::string>           order;
};
inline diff_index index_document(const document& doc) {
    struct scope {
        node                          next;
        std::string                   parent;
        std::map<std::string, size_t> counts;
    };
    diff_index         result;
    std::vector<scope> stack(1);
    stack.back().next = doc.first();
    const char* hex = "0123456789ABCDEF";
    while (!stack.empty()) {
        auto& frame = stack.back();
        if (!frame.next) {
            stack.pop_back();
            continue;
        }
        auto current = frame.next;
        frame.next = current.next();
        std::string tag;
        auto        tag_bytes = current.tag().as_bytes();
        for (size_t i = 0; i < tag_bytes.size(); ++i) {
            auto value = static_cast<unsigned char>(tag_bytes[i]);
            tag.push_back(hex[value >> 4]);
            tag.push_back(hex[value & 15]);
        }
        auto path = frame.parent + "/" + tag + "[" + std::to_string(++frame.counts[tag]) + "]";
        result.nodes.emplace(path, current);
        result.identities.emplace(current.c_node(), path);
        result.order.push_back(path);
        if (current.is_constructed()) {
            scope children;
            children.next = current.first_child();
            children.parent = path;
            stack.push_back(std::move(children));
        }
    }
    return result;
}
} // namespace detail
/** @endcond */
/** @brief Compare direct semantic node content selected on either original input.
 * @param left Original immutable owning Document.
 * @param right Original immutable owning Document.
 * @param where Optional compiled node selector, evaluated unchanged on each complete input.
 * @return Changes in left preorder followed by right-only additions, or native Query failure.
 * @note Correspondence uses ancestor raw tags and same-tag sibling occurrence, never byte
 * offsets. Inserting a repeated tag may shift later correspondences; no heuristic alignment.
 * Selection on either side includes its original counterpart, even if excluded on the other.
 * A selected ancestor compares only its own classification/primitive Value; excluded
 * descendants do not contribute changes. Constructed children are independent entries.
 * Allocates indexes, selections and checked handles. Source wire spelling is ignored;
 * Query variables/providers require callers to use separately bound selections instead. */
inline expected<std::vector<diff_entry>, query_failure>
semantic_diff(const document& left, const document& right, const query_program* where = nullptr) {
    auto                  a = detail::index_document(left), b = detail::index_document(right);
    std::set<std::string> included;
    if (where) {
        auto x = left.select(*where);
        if (!x) return unexpected<query_failure>(x.error());
        auto y = right.select(*where);
        if (!y) return unexpected<query_failure>(y.error());
        for (const auto& n : *x) included.insert(a.identities.at(n.c_node()));
        for (const auto& n : *y) included.insert(b.identities.at(n.c_node()));
    }
    std::vector<diff_entry> result;
    for (const auto& path : a.order) {
        if (where && !included.count(path)) continue;
        auto lhs = a.nodes.at(path);
        auto rhs = b.nodes.find(path);
        if (rhs == b.nodes.end())
            result.push_back({diff_kind::removed, path, lhs, node()});
        else if (lhs.is_constructed() != rhs->second.is_constructed() ||
                 (!lhs.is_constructed() && lhs.value() != rhs->second.value()))
            result.push_back({diff_kind::changed, path, lhs, rhs->second});
    }
    for (const auto& path : b.order) {
        if (a.nodes.count(path) || (where && !included.count(path))) continue;
        result.push_back({diff_kind::added, path, node(), b.nodes.at(path)});
    }
    return result;
}
} // namespace tlv
#endif
