// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_QUERY_BUILDER_HPP
#define OPENTLV_TLVPP_QUERY_BUILDER_HPP
#include "tlv++/query/program.hpp"

/** @file
 * @brief Typed Query expression composition; the C compiler owns all syntax and semantics. */
namespace tlv {
/** @brief Typed expression text, validated only when compiled through the canonical C engine.
 * @tparam Kind Expected result category; a mismatch is a native INVALID_ARG failure.
 * Building expressions allocates strings. This helper performs no semantic parsing. */
template <tlv_query_result_kind_t Kind> class query_expression {
public:
    /** @brief Adopt bounded expression text, including embedded NUL for C diagnostics. */
    explicit query_expression(std::string text) : text_(std::move(text)) {}
    /** @brief Borrow generated text; no syntax validity is implied before compile(). */
    const std::string& text() const {
        return text_;
    }
    /** @brief Compile composed text with typed variable declarations and borrowed providers.
     * @param options Native initialized compiler environment.
     * @return Immutable owning program or full native diagnostic. */
    expected<query_program, query_failure>
    compile(const tlv_query_compile_options_t* options = nullptr) const {
        auto program = query_program::compile(text_, options);
        if (!program) return program;
        if (program->info().result_kind != Kind)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        return program;
    }

private:
    std::string text_;
};
/** @brief Node selector expression. */
using query_nodes = query_expression<TLV_QUERY_RESULT_NODES>;
/** @brief Boolean assertion expression. */
using query_boolean = query_expression<TLV_QUERY_RESULT_BOOL>;
/** @brief Signed integer expression. */
using query_integer = query_expression<TLV_QUERY_RESULT_INTEGER>;
/** @brief Byte span expression. */
using query_bytes = query_expression<TLV_QUERY_RESULT_BYTES>;
/** @brief UTF-8 string expression. */
using query_string = query_expression<TLV_QUERY_RESULT_STRING>;
/** @brief Compose a selector predicate without parsing either expression. */
inline query_nodes where(const query_nodes& nodes, const query_boolean& condition) {
    return query_nodes("(" + nodes.text() + ")[" + condition.text() + "]");
}
/** @brief Compose existence using the native function. */
inline query_boolean exists(const query_nodes& nodes) {
    return query_boolean("exists(" + nodes.text() + ")");
}
/** @brief Compose cardinality using the native function. */
inline query_integer count(const query_nodes& nodes) {
    return query_integer("count(" + nodes.text() + ")");
}
/** @brief Compose strict integer conversion; requires the compiler's NUM environment. */
inline query_integer num(const query_nodes& nodes) {
    return query_integer("num(" + nodes.text() + ")");
}
/** @brief Compose a decimal comparison operand; no variable interpolation.
 * Bare digit strings remain raw tag tests outside numeric comparison context,
 * following the native language. Use this value as a comparison operand. */
inline query_integer integer(int64_t value) {
    return query_integer(std::to_string(value));
}
/** @brief Compose a typed variable reference; the C compiler validates its bounded name.
 * @tparam Kind Integer, bytes or string type matching the supplied compiler declaration.
 * @param name Variable name without a dollar prefix. */
template <tlv_query_result_kind_t Kind>
inline query_expression<Kind> variable(const std::string& name) {
    static_assert(Kind == TLV_QUERY_RESULT_INTEGER || Kind == TLV_QUERY_RESULT_BYTES ||
                      Kind == TLV_QUERY_RESULT_STRING,
                  "Query variables support integer, bytes and string only");
    return query_expression<Kind>("$" + name);
}
/** @brief Compose typed scalar equality. */
template <tlv_query_result_kind_t Kind>
inline query_boolean operator==(const query_expression<Kind>& a, const query_expression<Kind>& b) {
    return query_boolean("(" + a.text() + ") = (" + b.text() + ")");
}
/** @brief Compose signed integer ordering. */
inline query_boolean operator>(const query_integer& a, const query_integer& b) {
    return query_boolean("(" + a.text() + ") > (" + b.text() + ")");
}
/** @brief Compose signed integer ordering. */
inline query_boolean operator<(const query_integer& a, const query_integer& b) {
    return query_boolean("(" + a.text() + ") < (" + b.text() + ")");
}
/** @brief Compose short-circuit boolean conjunction. */
inline query_boolean operator&&(const query_boolean& a, const query_boolean& b) {
    return query_boolean("(" + a.text() + ") and (" + b.text() + ")");
}
/** @brief Compose short-circuit boolean disjunction. */
inline query_boolean operator||(const query_boolean& a, const query_boolean& b) {
    return query_boolean("(" + a.text() + ") or (" + b.text() + ")");
}
/** @brief Compose boolean negation using the native function. */
inline query_boolean operator!(const query_boolean& a) {
    return query_boolean("not(" + a.text() + ")");
}
} // namespace tlv
#endif
