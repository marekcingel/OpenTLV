// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_DIAGNOSTIC_HPP
#define OPENTLV_TLVPP_DIAGNOSTIC_HPP
#include "tlv/diagnostic.h"
#include "tlv++/types.hpp"

/**
 * @file diagnostic.hpp
 * @brief C++ wrapper for the structured diagnostic model.
 */

namespace tlv {

/** @brief C++ alias for the C diagnostic type, #tlv_diagnostic_t. */
using diagnostic = tlv_diagnostic_t;

/** @brief C++ alias for the C diagnostic context type, #tlv_diagnostic_context_t. */
using diagnostic_context = tlv_diagnostic_context_t;

/** @brief C++ alias for the C diagnostic path type, #tlv_diagnostic_path_t. */
using diagnostic_path = tlv_diagnostic_path_t;
/** @brief Maximum number of enclosing identifiers retained by a diagnostic path. */
constexpr size_t diagnostic_path_capacity = TLV_DIAGNOSTIC_PATH_MAX;
/** @brief Borrow the identifier at index, or an absent identifier when out of range. */
inline tlv::tag path_tag(const diagnostic_path& path, size_t index) noexcept {
    return index < path.length ? detail::semantic_access::borrow(path.tags[index]) : tlv::tag{};
}

/** @brief Immutable program-lifetime severity name. */
inline const char* message(severity value) noexcept {
    return tlv_diagnostic_severity_string(static_cast<tlv_diagnostic_severity_t>(value));
}
/** @brief Canonical C++ status of a common diagnostic. */
inline errc status(const diagnostic& value) noexcept {
    return static_cast<errc>(value.code);
}
/** @brief Severity of a common diagnostic. */
inline severity severity_of(const diagnostic& value) noexcept {
    return static_cast<severity>(value.severity);
}
/** @brief Assign severity without changing error detail. */
inline void set_severity(diagnostic& value, severity level) noexcept {
    value.severity = static_cast<tlv_diagnostic_severity_t>(level);
}
/** @brief Initialize common diagnostic metadata using C++ status and severity. */
inline diagnostic make_diagnostic(errc code, severity level = severity::error) noexcept {
    diagnostic result;
    tlv_diagnostic_init(&result, static_cast<tlv_result_t>(code),
                        static_cast<tlv_diagnostic_severity_t>(level));
    return result;
}
/** @brief Attach an absolute byte offset to a common diagnostic. */
inline void set_offset(diagnostic& value, size_t offset) noexcept {
    tlv_diagnostic_set_offset(&value, offset);
}
/** @brief Format a hierarchical identifier path into caller-owned character storage.
 * @param path Borrowed enclosing identifiers.
 * @param output Destination for text including its terminator.
 * @return Text length excluding the terminator, or insufficient-storage error.
 * @note Does not allocate; input identifiers need only remain alive for the call.
 */
inline expected<size_t, error> format_path(const diagnostic_path& path, span<char> output) {
    size_t     size = 0;
    const auto rc = tlv_diagnostic_path_string(&path, output.data(), output.size(), &size);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return size;
}

namespace native {
/**
 * @brief Builds a diagnostic with a code and severity, and no location, expectation or context.
 *
 * Wraps tlv_diagnostic_init().
 *
 * @param code     Stable code identifying the failure or observation.
 * @param severity How serious the diagnostic is.
 *
 * @return The initialized diagnostic.
 */
inline diagnostic make_diagnostic(tlv_result_t code, tlv_diagnostic_severity_t severity) {
    diagnostic result;
    tlv_diagnostic_init(&result, code, severity);
    return result;
}
} // namespace native

/**
 * @brief Attaches one context element to a diagnostic.
 *
 * Wraps tlv_diagnostic_add_context(); the same borrowing and lifetime rules apply.
 *
 * @param target  Diagnostic to update.
 * @param context Caller-owned storage for the new element; every field is overwritten.
 * @param layer   Borrowed name of the layer adding context, for example `"ber"`.
 * @param key     Borrowed name of the attribute, for example `"declared_length"`.
 * @param value   Borrowed formatted value of the attribute.
 */
inline void add_context(diagnostic& target, diagnostic_context& context, const char* layer,
                        const char* key, const char* value) {
    tlv_diagnostic_add_context(&target, &context, layer, key, value);
}

/**
 * @brief Builds an empty hierarchical path.
 *
 * Wraps tlv_diagnostic_path_init().
 *
 * @return The initialized, empty path.
 */
inline diagnostic_path make_diagnostic_path() {
    diagnostic_path path;
    tlv_diagnostic_path_init(&path);
    return path;
}

/**
 * @brief Pushes a tag onto the end of a path.
 *
 * Wraps tlv_diagnostic_path_push(); the same borrowing and lifetime rules apply.
 *
 * @param path Path to update.
 * @param tag  Tag of the element being descended into; borrowed.
 *
 * @return Success, or #error::from_c wrapping #TLV_ERR_BUFFER_TOO_SHORT if the path is full.
 * @note Overflow retains the outermost tags and increments path.omitted. Pair every
 *       push, including an overflowing push, with a pop when leaving that scope.
 */
inline expected<void, error> push_path(diagnostic_path& path, tlv::tag tag) {
    tlv_result_t rc = tlv_diagnostic_path_push(&path, detail::semantic_access::get(tag));
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}

/**
 * @brief Pops the last tag off a path.
 *
 * Wraps tlv_diagnostic_path_pop(). Omitted scopes are removed before retained tags.
 * Popping an empty path is a no-op.
 *
 * @param path Path to update.
 */
inline void pop_path(diagnostic_path& path) {
    tlv_diagnostic_path_pop(&path);
}

/**
 * @brief Sets the hierarchical path a diagnostic refers to.
 *
 * Wraps tlv_diagnostic_set_path(); the same borrowing and lifetime rules apply.
 *
 * @param target Diagnostic to update.
 * @param path   Borrowed path of enclosing tags.
 */
inline void set_path(diagnostic& target, const diagnostic_path& path) {
    tlv_diagnostic_set_path(&target, &path);
}

} // namespace tlv
#endif // OPENTLV_TLVPP_DIAGNOSTIC_HPP
