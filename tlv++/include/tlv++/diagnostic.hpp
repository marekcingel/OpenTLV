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

/**
 * @brief Attaches one context entry to a diagnostic.
 *
 * Wraps tlv_diagnostic_add_context(); the same borrowing and lifetime rules apply.
 *
 * @param target  Diagnostic to update.
 * @param context Caller-owned storage for the new entry; every field is overwritten.
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
 * @return Success, or #error::from_c wrapping #TLV_ERR_LIMIT if the path is already full.
 */
inline expected<void, error> push_path(diagnostic_path& path, tag_t tag) {
    tlv_result_t rc = tlv_diagnostic_path_push(&path, tag);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}

/**
 * @brief Pops the last tag off a path.
 *
 * Wraps tlv_diagnostic_path_pop(). Popping an empty path is a no-op.
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
