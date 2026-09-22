#ifndef OPENTLV_TLVPP_DIAGNOSTIC_HPP
#define OPENTLV_TLVPP_DIAGNOSTIC_HPP
#include "tlv/diagnostic.h"

/**
 * @file diagnostic.hpp
 * @brief C++ wrapper for the structured diagnostic model.
 */

namespace tlv {

/** @brief C++ alias for the C diagnostic type, #tlv_diagnostic_t. */
using diagnostic = tlv_diagnostic_t;

/** @brief C++ alias for the C diagnostic context type, #tlv_diagnostic_context_t. */
using diagnostic_context = tlv_diagnostic_context_t;

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

} // namespace tlv
#endif // OPENTLV_TLVPP_DIAGNOSTIC_HPP
