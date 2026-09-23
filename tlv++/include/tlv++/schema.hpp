#ifndef OPENTLV_TLVPP_SCHEMA_HPP
#define OPENTLV_TLVPP_SCHEMA_HPP
#include "tlv++/types.hpp"
#include "tlv/schema/schema.h"

/**
 * @file schema.hpp
 * @brief C++ wrapper for structural schema validation.
 */

namespace tlv {

/** @brief C++ alias for the schema-specific diagnostic type, #tlv_schema_diagnostic_t. */
using schema_diagnostic = tlv_schema_diagnostic_t;
/**
 * @brief Validates framing, nesting, lengths and occurrence counts against a schema.
 *
 * Wraps tlv_schema_validate(); the conventions for limits and offsets are
 * the same. Values are never decoded and no allocation occurs.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format.
 * @param is_constructed Nesting predicate, or `nullptr` to treat values as opaque.
 * @param schema        Structural schema; borrowed.
 * @param max_depth     Maximum nesting depth.
 * @param max_elements  Maximum total elements.
 * @param error_offset  Optional. On failure receives the offset of the
 *                      failure; see tlv_schema_validate().
 *
 * @return Success if the data conforms; otherwise the error of
 *         tlv_schema_validate(), including #TLV_ERR_SCHEMA and
 *         #TLV_ERR_SCHEMA_MISSING.
 */
TLV_NODISCARD inline expected<void, error> validate(bytes data, const tlv_reader_format_t& format,
                                                    tlv_is_constructed_fn         is_constructed,
                                                    const tlv_structure_schema_t& schema,
                                                    size_t max_depth, size_t max_elements,
                                                    size_t* error_offset = nullptr) {
    tlv_result_t rc =
        tlv_schema_validate(reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format,
                            is_constructed, &schema, max_depth, max_elements, error_offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}

/**
 * @brief Validates a structure and reports every schema violation.
 *
 * Wraps tlv_schema_validate_all(); the rules, the path and offset of each
 * violation and the storage conventions are the same. No allocation occurs.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format.
 * @param is_constructed Nesting predicate, or `nullptr` to treat values as opaque.
 * @param schema        Structural schema; borrowed.
 * @param max_depth     Maximum nesting depth.
 * @param max_elements  Maximum total elements.
 * @param issues        Destination for the first `capacity` violations; may be
 *                      `nullptr` only if `capacity` is zero.
 * @param capacity      Number of entries `issues` can hold.
 * @param unknown       Policy for tags without a rule.
 * @param error_offset  Optional. On a wire-level failure receives the offset
 *                      of the failure; see tlv_schema_validate_all().
 *
 * @return The total number of violations, which is zero if the data conforms
 *         and can exceed `capacity`; otherwise the error of
 *         tlv_schema_validate_all() for invalid arguments or unparseable input.
 *
 * @see tlv_schema_issue_path_string
 */
TLV_NODISCARD inline expected<size_t, error>
validate_all(bytes data, const tlv_reader_format_t& format, tlv_is_constructed_fn is_constructed,
             const tlv_structure_schema_t& schema, size_t max_depth, size_t max_elements,
             tlv_schema_issue_t* issues, size_t capacity,
             tlv_schema_unknown_policy_t unknown = TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
             size_t*                     error_offset = nullptr) {
    tlv_schema_report_t report = {issues, capacity, 0};
    tlv_result_t        rc = tlv_schema_validate_all(
        reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format, is_constructed,
        &schema, max_depth, max_elements, unknown, &report, error_offset);
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) return unexpected<error>(error::from_c(rc));
    return report.count;
}

/**
 * @brief Validates a structure and reports every schema violation as a #schema_diagnostic.
 *
 * Wraps tlv_schema_validate_all_diag(); the rules, order and storage
 * conventions are the same as validate_all(), and each diagnostic
 * additionally carries the schema field name (if the rule has one) and the
 * expected-versus-actual detail for its kind.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format.
 * @param is_constructed Nesting predicate, or `nullptr` to treat values as opaque.
 * @param schema        Structural schema; borrowed.
 * @param max_depth     Maximum nesting depth.
 * @param max_elements  Maximum total elements.
 * @param diagnostics   Destination for the first `capacity` violations; may be
 *                      `nullptr` only if `capacity` is zero.
 * @param capacity      Number of entries `diagnostics` can hold.
 * @param unknown       Policy for tags without a rule.
 * @param error_offset  Optional. On a wire-level failure receives the offset
 *                      of the failure; see tlv_schema_validate_all_diag().
 *
 * @return The total number of violations, which is zero if the data conforms
 *         and can exceed `capacity`; otherwise the error of
 *         tlv_schema_validate_all_diag() for invalid arguments or unparseable input.
 *
 * @see tlv_schema_diagnostic_t
 */
TLV_NODISCARD inline expected<size_t, error>
validate_all_diag(bytes data, const tlv_reader_format_t& format,
                  tlv_is_constructed_fn is_constructed, const tlv_structure_schema_t& schema,
                  size_t max_depth, size_t max_elements, schema_diagnostic* diagnostics,
                  size_t                      capacity,
                  tlv_schema_unknown_policy_t unknown = TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
                  size_t*                     error_offset = nullptr) {
    tlv_schema_diagnostic_report_t report = {diagnostics, capacity, 0};
    tlv_result_t                   rc = tlv_schema_validate_all_diag(
        reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format, is_constructed,
        &schema, max_depth, max_elements, unknown, &report, error_offset);
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) return unexpected<error>(error::from_c(rc));
    return report.count;
}
} // namespace tlv
#endif
