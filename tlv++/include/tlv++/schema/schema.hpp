// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_SCHEMA_HPP
#define OPENTLV_TLVPP_SCHEMA_HPP
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"
#include "tlv++/schema/definition.hpp"
#include "tlv++/schema/report.hpp"
#include "tlv/schema/schema.h"

/**
 * @file schema.hpp
 * @brief C++ wrapper for structural schema validation.
 */

namespace tlv {

/**
 * @brief Validate wire structure against a C++ Schema without allocation.
 * @param data Borrowed wire bytes.
 * @param format Borrowed Format and immutable context.
 * @param definition Borrowed Schema tables, names and identifiers.
 * @param max_depth Maximum nesting depth, bounded by the canonical engine's capacity.
 * @param max_elements Maximum element count.
 * @return Success or a canonical error with the failure's absolute byte offset.
 * @note Does not decode semantic Values; all borrows need only survive this call.
 */
inline expected<void, error> validate(bytes data, tlv::format format, schema definition,
                                      size_t max_depth = TLV_SCHEMA_MAX_DEPTH,
                                      size_t max_elements = SIZE_MAX) {
    tlv_schema_diagnostic_t diagnostic{};
    const auto rc = tlv_schema_validate(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                        &detail::format_access::get(format),
                                        detail::schema_access::get(definition), max_depth,
                                        max_elements, &diagnostic);
    if (rc != TLV_OK) return unexpected<error>(detail::error_access::schema(diagnostic));
    return {};
}

/** @brief Explicit interoperability with native Schema tables and diagnostic storage. */
namespace native {
/** @brief C++ alias for the schema-specific diagnostic type, #tlv_schema_diagnostic_t. */
using schema_diagnostic = tlv_schema_diagnostic_t;
/**
 * @brief Validates framing, nesting, lengths and occurrence counts against a schema.
 *
 * Wraps tlv_schema_validate(); the conventions for limits and offsets are
 * the same. Values are never decoded and no allocation occurs.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format. A `nullptr` `format.is_constructed`
 *                      treats values as opaque.
 * @param schema        Structural schema; borrowed.
 * @param max_depth     Maximum nesting depth.
 * @param max_elements  Maximum total elements.
 * @param diagnostic Optional typed Schema failure and location.
 *
 * @return Success if the data conforms; otherwise the error of
 *         tlv_schema_validate(), including #TLV_ERR_SCHEMA and
 *         #TLV_ERR_INVALID_SCHEMA.
 */
TLV_NODISCARD inline expected<void, error> validate(bytes data, const tlv_format_t& format,
                                                    const tlv_structure_schema_t& schema,
                                                    size_t max_depth, size_t max_elements,
                                                    tlv_schema_diagnostic_t* diagnostic = nullptr) {
    tlv_result_t rc =
        tlv_schema_validate(reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format,
                            &schema, max_depth, max_elements, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}

/**
 * @brief Validates a structure and reports every schema violation as a #schema_diagnostic.
 *
 * Wraps tlv_schema_validate_all_diag(); the rules, order and storage
 * conventions follow the C diagnostic report. Each diagnostic carries the schema field name (if the
 * rule has one) and the expected-versus-actual detail for its kind.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format. A `nullptr` `format.is_constructed`
 *                      treats values as opaque.
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
validate_all_diag(bytes data, const tlv_format_t& format, const tlv_structure_schema_t& schema,
                  size_t max_depth, size_t max_elements, schema_diagnostic* diagnostics,
                  size_t                      capacity,
                  tlv_schema_unknown_policy_t unknown = TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
                  size_t*                     error_offset = nullptr) {
    tlv_schema_diagnostic_report_t report = {diagnostics, capacity, 0};
    tlv_result_t rc = tlv_schema_validate_all_diag(reinterpret_cast<const uint8_t*>(data.data()),
                                                   data.size(), &format, &schema, max_depth,
                                                   max_elements, unknown, &report, error_offset);
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) return unexpected<error>(error::from_c(rc));
    return report.count;
}
/** @brief Validate a structure using a C++ Format view.
 * @copydetails validate(bytes, const tlv_format_t&, const tlv_structure_schema_t&, size_t, size_t,
 * tlv_schema_diagnostic_t*)
 */
TLV_NODISCARD inline expected<void, error> validate(bytes data, tlv::format format,
                                                    const tlv_structure_schema_t& schema,
                                                    size_t max_depth, size_t max_elements,
                                                    tlv_schema_diagnostic_t* diagnostic = nullptr) {
    return validate(data, detail::format_access::get(format), schema, max_depth, max_elements,
                    diagnostic);
}

/** @brief Collect structure diagnostics using a C++ Format view.
 * @copydetails validate_all_diag(bytes, const tlv_format_t&, const tlv_structure_schema_t&, size_t,
 * size_t, schema_diagnostic*, size_t, tlv_schema_unknown_policy_t, size_t*)
 */
TLV_NODISCARD inline expected<size_t, error>
validate_all_diag(bytes data, tlv::format format, const tlv_structure_schema_t& schema,
                  size_t max_depth, size_t max_elements, schema_diagnostic* diagnostics,
                  size_t                      capacity,
                  tlv_schema_unknown_policy_t unknown = TLV_SCHEMA_UNKNOWN_BY_SCHEMA,
                  size_t*                     error_offset = nullptr) {
    return validate_all_diag(data, detail::format_access::get(format), schema, max_depth,
                             max_elements, diagnostics, capacity, unknown, error_offset);
}
} // namespace native
} // namespace tlv
#endif
