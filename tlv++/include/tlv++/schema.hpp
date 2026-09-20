#ifndef OPENTLV_TLVPP_SCHEMA_HPP
#define OPENTLV_TLVPP_SCHEMA_HPP
#include "tlv++/types.hpp"
#include "tlv/schemas/schema.h"

/**
 * @file schema.hpp
 * @brief C++ wrapper for structural schema validation.
 */

namespace tlv {
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
} // namespace tlv
#endif
