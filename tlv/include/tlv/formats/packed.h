// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FORMATS_PACKED_H
#define OPENTLV_FORMATS_PACKED_H

#include "tlv/formats/compose.h"
#include "tlv/field/packed.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Definite packed Tag/Length header composition.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Immutable packed header configuration with borrowed canonical Tags.
 *
 * Both fields use header_size backing bytes and the same byte order. Their
 * bits must not overlap; their source byte envelopes may overlap. Unused header
 * bits are ignored on decode and zeroed on encode. TAG_AND_VALUE counts the
 * Tag's wire byte envelope, not tag_size canonical bytes.
 *
 * Entry i of tag_storage must be the unsigned big-endian encoding of i in
 * tag_size bytes (leading zero bytes allowed). The table contains all 2^width
 * entries. Validation checks capacity and arithmetic, not table contents;
 * decode checks the selected entry. No allocation occurs. The configuration
 * and table must remain unchanged and alive for all operations and retained
 * decoded Tags, including shallow copies.
 */
typedef struct tlv_packed_layout {
    size_t header_size;              /**< Header size in bytes, 1..8. */
    tlv_packed_field_t tag;          /**< Packed unsigned identifier. */
    tlv_packed_field_t length;       /**< Packed unsigned count. */
    tlv_length_scope_t length_scope; /**< Value or wire Tag envelope plus Value. */
    const uint8_t* tag_storage;      /**< Required immutable canonical identifier table. */
    size_t tag_size;                 /**< Canonical identifier width, ceil(tag.bit_width/8)..8. */
    size_t tag_storage_size;         /**< Available table capacity in bytes. */
} tlv_packed_layout_t;

/**
 * @brief Validate packed configuration without reading the identifier table.
 *
 * @param[in] layout Required borrowed configuration.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for NULL layout or storage.
 * @return #TLV_ERR_INVALID_ARG for invalid widths, overlap, scope or capacity.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported field byte order.
 * @return #TLV_ERR_OVERFLOW if the full table size cannot fit size_t.
 * @note Never allocates or modifies configuration.
 */
TLV_API tlv_result_t tlv_packed_layout_validate(const tlv_packed_layout_t* layout);

/**
 * @brief Decode one packed element using the canonical Format callback contract.
 *
 * @param[in] context Required immutable tlv_packed_layout_t.
 * @param[in] data Source buffer of size bytes; NULL only for zero size.
 * @param[in] size Available bytes.
 * @param[out] result Required decoded output; unchanged on failure.
 * @param[out] error Required diagnostic output; may change on failure.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for required NULL pointers.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for incomplete header or Value.
 * @return #TLV_ERR_INVALID_LENGTH if the count is smaller than its Tag scope.
 * @return #TLV_ERR_INVALID_TAG if the selected table entry is not canonical.
 * @return Configuration errors from tlv_packed_layout_validate().
 * @note Value borrows data; Tag borrows the immutable table. No allocation.
 * Outputs and input storage must not overlap. Prefer tlv_format_decode(),
 * which stages output and initializes diagnostics.
 */
TLV_API tlv_result_t tlv_packed_decode(const void* context, const uint8_t* data, size_t size,
                                       tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure packed encoding without accessing Value bytes.
 *
 * @param[in] context Required immutable tlv_packed_layout_t.
 * @param[in] element Required element with readable Tag bytes.
 * @param[out] result Required encoding sizes; unchanged on failure.
 * @param[out] error Required diagnostics; may change on failure.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for required NULL pointers.
 * @return #TLV_ERR_INVALID_TAG_SIZE for a different canonical Tag width.
 * @return #TLV_ERR_INVALID_TAG for a Tag outside the packed field range.
 * @return #TLV_ERR_INVALID_LENGTH for a count outside the packed field range.
 * @return Configuration errors from tlv_packed_layout_validate().
 * @note No allocation. Outputs must not overlap inputs. Sizes are logical;
 * encoding additionally checks native output capacity.
 */
TLV_API tlv_result_t tlv_packed_measure(const void* context, const tlv_element_t* element,
                                        tlv_encoding_t* result, tlv_format_error_t* error);

/**
 * @brief Encode packed framing with every unused header bit cleared.
 *
 * @param[in] context Required immutable tlv_packed_layout_t.
 * @param[in] element Required element with readable Tag and Value bytes.
 * @param[out] data Required destination, disjoint from inputs and configuration.
 * @param[in] capacity Available destination bytes.
 * @param[out] written Required byte count; unchanged on failure.
 * @param[out] error Required diagnostics; may change on failure.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for required NULL pointers, including nonempty Value.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the encoding exceeds capacity.
 * @return Errors from tlv_packed_measure().
 * @note No allocation. Destination is unchanged on failure. Outputs must be
 * disjoint. Prefer tlv_format_encode() for canonical size preflight.
 */
TLV_API tlv_result_t tlv_packed_encode(const void* context, const tlv_element_t* element,
                                       uint8_t* data, size_t capacity, size_t* written,
                                       tlv_format_error_t* error);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
