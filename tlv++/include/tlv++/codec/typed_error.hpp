// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_TYPED_ERROR_HPP
#define OPENTLV_TLVPP_TYPED_ERROR_HPP

#include "tlv++/compat.hpp"
#include "tlv/codec/codec.h"

/** @file
 * @brief Errors shared by typed field lookup, conversion and writing.
 */
namespace tlv {
/** @brief Identifies the stage that failed during a typed operation. */
enum class typed_errc {
    missing_field,     /**< No direct child with the requested tag exists. */
    tag_mismatch,      /**< The current element has a different tag. */
    invalid_node,      /**< The Node handle is empty or invalidated. */
    constructed_value, /**< Scalar decoding of constructed Nodes is unsupported. */
    codec,             /**< Value conversion failed; inspect codec_code. */
    framing            /**< Writer failed; inspect framing_code. */
};

/** @brief Allocation-free typed error retaining the original C error domain. */
struct typed_error {
    /** Failure stage. */
    typed_errc kind;
    /** Original codec code, or TLV_CODEC_OK for other stages. */
    tlv_codec_result_t codec_code;
    /** Original Writer code, or TLV_OK for other stages. */
    tlv_result_t framing_code;
    /** @brief Construct a lookup or Node error.
     * @param stage Failure stage.
     */
    explicit typed_error(typed_errc stage)
        : kind(stage), codec_code(TLV_CODEC_OK), framing_code(TLV_OK) {}
    /** @brief Preserve a Value codec error.
     * @param code Original codec failure.
     */
    explicit typed_error(tlv_codec_result_t code)
        : kind(typed_errc::codec), codec_code(code), framing_code(TLV_OK) {}
    /** @brief Preserve a Writer error.
     * @param code Original framing failure.
     */
    explicit typed_error(tlv_result_t code)
        : kind(typed_errc::framing), codec_code(TLV_CODEC_OK), framing_code(code) {}
};
} // namespace tlv
#endif
