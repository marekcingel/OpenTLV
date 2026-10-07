// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_TYPED_ERROR_HPP
#define OPENTLV_TLVPP_TYPED_ERROR_HPP

#include "tlv++/compat.hpp"
#include "tlv++/codec/dynamic.hpp"
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
    /** @brief Preserve a C++ Value codec failure without allocation. */
    explicit typed_error(codec_errc code)
        : kind(typed_errc::codec), codec_code(static_cast<tlv_codec_result_t>(code)),
          framing_code(TLV_OK) {}
    /** @brief Original Value codec status, meaningful for kind == typed_errc::codec. */
    codec_errc codec_status() const noexcept {
        return static_cast<codec_errc>(codec_code);
    }
    /** @brief Original framing status, meaningful for kind == typed_errc::framing. */
    errc framing_status() const noexcept {
        return static_cast<errc>(framing_code);
    }
    /** @brief Static description of the failed lookup, conversion or framing operation. */
    const char* message() const noexcept {
        switch (kind) {
            case typed_errc::codec: return tlv::message(codec_status());
            case typed_errc::framing: return tlv::message(framing_status());
            case typed_errc::missing_field: return "Required field is absent";
            case typed_errc::tag_mismatch: return "Field identifier does not match";
            case typed_errc::invalid_node: return "Node handle is invalid";
            case typed_errc::constructed_value:
                return "Constructed Value cannot be decoded as a scalar";
        }
        return "Unknown typed field failure";
    }
    /** @brief Project common diagnostic metadata; kind and codec_status() retain exact detail. */
    tlv::error failure() const noexcept {
        if (kind == typed_errc::codec) return to_error(codec_status());
        if (kind == typed_errc::framing) return tlv::error(framing_status(), operation::writer);
        const auto code =
            kind == typed_errc::missing_field ? errc::missing_field : errc::invalid_argument;
        return tlv::error(static_cast<tlv_result_t>(code), message()).during(operation::codec);
    }
    /** @brief Preserve a Writer error.
     * @param code Original framing failure.
     */
    explicit typed_error(tlv_result_t code)
        : kind(typed_errc::framing), codec_code(TLV_CODEC_OK), framing_code(code) {}
};
} // namespace tlv
#endif
