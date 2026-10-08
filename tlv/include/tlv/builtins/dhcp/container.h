// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_DHCP_CONTAINER_H
#define OPENTLV_BUILTINS_DHCP_CONTAINER_H

#include "tlv/schema/schema.h"

/** @file
 * @brief DHCPv4 options sequence validation above generic Reader.
 * @note Requires `OPENTLV_DHCP=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Policy for the bytes following the first End option. */
typedef enum tlv_dhcpv4_options_tail {
    /** Require every remaining byte to be zero (Pad). */
    TLV_DHCPV4_OPTIONS_TAIL_PAD = 0,
    /** Require End to be the final byte of the supplied region. */
    TLV_DHCPV4_OPTIONS_TAIL_EMPTY,
    /** Ignore all remaining bytes without decoding them. */
    TLV_DHCPV4_OPTIONS_TAIL_IGNORE
} tlv_dhcpv4_options_tail_t;

/** @brief Rules for one DHCPv4 options region. */
typedef struct tlv_dhcpv4_options_rules {
    /** Nonzero requires End; zero permits a complete region without End. */
    int require_end;
    /** Policy applied only after the first End. */
    tlv_dhcpv4_options_tail_t tail;
} tlv_dhcpv4_options_rules_t;

/**
 * @brief Validates option framing, termination and trailing bytes without allocation.
 *
 * Uses the DHCPv4 format through generic Reader. Pad before End is an ordinary
 * element. The significant prefix includes all Pads before End and End itself;
 * it can be passed unchanged to Reader/Document/Query, preserving offsets.
 * Bytes inside Values never terminate the region. Unknown and repeated options
 * are accepted; no option-specific lengths, values, overload or concatenation
 * semantics are validated. No input bytes are copied or retained.
 *
 * @param[in] data Borrowed options region without packet header or magic cookie;
 *                 NULL only when size is zero.
 * @param[in] size Input size in bytes, including any tail.
 * @param[in] rules Rules, or NULL for required End and a zero-only tail.
 * @param[in] max_elements Maximum elements including Pad and End, excluding the
 *                         tail. Zero permits none; SIZE_MAX imposes no count limit.
 *                         The limit is checked before decoding the next element.
 * @param[out] significant_size Required; receives the prefix size through End,
 *                              or size if End is absent and optional.
 * @param[out] diagnostic Optional first-failure diagnostic, reset on each call.
 *                       Offsets are relative to data: the failing Reader field,
 *                       first forbidden tail byte, next element at the limit,
 *                       or size for missing End. Argument errors have unknown byte location.
 *                       Descriptions have static lifetime.
 * @return #TLV_OK on success. Empty input succeeds only with optional End.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for an unknown tail policy.
 * @return #TLV_ERR_SCHEMA with MISSING detail and SCOPE_END anchor if End is absent.
 * @return #TLV_ERR_SCHEMA for a forbidden tail byte.
 * @return #TLV_ERR_LIMIT when the element limit would be exceeded.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for a truncated option.
 * @return Any other Reader error, propagated unchanged.
 * @note significant_size is unchanged on failure. Output storage must not
 *       overlap input, rules or other outputs. Optional End with no End present
 *       keeps the entire region, including trailing Pad elements.
 */
TLV_API tlv_result_t tlv_dhcpv4_options_validate(const uint8_t* data, size_t size,
                                                 const tlv_dhcpv4_options_rules_t* rules,
                                                 size_t max_elements, size_t* significant_size,
                                                 tlv_schema_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif
#endif
