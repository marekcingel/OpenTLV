// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_DHCP_DHCPV4_H
#define OPENTLV_BUILTINS_DHCP_DHCPV4_H

#include "tlv/format.h"

/**
 * @file
 * @ingroup formats
 * @brief DHCPv4 option framing from RFC 2132 sections 2, 3.1 and 3.2.
 *
 * Normal options have a one-byte Code, one-byte Length and 0..255 Value bytes.
 * Pad (0) and End (255) contain only Code and have an empty semantic Value.
 * Identifiers and Values borrow the input. All values are opaque; no operation
 * allocates. Requires `OPENTLV_DHCP=ON`.
 *
 * The caller supplies an option region without the packet header or magic
 * cookie. Pad and End are returned as elements; the generic Reader neither
 * skips Pad nor stops at End. Use tlv_dhcpv4_options_validate() from
 * `tlv/builtins/dhcp/container.h` for termination and tail validation.
 * Option-specific validation, concatenation, overload and nested suboptions
 * belong to the caller.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Immutable DHCPv4 option descriptor with static lifetime.
 *
 * Decode reports #TLV_ERR_TRUNCATED for incomplete normal options.
 * Pad/End consume exactly one byte, with absent source Length and present empty
 * Value/Trailer ranges at offset one. Measure/encode reject Tag widths other
 * than one with #TLV_ERR_INVALID_TAG_SIZE, normal Values above 255 bytes with
 * #TLV_ERR_INVALID_LENGTH, and nonempty Pad/End Values with #TLV_ERR_INVALID_LENGTH.
 * Measurement needs no Value storage. No automatically constructed Values.
 * @see tlv_source_preserve
 */
extern TLV_API const tlv_format_t tlv_format_dhcpv4;

#ifdef __cplusplus
}
#endif
#endif
