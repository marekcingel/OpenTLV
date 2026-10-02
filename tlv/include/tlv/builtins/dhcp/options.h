// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_DHCP_OPTIONS_H
#define OPENTLV_BUILTINS_DHCP_OPTIONS_H

#include "tlv/definition.h"

/**
 * @file
 * @ingroup core
 * @brief DHCPv4 option Code definitions.
 *
 * @note Requires `OPENTLV_DHCP=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Immutable DHCPv4 option registry with static lifetime.
 *
 * Maps canonical one-byte Codes to descriptive names. Initial coverage is
 * 0, 1, 3, 6, 12, 15, 50, 51, 53, 54, 55, 57, 58, 59, 60, 61 and 255.
 * This is not an exhaustive list of assigned options. Entries, identifier
 * bytes and names are borrowed immutable storage with static lifetime.
 *
 * Use tlv_definition_find() for allocation-free lookup. Unknown Codes return
 * NULL and remain valid for structural parsing. The registry neither defines
 * framing nor decodes Values, validates lengths or imposes schema constraints.
 * Requires `OPENTLV_DHCP=ON`; no Reader or Writer is required.
 *
 * @see tlv_definition_find
 * @see https://www.rfc-editor.org/rfc/rfc2132.html
 */
extern TLV_API const tlv_definition_registry_t tlv_dhcpv4_options;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_BUILTINS_DHCP_OPTIONS_H */
