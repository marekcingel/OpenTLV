// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_DHCP_CODEC_H
#define OPENTLV_BUILTINS_DHCP_CODEC_H

#include "tlv/codec/values.h"

/**
 * @file
 * @ingroup codecs
 * @brief DHCPv4 message type semantics composed with generic value codecs.
 *
 * These constants and the generic codec alias require no optional component.
 * DHCP framing/registry APIs require OPENTLV_DHCP=ON. Integers, IPv4 addresses, address lists,
 * opaque identifiers and Parameter Request Lists use the generic codecs in tlv/codec/values.h and
 * tlv/codec/ipv4.h directly. PRL bytes retain order, duplicates and unknown option Codes.
 * Option-specific length and value policy is not imposed here.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Named DHCP Message Type values from RFC 2132 section 9.6.
 * These constants are not the codec's C representation; use uint8_t. */
typedef enum tlv_dhcpv4_message_type {
    /** DHCPDISCOVER message. */
    TLV_DHCPV4_DISCOVER = 1,
    /** DHCPOFFER message. */
    TLV_DHCPV4_OFFER = 2,
    /** DHCPREQUEST message. */
    TLV_DHCPV4_REQUEST = 3,
    /** DHCPDECLINE message. */
    TLV_DHCPV4_DECLINE = 4,
    /** DHCPACK message. */
    TLV_DHCPV4_ACK = 5,
    /** DHCPNAK message. */
    TLV_DHCPV4_NAK = 6,
    /** DHCPRELEASE message. */
    TLV_DHCPV4_RELEASE = 7,
    /** DHCPINFORM message. */
    TLV_DHCPV4_INFORM = 8
} tlv_dhcpv4_message_type_t;

/**
 * @brief Converts exactly one DHCP Message Type byte to/from uint8_t.
 *
 * Source alias of #tlv_codec_uint8; no separate binary symbol or callbacks.
 * Named constants cover RFC 2132 types;
 * every other byte, including unassigned values, is preserved for round-trip.
 * This is representation validation, not validation of a DHCP exchange.
 * Uses the generic uint8 codec contract, including validated size queries,
 * exact encode object size, bounds checking and no allocation.
 *
 * @see https://www.rfc-editor.org/rfc/rfc2132.html#section-9.6
 */
#define tlv_dhcpv4_codec_message_type tlv_codec_uint8

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_BUILTINS_DHCP_CODEC_H */
