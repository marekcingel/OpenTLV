#ifndef OPENTLV_BUILTINS_LLDP_CODEC_H
#define OPENTLV_BUILTINS_LLDP_CODEC_H

#include "tlv/codec/values.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free codecs for the LLDP base information strings.
 *
 * Specialized descriptors require `OPENTLV_LLDP=ON`; the TTL/text source
 * aliases use core codecs and need no optional component. Descriptors have
 * static lifetime. Decode borrows
 * variable-length fields; keep input storage alive and unchanged. Encode takes
 * exactly sizeof the documented C representation; decode needs at least that
 * capacity. Use tlv_codec_encode() with NULL/0 for validated size queries.
 * Input and output must not overlap. Invalid lengths or field values return
 * #TLV_CODEC_ERR_INVALID_VALUE, nonempty NULL spans #TLV_CODEC_ERR_NULL_ARG,
 * and insufficient output capacity #TLV_CODEC_ERR_BUFFER_TOO_SHORT.
 * These codecs interpret Values only, without framing or sequence validation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Chassis or Port ID: subtype plus borrowed identifier octets. */
typedef struct tlv_lldp_id {
    /** Subtype in 1..7, interpreted in the selected Chassis/Port namespace. */
    uint8_t subtype;
    /** Nonempty identifier; includes address-family octet for network IDs.
     * The enclosing LLDP field length is checked by Schema. */
    tlv_value_t identifier;
} tlv_lldp_id_t;

/** @brief System Capabilities and Enabled Capabilities bitmaps. */
typedef struct tlv_lldp_capabilities {
    /** Advertised capabilities; unknown bits are preserved. */
    uint16_t supported;
    /** Enabled capabilities; must be a subset of supported. */
    uint16_t enabled;
} tlv_lldp_capabilities_t;

/** @brief Management Address fields with borrowed address and OID octets. */
typedef struct tlv_lldp_management_address {
    /** Nonzero address-family number; unknown families are preserved. */
    uint8_t address_subtype;
    /** Address alone, excluding subtype; 1..31 octets. */
    tlv_value_t address;
    /** Interface numbering: 1 (unknown), 2 (ifIndex), or 3 (system port). */
    uint8_t interface_subtype;
    /** Interface number, interpreted in the selected numbering namespace. */
    uint32_t interface_number;
    /** Encoded object identifier octets, 0..128; no ASN.1 decoding is performed. */
    tlv_value_t oid;
} tlv_lldp_management_address_t;

/** @brief Generic organisational information string, without vendor dispatch. */
typedef struct tlv_lldp_organisation {
    /** Three OUI octets in wire order, copied into the representation. */
    uint8_t oui[3];
    /** Organisation-defined subtype; all byte values are preserved. */
    uint8_t subtype;
    /** Borrowed remaining payload; enclosing field length is checked by Schema. */
    tlv_value_t payload;
} tlv_lldp_organisation_t;

/**
 * @brief Chassis ID codec (Type 1), represented by #tlv_lldp_id_t.
 *
 * Subtypes 1..7 and a nonempty identifier. Schema owns the maximum field
 * length. Subtype 4 requires six MAC
 * octets; subtype 5 requires an address-family byte and at least one address
 * octet. IPv4/IPv6 families require 4/16 address octets. Other identifier
 * subtypes are opaque; no textual normalization or assignment lookup occurs.
 */
extern TLV_API const tlv_codec_t tlv_lldp_codec_chassis_id;
/**
 * @brief Port ID codec (Type 2), represented by #tlv_lldp_id_t.
 *
 * Same representation as Chassis ID; MAC is subtype 3 and network address subtype 4.
 * Other subtype-specific syntax is left to the application.
 */
extern TLV_API const tlv_codec_t tlv_lldp_codec_port_id;
/** @brief Source alias of #tlv_codec_uint16_be for TTL (Type 3), including zero.
 * No separate binary symbol or domain dispatcher is used. */
#define tlv_lldp_codec_ttl tlv_codec_uint16_be
/**
 * @brief Text information codec for Types 4, 5 and 6, represented by #tlv_value_t.
 *
 * Source alias of #tlv_codec_bytes; no separate binary symbol. Preserves arbitrary
 * octets exactly, without a terminator, character conversion,
 * UTF-8 validation or locale interpretation. An empty string is representable.
 * The LLDP field limit of 255 octets belongs to tlv_lldp_schema.
 */
#define tlv_lldp_codec_text tlv_codec_bytes
/**
 * @brief Type 7 codec: #tlv_lldp_capabilities_t as two big-endian 16-bit fields.
 *
 * Requires four octets and enabled bits contained in supported. Reserved bits
 * are preserved; capability assignments and device-role policy are not checked.
 */
extern TLV_API const tlv_codec_t tlv_lldp_codec_capabilities;
/**
 * @brief Type 8 codec, represented by #tlv_lldp_management_address_t.
 *
 * Validates both inner lengths, exact consumption and interface subtype 1..3.
 * Address length excludes subtype in C and includes it on wire. IPv4/IPv6
 * require 4/16 address octets. Interface number is big-endian on wire.
 * OID octets remain opaque; the codec does not establish ASN.1 OID validity.
 */
extern TLV_API const tlv_codec_t tlv_lldp_codec_management_address;
/**
 * @brief Type 127 codec, represented by #tlv_lldp_organisation_t.
 *
 * Requires a four-octet prefix: three OUI bytes and subtype, then opaque payload.
 * No outer length limit is applied; tlv_lldp_schema owns the 511-octet limit.
 * Does not validate OUI ownership, vendor syntax, or nested TLVs.
 */
extern TLV_API const tlv_codec_t tlv_lldp_codec_organisation;

#ifdef __cplusplus
}
#endif
#endif
