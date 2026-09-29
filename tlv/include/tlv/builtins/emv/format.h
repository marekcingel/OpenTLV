#ifndef OPENTLV_BUILTINS_EMV_FORMAT_H
#define OPENTLV_BUILTINS_EMV_FORMAT_H

#include "tlv/format.h"

/**
 * @file
 * @ingroup formats
 * @brief EMV Contact Book 3 BER-TLV element framing.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Definite EMV BER-TLV framing, independent of ASN.1 BER policy.
 *
 * Identifiers retain their wire bytes and have one or two octets. An escaped
 * identifier has a nonzero seven-bit second octet with no continuation.
 * The first octet 00 is padding, not an element identifier. No ASN.1 universal
 * tag-number or value-type rules are applied; unknown identifiers are allowed.
 *
 * Lengths are unsigned big-endian counts from 0 through 65535, encoded in short
 * form or with one or two subsequent octets (81 or 82). Reading accepts padded
 * and nonminimal definite lengths; writing uses the shortest representation.
 * Indefinite lengths and EOC termination are unsupported. Values remain opaque,
 * including constructed values; framing does not recursively validate children.
 *
 * The constructed callback reports only bit 20 of the first identifier octet.
 * Semantic templates such as 9F31 require explicit EMV-aware traversal.
 * Padding, APDU boundaries, per-object length limits and restrictions on the
 * use of three-octet lengths belong to the enclosing application or schema.
 * This descriptor covers element framing, not full Book 3 conformance.
 *
 * @note Available with OPENTLV_EMV. Immutable, allocation-free, and
 * zero-copy on read. No ASN.1 format is called by this descriptor.
 */
extern TLV_API const tlv_format_t tlv_format_emv;

#ifdef __cplusplus
}
#endif
#endif
