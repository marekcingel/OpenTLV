#ifndef OPENTLV_BUILTINS_BLUETOOTH_BLUETOOTH_LTV_H
#define OPENTLV_BUILTINS_BLUETOOTH_BLUETOOTH_LTV_H

#include "tlv/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Bluetooth LTV: one length byte, one type byte, then the value.
 *
 * Bluetooth advertising and scan-response data, and the Generic Access
 * Profile data types, are a sequence of Length | Type | Value structures. The
 * length byte counts the type byte plus the value bytes, so a structure
 * occupies `length + 1` bytes and carries at most 254 value bytes. The type
 * (for example an AD type such as `01` Flags or `09` Complete Local Name) is
 * exposed as a one-byte OpenTLV tag; the value is opaque.
 *
 * Unknown types are structurally valid and are skipped by length alone.
 *
 * A length byte of zero is rejected with #TLV_ERR_INVALID_LENGTH: it has no
 * type byte, and in Bluetooth data it is the start of the non-significant
 * zero padding rather than an element.
 *
 * This format has no constructed types: nesting is left to the caller.
 *
 * This is the configurable Fixed format (tlv/formats/fixed.h) preset to
 * `{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_LTV,
 * TLV_LENGTH_SCOPE_TAG_AND_VALUE}`: every read and write goes through that
 * same generic implementation, so this global exists only to name and expose
 * the preset, not a separate parser or writer.
 *
 * @note Writing any tag size other than one returns #TLV_ERR_INVALID_TAG_SIZE,
 *       and a value longer than 254 bytes returns #TLV_ERR_INVALID_LENGTH.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */

/** @addtogroup formats
 * @{
 */

/** @brief Format for Bluetooth LTV; a borrowed, immutable global. */
extern TLV_API const tlv_format_t tlv_format_bluetooth_ltv;

#ifdef __cplusplus
}
#endif
/** @} */

#endif
