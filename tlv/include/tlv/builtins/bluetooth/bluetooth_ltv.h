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
 * @note Writing any tag size other than one returns #TLV_ERR_INVALID_TAG_SIZE,
 *       and a value longer than 254 bytes returns #TLV_ERR_INVALID_LENGTH.
 */

/** @addtogroup formats
 * @{
 */

/** @brief Reader format for Bluetooth LTV; a borrowed, immutable global. */
extern TLV_API const tlv_reader_format_t tlv_reader_format_bluetooth_ltv;
/** @brief Writer format for Bluetooth LTV; a borrowed, immutable global. */
extern TLV_API const tlv_writer_format_t tlv_writer_format_bluetooth_ltv;

#ifdef __cplusplus
}
#endif
/** @} */

#endif
