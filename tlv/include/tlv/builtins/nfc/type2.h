// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_NFC_TYPE2_H
#define OPENTLV_BUILTINS_NFC_TYPE2_H

#include "tlv/format.h"

/** @file
 * @ingroup formats
 * @brief NFC Forum Type 2 Tag TLV stream framing (Type 2 Tag Operation 1.1, section 2.3).
 *
 * Supply a contiguous TLV stream from the data area, excluding the Capability
 * Container, lock bytes and reserved memory. This descriptor does not map a
 * physical tag dump, interpret NDEF records or validate control Values/order.
 * Source offsets refer to the supplied stream. Requires `OPENTLV_NFC=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Defined one-byte Type 2 TLV identifier values.
 * @note Form a Tag from the corresponding byte; these constants do not change
 * the byte-identity contract of #tlv_tag_t.
 */
enum tlv_nfc_type2_tag {
    TLV_NFC_TYPE2_NULL = 0x00,           /**< Padding, with no Length or Value. */
    TLV_NFC_TYPE2_LOCK_CONTROL = 0x01,   /**< Opaque lock-control Value. */
    TLV_NFC_TYPE2_MEMORY_CONTROL = 0x02, /**< Opaque reserved-memory-control Value. */
    TLV_NFC_TYPE2_NDEF_MESSAGE = 0x03,   /**< Opaque NDEF message Value. */
    TLV_NFC_TYPE2_PROPRIETARY = 0xFD,    /**< Opaque proprietary Value. */
    TLV_NFC_TYPE2_TERMINATOR = 0xFE      /**< End marker, with no Length or Value. */
};

/** @brief Immutable NFC Type 2 framing descriptor with static lifetime.
 *
 * Tags have one byte. NULL and Terminator consume only Tag and expose an empty
 * Value, an absent source Length and present empty Value/Trailer at offset one.
 * Other tags (including reserved identifiers) have Length followed by opaque
 * Value. Length is one byte for 0..254 or FF followed by two big-endian bytes
 * for 255..65534. Extended counts below 255 and the reserved FFFF are rejected.
 *
 * Reader returns NULL and Terminator as elements; it neither skips padding nor
 * stops automatically. The caller handles termination and bytes after it.
 * No automatically constructed Values, allocations or NDEF validation.
 *
 * Decode returns #TLV_ERR_BUFFER_TOO_SHORT for incomplete fields/Values and
 * #TLV_ERR_INVALID_LENGTH for invalid extended counts. Encode/measure reject
 * nonempty NULL/Terminator Values and Values above 65534 with
 * #TLV_ERR_INVALID_LENGTH, and non-one-byte Tags with #TLV_ERR_INVALID_TAG_SIZE.
 * Tags and Values borrow the immutable source; retain it for their lifetime.
 * Measurement does not access Value storage. Encoding regenerates valid wire
 * bytes; exact unchanged-source preservation uses tlv_source_preserve().
 */
extern TLV_API const tlv_format_t tlv_format_nfc_type2;

#ifdef __cplusplus
}
#endif
#endif
