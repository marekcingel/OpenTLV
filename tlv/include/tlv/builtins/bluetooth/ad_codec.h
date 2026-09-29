#ifndef OPENTLV_BUILTINS_BLUETOOTH_AD_CODEC_H
#define OPENTLV_BUILTINS_BLUETOOTH_AD_CODEC_H

#include "tlv/codec/codec.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free codecs for basic Bluetooth Advertising Data values.
 *
 * Use tlv_codec_decode() and tlv_codec_encode() on value bytes only. Callers
 * select the codec from the AD Type; these immutable, static-lifetime
 * descriptors do not depend on the Bluetooth LTV format, schema or registry.
 * They require `OPENTLV_BLUETOOTH=ON`.
 *
 * Flags and Local Name use #tlv_value_t, borrowing the complete input without
 * changing it. Keep that storage alive and immutable while using the result.
 * Tx Power uses `int8_t`. Supply the documented type and alignment. Encode
 * requires exactly its `sizeof`; decode requires at least that capacity.
 * No codec allocates, adds framing, or changes the original element.
 * Input and output must not overlap. Size queries and error behavior follow
 * #tlv_codec_t; tlv_codec_strerror() supplies readable diagnostics.
 * UUID list codecs for AD Types 0x02 through 0x07 are declared separately in
 * tlv/builtins/bluetooth/uuid.h, together with reusable UUID value codecs.
 *
 * @see
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v14/out/en/core-supplementary-features/data-types-specification.html
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup codecs
 * @{
 */

/** @brief Defined masks in the first Flags octet (CSS Part A, section 1.3). */
typedef enum tlv_bluetooth_ad_flag {
    /** LE Limited Discoverable Mode. */
    TLV_BLUETOOTH_AD_FLAG_LE_LIMITED_DISCOVERABLE = 0x01,
    /** LE General Discoverable Mode. */
    TLV_BLUETOOTH_AD_FLAG_LE_GENERAL_DISCOVERABLE = 0x02,
    /** BR/EDR is not supported. */
    TLV_BLUETOOTH_AD_FLAG_BR_EDR_NOT_SUPPORTED = 0x04,
    /** Controller supports simultaneous LE and BR/EDR to the same device. */
    TLV_BLUETOOTH_AD_FLAG_SIMULTANEOUS_LE_BR_EDR_CONTROLLER = 0x08
} tlv_bluetooth_ad_flag_t;

/**
 * @brief Flags codec for AD Type 0x01, represented by a borrowed #tlv_value_t.
 *
 * Accepts zero or more octets, preserving unknown bits and extension octets.
 * Bit 4 was previously used and is not assigned a current meaning here.
 * An empty value means all bits clear; an absent AD structure is a separate
 * condition. Both directions reject a nonempty value ending in an all-zero
 * octet with #TLV_CODEC_ERR_INVALID_VALUE (CSS requires trailing zero octets
 * to be omitted). No channel-specific or connectability policy is enforced.
 *
 * Encode validates the borrowed pointer and native size before accessing it;
 * a nonempty NULL span is #TLV_CODEC_ERR_NULL_ARG, and an unrepresentable
 * size is #TLV_CODEC_ERR_INVALID_VALUE. Insufficient destination capacity is
 * #TLV_CODEC_ERR_BUFFER_TOO_SHORT. Encode preserves accepted bytes exactly.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_ad_codec_flags;

/**
 * @brief Tests masks in the first octet of a decoded Flags value.
 *
 * @param[in] flags Borrowed Flags view; NULL and empty views report false.
 *                 A nonempty view must have at least one readable byte.
 * @param[in] mask Bit mask, or bitwise OR of masks; zero reports false.
 *
 * @return `true` if any masked bit is set, otherwise `false`.
 *
 * @note Does not validate or modify the view and never allocates. An absent
 *       Flags AD structure must not be interpreted as an all-clear value.
 */
TLV_API bool tlv_bluetooth_ad_flags_test(const tlv_value_t* flags, uint8_t mask);

/**
 * @brief Local Name codec for AD Types 0x08 and 0x09, using a borrowed #tlv_value_t.
 *
 * Both shortened and complete names use the same codec. Accepts valid UTF-8
 * of any native length, including embedded U+0000; no NUL terminator is
 * appended or required. Length is in bytes, not characters. Encode copies
 * exactly the supplied bytes. The caller retains the AD Type to distinguish
 * a shortened name from a complete name; no full-name comparison is made.
 *
 * The 248-byte field limit belongs to tlv_bluetooth_ad_schema. Both directions
 * report #TLV_CODEC_ERR_INVALID_VALUE for malformed/truncated UTF-8, overlong
 * encodings, surrogates or code points
 * above U+10FFFF. A nonempty NULL span is #TLV_CODEC_ERR_NULL_ARG; insufficient
 * destination capacity is #TLV_CODEC_ERR_BUFFER_TOO_SHORT.
 *
 * @see
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/generic-access-profile.html
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_ad_codec_local_name;

/**
 * @brief Tx Power Level codec for AD Type 0x0A, represented by `int8_t` dBm.
 *
 * Decode requires exactly one signed two's-complement octet in the Bluetooth
 * range -127 through +127 dBm; for example, FC decodes to -4. Encode writes
 * exactly one octet. The excluded value -128 (80 on wire), incorrect wire
 * length or incorrect encode object size is #TLV_CODEC_ERR_INVALID_VALUE.
 * Insufficient destination capacity is #TLV_CODEC_ERR_BUFFER_TOO_SHORT.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_ad_codec_tx_power;

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_BUILTINS_BLUETOOTH_AD_CODEC_H */
