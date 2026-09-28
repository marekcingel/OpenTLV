#ifndef OPENTLV_BUILTINS_BLUETOOTH_SERVICE_DATA_H
#define OPENTLV_BUILTINS_BLUETOOTH_SERVICE_DATA_H

#include "tlv/builtins/bluetooth/uuid.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free Bluetooth Service Data value codecs.
 *
 * Descriptors have static lifetime and are independent of AD framing, schema
 * and registry. UUID byte order follows the Bluetooth UUID codecs.
 * Payload bytes are opaque: no GATT service interpretation is performed.
 * Use tlv_codec_decode() and tlv_codec_encode(); their NULL, overlap and
 * size-query contracts apply. Input and output (including borrowed storage)
 * must not overlap. Supply correctly typed and aligned representation objects.
 * Decode requires at least sizeof(object); encode requires exactly sizeof(object).
 * Decode preserves the destination on error. Encode reports written == 0 on error.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup codecs
 * @{
 */

/**
 * @brief Service Data with a 16-bit UUID and borrowed opaque payload.
 *
 * Keep decoded input storage alive and immutable while either span is used.
 * Encoding uses uuid and payload; raw is informational and ignored, so a
 * caller-constructed object may leave raw empty.
 */
typedef struct tlv_bluetooth_service_data16 {
    /** Service UUID in the representation of #tlv_bluetooth_codec_uuid16. */
    uint16_t uuid;
    /** Borrowed bytes after the UUID; may be empty (NULL is valid for size zero). */
    tlv_value_t payload;
    /** Complete borrowed original value, including the UUID prefix. */
    tlv_value_t raw;
} tlv_bluetooth_service_data16_t;

/**
 * @brief Service Data codec for AD Type 0x16, using #tlv_bluetooth_service_data16_t.
 *
 * Decode requires at least 2 UUID bytes; the remainder is borrowed as payload.
 * Encode regenerates the UUID through #tlv_bluetooth_codec_uuid16 and copies
 * payload unchanged. Empty payloads are valid; no AD framing size limit applies.
 * A short UUID, incorrect encode object size, non-native payload size or total
 * size overflow returns #TLV_CODEC_ERR_INVALID_VALUE. Missing required pointers
 * or nonempty NULL payload return #TLV_CODEC_ERR_NULL_ARG. Insufficient output
 * capacity returns #TLV_CODEC_ERR_BUFFER_TOO_SHORT. Neither direction allocates.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_service_data16;

/**
 * @brief Service Data with a 32-bit UUID and borrowed opaque payload.
 *
 * Keep decoded input storage alive and immutable while either span is used.
 * Encoding uses uuid and payload; raw is informational and ignored, so a
 * caller-constructed object may leave raw empty.
 */
typedef struct tlv_bluetooth_service_data32 {
    /** Service UUID in the representation of #tlv_bluetooth_codec_uuid32. */
    uint32_t uuid;
    /** Borrowed bytes after the UUID; may be empty (NULL is valid for size zero). */
    tlv_value_t payload;
    /** Complete borrowed original value, including the UUID prefix. */
    tlv_value_t raw;
} tlv_bluetooth_service_data32_t;

/**
 * @brief Service Data codec for AD Type 0x20, using #tlv_bluetooth_service_data32_t.
 *
 * Decode requires at least 4 UUID bytes; the remainder is borrowed as payload.
 * Encode regenerates the UUID through #tlv_bluetooth_codec_uuid32 and copies
 * payload unchanged. Empty payloads are valid; no AD framing size limit applies.
 * A short UUID, incorrect encode object size, non-native payload size or total
 * size overflow returns #TLV_CODEC_ERR_INVALID_VALUE. Missing required pointers
 * or nonempty NULL payload return #TLV_CODEC_ERR_NULL_ARG. Insufficient output
 * capacity returns #TLV_CODEC_ERR_BUFFER_TOO_SHORT. Neither direction allocates.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_service_data32;

/**
 * @brief Service Data with a 128-bit UUID and borrowed opaque payload.
 *
 * Keep decoded input storage alive and immutable while either span is used.
 * Encoding uses uuid and payload; raw is informational and ignored, so a
 * caller-constructed object may leave raw empty.
 */
typedef struct tlv_bluetooth_service_data128 {
    /** Service UUID in the representation of #tlv_bluetooth_codec_uuid128. */
    tlv_bluetooth_uuid128_t uuid;
    /** Borrowed bytes after the UUID; may be empty (NULL is valid for size zero). */
    tlv_value_t payload;
    /** Complete borrowed original value, including the UUID prefix. */
    tlv_value_t raw;
} tlv_bluetooth_service_data128_t;

/**
 * @brief Service Data codec for AD Type 0x21, using #tlv_bluetooth_service_data128_t.
 *
 * Decode requires at least 16 UUID bytes; the remainder is borrowed as payload.
 * Encode regenerates the UUID through #tlv_bluetooth_codec_uuid128 and copies
 * payload unchanged. Empty payloads are valid; no AD framing size limit applies.
 * A short UUID, incorrect encode object size, non-native payload size or total
 * size overflow returns #TLV_CODEC_ERR_INVALID_VALUE. Missing required pointers
 * or nonempty NULL payload return #TLV_CODEC_ERR_NULL_ARG. Insufficient output
 * capacity returns #TLV_CODEC_ERR_BUFFER_TOO_SHORT. Neither direction allocates.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_service_data128;

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_BUILTINS_BLUETOOTH_SERVICE_DATA_H */
