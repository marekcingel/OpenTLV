#ifndef OPENTLV_TAG_H
#define OPENTLV_TAG_H

#include "tlv/error.h"
#include "tlv/endian.h"
#include <stdint.h>
#include <stddef.h>

/* Fixed uint8_t representation limit, not a configurable or protocol limit. */
#ifdef TLV_TAG_MAX_SUPPORTED_SIZE
#error "TLV_TAG_MAX_SUPPORTED_SIZE is fixed and must not be configured"
#endif
#define TLV_TAG_MAX_SUPPORTED_SIZE UINT8_MAX

/* Override consistently in the library and all consumers: this affects ABI. */
#ifndef TLV_TAG_CAPACITY
#define TLV_TAG_CAPACITY 8
#endif

#if TLV_TAG_CAPACITY < 1 || TLV_TAG_CAPACITY > TLV_TAG_MAX_SUPPORTED_SIZE
#error "TLV_TAG_CAPACITY must be between 1 and TLV_TAG_MAX_SUPPORTED_SIZE (UINT8_MAX)"
#endif

/* Raw bytes independent of host endianness or TLV profile.
 * Direct assignment to size may truncate before validation; use construction
 * helpers for checked size_t lengths. Empty tags support raw construction and
 * comparison, but operations requiring a nonempty tag reject them. */
typedef struct {
    /* Inline storage for up to TLV_TAG_CAPACITY raw bytes in wire order. */
    uint8_t data[TLV_TAG_CAPACITY];
    /* Number of valid bytes: 0..TLV_TAG_CAPACITY. Zero is an empty tag;
     * format/profile validity is separate. uint8_t limits the supported
     * capacity to TLV_TAG_MAX_SUPPORTED_SIZE. */
    uint8_t size;
} tlv_tag_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Exact size and byte comparison across the full configured capacity,
 * ignoring unused storage. Empty tags compare equal. Returns 1 for equality,
 * 0 for mismatch, NULL arguments, or sizes exceeding capacity. */
int tlv_tag_equal(const tlv_tag_t* a, const tlv_tag_t* b);

/* Compare against raw bytes, including length and leading zeros. The caller
 * provides size readable bytes. data may be NULL only when size is zero.
 * The same result and capacity rules as tlv_tag_equal apply to both inputs. */
int tlv_tag_equal_bytes(const tlv_tag_t* tag, const uint8_t* data, size_t size);

/* Numeric comparison using tlv_tag_to_u64. Returns 1 for equality, 0 for
 * mismatch or invalid input. Zero padding at the most significant end does not affect equality.
 * The tag value is never truncated to the argument type. */
int tlv_tag_equal_u8(const tlv_tag_t* tag, uint8_t value, tlv_byte_order_t order);
int tlv_tag_equal_u16(const tlv_tag_t* tag, uint16_t value, tlv_byte_order_t order);
int tlv_tag_equal_u32(const tlv_tag_t* tag, uint32_t value, tlv_byte_order_t order);
int tlv_tag_equal_u64(const tlv_tag_t* tag, uint64_t value, tlv_byte_order_t order);

/* Same input rules as tlv_tag_to_u64. Zero padding is accepted within the
 * 8-byte input limit. Values exceeding the destination type's maximum return
 * TLV_ERR_INVALID_TAG. Output is unchanged on every failure. */
tlv_result_t tlv_tag_to_u8(const tlv_tag_t* tag, tlv_byte_order_t order, uint8_t* value);
tlv_result_t tlv_tag_to_u16(const tlv_tag_t* tag, tlv_byte_order_t order, uint16_t* value);
tlv_result_t tlv_tag_to_u32(const tlv_tag_t* tag, tlv_byte_order_t order, uint32_t* value);

/* Interpret 1..8 raw bytes using the explicit input byte order, including
 * zero padding at the most significant end. This is not a BER tag-number decode.
 * NULL arguments return TLV_ERR_NULL_ARG; empty tags, sizes exceeding capacity
 * or sizes above 8 return TLV_ERR_INVALID_TAG_SIZE. Unknown or invalid byte order
 * returns TLV_ERR_INVALID_ARG. Output is unchanged on failure. */
tlv_result_t tlv_tag_to_u64(const tlv_tag_t* tag, tlv_byte_order_t order, uint64_t* value);

/* Construct from size raw bytes (0..TLV_TAG_CAPACITY). data may be NULL
 * only for size zero. Overlap with the destination is supported.
 * NULL required pointers return TLV_ERR_NULL_ARG; excessive size returns
 * TLV_ERR_INVALID_TAG_SIZE. Length is checked before narrowing to uint8_t.
 * On success unused bytes are zeroed; on failure the
 * destination is unchanged. No profile-specific validity is checked. */
tlv_result_t tlv_tag_from_bytes(const uint8_t* data, size_t size, tlv_tag_t* tag);

/* Construct an explicitly sized (1..8 bytes, within capacity) raw tag.
 * Zero padding is written at the most significant end in the selected order.
 * NULL tag returns TLV_ERR_NULL_ARG; invalid size returns TLV_ERR_INVALID_TAG_SIZE.
 * A value that does not fit returns TLV_ERR_INVALID_TAG; unsupported order
 * returns TLV_ERR_INVALID_ARG.
 * The same destination guarantees as tlv_tag_from_bytes apply. */
tlv_result_t tlv_tag_from_u8(uint8_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag);
tlv_result_t tlv_tag_from_u16(uint16_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag);
tlv_result_t tlv_tag_from_u32(uint32_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag);
tlv_result_t tlv_tag_from_u64(uint64_t value, size_t size, tlv_byte_order_t order, tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_TAG_H */
