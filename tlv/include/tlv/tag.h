#ifndef OPENTLV_TAG_H
#define OPENTLV_TAG_H

#include "tlv/error.h"
#include "tlv/export.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @file
 * @ingroup core
 * @brief Borrowed raw TLV tag type with construction and comparison.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief A TLV tag: a borrowed sequence of raw bytes in wire order.
 *
 * A tag is only a pointer and a length. It does not own, allocate or copy
 * memory and imposes no OpenTLV-specific maximum length. It carries no format
 * metadata; the selected format or schema decides whether the bytes form a
 * valid tag.
 * Copying a #tlv_tag_t copies the pointer and length, not the bytes.
 *
 * The referenced bytes must stay valid, and unchanged, for as long as the
 * tag is used. OpenTLV functions never retain a borrowed tag beyond the call
 * unless their documentation says so. Tags produced by a reader reference the
 * input buffer that was parsed.
 *
 * `{ NULL, 0 }` is the empty tag. `{ NULL, size }` with `size > 0` is
 * invalid. Whether an empty tag is acceptable for reading or writing is
 * decided by the format.
 *
 * @see TLV_TAG, tlv_tag
 */
typedef struct {
    /** Raw tag bytes in wire order; `size` readable bytes, or `NULL` when `size` is zero. */
    const uint8_t* data;
    /** Number of bytes in `data`. */
    size_t size;
} tlv_tag_t;

/**
 * @brief Builds a tag that borrows `size` bytes at `data`.
 *
 * Nothing is copied or validated. `data` may be `NULL` only when `size` is zero.
 *
 * @param[in] data Tag bytes; must outlive every use of the returned tag.
 * @param[in] size Number of bytes in `data`.
 *
 * @return A tag referencing `data`.
 */
static inline tlv_tag_t tlv_tag(const uint8_t* data, size_t size) {
    tlv_tag_t tag;
    tag.data = data;
    tag.size = size;
    return tag;
}

/**
 * @def TLV_TAG
 * @brief Builds an allocation-free tag from literal bytes, e.g. `TLV_TAG(0x9F, 0x02)`.
 *
 * Every argument must be a constant byte value. The tag references constant
 * storage that the compiler provides: in C++ it has static storage duration,
 * so the tag may be stored and returned freely. In C it is a compound literal
 * that lives until the end of the enclosing block (at file scope it is
 * static), so do not return it or keep it beyond that block.
 */
#ifdef __cplusplus
#define TLV_TAG(...)                                                                               \
    ([]() -> tlv_tag_t {                                                                           \
        static const uint8_t tlv_tag_literal_bytes_[] = {__VA_ARGS__};                             \
        return tlv_tag(tlv_tag_literal_bytes_, sizeof tlv_tag_literal_bytes_);                     \
    }())
#else
#define TLV_TAG(...)                                                                               \
    (tlv_tag((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__})))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Tests whether two tags have the same size and bytes.
 *
 * Compares contents, not pointer identity, so tags backed by different memory
 * are equal when their bytes match. Two empty tags are equal.
 *
 * @pre Both tags are valid: `data` is not `NULL` when `size > 0`. An invalid
 *      tag is a contract violation, not a comparable value.
 *
 * @note `tlv_tag_equal(a, b)` is true exactly when `tlv_tag_compare(a, b) == 0`.
 *
 * @param[in] lhs First tag.
 * @param[in] rhs Second tag.
 *
 * @return `true` if both tags have the same size and bytes.
 */
TLV_API bool tlv_tag_equal(tlv_tag_t lhs, tlv_tag_t rhs);

/**
 * @brief Orders two tags lexicographically by their bytes.
 *
 * Compares byte by byte as unsigned values; if one tag is a prefix of the
 * other, the shorter tag orders first. The bytes are never interpreted as an
 * integer, so the result does not depend on host endianness.
 *
 * @pre Both tags are valid: `data` is not `NULL` when `size > 0`.
 *
 * @param[in] lhs First tag.
 * @param[in] rhs Second tag.
 *
 * @return A negative value if `lhs` orders before `rhs`, zero if the tags are
 *         equal, and a positive value if `lhs` orders after `rhs`.
 */
TLV_API int tlv_tag_compare(tlv_tag_t lhs, tlv_tag_t rhs);

/**
 * @brief Tests whether a tag has zero length.
 *
 * @param[in] tag Tag to test.
 *
 * @return `true` if `tag.size` is zero.
 */
TLV_API bool tlv_tag_is_empty(tlv_tag_t tag);

/**
 * @brief Computes a hash of a tag's bytes.
 *
 * Two tags for which tlv_tag_equal() is true always hash equal. The hash
 * value is not a wire encoding: it may differ across builds, platforms and
 * OpenTLV versions, so it must never be persisted or sent to another process.
 *
 * @pre The tag is valid: `data` is not `NULL` when `size > 0`.
 *
 * @param[in] tag Tag to hash.
 *
 * @return A hash of `tag`'s bytes.
 */
TLV_API size_t tlv_tag_hash(tlv_tag_t tag);

/**
 * @brief Copies a tag's bytes into caller-owned storage.
 *
 * With `data == NULL` and `capacity == 0`, reports the required size in
 * `*written` without copying. Overlapping source and destination byte ranges
 * are supported.
 *
 * @param[in]  tag      Tag whose bytes are copied.
 * @param[out] data     Destination buffer. `NULL` with zero `capacity`
 *                      queries the required size.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives `tag.size` (the required size for a query).
 *                      Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `written` is `NULL`, if `data` is `NULL` with
 *         a nonzero `capacity`, or if `tag.data` is `NULL` with a nonzero
 *         `tag.size`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient; `*written`
 *         is unchanged.
 */
TLV_API tlv_result_t tlv_tag_copy(tlv_tag_t tag, uint8_t* data, size_t capacity, size_t* written);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_TAG_H */
