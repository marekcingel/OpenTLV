#ifndef OPENTLV_TAG_H
#define OPENTLV_TAG_H

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

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_TAG_H */
