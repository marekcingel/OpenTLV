#ifndef OPENTLV_TLVPP_BUILTINS_FIXED_FIXED_FORMAT_HPP
#define OPENTLV_TLVPP_BUILTINS_FIXED_FIXED_FORMAT_HPP

#include "tlv/endian.h"
#include "tlv/format.h"
#include "tlv/tag.h"

#include <cstddef>
#include <cstdint>

/**
 * @file fixed_format.hpp
 * @brief Compile-time configurable fixed-width TLV formats.
 */

namespace tlv {

/**
 * @brief A fixed-width TLV format selected at compile time.
 *
 * Every element is `TagWidth` raw tag bytes, then a length field of
 * `LengthWidth` bytes in byte order `Order`, then that many value bytes. The
 * length counts only the value; it excludes the header. Tag bytes are copied
 * unchanged in wire order, so `Order` applies to the length field only. Tags
 * read by this format borrow the input bytes.
 *
 * | Parameter     | Supported values                                  |
 * | ------------- | ------------------------------------------------- |
 * | `TagWidth`    | 1 or more bytes                                   |
 * | `LengthWidth` | 1 to 8 bytes                                      |
 * | `Order`       | #TLV_BYTE_ORDER_BIG_ENDIAN, #TLV_BYTE_ORDER_LITTLE_ENDIAN |
 *
 * Any other value fails to compile with a `static_assert`.
 *
 * The descriptors returned by reader() and writer() have static storage
 * duration and a `NULL` context, so they never need lifetime management. The
 * format performs no allocation and reads values in place. Errors match the
 * built-in fixed format (`tlv_reader_format_fixed_1byte`):
 * - #TLV_ERR_BUFFER_TOO_SHORT when the input holds fewer bytes than a field
 *   needs, or the output has less capacity than a field needs;
 * - #TLV_ERR_INVALID_TAG_SIZE when a written tag is not `TagWidth` bytes;
 * - #TLV_ERR_INVALID_LENGTH when a value length exceeds the largest value
 *   `LengthWidth` bytes can hold, or a decoded length does not fit in `size_t`.
 *
 * `fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>` encodes like
 * `tlv_reader_format_fixed_1byte` and `tlv_writer_format_fixed_1byte`.
 *
 * @tparam TagWidth    Tag width in bytes.
 * @tparam LengthWidth Length field width in bytes.
 * @tparam Order       Byte order of the length field.
 */
template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
class fixed_format {
    static_assert(TagWidth >= 1, "fixed_format: TagWidth must be at least 1");
    static_assert(LengthWidth >= 1 && LengthWidth <= 8,
                  "fixed_format: LengthWidth must be between 1 and 8");
    static_assert(Order == TLV_BYTE_ORDER_BIG_ENDIAN || Order == TLV_BYTE_ORDER_LITTLE_ENDIAN,
                  "fixed_format: Order must be big or little endian");

public:
    /** @brief Tag width in bytes. */
    static constexpr std::size_t tag_width = TagWidth;
    /** @brief Length field width in bytes. */
    static constexpr std::size_t length_width = LengthWidth;
    /** @brief Largest value length the length field can hold. */
    static constexpr std::uint64_t max_length =
        ~static_cast<std::uint64_t>(0) >> (64 - 8 * LengthWidth);

    /**
     * @brief Returns the reader descriptor for this format.
     *
     * @return A borrowed, immutable descriptor that lives for the whole program.
     */
    static const tlv_reader_format_t& reader() {
        static const tlv_reader_format_t format = {nullptr, read_tag, read_length, nullptr,
                                                   nullptr};
        return format;
    }

    /**
     * @brief Returns the writer descriptor for this format.
     *
     * @return A borrowed, immutable descriptor that lives for the whole program.
     */
    static const tlv_writer_format_t& writer() {
        static const tlv_writer_format_t format = {nullptr, write_tag, write_length, length_size,
                                                   nullptr};
        return format;
    }

private:
    static tlv_result_t read_tag(const void*, const std::uint8_t* data, std::size_t size,
                                 tlv_tag_t* tag, std::size_t* consumed) {
        if (size < TagWidth) return TLV_ERR_BUFFER_TOO_SHORT;
        *tag = tlv_tag(data, TagWidth);
        *consumed = TagWidth;
        return TLV_OK;
    }

    static tlv_result_t read_length(const void*, const std::uint8_t* data, std::size_t size,
                                    std::size_t* length, std::size_t* consumed) {
        if (size < LengthWidth) return TLV_ERR_BUFFER_TOO_SHORT;
        std::uint64_t value = 0;
        tlv_result_t  rc = tlv_read_uint(data, LengthWidth, Order, &value);
        if (rc != TLV_OK) return rc;
        if (value > static_cast<std::uint64_t>(SIZE_MAX)) return TLV_ERR_INVALID_LENGTH;
        *length = static_cast<std::size_t>(value);
        *consumed = LengthWidth;
        return TLV_OK;
    }

    static tlv_result_t write_tag(const void*, std::uint8_t* data, std::size_t capacity,
                                  const tlv_tag_t* tag, std::size_t* written) {
        if (tag->size != TagWidth) return TLV_ERR_INVALID_TAG_SIZE;
        if (!tag->data) return TLV_ERR_NULL_ARG;
        *written = TagWidth;
        if (!data) return TLV_OK;
        if (capacity < TagWidth) return TLV_ERR_BUFFER_TOO_SHORT;
        for (std::size_t i = 0; i < TagWidth; ++i) data[i] = tag->data[i];
        return TLV_OK;
    }

    static tlv_result_t length_size(const void*, std::size_t length, std::size_t* size) {
        if (static_cast<std::uint64_t>(length) > max_length) return TLV_ERR_INVALID_LENGTH;
        *size = LengthWidth;
        return TLV_OK;
    }

    static tlv_result_t write_length(const void* context, std::uint8_t* data, std::size_t capacity,
                                     std::size_t length, std::size_t* written) {
        tlv_result_t rc = length_size(context, length, written);
        if (rc != TLV_OK) return rc;
        if (!data) return TLV_OK;
        if (capacity < LengthWidth) return TLV_ERR_BUFFER_TOO_SHORT;
        return tlv_write_uint(data, LengthWidth, Order, static_cast<std::uint64_t>(length));
    }
};

template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
constexpr std::size_t fixed_format<TagWidth, LengthWidth, Order>::tag_width;
template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
constexpr std::size_t fixed_format<TagWidth, LengthWidth, Order>::length_width;
template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
constexpr std::uint64_t fixed_format<TagWidth, LengthWidth, Order>::max_length;

} // namespace tlv

#endif // OPENTLV_TLVPP_BUILTINS_FIXED_FIXED_FORMAT_HPP
