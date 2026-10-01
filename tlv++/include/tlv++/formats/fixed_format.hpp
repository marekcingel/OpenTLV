#ifndef OPENTLV_TLVPP_FORMATS_FIXED_FORMAT_HPP
#define OPENTLV_TLVPP_FORMATS_FIXED_FORMAT_HPP

#include "tlv/endian.h"
#include "tlv/format.h"
#include "tlv/formats/fixed.h"
#include "tlv++/format.hpp"

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
 * A thin, `static_assert`-checked wrapper around the C
 * `tlv_fixed_format_t`/tlv_fixed_format_init(): every read and write goes
 * through that same C implementation, so behavior is identical to the
 * runtime-configured C format for the same widths and byte order, not merely
 * equivalent to it.
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
 * The descriptor returned by format() has static storage duration, so it
 * never needs lifetime management; its context is a static
 * `tlv_fixed_format_t` built from `TagWidth`, `LengthWidth` and `Order` with
 * the same static storage duration. The format performs no allocation and
 * reads values in place. Errors match the C `tlv_fixed_format_t`-based format
 * for the same widths and byte order:
 * - #TLV_ERR_BUFFER_TOO_SHORT when the input holds fewer bytes than a field
 *   needs, or the output has less capacity than a field needs;
 * - #TLV_ERR_INVALID_TAG_SIZE when a written tag is not `TagWidth` bytes;
 * - #TLV_ERR_INVALID_LENGTH when a value length exceeds the largest value
 *   `LengthWidth` bytes can hold, or a decoded length does not fit in `size_t`.
 *
 * @tparam TagWidth    Tag width in bytes.
 * @tparam LengthWidth Length field width in bytes.
 * @tparam Order       Byte order of the length field.
 *
 * @note Uses the always-available C Fixed format implementation;
 *       format() delegates to tlv_fixed_format_init().
 * @see tlv_fixed_format_t for the same format chosen at runtime instead of
 *      compile time (tlv/formats/fixed.h), usable from C++ via
 *      `tlv::writer`/`tlv::reader`'s `const tlv_format_t&` constructor
 *      parameter directly, with no wrapper of its own needed.
 * @see @docs{guides/memory,format context ownership and lifetime}
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
     * @brief Returns the descriptor for this format.
     *
     * @return A borrowed, immutable descriptor that lives for the whole program.
     */
    static const tlv_format_t& format() {
        static const tlv_fixed_format_t config = {TagWidth, LengthWidth, Order,
                                                  TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
        static const tlv_format_t       fmt = init(config);
        return fmt;
    }

    /**
     * @brief Return an allocation-free C++ view of this fixed-width Format.
     * @return Copyable view with program-lifetime descriptor and context.
     * @note Uses the same canonical implementation and configuration as format().
     */
    static tlv::format view() noexcept {
        return detail::format_access::borrow(format());
    }

private:
    static tlv_format_t init(const tlv_fixed_format_t& config) {
        tlv_format_t result{};
        tlv_fixed_format_init(&result, &config);
        return result;
    }
};

template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
constexpr std::size_t fixed_format<TagWidth, LengthWidth, Order>::tag_width;
template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
constexpr std::size_t fixed_format<TagWidth, LengthWidth, Order>::length_width;
template <std::size_t TagWidth, std::size_t LengthWidth, tlv_byte_order_t Order>
constexpr std::uint64_t fixed_format<TagWidth, LengthWidth, Order>::max_length;

} // namespace tlv

#endif // OPENTLV_TLVPP_FORMATS_FIXED_FORMAT_HPP
