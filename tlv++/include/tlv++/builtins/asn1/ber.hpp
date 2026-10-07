// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_BER_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_BER_HPP

#include "tlv/builtins/asn1/ber.h"
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"
#include "tlv/config.h"
#if OPENTLV_READER
#include "tlv++/reader/reader.hpp"
#endif
#if OPENTLV_WRITER
#include "tlv++/writer/builder.hpp"
#endif

/**
 * @file ber.hpp
 * @brief C++ wrapper for explicit BER indefinite-length framing.
 */

namespace tlv {

/** @brief BER-specific types backed by generic OpenTLV operations. */
namespace ber {
/** @brief Largest supported BER identifier width in bytes. */
constexpr size_t max_tag_size = TLV_ASN1_TAG_MAX_SIZE;
/**
 * @brief Read one canonical BER identifier without reading its Length or Value.
 * @param input Borrowed immutable input.
 * @param consumed Identifier byte count, unchanged on failure.
 * @return Borrowed identifier or canonical wire error; no allocation occurs.
 */
inline expected<tlv::tag, error> read_identifier(bytes input, size_t& consumed) {
    tlv_tag_t  identifier{};
    const auto rc = tlv_ber_read_identifier(reinterpret_cast<const uint8_t*>(input.data()),
                                            input.size(), &identifier, &consumed);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return detail::semantic_access::borrow(identifier);
}
/**
 * @brief Program-lifetime BER Format usable by generic C++ consumers.
 * @note Constructing or copying this view allocates nothing. BER parsing and
 * encoding use the canonical engine; no independent parser is introduced.
 */
class format : public tlv::format {
public:
    /** @brief Select the immutable built-in BER descriptor and context. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_ber)) {}
};

/**
 * @brief BER preset writing constructed elements with indefinite length and EOC.
 * @note Reads supported BER framing, but rejects primitive writes. Uses the
 * generic Reader, Writer and Format operations without allocating.
 */
class indefinite_format : public tlv::format {
public:
    /** @brief Borrow the immutable program-lifetime BER indefinite descriptor. */
    indefinite_format() noexcept
        : tlv::format(detail::format_access::borrow(tlv_format_ber_indefinite)) {}
};

#if OPENTLV_WRITER
/** @brief Build BER output with explicit caller-owned frames and scratch.
 * @param output Borrowed mutable byte span, array or contiguous byte container.
 * @param workspace Disjoint construction storage, never resized.
 * @param callback Callable taking writer_builder& and returning void; called once.
 * @param diagnostic Optional canonical C Writer failure detail.
 * @return Exact written size or allocation-free first failure; exceptions propagate.
 * @see tlv::encode
 */
template <typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure> encode(Output&& output, writer_workspace workspace,
                                                      Callback&&         callback,
                                                      writer_diagnostic* diagnostic = nullptr) {
    return tlv::encode<format>(std::forward<Output>(output), workspace,
                               std::forward<Callback>(callback), format{}, diagnostic);
}

/** @brief Build BER output using bounded local stack workspace.
 * @tparam ScratchCapacity Scratch bytes, default 1024; must fit the largest closed Value.
 * @tparam Depth Frame count and maximum item depth, default TLV_TREE_DEFAULT_DEPTH.
 * @param output Caller-owned mutable byte span, array or contiguous byte container.
 * @param callback Scoped writes taking writer_builder& and returning void, invoked once.
 * @param diagnostic Optional canonical C Writer failure detail.
 * @return Exact byte count or first failure; workspace never grows or allocates.
 */
template <size_t ScratchCapacity = 1024, size_t Depth = TLV_TREE_DEFAULT_DEPTH, typename Output,
          typename Callback>
TLV_NODISCARD expected<size_t, writer_failure> encode(Output&& output, Callback&& callback,
                                                      writer_diagnostic* diagnostic = nullptr) {
    return tlv::encode<format, ScratchCapacity, Depth>(
        std::forward<Output>(output), std::forward<Callback>(callback), format{}, diagnostic);
}
#endif

#if OPENTLV_READER
/**
 * @brief Parse final input as borrowed Elements using the built-in Format.
 * @param data Immutable borrowed final input.
 * @return Allocation-free single-pass range; no Schema or Value validation is performed.
 * @throws parse_error During iteration on any failure other than final EOF.
 * @warning Input must outlive the range and every retained Element or diagnostic.
 * @see tlv::parse
 */
TLV_NODISCARD inline detail::parsing_range<format> parse(bytes data) {
    return tlv::parse<format>(data);
}
#endif

} // namespace ber

/**
 * @brief Writes explicit BER indefinite framing around an already encoded child sequence.
 *
 * Wraps tlv_ber_write_indefinite().
 *
 * @param data     Destination buffer. Insufficient capacity, including
 *                 nullptr/0, reports BUFFER_TOO_SHORT; use measure() with
 *                 ber::indefinite_format to determine the required size.
 * @param capacity Destination capacity in bytes.
 * @param tag      Constructed element tag.
 * @param children Already encoded children, without the enclosing EOC. Must
 *                 not overlap the destination.
 *
 * @return The complete encoded size, or the error of
 *         tlv_ber_write_indefinite().
 *
 * @note On error the destination is unchanged.
 */
TLV_NODISCARD inline expected<size_t, error> ber_write_indefinite(byte* data, size_t capacity,
                                                                  tlv::tag tag, bytes children) {
    size_t       written = 0;
    tlv_result_t rc = tlv_ber_write_indefinite(
        reinterpret_cast<uint8_t*>(data), capacity, detail::semantic_access::get(tag),
        reinterpret_cast<const uint8_t*>(children.data()), children.size(), &written);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

namespace ber {
/**
 * @brief Wrap encoded children in explicit BER indefinite-length framing.
 * @param output Disjoint caller-owned destination; insufficient capacity is an error.
 * @param tag Constructed identifier; the C engine validates its form.
 * @param children Borrowed child sequence, without the enclosing EOC.
 * @return Written bytes, or the original C error.
 * @note Successful encoding allocates nothing; failure leaves the destination unchanged.
 * An error description may allocate. Measure using tlv::measure and indefinite_format.
 */
TLV_NODISCARD inline expected<size_t, error> write_indefinite(span<byte> output, tlv::tag tag,
                                                              bytes children) {
    return tlv::ber_write_indefinite(output.data(), output.size(), tag, children);
}
} // namespace ber

} // namespace tlv

#endif
