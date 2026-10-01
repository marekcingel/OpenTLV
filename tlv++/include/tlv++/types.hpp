#ifndef OPENTLV_TLVPP_TYPES_HPP
#define OPENTLV_TLVPP_TYPES_HPP

#include <string>
#include <stdexcept>
#include "tlv++/compat.hpp"
#include "tlv/element.h"

/**
 * @file types.hpp
 * @brief Core C++ types shared by the tlv++ wrappers.
 */

namespace tlv {

/// @cond INTERNAL
struct typed_error;
class element_view;
namespace detail {
template <typename Field>
expected<typename Field::value_type, typed_error> decode_field(const element_view& value);
}
/// @endcond

/**
 * @brief Idiomatic C++ error that wraps a C result code and its description.
 *
 * Returned in the error state of an `expected` by the tlv++ wrappers.
 *
 * @see tlv_result_t
 */
struct error {
    /** The C result code. */
    tlv_result_t code;
    /** Human-readable description of `code`, owned by this object. */
    std::string message;

    /**
     * @brief Builds an error from a C result code.
     *
     * @param c_code C result code.
     *
     * @return An error whose message is tlv_strerror(`c_code`).
     */
    static error from_c(tlv_result_t c_code) {
        return error{c_code, tlv_strerror(c_code)};
    }
};

/** @brief Non-owning, read-only byte span; storage must outlive every copy. */
using bytes = span<const byte>;

/// @cond INTERNAL
namespace detail {
struct semantic_access;
}
/// @endcond

/**
 * @brief Read-only borrowed identifier with byte identity, independent of Format.
 *
 * Copies retain the same immutable storage; they never allocate or copy bytes.
 * Storage must outlive every copy. A default tag is absent; a non-null empty
 * span is an explicitly empty identifier. Equality treats both as empty, while
 * source preservation retains this distinction. No numeric normalization occurs.
 */
class tag {
public:
    /** @brief Create an absent identifier without allocation. */
    tag() noexcept : raw_{nullptr, 0} {}
    /**
     * @brief Borrow identifier bytes without copying.
     * @param data Immutable storage that outlives all copies.
     * @throws std::invalid_argument If data is null with nonzero size.
     */
    explicit tag(bytes data) : raw_{reinterpret_cast<const uint8_t*>(data.data()), data.size()} {
        if (!data.data() && data.size()) throw std::invalid_argument("null tag storage");
    }
    /** @brief Borrowed byte pointer, possibly null for an absent tag. */
    const byte* data() const noexcept {
        return reinterpret_cast<const byte*>(raw_.data);
    }
    /** @brief Identifier byte count. */
    size_t size() const noexcept {
        return raw_.size;
    }
    /** @brief Whether there are no identifier bytes. */
    bool empty() const noexcept {
        return size() == 0;
    }
    /** @brief Whether an identifier is present, including an explicitly empty one. */
    bool present() const noexcept {
        return raw_.data != nullptr;
    }
    /** @brief Borrowed span with the same lifetime and pointer, without copying. */
    bytes as_bytes() const noexcept {
        return bytes(data(), size());
    }
    /** @brief Iterator to the first byte; storage must remain alive and unchanged. */
    const byte* begin() const noexcept {
        return data();
    }
    /** @brief Iterator past the last byte; avoids arithmetic on an absent pointer. */
    const byte* end() const noexcept {
        return empty() ? data() : data() + size();
    }
    /** @brief Read a byte; index must be less than size(). */
    byte operator[](size_t index) const noexcept {
        return data()[index];
    }
    /** @brief Read a byte, throwing std::out_of_range when index is not less than size(). */
    byte at(size_t index) const {
        if (index >= size()) throw std::out_of_range("tag byte index");
        return (*this)[index];
    }
    /** @brief Lexicographic byte comparison through the C engine; negative, zero or positive. */
    int compare(tlv::tag other) const noexcept {
        return tlv_tag_compare(raw_, other.raw_);
    }
    /** @brief Compare identifier contents, including equality of all empty tags. */
    friend bool operator==(tlv::tag lhs, tlv::tag rhs) noexcept {
        return lhs.compare(rhs) == 0;
    }
    /** @brief Compare identifier contents for inequality. */
    friend bool operator!=(tlv::tag lhs, tlv::tag rhs) noexcept {
        return !(lhs == rhs);
    }
    /** @brief Lexicographic byte ordering independent of host endianness. */
    friend bool operator<(tlv::tag lhs, tlv::tag rhs) noexcept {
        return lhs.compare(rhs) < 0;
    }
    /** @brief Lexicographic less-than-or-equal comparison. */
    friend bool operator<=(tlv::tag lhs, tlv::tag rhs) noexcept {
        return lhs.compare(rhs) <= 0;
    }
    /** @brief Lexicographic greater-than comparison. */
    friend bool operator>(tlv::tag lhs, tlv::tag rhs) noexcept {
        return lhs.compare(rhs) > 0;
    }
    /** @brief Lexicographic greater-than-or-equal comparison. */
    friend bool operator>=(tlv::tag lhs, tlv::tag rhs) noexcept {
        return lhs.compare(rhs) >= 0;
    }

private:
    explicit tag(tlv_tag_t raw) noexcept : raw_(raw) {}
    tlv_tag_t raw_;
    friend struct detail::semantic_access;
};

/**
 * @brief Borrow a literal identifier from immutable program-lifetime storage.
 * @tparam Bytes One or more constant bytes in identifier order, with no endian conversion.
 * @return A tag safe to retain or return without allocation or byte copying.
 * @note Available in C++11 and later; byte arguments are checked by the template type.
 */
template <uint8_t... Bytes> tlv::tag tag_bytes() noexcept {
    static_assert(sizeof...(Bytes) != 0, "Use tag() for an absent identifier");
    static const uint8_t storage[] = {Bytes...};
    return tlv::tag(bytes(reinterpret_cast<const byte*>(storage), sizeof(storage)));
}

/**
 * @brief Valid read-only borrowed Value with a native-addressable byte count.
 *
 * Copies never allocate or copy bytes and do not extend storage lifetime.
 * The caller guarantees the storage extent and keeps it alive and unchanged.
 * Native imports validate pointer requirements and size before byte access.
 */
class value_view {
public:
    /** @brief Create an empty Value without allocation. */
    value_view() noexcept : raw_{nullptr, 0} {}
    /**
     * @brief Borrow a byte span without copying or allocation.
     * @param data Immutable storage that outlives all copies.
     * @throws std::invalid_argument If data is null with nonzero size.
     */
    explicit value_view(bytes data)
        : raw_{reinterpret_cast<const uint8_t*>(data.data()), data.size()} {
        if (!data.data() && data.size()) throw std::invalid_argument("null value storage");
    }
    /** @brief Borrowed byte pointer; may be null for an empty Value. */
    const byte* data() const noexcept {
        return reinterpret_cast<const byte*>(raw_.data);
    }
    /** @brief Native byte count, validated on construction or import. */
    size_t size() const noexcept {
        return static_cast<size_t>(raw_.size);
    }
    /** @brief Whether the Value has no bytes. */
    bool empty() const noexcept {
        return size() == 0;
    }
    /** @brief Borrowed byte span without copying or narrowing an unchecked length. */
    bytes as_bytes() const noexcept {
        return bytes(data(), size());
    }
    /** @brief Iterator to the first byte; storage must remain alive and unchanged. */
    const byte* begin() const noexcept {
        return data();
    }
    /** @brief Iterator past the last byte, avoiding arithmetic on an empty null pointer. */
    const byte* end() const noexcept {
        return empty() ? data() : data() + size();
    }
    /** @brief Read a byte; index must be less than size(). */
    byte operator[](size_t index) const noexcept {
        return data()[index];
    }
    /** @brief Read a byte, throwing std::out_of_range for an index outside the Value. */
    byte at(size_t index) const {
        if (index >= size()) throw std::out_of_range("value byte index");
        return (*this)[index];
    }
    /** @brief Compare opaque bytes through C; negative, zero or positive, without decoding. */
    int compare(value_view other) const noexcept {
        return tlv_value_compare(raw_, other.raw_);
    }
    /** @brief Compare Value contents, independently of storage identity. */
    friend bool operator==(value_view lhs, value_view rhs) noexcept {
        return lhs.compare(rhs) == 0;
    }
    /** @brief Compare Value contents for inequality. */
    friend bool operator!=(value_view lhs, value_view rhs) noexcept {
        return !(lhs == rhs);
    }

private:
    explicit value_view(tlv_value_t raw) noexcept : raw_(raw) {}
    tlv_value_t raw_;
    friend struct detail::semantic_access;
};

/**
 * @brief Format-independent borrowed Tag and Value, without source metadata.
 *
 * Copies copy descriptors only. Both immutable storages must outlive every
 * retained copy, including identifiers supplied by a Format. Reader advancement
 * does not invalidate stable input; relocating or overwriting that input does.
 */
class element_view {
public:
    /** @brief Decode this element with a typed field, checking its tag first.
     * @tparam Field A tlv::field specialization; include codec/typed.hpp.
     * @return Typed value, tag_mismatch, or the original codec error.
     * @warning Borrowed results retain the input lifetime. Owning codecs may allocate.
     */
    template <typename Field>
    TLV_NODISCARD expected<typename Field::value_type, typed_error> decode() const {
        return detail::decode_field<Field>(*this);
    }
    /** @brief Create an absent Tag and empty Value without allocation. */
    element_view() noexcept = default;
    /** @brief Combine borrowed semantic views; their storage must outlive every copy. */
    element_view(tlv::tag identifier, value_view value) noexcept
        : tag_(identifier), value_(value) {}
    /** @brief Identifier view retaining its original borrowed lifetime. */
    tlv::tag tag() const noexcept {
        return tag_;
    }
    /** @brief Value view retaining its original borrowed lifetime. */
    value_view value() const noexcept {
        return value_;
    }
    /** @brief Compare Tag and Value contents; source framing and location are excluded. */
    friend bool operator==(element_view lhs, element_view rhs) noexcept {
        return lhs.tag_ == rhs.tag_ && lhs.value_ == rhs.value_;
    }
    /** @brief Compare semantic contents for inequality. */
    friend bool operator!=(element_view lhs, element_view rhs) noexcept {
        return !(lhs == rhs);
    }

private:
    tlv::tag   tag_;
    value_view value_;
};

/// @cond INTERNAL
namespace detail {
struct semantic_access {
    static tlv::tag borrow(tlv_tag_t raw) noexcept {
        return tlv::tag(raw);
    }
    static value_view borrow(tlv_value_t raw) noexcept {
        return value_view(raw);
    }
    static element_view borrow(tlv_element_t raw) noexcept {
        return {borrow(raw.tag), borrow(raw.value)};
    }
    static tlv_tag_t get(tlv::tag view) noexcept {
        return view.raw_;
    }
    static tlv_value_t get(value_view view) noexcept {
        return view.raw_;
    }
    static tlv_element_t get(element_view view) noexcept {
        return {get(view.tag()), view.value().raw_};
    }
};
} // namespace detail
/// @endcond

} // namespace tlv
#endif
