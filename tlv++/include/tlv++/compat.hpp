#ifndef OPENTLV_TLVPP_COMPAT_HPP
#define OPENTLV_TLVPP_COMPAT_HPP

/**
 * @file compat.hpp
 * @brief C++11-to-C++23 compatibility shims for tlv++ (byte, any, span, expected).
 *
 * Each shim aliases the standard type when the language mode provides it and
 * otherwise supplies a minimal equivalent with the same core interface.
 */

#if (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L) || __cplusplus >= 201703L
/**
 * @brief Expands to `[[nodiscard]]` from C++17 onward, and to nothing before.
 *
 * Applied to functions whose result must not be ignored.
 */
#define TLV_NODISCARD [[nodiscard]]
#else
#define TLV_NODISCARD
#endif

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

#if __cplusplus >= 201703L
#include <any>
#endif

#if __cplusplus >= 202002L
#include <span>
#endif

#if (defined(_MSVC_LANG) && _MSVC_LANG >= 202302L) || __cplusplus > 202002L
#if defined(__has_include)
#if __has_include(<expected>)
#include <expected>
#endif
#endif
#endif

namespace tlv {

#if __cplusplus >= 201703L
/** @brief `std::byte` from C++17; a compatible `unsigned char`-based enum before. */
using byte = std::byte;
/** @brief `std::any` from C++17; a minimal copyable type-erased holder before. */
using any = std::any;
using std::any_cast;
#else
enum class byte : unsigned char {};

/**
 * @brief Minimal copyable type-erased value holder for pre-C++17 builds.
 *
 * Provides value semantics with copy and move; retrieve the value with
 * any_cast(), which throws `std::bad_cast` on a type mismatch.
 */
class any {
    struct holder_base {
        virtual ~holder_base() {}
        virtual std::unique_ptr<holder_base> clone() const = 0;
    };

    template <typename T> struct holder : holder_base {
        explicit holder(const T& value) : value(value) {}
        explicit holder(T&& value) : value(std::move(value)) {}
        std::unique_ptr<holder_base> clone() const override {
            return std::unique_ptr<holder_base>(new holder<T>(value));
        }
        T value;
    };

public:
    /** @brief Creates an empty holder. */
    any() {}
    /** @brief Copies the held value, if any, by cloning it. */
    any(const any& other) : value_(other.value_ ? other.value_->clone() : 0) {}
    /** @brief Moves the held value out of `other`, leaving it empty. */
    any(any&& other) noexcept : value_(std::move(other.value_)) {}

    /** @brief Holds `value` of type `T`. */
    template <typename T> any(T value) : value_(new holder<T>(std::move(value))) {}

    /** @brief Replaces the held value with that of `other` (copy-and-swap). */
    any& operator=(any other) {
        value_.swap(other.value_);
        return *this;
    }

private:
    template <typename T> friend T any_cast(const any&);
    std::unique_ptr<holder_base>   value_;
};

/**
 * @brief Retrieves the value held by a pre-C++17 #tlv::any.
 *
 * @tparam T The exact stored type.
 *
 * @param value Holder to read.
 *
 * @return A copy of the stored value.
 *
 * @throws std::bad_cast if `value` does not hold a `T`.
 */
template <typename T> T any_cast(const any& value) {
    const any::holder<T>* stored = dynamic_cast<const any::holder<T>*>(value.value_.get());
    if (!stored) {
        throw std::bad_cast();
    }
    return stored->value;
}
#endif

#if __cplusplus >= 202002L
/** @brief `std::span` from C++20; a minimal non-owning view before. */
template <typename T> using span = std::span<T>;
#else
/**
 * @brief Minimal non-owning view of contiguous elements for pre-C++20 builds.
 *
 * Does not own or bounds-check its storage; the caller must keep the
 * referenced memory alive while the span is used.
 */
template <typename T> class span {
public:
    /** @brief Creates an empty span with a null data pointer. */
    span() : data_(0), size_(0) {}
    /**
     * @brief Creates a span over `size` elements starting at `data`.
     *
     * @param data Start of the referenced elements; borrowed.
     * @param size Number of elements.
     */
    span(T* data, std::size_t size) : data_(data), size_(size) {}

    /** @brief Returns the pointer to the first element. */
    T* data() const {
        return data_;
    }
    /** @brief Returns the number of elements. */
    std::size_t size() const {
        return size_;
    }
    /** @brief Returns `true` if the span has no elements. */
    bool empty() const {
        return size_ == 0;
    }
    /** @brief Returns the element at `index`; the index is not bounds-checked. */
    T& operator[](std::size_t index) const {
        return data_[index];
    }

private:
    T*          data_;
    std::size_t size_;
};
#endif

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
/** @brief `std::expected` from C++23; a minimal move-only equivalent before. */
template <typename T, typename E> using expected = std::expected<T, E>;
/** @brief `std::unexpected` from C++23; a minimal equivalent before. */
template <typename E> using unexpected = std::unexpected<E>;
#else
/** @brief Minimal holder of an error value, used to construct a failed #tlv::expected. */
template <typename E> class unexpected {
public:
    /** @brief Creates an error holder by copying `error`. */
    explicit unexpected(const E& error) : error_(error) {}
    /** @brief Creates an error holder by moving `error`. */
    explicit unexpected(E&& error) : error_(std::move(error)) {}
    /** @brief Returns the held error. */
    E& error() {
        return error_;
    }
    /** @brief Returns the held error. */
    const E& error() const {
        return error_;
    }

private:
    E error_;
};

/**
 * @brief Minimal move-only result holding either a value or an error.
 *
 * Pre-C++23 stand-in for `std::expected`. Check has_value() (or the `bool`
 * conversion) before dereferencing; accessing the wrong alternative is
 * undefined behavior.
 *
 * @tparam T Value type.
 * @tparam E Error type.
 */
template <typename T, typename E> class expected {
public:
    /** @brief Creates a successful result holding a copy of `value`. */
    expected(const T& value) : has_value_(true) {
        new (&storage_.value) T(value);
    }
    /** @brief Creates a successful result by moving in `value`. */
    expected(T&& value) : has_value_(true) {
        new (&storage_.value) T(std::move(value));
    }
    /** @brief Creates a failed result holding a copy of the error. */
    expected(const unexpected<E>& error) : has_value_(false) {
        new (&storage_.error) E(error.error());
    }
    /** @brief Creates a failed result by moving in the error. */
    expected(unexpected<E>&& error) : has_value_(false) {
        new (&storage_.error) E(std::move(error.error()));
    }
    /** @brief Moves the value or error out of `other`. */
    expected(expected&& other) noexcept(std::is_nothrow_move_constructible<T>::value &&
                                        std::is_nothrow_move_constructible<E>::value)
        : has_value_(other.has_value_) {
        if (has_value_)
            new (&storage_.value) T(std::move(other.storage_.value));
        else
            new (&storage_.error) E(std::move(other.storage_.error));
    }
    /** @brief Destroys the held value or error. */
    ~expected() {
        destroy();
    }

    /** @brief Copying is disabled; the type is move-only. */
    expected(const expected&) = delete;
    /** @brief Copy assignment is disabled; the type is move-only. */
    expected& operator=(const expected&) = delete;
    /** @brief Returns `true` if the result holds a value. */
    bool has_value() const {
        return has_value_;
    }
    /** @brief Returns `true` if the result holds a value. */
    explicit operator bool() const {
        return has_value_;
    }
    /** @brief Returns the value; undefined behavior if the result holds an error. */
    T& operator*() {
        return storage_.value;
    }
    /** @brief Returns the value; undefined behavior if the result holds an error. */
    const T& operator*() const {
        return storage_.value;
    }
    /** @brief Accesses the value; undefined behavior if the result holds an error. */
    T* operator->() {
        return &storage_.value;
    }
    /** @brief Accesses the value; undefined behavior if the result holds an error. */
    const T* operator->() const {
        return &storage_.value;
    }
    /** @brief Returns the error; undefined behavior if the result holds a value. */
    E& error() {
        return storage_.error;
    }
    /** @brief Returns the error; undefined behavior if the result holds a value. */
    const E& error() const {
        return storage_.error;
    }

private:
    void destroy() {
        if (has_value_)
            storage_.value.~T();
        else
            storage_.error.~E();
    }
    union storage {
        storage() {}
        ~storage() {}
        T value;
        E error;
    } storage_;
    bool has_value_;
};

/**
 * @brief Minimal result holding either success or an error; the `void` specialization.
 *
 * @tparam E Error type.
 */
template <typename E> class expected<void, E> {
public:
    /** @brief Creates a successful result. */
    expected() : has_value_(true), error_() {}
    /** @brief Creates a failed result holding a copy of the error. */
    expected(const unexpected<E>& error) : has_value_(false), error_(error.error()) {}
    /** @brief Creates a failed result by moving in the error. */
    expected(unexpected<E>&& error) : has_value_(false), error_(std::move(error.error())) {}
    /** @brief Returns `true` if the result is successful. */
    bool has_value() const {
        return has_value_;
    }
    /** @brief Returns `true` if the result is successful. */
    explicit operator bool() const {
        return has_value_;
    }
    /** @brief Returns the error; meaningful only if the result failed. */
    E& error() {
        return error_;
    }
    /** @brief Returns the error; meaningful only if the result failed. */
    const E& error() const {
        return error_;
    }

private:
    bool has_value_;
    E    error_;
};
#endif

} // namespace tlv

#endif
