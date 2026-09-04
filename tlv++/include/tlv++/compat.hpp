#ifndef OPENTLV_TLVPP_COMPAT_HPP
#define OPENTLV_TLVPP_COMPAT_HPP

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

#if __cplusplus >= 201703L
#include <any>
#include <cstddef>
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
using byte = std::byte;
using any = std::any;
using std::any_cast;
#else
enum class byte : unsigned char {};

class any {
  struct holder_base {
    virtual ~holder_base() {}
    virtual std::unique_ptr<holder_base> clone() const = 0;
  };

  template <typename T> struct holder : holder_base {
    explicit holder(const T &value) : value(value) {}
    explicit holder(T &&value) : value(std::move(value)) {}
    std::unique_ptr<holder_base> clone() const {
      return std::unique_ptr<holder_base>(new holder<T>(value));
    }
    T value;
  };

public:
  any() {}
  any(const any &other) : value_(other.value_ ? other.value_->clone() : 0) {}
  any(any &&other) noexcept : value_(std::move(other.value_)) {}

  template <typename T>
  any(T value) : value_(new holder<T>(std::move(value))) {}

  any &operator=(any other) {
    value_.swap(other.value_);
    return *this;
  }

private:
  template <typename T> friend T any_cast(const any &);
  std::unique_ptr<holder_base> value_;
};

template <typename T> T any_cast(const any &value) {
  const any::holder<T> *stored =
      dynamic_cast<const any::holder<T> *>(value.value_.get());
  if (!stored) {
    throw std::bad_cast();
  }
  return stored->value;
}
#endif

#if __cplusplus >= 202002L
template <typename T> using span = std::span<T>;
#else
template <typename T> class span {
public:
  span() : data_(0), size_(0) {}
  span(T *data, std::size_t size) : data_(data), size_(size) {}

  T *data() const { return data_; }
  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }
  T &operator[](std::size_t index) const { return data_[index]; }

private:
  T *data_;
  std::size_t size_;
};
#endif

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
template <typename T, typename E> using expected = std::expected<T, E>;
template <typename E> using unexpected = std::unexpected<E>;
#else
template <typename E> class unexpected {
public:
  explicit unexpected(const E &error) : error_(error) {}
  explicit unexpected(E &&error) : error_(std::move(error)) {}
  E &error() { return error_; }
  const E &error() const { return error_; }

private:
  E error_;
};

template <typename T, typename E> class expected {
public:
  expected(const T &value) : has_value_(true) { new (&storage_.value) T(value); }
  expected(T &&value) : has_value_(true) {
    new (&storage_.value) T(std::move(value));
  }
  expected(const unexpected<E> &error) : has_value_(false) {
    new (&storage_.error) E(error.error());
  }
  expected(unexpected<E> &&error) : has_value_(false) {
    new (&storage_.error) E(std::move(error.error()));
  }
  expected(expected &&other) : has_value_(other.has_value_) {
    if (has_value_) new (&storage_.value) T(std::move(other.storage_.value));
    else new (&storage_.error) E(std::move(other.storage_.error));
  }
  ~expected() { destroy(); }

  expected(const expected &) = delete;
  expected &operator=(const expected &) = delete;
  bool has_value() const { return has_value_; }
  explicit operator bool() const { return has_value_; }
  T &operator*() { return storage_.value; }
  const T &operator*() const { return storage_.value; }
  T *operator->() { return &storage_.value; }
  const T *operator->() const { return &storage_.value; }
  E &error() { return storage_.error; }
  const E &error() const { return storage_.error; }

private:
  void destroy() {
    if (has_value_) storage_.value.~T();
    else storage_.error.~E();
  }
  union storage { storage() {} ~storage() {} T value; E error; } storage_;
  bool has_value_;
};

template <typename E> class expected<void, E> {
public:
  expected() : has_value_(true), error_() {}
  expected(const unexpected<E> &error) : has_value_(false), error_(error.error()) {}
  expected(unexpected<E> &&error)
      : has_value_(false), error_(std::move(error.error())) {}
  bool has_value() const { return has_value_; }
  explicit operator bool() const { return has_value_; }
  E &error() { return error_; }
  const E &error() const { return error_; }

private:
  bool has_value_;
  E error_;
};
#endif

} // namespace tlv

#endif
