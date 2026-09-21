#ifndef OPENTLV_TLVPP_DOCUMENT_HPP
#define OPENTLV_TLVPP_DOCUMENT_HPP

#include <cstddef>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>

#include "tlv++/query.hpp"
#include "tlv++/types.hpp"
#include "tlv/document/document.h"

/**
 * @file document.hpp
 * @brief C++ wrapper for the optional mutable TLV document.
 *
 * Available when the library is built with `OPENTLV_DOCUMENT` (see tlv/config.h).
 * Unlike the reader and writer wrappers, the document allocates.
 */

namespace tlv {

/**
 * @brief A non-owning handle to one element of a #tlv::document.
 *
 * A handle is a pointer-sized value that may be copied freely. It stays valid for as long as the
 * element exists in its document: until the element (or an ancestor) is erased or the document is
 * destroyed or moved-from. A handle that refers to nothing is *empty* and tests as `false`. The
 * tag and value it returns borrow the document's storage; see tlv/document/document.h for the
 * exact lifetime rules.
 */
class node {
public:
    /** @brief Creates an empty handle. */
    node() : node_(nullptr) {}

    /** @brief Wraps a C node. Prefer the accessors of #tlv::document. */
    explicit node(tlv_node_t* c_node) : node_(c_node) {}

    /** @brief Reports whether the handle refers to an element. */
    explicit operator bool() const {
        return node_ != nullptr;
    }

    /** @brief The underlying C node, for use with the C API. */
    tlv_node_t* c_node() const {
        return node_;
    }

    /** @brief The element's tag, borrowing the document; empty for an empty handle. */
    tag_t tag() const {
        return tlv_node_tag(node_);
    }

    /** @brief Reports whether the element's value holds nested elements. */
    bool is_constructed() const {
        return tlv_node_is_constructed(node_) != 0;
    }

    /**
     * @brief The value bytes of a primitive element, borrowing the document.
     *
     * Empty for an empty value and for a constructed element; read a constructed element through
     * its children instead.
     */
    bytes value() const {
        return bytes(reinterpret_cast<const byte*>(tlv_node_value_data(node_)),
                     tlv_node_value_size(node_));
    }

    /** @brief The first child of a constructed element, or an empty handle. */
    node first_child() const {
        return node(tlv_node_first_child(node_));
    }

    /** @brief The next sibling, or an empty handle. */
    node next() const {
        return node(tlv_node_next(node_));
    }

    /** @brief The next sibling with the same tag, or an empty handle. */
    node next_same_tag() const {
        return node(tlv_node_next_same_tag(node_));
    }

    /** @brief The parent element, or an empty handle for a top-level element. */
    node parent() const {
        return node(tlv_node_parent(node_));
    }

    /**
     * @brief Finds the first direct child with a tag.
     *
     * @param wanted Tag to look for; compared by contents.
     *
     * @return The child, or an empty handle.
     */
    node find(tag_t wanted) const {
        return node(tlv_document_find(nullptr, node_, wanted));
    }

    /**
     * @brief Replaces the element's value.
     *
     * Wraps tlv_node_set_value(): the bytes are copied, and for a constructed element they are
     * parsed as nested elements that replace the children.
     *
     * @param value New value bytes; not retained.
     *
     * @return Success, or the error of tlv_node_set_value(). On error nothing changed.
     *
     * @warning Invalidates the previous #value() of the element and, for a constructed element,
     *          the handles of its children.
     */
    TLV_NODISCARD expected<void, error> set(bytes value) {
        tlv_result_t rc =
            tlv_node_set_value(node_, reinterpret_cast<const uint8_t*>(value.data()), value.size());
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

    /**
     * @brief Removes the element and its descendants from the document.
     *
     * The handle becomes empty. Handles to the element or anything below it become invalid.
     */
    void erase() {
        tlv_node_erase(node_);
        node_ = nullptr;
    }

    /** @brief Computes the encoded size of the element with its descendants; see
     * tlv_node_encoded_size(). */
    TLV_NODISCARD expected<size_t, error> encoded_size() const {
        size_t       size = 0;
        tlv_result_t rc = tlv_node_encoded_size(node_, &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return size;
    }

    /** @brief Encodes the element with its descendants into a new vector; see tlv_node_encode(). */
    TLV_NODISCARD expected<std::vector<byte>, error> encode() const {
        auto size = encoded_size();
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        tlv_result_t      rc =
            tlv_node_encode(node_, reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        out.resize(written);
        return out;
    }

    /** @brief Compares two handles for referring to the same element. */
    friend bool operator==(const node& lhs, const node& rhs) {
        return lhs.node_ == rhs.node_;
    }

    /** @brief Compares two handles for referring to different elements. */
    friend bool operator!=(const node& lhs, const node& rhs) {
        return lhs.node_ != rhs.node_;
    }

private:
    tlv_node_t* node_;
};

/** @brief Forward iterator over sibling elements, yielding #tlv::node handles. */
class node_iterator {
public:
    /** @cond */
    using iterator_category = std::forward_iterator_tag;
    using value_type = node;
    using difference_type = std::ptrdiff_t;
    using pointer = const node*;
    using reference = const node&;
    /** @endcond */

    /** @brief Creates an iterator at a sibling; an empty handle is the end. */
    explicit node_iterator(node current = node()) : current_(current) {}

    /** @brief The current element. */
    reference operator*() const {
        return current_;
    }

    /** @brief Pointer access to the current element. */
    pointer operator->() const {
        return &current_;
    }

    /** @brief Advances to the next sibling. */
    node_iterator& operator++() {
        current_ = current_.next();
        return *this;
    }

    /** @brief Advances to the next sibling, returning the previous position. */
    node_iterator operator++(int) {
        node_iterator previous = *this;
        ++*this;
        return previous;
    }

    /** @brief Compares positions. */
    friend bool operator==(const node_iterator& lhs, const node_iterator& rhs) {
        return lhs.current_ == rhs.current_;
    }

    /** @brief Compares positions. */
    friend bool operator!=(const node_iterator& lhs, const node_iterator& rhs) {
        return !(lhs == rhs);
    }

private:
    node current_;
};

/** @brief A range of sibling elements, for use in range-based `for` loops. */
class node_range {
public:
    /** @brief Creates the range that starts at `first` and ends after the last sibling. */
    explicit node_range(node first = node()) : first_(first) {}

    /** @brief Iterator at the first element. */
    node_iterator begin() const {
        return node_iterator(first_);
    }

    /** @brief The end iterator. */
    node_iterator end() const {
        return node_iterator();
    }

    /** @brief Reports whether the range has no elements. */
    bool empty() const {
        return !first_;
    }

private:
    node first_;
};

/** @brief Format descriptor of a #tlv::document, as for tlv_walk_tree(). */
struct document_format {
    /** Reader format used for parsing; its contents are copied, its context is borrowed. */
    tlv_reader_format_t reader;
    /** Writer format used for encoding; its contents are copied, its context is borrowed. */
    tlv_writer_format_t writer;
    /** Predicate receiving `reader.context` that selects nested values, or `nullptr` for opaque
     * values. */
    tlv_is_constructed_fn is_constructed;
    /** Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`. */
    size_t max_depth;
    /** Maximum number of elements, including nested ones. */
    size_t max_elements;

    /**
     * @brief Bundles the formats with the default limits.
     *
     * @param reader_format  Reader format.
     * @param writer_format  Writer format.
     * @param constructed    Nesting predicate, or `nullptr`.
     */
    document_format(const tlv_reader_format_t& reader_format,
                    const tlv_writer_format_t& writer_format,
                    tlv_is_constructed_fn      constructed = nullptr)
        : reader(reader_format), writer(writer_format), is_constructed(constructed),
          max_depth(TLV_WALK_MAX_DEPTH), max_elements(TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS) {}
};

/**
 * @brief An owned, mutable TLV document.
 *
 * Wraps #tlv_document_t. Unlike the reader and walker wrappers, a document copies the data it
 * is given, allocates memory and lets the data be searched, changed and encoded again. It is
 * independent of the zero-copy APIs: nothing in the core depends on it, and it never refers to
 * the buffer it was parsed from.
 *
 * A document is move-only. Moving keeps every #tlv::node handle valid; the moved-from document
 * is empty and unusable except for destruction and assignment.
 *
 * @warning The format callbacks' contexts are borrowed and must outlive the document.
 */
class document {
public:
    document(const document&) = delete;
    document& operator=(const document&) = delete;

    /** @brief Takes over another document. */
    document(document&& other) noexcept : impl_(std::move(other.impl_)) {}

    /** @brief Takes over another document, freeing the current one. */
    document& operator=(document&& other) noexcept {
        impl_ = std::move(other.impl_);
        return *this;
    }

    /**
     * @brief Parses encoded elements into a new document.
     *
     * Wraps tlv_document_parse().
     *
     * @param data         Encoded input; copied, so it may be released afterwards.
     * @param format       Format descriptor and limits; copied.
     * @param error_offset Optional. On a malformed input receives the absolute offset of the
     *                     offending element.
     *
     * @return The document, or the error of tlv_document_parse().
     */
    TLV_NODISCARD static expected<document, error> parse(bytes data, const document_format& format,
                                                         size_t* error_offset = nullptr) {
        return make(&data, format, error_offset);
    }

    /**
     * @brief Creates an empty document.
     *
     * Wraps tlv_document_create().
     *
     * @param format Format descriptor and limits; copied.
     *
     * @return The document, or the error of tlv_document_create().
     */
    TLV_NODISCARD static expected<document, error> create(const document_format& format) {
        return make(nullptr, format, nullptr);
    }

    /** @brief Number of elements, including nested ones. */
    size_t size() const {
        return tlv_document_count(impl_->handle.get());
    }

    /** @brief Reports whether the document has no elements. */
    bool empty() const {
        return size() == 0;
    }

    /** @brief The first top-level element, or an empty handle. */
    node first() const {
        return node(tlv_document_first(impl_->handle.get()));
    }

    /** @brief The top-level elements, in encoding order. */
    node_range children() const {
        return node_range(first());
    }

    /**
     * @brief Finds the first top-level element with a tag.
     *
     * @param wanted Tag to look for; compared by contents.
     *
     * @return The element, or an empty handle.
     */
    node find(tag_t wanted) const {
        return node(tlv_document_find(impl_->handle.get(), nullptr, wanted));
    }

    /**
     * @brief Finds the first element addressed by a path query such as `6F/A5/50`.
     *
     * Wraps tlv_document_find_path().
     *
     * @param path Parsed query.
     *
     * @return The first addressed element in document order, or an empty handle.
     */
    node find(const query& path) const {
        return node(tlv_document_find_path(impl_->handle.get(), &path.c_query()));
    }

    /**
     * @brief Inserts a new element.
     *
     * Wraps tlv_document_insert(): tag and value are copied, and the value of a constructed tag is
     * parsed as nested elements.
     *
     * @param wanted Tag of the new element.
     * @param value  Value bytes; not retained.
     * @param parent Constructed element that receives it, or an empty handle for the top level.
     * @param before Existing child of `parent` that the new element precedes, or an empty handle
     *               to append.
     *
     * @return The new element, or the error of tlv_document_insert(). On error nothing changed.
     */
    TLV_NODISCARD expected<node, error> insert(tag_t wanted, bytes value, node parent = node(),
                                               node before = node()) {
        tlv_node_t*  created = nullptr;
        tlv_result_t rc = tlv_document_insert(
            impl_->handle.get(), parent.c_node(), before.c_node(), wanted,
            reinterpret_cast<const uint8_t*>(value.data()), value.size(), &created);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return node(created);
    }

    /**
     * @brief Removes the first top-level element with a tag.
     *
     * @param wanted Tag to look for.
     *
     * @return `true` if an element was removed. Handles to it and to its descendants are invalid.
     */
    bool erase(tag_t wanted) {
        node found = find(wanted);
        if (!found) return false;
        found.erase();
        return true;
    }

    /** @brief Computes the encoded size of the document; see tlv_document_encoded_size(). */
    TLV_NODISCARD expected<size_t, error> encoded_size() const {
        size_t       size = 0;
        tlv_result_t rc = tlv_document_encoded_size(impl_->handle.get(), &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return size;
    }

    /**
     * @brief Encodes the document into a new vector with the writer format.
     *
     * Wraps tlv_document_encode().
     *
     * @return The encoded bytes, or the error of tlv_document_encode().
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode() const {
        auto size = encoded_size();
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        tlv_result_t      rc = tlv_document_encode(
            impl_->handle.get(), reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        out.resize(written);
        return out;
    }

    /** @brief The underlying C document, for use with the C API. */
    tlv_document_t* c_document() const {
        return impl_->handle.get();
    }

private:
    struct deleter {
        void operator()(tlv_document_t* handle) const {
            tlv_document_free(handle);
        }
    };

    // The formats live on the heap so that the C document's pointers survive a move.
    struct state {
        tlv_reader_format_t                      reader;
        tlv_writer_format_t                      writer;
        std::unique_ptr<tlv_document_t, deleter> handle;
    };

    explicit document(std::unique_ptr<state> impl) : impl_(std::move(impl)) {}

    static expected<document, error> make(const bytes* data, const document_format& format,
                                          size_t* error_offset) {
        std::unique_ptr<state> impl(new state());
        impl->reader = format.reader;
        impl->writer = format.writer;

        tlv_document_options_t options;
        tlv_result_t rc = tlv_document_options_init(&options, &impl->reader, &impl->writer,
                                                    format.is_constructed);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        options.max_depth = format.max_depth;
        options.max_elements = format.max_elements;

        tlv_document_t* raw = nullptr;
        if (data) {
            rc = tlv_document_parse(reinterpret_cast<const uint8_t*>(data->data()), data->size(),
                                    &options, &raw, error_offset);
        } else {
            rc = tlv_document_create(&options, &raw);
        }
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        impl->handle.reset(raw);
        return document(std::move(impl));
    }

    std::unique_ptr<state> impl_;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_DOCUMENT_HPP
