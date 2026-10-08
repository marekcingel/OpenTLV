// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_DOCUMENT_HPP
#define OPENTLV_TLVPP_DOCUMENT_HPP

#include <cstddef>
#include <exception>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>

#include "tlv++/query/query.hpp"
#include "tlv++/query/program.hpp"
#include "tlv++/reader/tree.hpp"
#include "tlv++/types.hpp"
#include "tlv++/codec/typed.hpp"
#include "tlv++/writer/builder.hpp"
#include "tlv/document/document.h"
#include "tlv/writer/tree.h"

/**
 * @file document.hpp
 * @brief C++ wrapper for the optional mutable TLV document.
 *
 * Available when the library is built with `OPENTLV_DOCUMENT` (see tlv/config.h).
 * Unlike the reader and writer wrappers, the document allocates its owned tree and one shared
 * lifetime record. Node observation and handle copying do not allocate. Allocation failures in the
 * C++ layer throw std::bad_alloc; native allocation failures are returned as errors.
 */

namespace tlv {
class node;
class const_node;
class document;

/** @cond INTERNAL */
namespace detail {
struct document_access {
    static tlv_node_t*           get(const node& value);
    static const tlv_node_t*     get(const const_node& value);
    static tlv_document_t*       get(document& value);
    static const tlv_document_t* get(const document& value);
};
// Metadata only: the canonical C Document remains the sole tree representation.
struct document_lifetime {
    tlv_document_t* document = nullptr;
};
} // namespace detail
/** @endcond */

class node_range;

/** @brief Original input coordinates and presence flags; owns no input bytes.
 * @see tlv_node_source_location for edit invalidation and coordinate semantics. */
using document_source_location = tlv_document_source_location_t;

/**
 * @brief A non-owning handle to one element of a #tlv::document.
 *
 * Copies retain identity and retirement epoch and borrow one shared lifetime record.
 * Node observation/copying allocates nothing. After an edit retires any Node, the first
 * access through each retained handle performs an O(number of nodes) membership
 * check before dereferencing it; subsequent accesses at that epoch are O(1).
 * Insertions and primitive Value replacement preserve this cache because no Node
 * retires. Borrowed Value bytes still invalidate when their Value is replaced.
 * Handles do not own the Document or its tree.
 * Moving a Document preserves handles. Erasure invalidates the erased subtree;
 * replacing a constructed Value invalidates its descendants only. Destruction or
 * replacement of the owning Document invalidates all its handles. Invalid handles
 * test false and accessors return empty results; fallible operations return INVALID_STATE.
 * Tag and Value views borrow storage and must not be retained across invalidating
 * edits or destruction.
 * @warning Operations are not thread-safe. Const access can update the handle's
 * validity cache; externally synchronize concurrent access to a shared handle,
 * including read-only access after a Document mutation has completed.
 */
class node {
public:
    /** @brief Decode this primitive Node, checking the typed field's tag.
     * @tparam Field Typed field selecting Value type and codec.
     * @return Typed value, invalid_node, tag_mismatch, constructed_value, or codec error.
     * @warning Borrowed codec results retain Document storage lifetime and edit invalidation.
     * Owning codecs may allocate; allocation exceptions propagate.
     */
    template <typename Field>
    TLV_NODISCARD expected<typename Field::value_type, typed_error> decode() const {
        if (!*this) return unexpected<typed_error>(typed_error(typed_errc::invalid_node));
        if (tag() != Field::tag())
            return unexpected<typed_error>(typed_error(typed_errc::tag_mismatch));
        if (is_constructed())
            return unexpected<typed_error>(typed_error(typed_errc::constructed_value));
        return element_view(tag(), value()).template decode<Field>();
    }
    /** @brief Decode the first direct child matching a typed field; no recursive lookup.
     * @tparam Field Typed field selecting identifier, Value type and codec.
     * @return Typed value, invalid_node, missing_field, or the child's decode error.
     * @warning Borrowed results follow the child's Value lifetime. Does not validate Schema.
     */
    template <typename Field>
    TLV_NODISCARD expected<typename Field::value_type, typed_error> get() const {
        if (!*this) return unexpected<typed_error>(typed_error(typed_errc::invalid_node));
        auto child = find(Field::tag());
        if (!child) return unexpected<typed_error>(typed_error(typed_errc::missing_field));
        return child.template decode<Field>();
    }
    /** @brief Creates an empty handle. */
    node() noexcept : pointer_(nullptr), identity_(0), retire_epoch_(0) {}

    /** @brief Reports whether the handle refers to an element. */
    explicit operator bool() const {
        return c_node() != nullptr;
    }

private:
    /** @brief Borrow the underlying C node, or nullptr for an invalid handle.
     * @warning Never free the owner through this handle. Native edits are checked
     * by retirement epoch and identity before exposing a retained Node again.
     */
    tlv_node_t* c_node() const {
        auto owner = owner_.lock();
        if (!owner || !pointer_) return nullptr;
        const auto epoch = tlv_document_retire_epoch(owner->document);
        if (retire_epoch_ != epoch) {
            // Membership is checked before dereferencing a potentially retired pointer.
            // Identity rejects allocator address reuse after erase/replacement.
            if (tlv_document_node_identity(owner->document, pointer_) != identity_)
                pointer_ = nullptr;
            retire_epoch_ = epoch;
        }
        return pointer_;
    }

public:
    /** @brief The element's tag, borrowing the document; empty for an empty handle. */
    tlv::tag tag() const {
        return detail::semantic_access::borrow(tlv_node_tag(c_node()));
    }

    /** @brief Reports whether the element's value holds nested elements. */
    bool is_constructed() const {
        return tlv_node_is_constructed(c_node()) != 0;
    }

    /** @brief Copy optional original coordinates; unavailable for invalid or edited nodes.
     * @return Location with explicit presence flags, independent of input lifetime. */
    document_source_location source_location() const {
        return tlv_node_source_location(c_node());
    }

    /**
     * @brief The value bytes of a primitive element, borrowing the document.
     *
     * Empty for an empty value and for a constructed element; read a constructed element through
     * its children instead.
     */
    value_view value() const {
        return value_view(bytes(reinterpret_cast<const byte*>(tlv_node_value_data(c_node())),
                                tlv_node_value_size(c_node())));
    }

    /** @brief The first child of a constructed element, or an empty handle. */
    node first_child() const {
        return related(tlv_node_first_child(c_node()));
    }

    /** @brief The next sibling, or an empty handle. */
    node next() const {
        return related(tlv_node_next(c_node()));
    }

    /** @brief The next sibling with the same tag, or an empty handle. */
    node next_same_tag() const {
        return related(tlv_node_next_same_tag(c_node()));
    }

    /** @brief The parent element, or an empty handle for a top-level element. */
    node parent() const {
        return related(tlv_node_parent(c_node()));
    }

    /**
     * @brief Finds the first direct child with a tag.
     *
     * @param wanted Tag to look for; compared by contents.
     *
     * @return The child, or an empty handle.
     */
    node find(tlv::tag wanted) const {
        return related(tlv_document_find(nullptr, c_node(), detail::semantic_access::get(wanted)));
    }

    /** @brief Direct children in encoding order; empty for primitive or invalid nodes. */
    node_range children() const;

    /** @brief Insert a direct child, optionally before an existing child.
     * @param wanted New child's Tag; copied.
     * @param value New child's Value; copied and parsed if constructed.
     * @param before Direct child to precede, or an empty handle to append.
     * @return New child or the C insertion error; invalid handles return INVALID_STATE.
     * @note Existing handles and iterators remain valid. Failed insertion changes nothing.
     */
    TLV_NODISCARD expected<node, error> insert(tlv::tag wanted, bytes value, node before = node()) {
        auto owner = owner_.lock();
        if (!c_node() || (before.identity_ && !before))
            return unexpected<error>(
                error::from_c(TLV_ERR_INVALID_STATE).during(operation::document));
        tlv_node_t* created = nullptr;
        auto        rc = tlv_document_insert(
            owner->document, c_node(), before.c_node(), detail::semantic_access::get(wanted),
            reinterpret_cast<const uint8_t*>(value.data()), value.size(), &created);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        try {
            return related(created);
        } catch (...) {
            tlv_node_erase(created);
            throw;
        }
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
        auto owner = owner_.lock();
        if (!c_node())
            return unexpected<error>(
                error::from_c(TLV_ERR_INVALID_STATE).during(operation::document));
        tlv_result_t rc = tlv_node_set_value(
            c_node(), reinterpret_cast<const uint8_t*>(value.data()), value.size());
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        return {};
    }

    /**
     * @brief Removes the element and its descendants from the document.
     *
     * The handle becomes empty. Handles to the element or anything below it become invalid.
     */
    void erase() {
        auto owner = owner_.lock();
        if (!c_node()) return;
        tlv_node_erase(c_node());
    }

    /** @brief Computes the encoded size of the element with its descendants; see
     * tlv_node_encoded_size(). */
    TLV_NODISCARD expected<size_t, error> encoded_size() const {
        if (!c_node())
            return unexpected<error>(
                error::from_c(TLV_ERR_INVALID_STATE).during(operation::document));
        size_t       size = 0;
        tlv_result_t rc = tlv_node_encoded_size(c_node(), &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        return size;
    }

    /** @brief Encodes the element with its descendants into a new vector; see tlv_node_encode(). */
    TLV_NODISCARD expected<std::vector<byte>, error> encode() const {
        auto size = encoded_size();
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        tlv_result_t      rc =
            tlv_node_encode(c_node(), reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        out.resize(written);
        return out;
    }

    /**
     * @brief Measure this node with an explicit destination Format.
     * @param format Borrowed writable Format; must preserve constructed classification.
     * @return Exact size or the error from tlv_node_encoded_size_as().
     * @note Stages encoded children using the Document allocator; never changes the tree.
     */
    TLV_NODISCARD expected<size_t, error> encoded_size(tlv::format format) const {
        if (!c_node())
            return unexpected<error>(
                error::from_c(TLV_ERR_INVALID_STATE).during(operation::document));
        size_t     size = 0;
        const auto rc =
            tlv_node_encoded_size_as(c_node(), &detail::format_access::get(format), &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        return size;
    }

    /**
     * @brief Encode this node with an explicit destination Format.
     * @param format Borrowed writable Format as for encoded_size(format).
     * @return Owned bytes or the error from tlv_node_encode_as().
     * @note Identifiers are not remapped and the tree's original Format is unchanged.
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode(tlv::format format) const {
        auto size = encoded_size(format);
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        const auto        rc =
            tlv_node_encode_as(c_node(), &detail::format_access::get(format),
                               reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        out.resize(written);
        return out;
    }

    /** @brief Compare node identity; all empty or invalid handles compare equal. */
    friend bool operator==(const node& lhs, const node& rhs) {
        return lhs.c_node() == rhs.c_node();
    }

    /** @brief Compares two handles for referring to different elements. */
    friend bool operator!=(const node& lhs, const node& rhs) {
        return !(lhs == rhs);
    }

private:
    node(tlv_node_t* pointer, const std::shared_ptr<detail::document_lifetime>& owner)
        : owner_(owner), pointer_(pointer), identity_(tlv_node_identity(pointer)),
          retire_epoch_(tlv_document_retire_epoch(owner->document)) {}

    node related(tlv_node_t* pointer) const {
        auto owner = owner_.lock();
        return owner ? node(pointer, owner) : node();
    }

    std::weak_ptr<detail::document_lifetime> owner_;
    mutable tlv_node_t*                      pointer_;
    uint64_t                                 identity_;
    mutable uint64_t                         retire_epoch_;
    friend class document;
    friend struct detail::document_access;
};

/** @brief Forward iterator over sibling elements, yielding #tlv::node handles.
 * @note Copies share node validity. Invalidating the current node makes the
 * iterator compare equal to end; insertion preserves existing positions.
 */
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

/** @brief A borrowed range of siblings, for range-based `for` loops.
 * @note Follows live sibling links rather than a snapshot. Invalidating its first
 * node makes the range empty. Capture the next sibling before erasing a current node.
 */
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

inline node_range node::children() const {
    return node_range(first_child());
}

class const_node_range;
/**
 * @brief Read-only checked Node handle; cannot recover mutable Node or native storage.
 * Copies allocate nothing and retain the same validity and borrowed-view rules as node.
 * @warning Read-only access does not imply thread safety. Const methods may update
 * the validity cache after a Document mutation; concurrent access to the same
 * handle requires external synchronization even when the Document is no longer mutating.
 */
class const_node {
public:
    /** @brief Create an empty read-only handle. */
    const_node() = default;
    /** @brief Restrict a mutable handle to observation. */
    const_node(node value) : value_(std::move(value)) {}
    /** @brief Whether this handle still identifies a live element. */
    explicit operator bool() const {
        return static_cast<bool>(value_);
    }
    /** @brief Borrow the identifier; invalid handles return an absent identifier. */
    tlv::tag tag() const {
        return value_.tag();
    }
    /** @brief Borrow immutable primitive Value bytes. */
    value_view value() const {
        return value_.value();
    }
    /** @brief Whether this element contains nested elements. */
    bool is_constructed() const {
        return value_.is_constructed();
    }
    /** @brief Copy optional retained source coordinates. */
    document_source_location source_location() const {
        return value_.source_location();
    }
    /** @brief Read-only first child, or empty. */
    const_node first_child() const {
        return value_.first_child();
    }
    /** @brief Read-only next sibling, or empty. */
    const_node next() const {
        return value_.next();
    }
    /** @brief Read-only next sibling with the same identifier, or empty. */
    const_node next_same_tag() const {
        return value_.next_same_tag();
    }
    /** @brief Read-only parent, or empty for roots. */
    const_node parent() const {
        return value_.parent();
    }
    /** @brief Find a direct child by byte identity. */
    const_node find(tlv::tag wanted) const {
        return value_.find(wanted);
    }
    /** @brief Borrow read-only child traversal. */
    const_node_range children() const;
    /** @brief Decode this field; borrowed results follow Document lifetime. */
    template <typename Field> expected<typename Field::value_type, typed_error> decode() const {
        return value_.template decode<Field>();
    }
    /** @brief Decode the first matching direct child. */
    template <typename Field> expected<typename Field::value_type, typed_error> get() const {
        return value_.template get<Field>();
    }
    /** @brief Measure this subtree using its original Format. */
    expected<size_t, error> encoded_size() const {
        return value_.encoded_size();
    }
    /** @brief Measure this subtree using a borrowed destination Format. */
    expected<size_t, error> encoded_size(tlv::format format) const {
        return value_.encoded_size(format);
    }
    /** @brief Encode an owning byte vector; may allocate. */
    expected<std::vector<byte>, error> encode() const {
        return value_.encode();
    }
    /** @brief Encode with a destination Format into an owning vector; may allocate. */
    expected<std::vector<byte>, error> encode(tlv::format format) const {
        return value_.encode(format);
    }
    /** @brief Compare checked node identity. */
    friend bool operator==(const const_node& a, const const_node& b) {
        return a.value_ == b.value_;
    }
    /** @brief Compare checked node identity. */
    friend bool operator!=(const const_node& a, const const_node& b) {
        return !(a == b);
    }

private:
    node value_;
    friend class document;
    friend struct detail::document_access;
};
/** @brief Forward iterator that exposes only read-only checked Node handles. */
class const_node_iterator {
public:
    /// @cond INTERNAL
    using iterator_category = std::forward_iterator_tag;
    using value_type = const_node;
    using difference_type = std::ptrdiff_t;
    using pointer = const const_node*;
    using reference = const const_node&;
    /// @endcond
    /** @brief Begin at a sibling; an empty handle is end. */
    explicit const_node_iterator(const_node current = {}) : current_(current) {}
    /** @brief Observe the current handle. */
    reference operator*() const {
        return current_;
    }
    /** @brief Observe the current handle. */
    pointer operator->() const {
        return &current_;
    }
    /** @brief Advance to the next sibling. */
    const_node_iterator& operator++() {
        current_ = current_.next();
        return *this;
    }
    /** @brief Advance and return the previous position. */
    const_node_iterator operator++(int) {
        auto old = *this;
        ++*this;
        return old;
    }
    /** @brief Compare positions, including invalidated/end positions. */
    friend bool operator==(const const_node_iterator& a, const const_node_iterator& b) {
        return a.current_ == b.current_;
    }
    /** @brief Compare positions. */
    friend bool operator!=(const const_node_iterator& a, const const_node_iterator& b) {
        return !(a == b);
    }

private:
    const_node current_;
};
/** @brief Read-only sibling range; follows live links with the normal Node invalidation rules. */
class const_node_range {
public:
    /** @brief Begin at the supplied read-only handle. */
    explicit const_node_range(const_node first = {}) : first_(first) {}
    /** @brief First sibling. */
    const_node_iterator begin() const {
        return const_node_iterator(first_);
    }
    /** @brief End position. */
    const_node_iterator end() const {
        return const_node_iterator();
    }
    /** @brief Whether the first handle is absent or invalidated. */
    bool empty() const {
        return !first_;
    }

private:
    const_node first_;
};
inline const_node_range const_node::children() const {
    return const_node_range(first_child());
}

/**
 * @brief Format and runtime resource limits of a #tlv::document.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
struct document_format {
    /**
     * Format used for parsing and encoding; its contents are copied, its context is borrowed.
     * `format.is_constructed` selects nested values, or `nullptr` for opaque values.
     */
private:
    tlv_format_t descriptor_;

public:
    /** Runtime maximum nesting depth (default TLV_TREE_DEFAULT_DEPTH). */
    size_t max_depth;
    /** Maximum number of elements, including nested ones. */
    size_t max_elements;

    /** Retain original offsets/header lengths when parsing; false by default.
     * Does not retain input bytes. See tlv_node_source_location for invalidation. */
    bool retain_source_locations;

    /** @brief Copy a Format descriptor and borrow its immutable context.
     * @param format Format whose context outlives every Document created with these options.
     * @note Copies allocate nothing and use canonical default resource limits.
     */
    document_format(tlv::format format)
        : descriptor_(detail::format_access::get(format)), max_depth(TLV_TREE_DEFAULT_DEPTH),
          max_elements(TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS), retain_source_locations(false) {}
    /** @brief Borrow these options' descriptor; the options and context must outlive the view. */
    tlv::format view() const& noexcept {
        return detail::format_access::borrow(descriptor_);
    }
    /** @brief Reject views into temporary options. */
    tlv::format view() const&& = delete;
};

/**
 * @brief An owned, mutable TLV document.
 *
 * Wraps #tlv_document_t. Unlike the reader and visitor wrappers, a document copies the data it
 * is given, allocates memory and lets the data be searched, changed and encoded again. It is
 * independent of the zero-copy APIs: nothing in the core depends on it, and it never refers to
 * the buffer it was parsed from.
 *
 * A document is move-only. Moving keeps every #tlv::node handle valid; the moved-from document
 * is empty and unusable except for destruction and assignment.
 *
 * @warning Const access provides a read-only interface, not a concurrent-read guarantee.
 * Externally synchronize concurrent access to the Document and shared handles;
 * even const Node access may update a handle's validity cache after a mutation.
 * @warning The format callbacks' contexts are borrowed and must outlive the document.
 * Documents returned by document_builder also borrow the reader's Format descriptor.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
class document {
public:
    /** @brief Decode the first top-level element matching a typed field.
     * @tparam Field Typed field selecting identifier, Value type and codec.
     * @return Typed value, missing_field, or the Node decode error.
     * @warning Borrowed results retain Document Value lifetime and edit invalidation.
     * This operation does not validate Schema or enforce uniqueness; owning codecs may allocate.
     */
    template <typename Field>
    TLV_NODISCARD expected<typename Field::value_type, typed_error> get() const {
        auto found = find(Field::tag());
        if (!found) return unexpected<typed_error>(typed_error(typed_errc::missing_field));
        return found.template decode<Field>();
    }
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
     * @param diagnostic Optional original Reader detail with INPUT coordinates relative
     *                   to data. Tag and text views remain borrowed.
     *
     * @return The document, or the error of tlv_document_parse().
     */
    TLV_NODISCARD static expected<document, error>
    parse(bytes data, const document_format& format,
          tlv_reader_diagnostic_t* diagnostic = nullptr) {
        return make(&data, format, diagnostic);
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

    /** @brief Read-only first top-level element; never exposes mutation. */
    const_node first() const {
        return const_cast<document*>(this)->first();
    }
    /** @brief Read-only top-level siblings. */
    const_node_range children() const {
        return const_node_range(first());
    }
    /** @brief Begin read-only top-level traversal. */
    const_node_iterator begin() const {
        return children().begin();
    }
    /** @brief End read-only traversal. */
    const_node_iterator end() const {
        return const_node_iterator();
    }
    /** @brief Read-only lookup by byte identifier. */
    const_node find(tlv::tag wanted) const {
        return const_cast<document*>(this)->find(wanted);
    }
    /** @brief Read-only lookup by compiled path. */
    const_node find(const query& path) const {
        return const_cast<document*>(this)->find(path);
    }
    /** @brief Read-only snapshot of path matches; allocates the result vector. */
    std::vector<const_node> select(const query& path) const {
        auto values = const_cast<document*>(this)->select(path);
        return std::vector<const_node>(values.begin(), values.end());
    }
    /** @brief Compile a path and obtain a read-only snapshot; throws query_error on syntax failure.
     */
    std::vector<const_node> select(const char* text) const {
        return select(query::compile(text));
    }
    /** @brief Evaluate a compiled query and return read-only handles; may allocate. */
    expected<std::vector<const_node>, query_failure>
    select(const query_program& program, query_capabilities environment = nullptr,
           size_t max_work = 100000000) const {
        auto values = const_cast<document*>(this)->select(program, environment, max_work);
        if (!values) return unexpected<query_failure>(values.error());
        return std::vector<const_node>(values->begin(), values->end());
    }
    /** @brief Consume a checked read-only query result; preserves Query error and end outcomes. */
    expected<const_node, query_failure> next(query_execution& execution) const {
        auto value = const_cast<document*>(this)->next(execution);
        if (!value) return unexpected<query_failure>(value.error());
        return const_node(*value);
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
    node first() {
        return node(tlv_document_first(c_document()), impl_->lifetime);
    }

    /** @brief The top-level elements, in encoding order. */
    node_range children() {
        return node_range(first());
    }

    /** @brief Begin iteration over top-level elements in encoding order.
     * @note Insertion preserves iterators. Erasing the current node or replacing
     * an ancestor's constructed Value invalidates its iterator, which then
     * compares equal to end().
     */
    node_iterator begin() {
        return children().begin();
    }

    /** @brief End of top-level iteration. */
    node_iterator end() {
        return node_iterator();
    }

    /**
     * @brief Finds the first top-level element with a tag.
     *
     * @param wanted Tag to look for; compared by contents.
     *
     * @return The element, or an empty handle.
     */
    node find(tlv::tag wanted) {
        return node(
            tlv_document_find(impl_->handle.get(), nullptr, detail::semantic_access::get(wanted)),
            impl_->lifetime);
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
    node find(const query& path) {
        return node(tlv_document_find_path(impl_->handle.get(), &path.c_query()), impl_->lifetime);
    }

    /** @brief Select all matching Nodes in Document order.
     * @param path Compiled Query; not retained.
     * @return Snapshot of normal non-owning Node handles; no matches is empty.
     * @note Allocates result storage and Node validity metadata. Insertions after
     * selection are not included. Erasure, Value replacement and Document destruction
     * invalidate handles following the normal Node contract; vector positions remain.
     * @throws std::bad_alloc If result storage or validity metadata allocation fails.
     */
    std::vector<node> select(const query& path) {
        struct collection {
            const document*           owner;
            std::vector<node>         results;
            std::exception_ptr        failure;
            static tlv_visit_result_t append(tlv_node_t* raw, void* context) {
                auto& state = *static_cast<collection*>(context);
                try {
                    state.results.push_back(node(raw, state.owner->impl_->lifetime));
                    return TLV_VISIT_CONTINUE;
                } catch (...) {
                    state.failure = std::current_exception();
                    return TLV_VISIT_ERROR;
                }
            }
        };
        collection state{this, {}, {}};
        auto       rc = tlv_document_query_visit(impl_->handle.get(), &path.c_query(),
                                                 &collection::append, &state);
        if (state.failure) std::rethrow_exception(state.failure);
        if (rc != TLV_OK) throw query_error(rc, tlv_diagnostic_t{});
        return std::move(state.results);
    }

    /** @brief Compile a text path and select all matching Nodes.
     * @param text NUL-terminated Query text; not retained.
     * @return Snapshot with the lifetime and mutation rules of select(const query&).
     * @throws query_error On compilation failure, retaining the original text offset.
     * @throws std::bad_alloc On C++ result or handle allocation failure.
     */
    std::vector<node> select(const char* text) {
        return select(query::compile(text));
    }

    /** @brief Complete full-language selection and return checked Node snapshots.
     * @param program Immutable compiled full Query with node result kind.
     * @param environment Optional compatible native providers, borrowed for the call.
     * @param max_work Explicit charged execution budget.
     * @return Document-order unique checked handles or full native diagnostic.
     * @note Allocates workspace, optional canonical Value snapshot and result handles.
     * Insertions after selection are excluded; handles follow the normal granular
     * Node invalidation rules. Selection always completes before returning results. */
    expected<std::vector<node>, query_failure> select(const query_program& program,
                                                      query_capabilities   environment = nullptr,
                                                      size_t               max_work = 100000000) {
        if (program.info().result_kind != TLV_QUERY_RESULT_NODES)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        auto execution = query_execution::create(program, impl_->max_depth, size() ? size() : 1,
                                                 max_work, environment);
        if (!execution) return unexpected<query_failure>(execution.error());
        std::vector<uint8_t> values;
        auto                 rc = evaluate_owned(program, *execution, values);
        if (!rc) return unexpected<query_failure>(rc.error());
        std::vector<node> results;
        for (;;) {
            tlv_node_t* pointer = nullptr;
            auto        code = tlv_document_query_next(execution->c_exec(), &pointer);
            if (code == TLV_ERR_END_OF_BUFFER) break;
            if (code != TLV_OK) return unexpected<query_failure>(detail::query_failed(code));
            results.push_back(node(pointer, impl_->lifetime));
        }
        return results;
    }

    /** @brief Evaluate full Query with C++ snapshot and Writer storage views.
     * @param execution Fresh retained execution, with variables already bound.
     * @param values Caller-owned snapshot storage, alive through result consumption.
     * @param staging Optional Writer workspace, needed for constructed Value snapshots.
     * @param context Optional relative context in this Document.
     * @return Complete Query failure or success; does not allocate.
     * @warning Keep the Document and snapshot unchanged while consuming results.
     */
    expected<void, query_failure> evaluate(query_execution& execution, span<byte> values,
                                           const writer_workspace* staging = nullptr,
                                           node                    context = node()) const {
        tlv_tree_writer_workspace_t raw{};
        if (staging) {
            raw.frames = staging->frames.data();
            raw.frame_capacity = staging->frames.size();
            raw.scratch = reinterpret_cast<uint8_t*>(staging->scratch.data());
            raw.scratch_capacity = staging->scratch.size();
        }
        return evaluate(execution, reinterpret_cast<uint8_t*>(values.data()), values.size(),
                        staging ? &raw : nullptr, context);
    }

private:
    /** @brief Evaluate full Query using caller-owned execution and optional Value staging.
     * @param execution Fresh retained continuation, with variables already bound.
     * @param values Stable snapshot destination, alive through result consumption.
     * @param capacity Snapshot capacity.
     * @param staging Bounded Writer staging, or NULL when Values are unnecessary.
     * @param context Optional checked node selecting relative context.
     * @return Native diagnostic; successful evaluation allocates nothing.
     * @warning Keep Document alive and unchanged until consuming execution results. */
    expected<void, query_failure> evaluate(query_execution& execution, uint8_t* values,
                                           size_t capacity, tlv_tree_writer_workspace_t* staging,
                                           node context = node()) const {
        if (context.identity_ && !context)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_STATE));
        if (context.identity_ && context.owner_.lock() != impl_->lifetime)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        tlv_query_diagnostic_t d{};
        auto rc = tlv_document_query_evaluate(c_document(), execution.c_exec(), context.c_node(),
                                              values, capacity, staging, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        execution.document_lifetime_ = impl_->lifetime;
        execution.has_document_ = true;
        return {};
    }

public:
    /** @brief Pull a checked Document handle from a completed execution for this Document.
     * @param execution Completed continuation, with this Document alive and unchanged.
     * @return Checked Node, END_OF_BUFFER, or INVALID_STATE for missing, expired or stale
     * Document execution; INVALID_ARG for an execution owned by a different Document. */
    expected<node, query_failure> next(query_execution& execution) {
        if (!execution.has_document_ || execution.document_lifetime_.expired())
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_STATE));
        if (execution.document_lifetime_.lock() != impl_->lifetime)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        tlv_node_t* pointer = nullptr;
        auto        rc = tlv_document_query_next(execution.c_exec(), &pointer);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return node(pointer, impl_->lifetime);
    }

    /** @brief Remove completed selection, with ancestors dominating selected descendants.
     * @param program Immutable full node Query.
     * @return Number of removed selected roots or native selection failure.
     * @note Selection and C++ tracking allocations finish before the first edit.
     * Snapshot handles follow normal Node invalidation. No-match succeeds with zero. */
    expected<size_t, query_failure> query_remove(const query_program& program) {
        return edit_query(program, TLV_DOCUMENT_QUERY_REMOVE, tlv_tag(nullptr, 0), bytes(),
                          nullptr);
    }

    /** @brief Replace Values selected against the initial tree; selected ancestors dominate.
     * @param program Immutable node selector.
     * @param value New Value bytes, copied before mutation using the Document allocator.
     * @param applied Optional successful edit count, including partial failure.
     * @return Edited selected roots or native error. No matches succeeds with zero.
     * @note Preorder commits stop at the first failure; no rollback. Each native Value
     * replacement is atomic and respects Format/constructed parsing. Checked handles
     * detect erased descendants lazily through native retirement epoch and identity. */
    expected<size_t, query_failure> query_replace(const query_program& program, bytes value,
                                                  size_t* applied = nullptr) {
        return edit_query(program, TLV_DOCUMENT_QUERY_REPLACE, tlv_tag(nullptr, 0), value, applied);
    }

    /** @brief Insert one sibling immediately after every node in the initial selection.
     * @param program Immutable node selector.
     * @param tag New sibling identifier, copied by the normal Document operation.
     * @param value New Value bytes, copied before mutation.
     * @param applied Optional successful insert count, including partial failure.
     * @return Successful inserts or native error; prior inserts remain on failure.
     * @note Initial preorder selection completes first. Original sibling order and
     * existing checked handles are preserved; inserted nodes never become new targets. */
    expected<size_t, query_failure> query_insert_after(const query_program& program, tlv::tag tag,
                                                       bytes value, size_t* applied = nullptr) {
        return edit_query(program, TLV_DOCUMENT_QUERY_INSERT_AFTER,
                          detail::semantic_access::get(tag), value, applied);
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
    TLV_NODISCARD expected<node, error> insert(tlv::tag wanted, bytes value, node parent = node(),
                                               node before = node()) {
        if ((parent.identity_ && !parent) || (before.identity_ && !before))
            return unexpected<error>(
                error::from_c(TLV_ERR_INVALID_STATE).during(operation::document));
        tlv_node_t*  created = nullptr;
        tlv_result_t rc = tlv_document_insert(impl_->handle.get(), parent.c_node(), before.c_node(),
                                              detail::semantic_access::get(wanted),
                                              reinterpret_cast<const uint8_t*>(value.data()),
                                              value.size(), &created);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        try {
            return node(created, impl_->lifetime);
        } catch (...) {
            tlv_node_erase(created);
            throw;
        }
    }

    /**
     * @brief Removes the first top-level element with a tag.
     *
     * @param wanted Tag to look for.
     *
     * @return `true` if an element was removed. Handles to it and to its descendants are invalid.
     */
    bool erase(tlv::tag wanted) {
        node found = find(wanted);
        if (!found) return false;
        found.erase();
        return true;
    }

    /** @brief Computes the encoded size of the document; see tlv_document_encoded_size(). */
    TLV_NODISCARD expected<size_t, error> encoded_size() const {
        size_t       size = 0;
        tlv_result_t rc = tlv_document_encoded_size(impl_->handle.get(), &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
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
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        out.resize(written);
        return out;
    }

    /**
     * @brief Measure this document with an explicit destination Format.
     * @param format Borrowed writable Format; must preserve constructed classification.
     * @return Exact size or the error from tlv_document_encoded_size_as().
     * @note Stages encoded children using the Document allocator; never changes the tree.
     */
    TLV_NODISCARD expected<size_t, error> encoded_size(tlv::format format) const {
        size_t     size = 0;
        const auto rc = tlv_document_encoded_size_as(impl_->handle.get(),
                                                     &detail::format_access::get(format), &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        return size;
    }

    /**
     * @brief Encode this document with an explicit destination Format.
     * @param format Borrowed writable Format as for encoded_size(format).
     * @return Owned bytes or the error from tlv_document_encode_as().
     * @note Identifiers are not remapped and the tree's original Format is unchanged.
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode(tlv::format format) const {
        auto size = encoded_size(format);
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        const auto        rc =
            tlv_document_encode_as(impl_->handle.get(), &detail::format_access::get(format),
                                   reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        out.resize(written);
        return out;
    }

private:
    /** @brief Borrow the underlying C document for interoperability.
     * @warning Never free this handle. Native edits are checked by retirement epoch and identity
     * when a retained Node is next accessed. Raw pointers must not outlive this owner.
     */
    tlv_document_t* c_document() const {
        return impl_->handle.get();
    }

private:
    struct deleter {
        void operator()(tlv_document_t* handle) const {
            tlv_document_free(handle);
        }
    };

    // The format lives on the heap so that the C document's pointer survives a move.
    struct state {
        size_t                                     max_depth = TLV_TREE_DEFAULT_DEPTH;
        tlv_format_t                               format;
        std::unique_ptr<tlv_document_t, deleter>   handle;
        std::shared_ptr<detail::document_lifetime> lifetime =
            std::make_shared<detail::document_lifetime>();
    };

    explicit document(std::unique_ptr<state> impl) : impl_(std::move(impl)) {
        impl_->lifetime->document = impl_->handle.get();
    }

    static expected<document, error> make(const bytes* data, const document_format& format,
                                          tlv_reader_diagnostic_t* diagnostic) {
        std::unique_ptr<state> impl(new state());
        impl->format = detail::format_access::get(format.view());
        impl->max_depth = format.max_depth;

        tlv_document_options_t options;
        tlv_result_t           rc = tlv_document_options_init(&options, &impl->format);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        options.max_depth = format.max_depth;
        options.max_elements = format.max_elements;
        options.retain_source_locations = format.retain_source_locations;

        tlv_document_t*         raw = nullptr;
        tlv_reader_diagnostic_t local{};
        if (!diagnostic) diagnostic = &local;
        if (data) {
            rc = tlv_document_parse(reinterpret_cast<const uint8_t*>(data->data()), data->size(),
                                    &options, &raw, diagnostic);
        } else {
            rc = tlv_document_create(&options, &raw);
        }
        if (rc != TLV_OK) {
            auto failure = error::from_c(rc).during(operation::document);
            diagnostic->diagnostic.code = rc;
            failure = detail::error_access::diagnostic(diagnostic->diagnostic, operation::document);
            return unexpected<error>(failure);
        }
        impl->handle.reset(raw);
        return document(std::move(impl));
    }

    std::unique_ptr<state>          impl_;
    expected<size_t, query_failure> edit_query(const query_program&           program,
                                               tlv_document_query_edit_kind_t kind, tlv_tag_t tag,
                                               bytes value, size_t* applied) {
        size_t count = 0;
        if (applied) *applied = 0;
        if (program.info().result_kind != TLV_QUERY_RESULT_NODES)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        auto execution =
            query_execution::create(program, impl_->max_depth, size() ? size() : 1, 100000000);
        if (!execution) return unexpected<query_failure>(execution.error());
        std::vector<uint8_t> values;
        auto                 evaluated = evaluate_owned(program, *execution, values);
        if (!evaluated) return unexpected<query_failure>(evaluated.error());
        std::vector<tlv_node_t*> targets(size());
        auto rc = tlv_document_query_edit(c_document(), execution->c_exec(), kind, tag,
                                          reinterpret_cast<const uint8_t*>(value.data()),
                                          value.size(), targets.data(), targets.size(), &count);
        if (applied) *applied = count;
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return count;
    }
    expected<void, query_failure> evaluate_owned(const query_program&  program,
                                                 query_execution&      execution,
                                                 std::vector<uint8_t>& values) const {
        if (!program.info().constructed_values_required)
            return evaluate(execution, nullptr, 0, nullptr);
        std::vector<tlv_tree_writer_frame_t> frames(impl_->max_depth + 1);
        std::vector<uint8_t>                 scratch;
        tlv_tree_writer_workspace_t          staging{};
        staging.frames = frames.data();
        staging.frame_capacity = frames.size();
        size_t bytes = 0;
        for (;;) {
            staging.data = values.data();
            staging.data_capacity = values.size();
            staging.scratch = scratch.data();
            staging.scratch_capacity = scratch.size();
            auto rc = tlv_document_query_value_size(c_document(), &staging, &bytes);
            if (rc == TLV_OK) break;
            if (rc != TLV_ERR_BUFFER_TOO_SHORT)
                return unexpected<query_failure>(detail::query_failed(rc));
            if (staging.required_data <= values.size() &&
                staging.required_scratch <= scratch.size())
                return unexpected<query_failure>(detail::query_failed(rc));
            if (staging.required_data > values.size()) values.resize(staging.required_data);
            if (staging.required_scratch > scratch.size()) scratch.resize(staging.required_scratch);
        }
        return evaluate(execution, values.data(), values.size(), &staging);
    }
    friend class document_builder;
    friend struct detail::document_access;
};

/// @cond INTERNAL
inline tlv_node_t* detail::document_access::get(const node& value) {
    return value.c_node();
}
inline const tlv_node_t* detail::document_access::get(const const_node& value) {
    return value.value_.c_node();
}
inline tlv_document_t* detail::document_access::get(document& value) {
    return value.c_document();
}
inline const tlv_document_t* detail::document_access::get(const document& value) {
    return value.c_document();
}
/// @endcond

/**
 * @brief Owning, resumable adapter over the canonical C Document Builder.
 * @warning The reader and its frames must outlive the active builder. Do not pull,
 * skip or visit that reader while building; set_input() is permitted. The reader's
 * Format and context must outlive both builder and returned document.
 */
class document_builder {
public:
    /** @brief Exclusive ownership; copying is prohibited. */
    document_builder(const document_builder&) = delete;
    /** @brief Exclusive ownership; copying is prohibited. */
    document_builder& operator=(const document_builder&) = delete;
    /** @brief Transfer the active builder without moving its borrowed reader. */
    document_builder(document_builder&&) noexcept = default;
    /** @brief Discard unfinished work and take over another builder. */
    document_builder& operator=(document_builder&&) noexcept = default;

    /**
     * @brief Materialize a fresh whole stream.
     * @param reader Borrowed initialized Tree Reader; invalidates subtree selection.
     * @param max_depth Maximum materialized depth.
     * @param max_elements Maximum materialized node count.
     * @param retain_source_locations Copy original source coordinates without borrowing bytes.
     * @return Builder or the original C error; does not advance the reader.
     */
    TLV_NODISCARD static expected<document_builder, error>
    create(tree_reader& reader, size_t max_depth = TLV_TREE_DEFAULT_DEPTH,
           size_t max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS,
           bool   retain_source_locations = false) {
        return create_impl(reader, nullptr, max_depth, max_elements, retain_source_locations);
    }

    /**
     * @brief Materialize the last item published by an explicit reader.next().
     * @param reader Borrowed Tree Reader with a current subtree selection.
     * @param max_depth Maximum materialized depth relative to the selected root.
     * @param max_elements Maximum materialized node count.
     * @param retain_source_locations Preserve absolute Reader coordinates of selected nodes.
     * @return Builder, INVALID_STATE if selection was invalidated, or original C error.
     * @note Root content is copied immediately without another pull. This attempt
     * consumes selection, even on failure. Pulls, skips, input replacement,
     * validation, visitors and builder creation invalidate selection.
     */
    TLV_NODISCARD static expected<document_builder, error>
    current_subtree(tree_reader& reader, size_t max_depth = TLV_TREE_DEFAULT_DEPTH,
                    size_t max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS,
                    bool   retain_source_locations = false) {
        if (!reader.has_current_)
            return unexpected<error>(
                error::from_c(TLV_ERR_INVALID_STATE).during(operation::document));
        const tlv_tree_item_t root = reader.current_;
        return create_impl(reader, &root, max_depth, max_elements, retain_source_locations);
    }

    /**
     * @brief Consume available items and return the owning document when complete.
     * @param diagnostic Optional borrowed Reader failure detail.
     * @return Document, NEED_MORE_DATA with continuation retained, or terminal error.
     * @note Selected subtrees leave the following sibling unread. Completion and
     * terminal errors end consumption; destroying this builder discards unfinished work.
     */
    TLV_NODISCARD expected<document, error> consume(reader_diagnostic* diagnostic = nullptr) {
        reader_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        std::unique_ptr<document::state> state(new document::state());
        tlv_document_t*                  raw = nullptr;
        auto rc = tlv_document_builder_consume(handle_.get(), &raw, diagnostic);
        if (rc != TLV_OK) {
            diagnostic->diagnostic.code = rc;
            return unexpected<error>(
                detail::error_access::diagnostic(diagnostic->diagnostic, operation::document));
        }
        state->handle.reset(raw);
        state->max_depth = max_depth_;
        return document(std::move(state));
    }

private:
    static expected<document_builder, error> create_impl(tree_reader&           reader,
                                                         const tlv_tree_item_t* root,
                                                         size_t max_depth, size_t max_elements,
                                                         bool retain_source_locations) {
        reader.has_current_ = false;
        if (reader.init_result_ != TLV_OK)
            return unexpected<error>(
                error::from_c(reader.init_result_).during(operation::document));
        tlv_document_options_t options{};
        auto                   rc = tlv_document_options_init(&options, reader.impl_.input.format);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        options.max_depth = max_depth;
        options.max_elements = max_elements;
        options.retain_source_locations = retain_source_locations;
        tlv_document_builder_t* raw = nullptr;
        rc = tlv_document_builder_create(&options, &reader.impl_, root, &raw);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::document));
        return document_builder(raw, max_depth);
    }

    struct deleter {
        void operator()(tlv_document_builder_t* handle) const {
            tlv_document_builder_free(handle);
        }
    };
    explicit document_builder(tlv_document_builder_t* handle, size_t max_depth)
        : handle_(handle), max_depth_(max_depth) {}
    std::unique_ptr<tlv_document_builder_t, deleter> handle_;
    size_t                                           max_depth_;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_DOCUMENT_HPP
