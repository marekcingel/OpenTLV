// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_DOCUMENT_HPP
#define OPENTLV_TLVPP_DOCUMENT_HPP

#include <cstddef>
#include <exception>
#include <iterator>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "tlv++/query/query.hpp"
#include "tlv++/reader/tree.hpp"
#include "tlv++/types.hpp"
#include "tlv++/codec/typed.hpp"
#include "tlv/document/document.h"

/**
 * @file document.hpp
 * @brief C++ wrapper for the optional mutable TLV document.
 *
 * Available when the library is built with `OPENTLV_DOCUMENT` (see tlv/config.h).
 * Unlike the reader and writer wrappers, the document allocates, including
 * validity metadata when exposing a Node. Allocation failures in the C++ layer
 * throw std::bad_alloc; native allocation failures are returned as errors.
 */

namespace tlv {

/** @cond INTERNAL */
namespace detail {
// Metadata only: the canonical C Document remains the sole tree representation.
struct node_token {
    tlv_node_t* pointer;
    explicit node_token(tlv_node_t* value) : pointer(value) {}
};
struct document_lifetime {
    tlv_document_t*                                            document = nullptr;
    std::unordered_map<tlv_node_t*, std::weak_ptr<node_token>> handles;

    std::shared_ptr<node_token> track(tlv_node_t* pointer) {
        if (!pointer) return {};
        auto& entry = handles[pointer];
        auto  token = entry.lock();
        if (!token) {
            token = std::make_shared<node_token>(pointer);
            entry = token;
        }
        return token;
    }

    std::vector<std::shared_ptr<node_token>> affected(tlv_node_t* root, bool include_root) {
        std::vector<std::shared_ptr<node_token>> result;
        for (auto it = handles.begin(); it != handles.end();) {
            auto token = it->second.lock();
            if (!token) {
                it = handles.erase(it);
                continue;
            }
            auto candidate = include_root ? token->pointer : tlv_node_parent(token->pointer);
            for (; candidate; candidate = tlv_node_parent(candidate)) {
                if (candidate == root) {
                    result.push_back(token);
                    break;
                }
            }
            ++it;
        }
        return result;
    }

    void invalidate(const std::vector<std::shared_ptr<node_token>>& tokens) {
        for (const auto& token : tokens) {
            handles.erase(token->pointer);
            token->pointer = nullptr;
        }
    }
};
} // namespace detail
/** @endcond */

class node_range;

/**
 * @brief A non-owning handle to one element of a #tlv::document.
 *
 * Copies share inexpensive validity metadata without owning the Document or its tree.
 * Moving a Document preserves handles. Erasure invalidates the erased subtree;
 * replacing a constructed Value invalidates its descendants only. Destruction or
 * replacement of the owning Document invalidates all its handles. Invalid handles
 * test false and accessors return empty results; fallible operations return INVALID_ARG.
 * Tag and Value views borrow storage and must not be retained across invalidating
 * edits or destruction. Operations are not thread-safe.
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
    node() = default;

    /** @brief Reports whether the handle refers to an element. */
    explicit operator bool() const {
        return c_node() != nullptr;
    }

    /** @brief Borrow the underlying C node, or nullptr for an invalid handle.
     * @warning Native mutation bypasses C++ validity tracking. Do not erase nodes,
     * replace constructed Values or free the Document through this escape hatch.
     */
    tlv_node_t* c_node() const {
        return !owner_.expired() && token_ ? token_->pointer : nullptr;
    }

    /** @brief The element's tag, borrowing the document; empty for an empty handle. */
    tlv::tag tag() const {
        return detail::semantic_access::borrow(tlv_node_tag(c_node()));
    }

    /** @brief Reports whether the element's value holds nested elements. */
    bool is_constructed() const {
        return tlv_node_is_constructed(c_node()) != 0;
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
     * @return New child or the C insertion error; invalid handles return INVALID_ARG.
     * @note Existing handles and iterators remain valid. Failed insertion changes nothing.
     */
    TLV_NODISCARD expected<node, error> insert(tlv::tag wanted, bytes value, node before = node()) {
        auto owner = owner_.lock();
        if (!c_node() || (before.token_ && !before))
            return unexpected<error>(error::from_c(TLV_ERR_INVALID_ARG));
        tlv_node_t* created = nullptr;
        auto        rc = tlv_document_insert(
            owner->document, c_node(), before.c_node(), detail::semantic_access::get(wanted),
            reinterpret_cast<const uint8_t*>(value.data()), value.size(), &created);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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
        if (!c_node()) return unexpected<error>(error::from_c(TLV_ERR_INVALID_ARG));
        auto affected = is_constructed() ? owner->affected(c_node(), false)
                                         : std::vector<std::shared_ptr<detail::node_token>>{};
        tlv_result_t rc = tlv_node_set_value(
            c_node(), reinterpret_cast<const uint8_t*>(value.data()), value.size());
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        owner->invalidate(affected);
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
        auto affected = owner->affected(c_node(), true);
        auto pointer = c_node();
        owner->invalidate(affected);
        tlv_node_erase(pointer);
    }

    /** @brief Computes the encoded size of the element with its descendants; see
     * tlv_node_encoded_size(). */
    TLV_NODISCARD expected<size_t, error> encoded_size() const {
        if (!c_node()) return unexpected<error>(error::from_c(TLV_ERR_INVALID_ARG));
        size_t       size = 0;
        tlv_result_t rc = tlv_node_encoded_size(c_node(), &size);
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
            tlv_node_encode(c_node(), reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        out.resize(written);
        return out;
    }

    /**
     * @brief Measure this node with an explicit destination Format.
     * @param format Borrowed writable Format; must preserve constructed classification.
     * @return Exact size or the error from tlv_node_encoded_size_as().
     * @note Stages encoded children using the Document allocator; never changes the tree.
     */
    TLV_NODISCARD expected<size_t, error> encoded_size(const tlv_format_t& format) const {
        if (!c_node()) return unexpected<error>(error::from_c(TLV_ERR_INVALID_ARG));
        size_t     size = 0;
        const auto rc = tlv_node_encoded_size_as(c_node(), &format, &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return size;
    }

    /** @brief Measure this subtree using a C++ Format view.
     * @copydetails encoded_size(const tlv_format_t&) const
     */
    TLV_NODISCARD expected<size_t, error> encoded_size(tlv::format format) const {
        return encoded_size(detail::format_access::get(format));
    }

    /**
     * @brief Encode this node with an explicit destination Format.
     * @param format Borrowed writable Format as for encoded_size(format).
     * @return Owned bytes or the error from tlv_node_encode_as().
     * @note Identifiers are not remapped and the tree's original Format is unchanged.
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode(const tlv_format_t& format) const {
        auto size = encoded_size(format);
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        const auto        rc = tlv_node_encode_as(
            c_node(), &format, reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        out.resize(written);
        return out;
    }

    /** @brief Encode this subtree using a C++ Format view.
     * @copydetails encode(const tlv_format_t&) const
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode(tlv::format format) const {
        return encode(detail::format_access::get(format));
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
        : owner_(owner), token_(owner->track(pointer)) {}

    node related(tlv_node_t* pointer) const {
        auto owner = owner_.lock();
        return owner ? node(pointer, owner) : node();
    }

    std::weak_ptr<detail::document_lifetime> owner_;
    std::shared_ptr<detail::node_token>      token_;
    friend class document;
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

/**
 * @brief Format and runtime resource limits of a #tlv::document.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
struct document_format {
    /**
     * Format used for parsing and encoding; its contents are copied, its context is borrowed.
     * `format.is_constructed` selects nested values, or `nullptr` for opaque values.
     */
    tlv_format_t format;
    /** Runtime maximum nesting depth (default TLV_TREE_DEFAULT_DEPTH). */
    size_t max_depth;
    /** Maximum number of elements, including nested ones. */
    size_t max_elements;

    /**
     * @brief Bundles the format with the default limits.
     *
     * @param fmt Format.
     */
    document_format(const tlv_format_t& fmt)
        : format(fmt), max_depth(TLV_TREE_DEFAULT_DEPTH),
          max_elements(TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS) {}

    /**
     * @brief Copy a C++ Format's descriptor and apply default Document limits.
     * @param fmt Borrowed Format view; the descriptor is copied and context remains borrowed.
     * @note No allocation occurs. Context must outlive every Document created with these options.
     */
    document_format(tlv::format fmt) : document_format(detail::format_access::get(fmt)) {}
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
        return node(tlv_document_first(c_document()), impl_->lifetime);
    }

    /** @brief The top-level elements, in encoding order. */
    node_range children() const {
        return node_range(first());
    }

    /** @brief Begin iteration over top-level elements in encoding order.
     * @note Insertion preserves iterators. Erasing the current node or replacing
     * an ancestor's constructed Value invalidates its iterator, which then
     * compares equal to end().
     */
    node_iterator begin() const {
        return children().begin();
    }

    /** @brief End of top-level iteration. */
    node_iterator end() const {
        return node_iterator();
    }

    /**
     * @brief Finds the first top-level element with a tag.
     *
     * @param wanted Tag to look for; compared by contents.
     *
     * @return The element, or an empty handle.
     */
    node find(tlv::tag wanted) const {
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
    node find(const query& path) const {
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
    std::vector<node> select(const query& path) const {
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
        if (rc != TLV_OK) throw query_error(rc, 0);
        return std::move(state.results);
    }

    /** @brief Compile a text path and select all matching Nodes.
     * @param text NUL-terminated Query text; not retained.
     * @return Snapshot with the lifetime and mutation rules of select(const query&).
     * @throws query_error On compilation failure, retaining the original text offset.
     * @throws std::bad_alloc On C++ result or handle allocation failure.
     */
    std::vector<node> select(const char* text) const {
        return select(query::compile(text));
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
        if ((parent.token_ && !parent) || (before.token_ && !before))
            return unexpected<error>(error::from_c(TLV_ERR_INVALID_ARG));
        tlv_node_t*  created = nullptr;
        tlv_result_t rc = tlv_document_insert(impl_->handle.get(), parent.c_node(), before.c_node(),
                                              detail::semantic_access::get(wanted),
                                              reinterpret_cast<const uint8_t*>(value.data()),
                                              value.size(), &created);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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

    /**
     * @brief Measure this document with an explicit destination Format.
     * @param format Borrowed writable Format; must preserve constructed classification.
     * @return Exact size or the error from tlv_document_encoded_size_as().
     * @note Stages encoded children using the Document allocator; never changes the tree.
     */
    TLV_NODISCARD expected<size_t, error> encoded_size(const tlv_format_t& format) const {
        size_t     size = 0;
        const auto rc = tlv_document_encoded_size_as(impl_->handle.get(), &format, &size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return size;
    }

    /** @brief Measure this Document using a C++ Format view.
     * @copydetails encoded_size(const tlv_format_t&) const
     */
    TLV_NODISCARD expected<size_t, error> encoded_size(tlv::format format) const {
        return encoded_size(detail::format_access::get(format));
    }

    /**
     * @brief Encode this document with an explicit destination Format.
     * @param format Borrowed writable Format as for encoded_size(format).
     * @return Owned bytes or the error from tlv_document_encode_as().
     * @note Identifiers are not remapped and the tree's original Format is unchanged.
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode(const tlv_format_t& format) const {
        auto size = encoded_size(format);
        if (!size.has_value()) return unexpected<error>(size.error());
        std::vector<byte> out(*size);
        size_t            written = 0;
        const auto        rc =
            tlv_document_encode_as(impl_->handle.get(), &format,
                                   reinterpret_cast<uint8_t*>(out.data()), out.size(), &written);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        out.resize(written);
        return out;
    }

    /** @brief Encode this Document using a C++ Format view.
     * @copydetails encode(const tlv_format_t&) const
     */
    TLV_NODISCARD expected<std::vector<byte>, error> encode(tlv::format format) const {
        return encode(detail::format_access::get(format));
    }

    /** @brief Borrow the underlying C document for interoperability.
     * @warning Native mutations bypass C++ validity tracking; use C++ operations
     * for edits and never free this handle. Raw handles must not outlive this owner.
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
        tlv_format_t                               format;
        std::unique_ptr<tlv_document_t, deleter>   handle;
        std::shared_ptr<detail::document_lifetime> lifetime =
            std::make_shared<detail::document_lifetime>();
    };

    explicit document(std::unique_ptr<state> impl) : impl_(std::move(impl)) {
        impl_->lifetime->document = impl_->handle.get();
    }

    static expected<document, error> make(const bytes* data, const document_format& format,
                                          size_t* error_offset) {
        std::unique_ptr<state> impl(new state());
        impl->format = format.format;

        tlv_document_options_t options;
        tlv_result_t           rc = tlv_document_options_init(&options, &impl->format);
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
    friend class document_builder;
};

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
     * @return Builder or the original C error; does not advance the reader.
     */
    TLV_NODISCARD static expected<document_builder, error>
    create(tree_reader& reader, size_t max_depth = TLV_TREE_DEFAULT_DEPTH,
           size_t max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS) {
        return create_impl(reader, nullptr, max_depth, max_elements);
    }

    /**
     * @brief Materialize the last item published by an explicit reader.next().
     * @param reader Borrowed Tree Reader with a current subtree selection.
     * @param max_depth Maximum materialized depth relative to the selected root.
     * @param max_elements Maximum materialized node count.
     * @return Builder, INVALID_ARG if selection was invalidated, or original C error.
     * @note Root content is copied immediately without another pull. This attempt
     * consumes selection, even on failure. Pulls, skips, input replacement,
     * validation, visitors and builder creation invalidate selection.
     */
    TLV_NODISCARD static expected<document_builder, error>
    current_subtree(tree_reader& reader, size_t max_depth = TLV_TREE_DEFAULT_DEPTH,
                    size_t max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS) {
        if (!reader.has_current_) return unexpected<error>(error::from_c(TLV_ERR_INVALID_ARG));
        const tlv_tree_item_t root = reader.current_;
        return create_impl(reader, &root, max_depth, max_elements);
    }

    /**
     * @brief Consume available items and return the owning document when complete.
     * @param error_offset Optional absolute source failure offset.
     * @param diagnostic Optional borrowed Reader failure detail.
     * @return Document, NEED_MORE_DATA with continuation retained, or terminal error.
     * @note Selected subtrees leave the following sibling unread. Completion and
     * terminal errors end consumption; destroying this builder discards unfinished work.
     */
    TLV_NODISCARD expected<document, error> consume(size_t*            error_offset = nullptr,
                                                    reader_diagnostic* diagnostic = nullptr) {
        std::unique_ptr<document::state> state(new document::state());
        tlv_document_t*                  raw = nullptr;
        auto rc = tlv_document_builder_consume(handle_.get(), &raw, error_offset, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        state->handle.reset(raw);
        return document(std::move(state));
    }

private:
    static expected<document_builder, error> create_impl(tree_reader&           reader,
                                                         const tlv_tree_item_t* root,
                                                         size_t max_depth, size_t max_elements) {
        reader.has_current_ = false;
        if (reader.init_result_ != TLV_OK)
            return unexpected<error>(error::from_c(reader.init_result_));
        tlv_document_options_t options{};
        auto                   rc = tlv_document_options_init(&options, reader.impl_.input.format);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        options.max_depth = max_depth;
        options.max_elements = max_elements;
        tlv_document_builder_t* raw = nullptr;
        rc = tlv_document_builder_create(&options, &reader.impl_, root, &raw);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return document_builder(raw);
    }

    struct deleter {
        void operator()(tlv_document_builder_t* handle) const {
            tlv_document_builder_free(handle);
        }
    };
    explicit document_builder(tlv_document_builder_t* handle) : handle_(handle) {}
    std::unique_ptr<tlv_document_builder_t, deleter> handle_;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_DOCUMENT_HPP
