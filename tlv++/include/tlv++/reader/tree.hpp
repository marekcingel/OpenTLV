// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_TREE_READER_HPP
#define OPENTLV_TLVPP_TREE_READER_HPP

#include "tlv++/reader/reader.hpp"
#include "tlv++/tree.hpp"

/** @file tree.hpp
 * @brief Borrowed C++ preorder cursor backed by the canonical C Tree Reader.
 */
namespace tlv {
class query;
class query_range;

/** @brief Caller-owned structural continuation storage. */
using tree_frame = tlv_tree_frame_t;
/**
 * @brief Bounded preorder traversal with incremental input and subtree control.
 * @warning Input, Format and context must outlive returned views. Frames must
 * remain writable and alive throughout traversal and must not overlap input.
 * Pull operations and returned structured errors do not allocate.
 * Only the last successful explicit next() selects a subtree for Document building.
 * Every pull, skip, input replacement, validation, visitor or builder creation
 * attempt invalidates the previous selection, including failed attempts.
 */
class tree_reader {
public:
    /** @brief Select path matches from the current tree boundary.
     * @param pattern Compiled Query copied into the selection.
     * @return Lazy borrowed single-pass selection; include query/query.hpp to use it.
     * @warning Do not interleave cursor operations except input replacement after
     * NEED_MORE_DATA. Reader, frames, input and Format retain their normal lifetimes.
     */
    query_range select(const query& pattern);
    /** @brief Compile a text path and select its matches.
     * @param text NUL-terminated path, not retained.
     * @return Lazy selection with the lifetime rules of select(const query&).
     * @throws query_error On invalid Query text, retaining its text offset.
     */
    query_range select(const char* text);

    /**
     * @brief Initialize traversal over borrowed input and frame storage.
     * @param data Immutable input window.
     * @param format Borrowed readable Format and context.
     * @param frames Writable structural storage, one frame per entered nonempty parent.
     * @param max_depth Largest allowed item depth; zero permits roots only.
     * @param max_elements Publication limit; skipped descendants do not count.
     * @param mode Whether the input is final or resumable.
     * @note Initialization errors are reported by subsequent operations.
     */
    tree_reader(bytes data, tlv::format format, span<tree_frame> frames, size_t max_depth,
                size_t max_elements, input_mode mode = input_mode::final) {
        auto init =
            mode == input_mode::final ? tlv_tree_reader_init : tlv_tree_reader_init_incremental;
        init_result_ = init(&impl_, reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                            &detail::format_access::get(format), frames.data(), frames.size(),
                            max_depth, max_elements);
    }

    /** @brief Copying a cursor would share mutable frame storage and is prohibited. */
    tree_reader(const tree_reader&) = delete;
    /** @brief Assigning a cursor would share mutable frame storage and is prohibited. */
    tree_reader& operator=(const tree_reader&) = delete;

    /**
     * @brief Publish the next complete borrowed preorder item.
     * @param[out] diagnostic Optional Reader failure detail; unchanged on success
     * or tree resource errors.
     * @return Item, NEED_MORE_DATA, TLV_END, or the original C error.
     * @note Hides pending END events before reading a node. Apart from those
     * closures, non-success preserves traversal state. A parent requires its
     * entire encoded extent; use next_event() for explicit structural events.
     */
    TLV_NODISCARD expected<tree_item, error> next(reader_diagnostic* diagnostic = nullptr) {
        tree_item         result{};
        reader_diagnostic local{};
        auto*             report = diagnostic ? diagnostic : &local;
        auto              rc = next_item(result, report);
        if (rc != TLV_OK) return unexpected<error>(detail::reader_failed(rc, *report, offset()));
        return result;
    }

    /**
     * @brief Pull a canonical structural event from the C engine.
     * @param diagnostic Optional original Reader failure detail.
     * @return Event or the original Reader error; borrowed payload follows input lifetime.
     * @note Do not mix with node-only pulls when consuming a balanced stream.
     */
    TLV_NODISCARD expected<tree_event, error> next_event(reader_diagnostic* diagnostic = nullptr) {
        has_current_ = false;
        tlv_tree_event_t  event{};
        reader_diagnostic local{};
        auto*             report = diagnostic ? diagnostic : &local;
        auto rc = init_result_ == TLV_OK ? tlv_tree_reader_next_event_diag(&impl_, &event, report)
                                         : init_result_;
        if (rc != TLV_OK) return unexpected<error>(detail::reader_failed(rc, *report, offset()));
        return detail::tree_access::borrow(event);
    }

    /**
     * @brief Skip the pending nonempty subtree without decoding descendants.
     * @return Success, INVALID_ARG if no subtree is pending, or initialization error.
     * @note May recover from a descent limit failure; skipped children do not count.
     */
    TLV_NODISCARD expected<void, error> skip_subtree() {
        has_current_ = false;
        return result(init_result_ == TLV_OK ? tlv_tree_reader_skip_subtree(&impl_) : init_result_);
    }

    /**
     * @brief Replace the borrowed input window without resetting traversal.
     * @param data Replacement retaining undiscarded bytes unchanged.
     * @param discard Consumed prefix bytes, at most consumed().
     * @param mode Whether this window declares final EOF.
     * @return Success or original C error; failure preserves state.
     * @warning Release views before moving or overwriting their backing storage.
     */
    TLV_NODISCARD expected<void, error> set_input(bytes data, size_t discard, input_mode mode) {
        has_current_ = false;
        return result(
            init_result_ == TLV_OK
                ? tlv_tree_reader_set_input(&impl_, reinterpret_cast<const uint8_t*>(data.data()),
                                            data.size(), discard, mode == input_mode::final)
                : init_result_);
    }

    /** @brief Prefix bytes discardable by the cursor; retained views may still borrow them. */
    TLV_NODISCARD size_t consumed() const {
        return tlv_tree_reader_consumed(&impl_);
    }
    /** @brief Absolute traversal frontier in bytes. */
    TLV_NODISCARD size_t offset() const {
        return tlv_tree_reader_offset(&impl_);
    }
    /**
     * @brief True only at a successfully initialized final input boundary.
     * @return False after initialization failure or while waiting for more input;
     * next() reports the corresponding error or resumable pause.
     */
    TLV_NODISCARD bool at_end() const {
        return init_result_ == TLV_OK && tlv_tree_reader_at_end(&impl_) != 0;
    }

    /**
     * @brief Validate remaining traversal without a callback using the C Visitor engine.
     * @param[out] diagnostic Optional Reader detail, cleared at entry for a valid cursor.
     * @return Success at EOF; NEED_MORE_DATA or the original C error otherwise.
     * @note This checks framing and traversal limits, not Schema or value semantics.
     */
    TLV_NODISCARD expected<void, error> validate(reader_diagnostic* diagnostic = nullptr) {
        has_current_ = false;
        reader_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        const auto rc = init_result_ == TLV_OK
                            ? tlv_tree_reader_visit(&impl_, nullptr, nullptr, diagnostic)
                            : init_result_;
        if (rc != TLV_OK)
            return unexpected<error>(detail::reader_failed(rc, *diagnostic, offset()));
        return {};
    }

    /**
     * @brief Visit remaining items using the canonical C Visitor engine.
     * @param visitor Callable taking Element, depth and absolute offset, returning
     * visit_control.
     * @param[out] diagnostic Optional Reader detail, cleared at entry for a valid cursor.
     * @return Success at EOF or STOP; NEED_MORE_DATA or original C error otherwise.
     * @warning Do not mutate cursor, frames, input or Format in callbacks. Effects
     * are not rolled back. STOP leaves the current item published for resume or skip.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error> visit(Visitor&&          visitor,
                                              reader_diagnostic* diagnostic = nullptr) {
        has_current_ = false;
        if (init_result_ != TLV_OK) return result(init_result_);
        detail::tree_visitor<Visitor> context{&visitor};
        reader_diagnostic             local{};
        if (!diagnostic) diagnostic = &local;
        const auto rc = tlv_tree_reader_visit(&impl_, &detail::tree_visitor<Visitor>::call,
                                              &context, diagnostic);
        if (rc != TLV_OK)
            return unexpected<error>(detail::reader_failed(rc, *diagnostic, offset()));
        return {};
    }

private:
    friend class query_range;
    tlv_result_t next_item(tree_item& item, reader_diagnostic* diagnostic) {
        has_current_ = false;
        tlv_tree_item_t result{};
        auto rc = init_result_ == TLV_OK ? tlv_tree_reader_next_diag(&impl_, &result, diagnostic)
                                         : init_result_;
        if (rc != TLV_OK) return rc;
        current_ = result;
        has_current_ = true;
        item = tree_item{detail::semantic_access::borrow(result.element), result.source,
                         result.depth, result.offset, result.constructed != 0};
        return TLV_OK;
    }
    friend class document_builder;
    friend class query_matcher;
    friend class query_execution;
    static expected<void, error> result(tlv_result_t rc) {
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::reader));
        return {};
    }
    tlv_tree_item_t   current_{};
    bool              has_current_ = false;
    tlv_tree_reader_t impl_{};
    tlv_result_t      init_result_ = TLV_ERR_INVALID_ARG;
};
} // namespace tlv
#endif
