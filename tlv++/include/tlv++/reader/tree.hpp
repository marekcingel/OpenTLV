#ifndef OPENTLV_TLVPP_TREE_READER_HPP
#define OPENTLV_TLVPP_TREE_READER_HPP

#include "tlv++/reader/reader.hpp"

/** @file tree.hpp
 * @brief Borrowed C++ preorder cursor backed by the canonical C Tree Reader.
 */
namespace tlv {

/** @brief Caller-owned structural continuation storage. */
using tree_frame = tlv_tree_frame_t;
/** @brief Complete borrowed element, source, depth, absolute offset and classification. */
using tree_item = tlv_tree_item_t;
/** @brief Canonical borrowed BEGIN, ELEMENT or END event. */
using tree_event = tlv_tree_event_t;

/**
 * @brief Bounded preorder traversal with incremental input and subtree control.
 * @warning Input, Format and context must outlive returned views. Frames must
 * remain writable and alive throughout traversal and must not overlap input.
 * Successful pull operations allocate nothing; error messages may allocate.
 * Only the last successful explicit next() selects a subtree for Document building.
 * Every pull, skip, input replacement, validation, visitor or builder creation
 * attempt invalidates the previous selection, including failed attempts.
 */
class tree_reader {
public:
    /**
     * @brief Initialize bounded traversal using a C++ Format view.
     * @copydetails tree_reader(bytes, const tlv_format_t&, span<tree_frame>, size_t, size_t,
     * input_mode)
     * @note The view may be temporary; its descriptor and context remain borrowed.
     */
    tree_reader(bytes data, tlv::format format, span<tree_frame> frames, size_t max_depth,
                size_t max_elements, input_mode mode = input_mode::final)
        : tree_reader(data, detail::format_access::get(format), frames, max_depth, max_elements,
                      mode) {}

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
    tree_reader(bytes data, const tlv_format_t& format, span<tree_frame> frames, size_t max_depth,
                size_t max_elements, input_mode mode = input_mode::final) {
        auto init =
            mode == input_mode::final ? tlv_tree_reader_init : tlv_tree_reader_init_incremental;
        init_result_ = init(&impl_, reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                            &format, frames.data(), frames.size(), max_depth, max_elements);
    }

    /** @brief Copying a cursor would share mutable frame storage and is prohibited. */
    tree_reader(const tree_reader&) = delete;
    /** @brief Assigning a cursor would share mutable frame storage and is prohibited. */
    tree_reader& operator=(const tree_reader&) = delete;

    /**
     * @brief Publish the next complete borrowed preorder item.
     * @param[out] diagnostic Optional Reader failure detail; unchanged on success
     * or tree resource errors.
     * @return Item, NEED_MORE_DATA, END_OF_BUFFER, or the original C error.
     * @note Hides pending END events before reading a node. Apart from those
     * closures, non-success preserves traversal state. A parent requires its
     * entire encoded extent; use next_event() for explicit structural events.
     */
    TLV_NODISCARD expected<tree_item, error> next(reader_diagnostic* diagnostic = nullptr) {
        has_current_ = false;
        tree_item result{};
        auto rc = init_result_ == TLV_OK ? tlv_tree_reader_next_diag(&impl_, &result, diagnostic)
                                         : init_result_;
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        current_ = result;
        has_current_ = true;
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
        tree_event event{};
        auto       rc = init_result_ == TLV_OK
                            ? tlv_tree_reader_next_event_diag(&impl_, &event, diagnostic)
                            : init_result_;
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return event;
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
    /** @brief True at final exhaustion or when initialization failed. */
    TLV_NODISCARD bool at_end() const {
        return init_result_ != TLV_OK || tlv_tree_reader_at_end(&impl_) != 0;
    }

    /**
     * @brief Validate remaining traversal without a callback using the C Visitor engine.
     * @param[out] error_offset Optional absolute failure offset; unchanged on success.
     * @param[out] diagnostic Optional Reader detail, cleared at entry for a valid cursor.
     * @return Success at EOF; NEED_MORE_DATA or the original C error otherwise.
     * @note This checks framing and traversal limits, not Schema or value semantics.
     */
    TLV_NODISCARD expected<void, error> validate(size_t*            error_offset = nullptr,
                                                 reader_diagnostic* diagnostic = nullptr) {
        has_current_ = false;
        return result(init_result_ == TLV_OK ? tlv_tree_reader_visit_diag(&impl_, nullptr, nullptr,
                                                                          error_offset, diagnostic)
                                             : init_result_);
    }

    /**
     * @brief Visit remaining items using the canonical C Visitor engine.
     * @param visitor Callable taking Element, depth and absolute offset, returning
     * tlv_visit_result_t.
     * @param[out] error_offset Optional absolute failure offset; unchanged on success.
     * @param[out] diagnostic Optional Reader detail, cleared at entry for a valid cursor.
     * @return Success at EOF or STOP; NEED_MORE_DATA or original C error otherwise.
     * @warning Do not mutate cursor, frames, input or Format in callbacks. Effects
     * are not rolled back. STOP leaves the current item published for resume or skip.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error> visit(Visitor&& visitor, size_t* error_offset = nullptr,
                                              reader_diagnostic* diagnostic = nullptr) {
        has_current_ = false;
        if (init_result_ != TLV_OK) return result(init_result_);
        detail::tree_visitor<Visitor> context{&visitor};
        return result(tlv_tree_reader_visit_diag(&impl_, &detail::tree_visitor<Visitor>::call,
                                                 &context, error_offset, diagnostic));
    }

private:
    friend class document_builder;
    friend class query_matcher;
    static expected<void, error> result(tlv_result_t rc) {
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }
    tree_item         current_{};
    bool              has_current_ = false;
    tlv_tree_reader_t impl_{};
    tlv_result_t      init_result_ = TLV_ERR_INVALID_ARG;
};
} // namespace tlv
#endif
