#ifndef OPENTLV_TLVPP_TREE_WRITER_HPP
#define OPENTLV_TLVPP_TREE_WRITER_HPP

#include "tlv/writer/tree.h"
#include "tlv/defaults.h"
#include "tlv++/writer/writer.hpp"

namespace tlv {
/** @file
 * @brief C++ bounded Tree Writer over caller-owned output, frames and workspace.
 */

/** @brief Caller-owned Tree Writer frame; retains a borrowed Tag until end(). */
using tree_writer_frame = tlv_tree_writer_frame_t;

/**
 * @brief Iterative bounded writer with the storage and failure contracts of #tlv_tree_writer_t.
 *
 * Success paths do not allocate. Error conversion may allocate a message string.
 * Output, frames, scratch and immutable Format/context must outlive this cursor.
 * Only size() bytes form a final prefix; open subtrees occupy provisional storage.
 */
class tree_writer {
public:
    /**
     * @brief Initialize borrowed output and structural storage.
     * @param data Output buffer; NULL only when capacity is zero.
     * @param capacity Output capacity in bytes.
     * @param format Borrowed writable Format.
     * @param frames Caller-owned stack; NULL only for zero frame_capacity.
     * @param frame_capacity Number of frames, one per open parent.
     * @param scratch Disjoint workspace; NULL only for zero scratch_capacity.
     * @param scratch_capacity Workspace size in bytes; must fit the largest closed Value.
     * @param max_depth Largest item depth, with roots at zero.
     * @param max_elements Maximum begin/write operations.
     * @note Initialization errors are retained and returned by subsequent operations.
     */
    tree_writer(byte* data, size_t capacity, const tlv_format_t& format, tree_writer_frame* frames,
                size_t frame_capacity, byte* scratch, size_t scratch_capacity,
                size_t max_depth = TLV_TREE_DEFAULT_DEPTH, size_t max_elements = SIZE_MAX)
        : init_result_(tlv_tree_writer_init(
              &impl_, reinterpret_cast<uint8_t*>(data), capacity, &format, frames, frame_capacity,
              reinterpret_cast<uint8_t*>(scratch), scratch_capacity, max_depth, max_elements)) {}

    /**
     * @brief Open a constructed parent; Tag bytes remain borrowed until end().
     * @param tag Immutable identifier disjoint from all writable storage.
     * @param diagnostic Optional failure detail, unchanged on success.
     * @return C begin result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> begin(tag_t tag, writer_diagnostic* diagnostic = nullptr) {
        return result(init_result_ == TLV_OK ? tlv_tree_writer_begin_diag(&impl_, tag, diagnostic)
                                             : init_result_);
    }

    /**
     * @brief Append a primitive or complete subtree without retaining its Element.
     * @param value Readable semantic content, disjoint from output storage.
     * @param diagnostic Optional detail with current absolute output offsets.
     * @return C write result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> write(const element&     value,
                                              writer_diagnostic* diagnostic = nullptr) {
        return result(init_result_ == TLV_OK
                          ? tlv_tree_writer_write_element_diag(&impl_, &value, diagnostic)
                          : init_result_);
    }

    /**
     * @brief Close the innermost parent; failures preserve accumulated output and cursor.
     * @param diagnostic Optional structured failure detail, unchanged on success.
     * @return C end result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> end(writer_diagnostic* diagnostic = nullptr) {
        return result(init_result_ == TLV_OK ? tlv_tree_writer_end_diag(&impl_, diagnostic)
                                             : init_result_);
    }

    /**
     * @brief Check that all parents have been explicitly closed; does not seal output.
     * @return C finish result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> finish() const {
        return result(init_result_ == TLV_OK ? tlv_tree_writer_finish(&impl_) : init_result_);
    }

    /** @brief Return the final output prefix size, excluding open roots; zero on init failure. */
    size_t size() const {
        return tlv_tree_writer_size(&impl_);
    }

private:
    static expected<void, error> result(tlv_result_t rc) {
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }
    tlv_tree_writer_t impl_{};
    tlv_result_t      init_result_;
};
} // namespace tlv
#endif
