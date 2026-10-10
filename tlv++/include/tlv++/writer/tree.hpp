// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_TREE_WRITER_HPP
#define OPENTLV_TLVPP_TREE_WRITER_HPP

#include "tlv/writer/tree.h"
#include "tlv/defaults.h"
#include "tlv++/writer/writer.hpp"
#include "tlv++/tree.hpp"
#include <type_traits>

namespace tlv {
/** @file
 * @brief C++ bounded Tree Writer over caller-owned output, frames and workspace.
 */

/** @brief Caller-owned Tree Writer frame; retains a borrowed Tag until end(). */
using tree_writer_frame = tlv_tree_writer_frame_t;

/** @brief Borrowed bounded staging storage and required-capacity results for tree measurement. */
using tree_writer_workspace = tlv_tree_writer_workspace_t;

/**
 * @brief Measure and stage semantic preorder records using the canonical C engine.
 * @param format Borrowed writable Format and context.
 * @param next Callable taking element_view&, size_t& depth and bool& constructed, returning
 * expected<bool, error>: true publishes an item, false ends input, error aborts.
 * @param workspace Disjoint caller-owned frames, output and scratch. On success its
 * data contains the exact encoding; required_data/required_scratch report storage
 * exhaustion lower bounds. Bytes may change on failure.
 * @param max_depth Maximum item depth, roots at zero.
 * @param max_elements Maximum source records.
 * @param diagnostic Optional borrowed failure detail, unchanged on success.
 * @return Exact encoded size or the original source/Writer error.
 * @warning Source is consumed on failure; retries require a fresh source. Tags must
 * remain alive until return and while inspecting diagnostics; primitive Values must
 * remain readable until the next callback. The callable must not throw exceptions.
 */
template <typename Source>
TLV_NODISCARD expected<size_t, error>
measure_tree(tlv::format format, Source&& next, tree_writer_workspace& workspace,
             size_t max_depth = TLV_TREE_DEFAULT_DEPTH, size_t max_elements = SIZE_MAX,
             writer_diagnostic* diagnostic = nullptr) {
    writer_diagnostic local{};
    if (!diagnostic) diagnostic = &local;
    using callable = typename std::remove_reference<Source>::type;
    struct state {
        callable* function;
    } context{&next};
    auto callback = [](void* context, tlv_element_t* value, size_t* depth,
                       int* constructed) -> tlv_result_t {
        bool         parent = false;
        element_view view;
        auto         item = (*static_cast<state*>(context)->function)(view, *depth, parent);
        if (!item) return static_cast<tlv_result_t>(item.error().status());
        *value = detail::semantic_access::get(view);
        *constructed = parent ? 1 : 0;
        return *item ? TLV_OK : TLV_END;
    };
    size_t size = 0;
    auto   code = tlv_tree_writer_measure(&detail::format_access::get(format), callback, &context,
                                          &workspace, max_depth, max_elements, &size, diagnostic);
    if (code != TLV_OK) return unexpected<error>(detail::writer_failed(code, *diagnostic));
    return size;
}

/**
 * @brief Measure and stage a balanced canonical event stream through C.
 * @param format Borrowed destination Format.
 * @param next Callable taking tree_event& and returning expected<bool, error>.
 * True supplies one event; false is final EOF. The callable must not throw.
 * @param workspace Caller-owned bounded staging storage.
 * @param max_depth Maximum node depth.
 * @param max_elements Maximum BEGIN/ELEMENT count.
 * @param diagnostic Optional failure detail.
 * @return Exact staged size or source/Writer error. Retry with a fresh producer.
 * @warning BEGIN Tags must remain alive until this operation returns.
 */
template <typename Source>
TLV_NODISCARD expected<size_t, error>
measure_tree_events(tlv::format format, Source&& next, tree_writer_workspace& workspace,
                    size_t max_depth = TLV_TREE_DEFAULT_DEPTH, size_t max_elements = SIZE_MAX,
                    writer_diagnostic* diagnostic = nullptr) {
    writer_diagnostic local{};
    if (!diagnostic) diagnostic = &local;
    using callable = typename std::remove_reference<Source>::type;
    auto callback = [](void* context, tlv_tree_event_t* event) -> tlv_result_t {
        tree_event view{};
        auto       item = (*static_cast<callable*>(context))(view);
        if (!item) return static_cast<tlv_result_t>(item.error().status());
        *event = detail::tree_access::get(view);
        return *item ? TLV_OK : TLV_END;
    };
    size_t size = 0;
    auto   rc =
        tlv_tree_writer_measure_events(&detail::format_access::get(format), callback, &next,
                                       &workspace, max_depth, max_elements, &size, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
    return size;
}

/**
 * @brief Iterative bounded writer with the storage and failure contracts of #tlv_tree_writer_t.
 *
 * Operations and returned structured errors do not allocate.
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
    tree_writer(byte* data, size_t capacity, tlv::format format, tree_writer_frame* frames,
                size_t frame_capacity, byte* scratch, size_t scratch_capacity,
                size_t max_depth = TLV_TREE_DEFAULT_DEPTH, size_t max_elements = SIZE_MAX)
        : init_result_(tlv_tree_writer_init(&impl_, reinterpret_cast<uint8_t*>(data), capacity,
                                            &detail::format_access::get(format), frames,
                                            frame_capacity, reinterpret_cast<uint8_t*>(scratch),
                                            scratch_capacity, max_depth, max_elements)) {}

    /**
     * @brief Copy open Tags into disjoint caller-owned storage until matching END.
     * @param storage Storage that outlives this writer; empty NULL storage restores borrowing.
     * @return C configuration result; cannot change storage with open parents.
     */
    TLV_NODISCARD expected<void, error> set_tag_storage(span<byte> storage) {
        return result(init_result_ == TLV_OK
                          ? tlv_tree_writer_set_tag_storage(
                                &impl_, reinterpret_cast<uint8_t*>(storage.data()), storage.size())
                          : init_result_);
    }

    /**
     * @brief Consume a canonical event, checking depth and destination classification.
     * @param event Borrowed event; BEGIN retains Tag unless copying storage is configured.
     * @param diagnostic Optional Writer failure detail.
     * @return C result; retry the same event on recoverable failure.
     */
    TLV_NODISCARD expected<void, error> write_event(const tree_event&  event,
                                                    writer_diagnostic* diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        const auto raw = detail::tree_access::get(event);
        return result(init_result_ == TLV_OK
                          ? tlv_tree_writer_write_event_diag(&impl_, &raw, diagnostic)
                          : init_result_,
                      diagnostic);
    }

    /**
     * @brief Open a constructed parent; Tag bytes remain borrowed until end().
     * @param tag Immutable identifier disjoint from all writable storage.
     * @param diagnostic Optional failure detail, unchanged on success.
     * @return C begin result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> begin(tlv::tag           tag,
                                              writer_diagnostic* diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        return result(
            init_result_ == TLV_OK
                ? tlv_tree_writer_begin_diag(&impl_, detail::semantic_access::get(tag), diagnostic)
                : init_result_,
            diagnostic);
    }

    /**
     * @brief Append a primitive or complete subtree without retaining its Element.
     * @param value Readable semantic content, disjoint from output storage.
     * @param diagnostic Optional detail with current absolute output offsets.
     * @return C write result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> write(const element_view& value,
                                              writer_diagnostic*  diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        const auto raw = detail::semantic_access::get(value);
        return result(init_result_ == TLV_OK
                          ? tlv_tree_writer_write_element_diag(&impl_, &raw, diagnostic)
                          : init_result_,
                      diagnostic);
    }

    /**
     * @brief Close the innermost parent; failures preserve accumulated output and cursor.
     * @param diagnostic Optional structured failure detail, unchanged on success.
     * @return C end result or the retained initialization error.
     */
    TLV_NODISCARD expected<void, error> end(writer_diagnostic* diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        return result(init_result_ == TLV_OK ? tlv_tree_writer_end_diag(&impl_, diagnostic)
                                             : init_result_,
                      diagnostic);
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
    static expected<void, error> result(tlv_result_t             rc,
                                        const writer_diagnostic* diagnostic = nullptr) {
        if (rc != TLV_OK && diagnostic)
            return unexpected<error>(detail::writer_failed(rc, *diagnostic));
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::writer));
        return {};
    }
    tlv_tree_writer_t impl_{};
    tlv_result_t      init_result_;
};

} // namespace tlv
#endif
