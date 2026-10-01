#ifndef OPENTLV_TLVPP_WRITER_BUILDER_HPP
#define OPENTLV_TLVPP_WRITER_BUILDER_HPP

#include "tlv++/writer/writer.hpp"
#include "tlv/writer/tree.h"
#include <array>

/** @file
 * @brief Allocation-free typed construction through the canonical C Tree Writer.
 */
namespace tlv {

/** @brief Writer failure without an allocating message string. */
struct writer_failure {
    /** @brief Original canonical Writer result. */
    tlv_result_t code;
    /** @brief Borrow a static description; no allocation or ownership transfer. */
    const char* message() const noexcept {
        return tlv_strerror(code);
    }
};

/** @brief Borrowed, disjoint construction storage and explicit traversal limits.
 * @warning Frames, scratch, output and input must remain disjoint and alive during use.
 */
struct writer_workspace {
    /** @brief One frame for each simultaneously open constructed element. */
    span<tlv_tree_writer_frame_t> frames;
    /** @brief Bytes sufficient for the largest constructed Value closed during writing. */
    span<byte> scratch;
    /** @brief Largest item depth, with roots at zero. */
    size_t max_depth;
    /** @brief Maximum successful primitive writes and parent openings. */
    size_t max_elements;

    /** @brief Borrow workspace without allocating or initializing its storage.
     * @param frames Caller-owned structural stack, immutable while active.
     * @param scratch Caller-owned staging bytes, overwritten when a parent closes.
     * @param max_depth Largest permitted item depth, independent of frame capacity.
     * @param max_elements Maximum element count, SIZE_MAX for no practical limit.
     */
    writer_workspace(span<tlv_tree_writer_frame_t> frames, span<byte> scratch,
                     size_t max_depth = TLV_TREE_DEFAULT_DEPTH,
                     size_t max_elements = SIZE_MAX) noexcept
        : frames(frames), scratch(scratch), max_depth(max_depth), max_elements(max_elements) {}
};

/** @brief Fixed-capacity, caller-owned workspace with no dynamic storage.
 * @tparam ScratchCapacity Available staging bytes, including zero for flat output.
 * @tparam Depth Number of simultaneously open parents.
 * @warning This stationary storage must outlive every Writer borrowing it.
 */
template <size_t ScratchCapacity, size_t Depth = TLV_TREE_DEFAULT_DEPTH> class writer_storage {
public:
    /** @brief Reserve fixed storage without initializing unused frames or scratch bytes. */
    writer_storage() = default;
    /** @brief Prohibit copying storage and active construction frames. */
    writer_storage(const writer_storage&) = delete;
    /** @brief Prohibit replacement of storage borrowed by a Writer. */
    writer_storage& operator=(const writer_storage&) = delete;

    /** @brief Borrow this storage for one Writer, with explicit traversal limits.
     * @param max_depth Largest item depth, roots at zero; defaults to Depth.
     * @param max_elements Maximum successful writes and parent openings.
     * @return View valid while this object remains alive and stationary.
     */
    writer_workspace view(size_t max_depth = Depth, size_t max_elements = SIZE_MAX) noexcept {
        return writer_workspace(span<tlv_tree_writer_frame_t>(frames_.data(), Depth),
                                span<byte>(scratch_.data(), ScratchCapacity), max_depth,
                                max_elements);
    }

private:
    std::array<tlv_tree_writer_frame_t, Depth> frames_;
    std::array<byte, ScratchCapacity>          scratch_;
};

/** @brief Sequential typed builder retaining the first error without allocation.
 *
 * Every operation delegates encoding to C. After failure all writes and nested
 * callbacks are skipped; finish() reports the first error. Previously completed
 * roots remain published by size(), while unfinished root bytes are provisional.
 * There is no whole-buffer rollback or implicit close in the destructor.
 *
 * @warning Output, workspace, Format/context and optional diagnostics must outlive
 * this noncopyable cursor. Input is borrowed only during write(); constructed Tags
 * remain borrowed until their callback and closing operation complete. Diagnostics
 * may retain borrowed Tags. Callbacks must not retain the builder reference.
 */
class writer_builder {
public:
    /** @brief Initialize a builder using caller-owned storage and a borrowed Format.
     * @param output Bounded destination; bytes can change on failed encoding.
     * @param format Immutable borrowed Format and context.
     * @param workspace Disjoint bounded construction storage.
     * @param diagnostic Optional C operation failure detail, unchanged on success.
     * Initialization errors are retained; they and fail() do not populate diagnostics.
     */
    writer_builder(span<byte> output, tlv::format format, writer_workspace workspace,
                   writer_diagnostic* diagnostic = nullptr) noexcept
        : code_(tlv_tree_writer_init(
              &impl_, reinterpret_cast<uint8_t*>(output.data()), output.size(),
              &detail::format_access::get(format), workspace.frames.data(), workspace.frames.size(),
              reinterpret_cast<uint8_t*>(workspace.scratch.data()), workspace.scratch.size(),
              workspace.max_depth, workspace.max_elements)),
          diagnostic_(diagnostic) {}

    /** @brief A cursor cannot be copied while sharing active caller-owned frames. */
    writer_builder(const writer_builder&) = delete;
    /** @brief A cursor cannot be assigned while sharing active caller-owned frames. */
    writer_builder& operator=(const writer_builder&) = delete;

    /** @brief Encode one semantic Element; content is borrowed only for this call.
     * @param value Readable content disjoint from output; complete subtrees are accepted.
     */
    void write(const element_view& value) noexcept {
        if (code_ != TLV_OK) return;
        const auto raw = detail::semantic_access::get(value);
        fail(tlv_tree_writer_write_element_diag(&impl_, &raw, diagnostic_));
    }

    /** @brief Borrow a supported byte sequence or text and encode one Element.
     * @param tag Identifier, borrowed for this call.
     * @param value Byte/uint8_t array or contiguous container, Value view, string,
     * or C++17 string_view. Character arrays omit one final NUL and preserve embedded
     * NULs; strings preserve their explicit size. Numeric inputs require an explicit
     * value codec and caller-owned encoded Value storage. No conversion allocates.
     */
    template <typename T>
    auto write(tlv::tag tag, const T& value) noexcept(noexcept(detail::writer_bytes(value)))
        -> decltype(detail::writer_bytes(value), void()) {
        if (code_ != TLV_OK) return;
        const auto          content = detail::writer_bytes(value);
        const tlv_element_t raw = {
            detail::semantic_access::get(tag),
            {reinterpret_cast<const uint8_t*>(content.data()), content.size()}};
        fail(tlv_tree_writer_write_element_diag(&impl_, &raw, diagnostic_));
    }

    /** @brief Write with static identifier bytes and the same Value rules as write(tag, value).
     * @tparam TagBytes Individual identifier bytes in order, without integer normalization.
     * @param value Borrowed supported byte sequence or text.
     */
    template <uint8_t... TagBytes, typename T>
    auto write(const T& value) noexcept(noexcept(detail::writer_bytes(value)))
        -> decltype(detail::writer_bytes(value), void()) {
        write(tlv::tag_bytes<TagBytes...>(), value);
    }

    /** @brief Open a parent, invoke its callback once, then explicitly close it through C.
     * @param tag Format-classified constructed identifier, borrowed through completion.
     * @param callback Callable accepting writer_builder& and returning void.
     * @note Failed begin skips the callback; failed children skip end. The first error
     * is retained. User exceptions propagate, mark this builder failed, and leave
     * the unfinished root unpublished. No exception crosses a C callback boundary.
     */
    template <typename Callback> void constructed(tlv::tag tag, Callback&& callback) {
        if (code_ != TLV_OK) return;
        fail(tlv_tree_writer_begin_diag(&impl_, detail::semantic_access::get(tag), diagnostic_));
        if (code_ != TLV_OK) return;
        invoke(std::forward<Callback>(callback));
        if (code_ == TLV_OK) fail(tlv_tree_writer_end_diag(&impl_, diagnostic_));
    }

    /** @brief Construct a parent with program-lifetime identifier bytes.
     * @tparam TagBytes Individual identifier bytes in order.
     * @param callback Scoped child writes; follows constructed(tag, callback).
     */
    template <uint8_t... TagBytes, typename Callback> void constructed(Callback&& callback) {
        constructed(tlv::tag_bytes<TagBytes...>(), std::forward<Callback>(callback));
    }

    /** @brief Retain an application failure if no earlier failure exists.
     * @param code Canonical error; TLV_OK leaves the builder unchanged.
     */
    void fail(tlv_result_t code) noexcept {
        if (code_ == TLV_OK) code_ = code;
    }
    /** @brief Return the first error, or TLV_OK, without allocating. */
    tlv_result_t status() const noexcept {
        return code_;
    }
    /** @brief Return only the final prefix of fully closed root elements. */
    size_t size() const noexcept {
        return tlv_tree_writer_size(&impl_);
    }

    /** @brief Check balanced construction and return exact output size or first failure.
     * @return Allocation-free result; does not close scopes or seal the builder.
     */
    TLV_NODISCARD expected<size_t, writer_failure> finish() const {
        const auto code = code_ == TLV_OK ? tlv_tree_writer_finish(&impl_) : code_;
        if (code != TLV_OK) return unexpected<writer_failure>(writer_failure{code});
        return size();
    }

    /// @cond INTERNAL
    template <typename Callback> void invoke(Callback&& callback) {
        static_assert(
            std::is_same<decltype(callback(*this)), void>::value,
            "Writer callbacks return void; use builder.fail(code) for application errors");
        if (code_ != TLV_OK) return;
        try {
            callback(*this);
        } catch (...) {
            fail(TLV_ERR_INVALID_ARG);
            throw;
        }
    }
    /// @endcond
private:
    tlv_tree_writer_t  impl_{};
    tlv_result_t       code_;
    writer_diagnostic* diagnostic_;
};

/** @brief Encode a sequence once through the canonical C Tree Writer.
 * @param output Mutable byte span, byte array, or contiguous byte container; borrowed, never
 * resized.
 * @param format Borrowed immutable runtime Format and context.
 * @param workspace Caller-owned disjoint frames and scratch.
 * @param callback Callable accepting writer_builder& and returning void, invoked once
 * after successful initialization. Exceptions propagate; no callback is replayed.
 * @param diagnostic Optional borrowed C failure detail; Tag lifetimes must cover inspection.
 * @return Exact written size or first failure, without allocating even on errors.
 * @warning Failed output can contain completed roots and provisional bytes; no whole-output
 * rollback.
 */
template <typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure>
encode(Output&& output, tlv::format format, writer_workspace workspace, Callback&& callback,
       writer_diagnostic* diagnostic = nullptr) {
    writer_builder builder(detail::writer_output(output), format, workspace, diagnostic);
    builder.invoke(std::forward<Callback>(callback));
    return builder.finish();
}

/** @brief Encode with a typed Format and explicit caller-owned workspace.
 * @tparam F Writable Format adapted for this operation; its configuration stays stationary.
 * @param output Borrowed mutable byte storage, never resized.
 * @param workspace Disjoint caller-owned frames and scratch.
 * @param callback Scoped writes; follows the runtime encode() callback contract.
 * @param format Immutable Format configuration, owned for the operation.
 * @param diagnostic Optional C operation failure detail.
 * @return Exact byte count or allocation-free first failure.
 */
template <typename F, typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure> encode(Output&& output, writer_workspace workspace,
                                                      Callback&& callback, F format = F{},
                                                      writer_diagnostic* diagnostic = nullptr) {
    static_assert(format_capabilities<F>::writable, "encode requires a writable Format");
    format_adapter<F> adapter(std::move(format));
    return tlv::encode(std::forward<Output>(output), adapter.view(), workspace,
                       std::forward<Callback>(callback), diagnostic);
}

/** @brief Encode with bounded local stack workspace and a typed Format.
 * @tparam F Writable Format.
 * @tparam ScratchCapacity Local scratch bytes, default 1024; never grows automatically.
 * @tparam Depth Local frame count and maximum item depth, default TLV_TREE_DEFAULT_DEPTH.
 * @param output Caller-owned output span, array or contiguous byte container.
 * @param callback Scoped construction, invoked once after successful initialization.
 * @param format Immutable Format configuration owned for the call.
 * @param diagnostic Optional C failure detail.
 * @return Exact size or first error, including insufficient scratch or frames.
 */
template <typename F, size_t ScratchCapacity = 1024, size_t Depth = TLV_TREE_DEFAULT_DEPTH,
          typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure> encode(Output&& output, Callback&& callback,
                                                      F                  format = F{},
                                                      writer_diagnostic* diagnostic = nullptr) {
    writer_storage<ScratchCapacity, Depth> storage;
    return tlv::encode<F>(std::forward<Output>(output), storage.view(),
                          std::forward<Callback>(callback), std::move(format), diagnostic);
}

/** @brief Measure exact sequence size by staging its encoding once in caller storage.
 * @param staging Mutable byte span, array or container holding the full encoding on success.
 * @param format Borrowed immutable Format and context.
 * @param workspace Disjoint frames and scratch, as for encode().
 * @param callback Scoped writes, executed once. Content-dependent Formats see encoded children.
 * @param diagnostic Optional C failure detail.
 * @return Exact encoded byte count or first error. Successful staged bytes can be
 * reused directly; no second callback execution is needed. Failed storage is not
 * a size query and provides no prediction of the complete required capacity.
 */
template <typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure>
encoded_size(Output&& staging, tlv::format format, writer_workspace workspace, Callback&& callback,
             writer_diagnostic* diagnostic = nullptr) {
    return tlv::encode(std::forward<Output>(staging), format, workspace,
                       std::forward<Callback>(callback), diagnostic);
}

/** @brief Stage exact measurement with a typed Format and explicit workspace.
 * @tparam F Writable Format, owned and adapted for the call.
 * @param staging Caller-owned full encoding storage; reusable on success.
 * @param workspace Disjoint frames and scratch.
 * @param callback Scoped writes executed once; follows encoded_size() staging semantics.
 * @param format Immutable Format configuration.
 * @param diagnostic Optional C failure detail.
 * @return Exact encoded size or allocation-free first failure.
 */
template <typename F, typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure>
encoded_size(Output&& staging, writer_workspace workspace, Callback&& callback, F format = F{},
             writer_diagnostic* diagnostic = nullptr) {
    return tlv::encode<F>(std::forward<Output>(staging), workspace,
                          std::forward<Callback>(callback), std::move(format), diagnostic);
}
} // namespace tlv
#endif
