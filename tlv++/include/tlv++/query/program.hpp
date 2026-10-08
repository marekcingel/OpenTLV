// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_QUERY_PROGRAM_HPP
#define OPENTLV_TLVPP_QUERY_PROGRAM_HPP
#include <memory>
#include <vector>
#include <string>
#include <exception>
#include <type_traits>
#include <stdexcept>
#include "tlv/query/plan.h"
#include "tlv/config.h"
#include "tlv++/reader/tree.hpp"
#include "tlv++/query/options.hpp"

/** @file
 * @brief Full Query compilation and execution through the canonical C engine. */
namespace tlv {
namespace detail {
struct query_program_access;
}
/** @brief Structured Query error category. */
enum class query_issue {
    none = TLV_QUERY_ERROR_NONE,                   /**< No failure. */
    syntax = TLV_QUERY_ERROR_SYNTAX,               /**< Invalid expression. */
    capability = TLV_QUERY_ERROR_CAPABILITY,       /**< Unavailable capability. */
    limit = TLV_QUERY_ERROR_LIMIT,                 /**< Exhausted budget. */
    storage = TLV_QUERY_ERROR_STORAGE,             /**< Invalid storage. */
    events = TLV_QUERY_ERROR_EVENTS,               /**< Invalid event sequence. */
    source = TLV_QUERY_ERROR_SOURCE,               /**< Missing source locations. */
    reader = TLV_QUERY_ERROR_READER,               /**< Wire Reader failure. */
    binding = TLV_QUERY_ERROR_BINDING,             /**< Invalid variable binding. */
    cardinality = TLV_QUERY_ERROR_CARDINALITY,     /**< Scalar cardinality mismatch. */
    codec = TLV_QUERY_ERROR_CODEC,                 /**< Value conversion failure. */
    image_version = TLV_QUERY_ERROR_IMAGE_VERSION, /**< Incompatible program image. */
    state = TLV_QUERY_ERROR_STATE                  /**< Invalid lifecycle or callback reentrancy. */
};
/** @brief Scalar result borrowing immutable input, program or execution storage until reset. */
struct query_value {
    query_type kind;    /**< Result category; node sequences are consumed with next(). */
    bool       boolean; /**< Boolean result when kind is boolean. */
    int64_t    integer; /**< Integer result when kind is integer. */
    tlv::bytes data;    /**< Bytes or UTF-8 text when kind is bytes or string. */
};
/** @brief Original native status and complete Query diagnostic, including Reader/codec detail. */
struct query_failure {
    tlv_result_t code; /**< Original status, including NEED_MORE_DATA and END_OF_BUFFER. */
    tlv_query_diagnostic_t diagnostic; /**< Byte span, source, limit and codec context. */
    /** @brief Canonical C++ operation status, preserving resumable input and EOF. */
    errc status() const noexcept {
        return static_cast<errc>(code);
    }
    /** @brief Immutable program-lifetime error description. */
    const char* message() const noexcept {
        return tlv::message(status());
    }
    /** @brief Category identifying the relevant subsystem detail. */
    query_issue kind() const noexcept {
        return static_cast<query_issue>(diagnostic.kind);
    }
    /** @brief Copy common diagnostic information while preserving Query detail on this object. */
    tlv::error failure() const noexcept {
        if (kind() == query_issue::reader || diagnostic.reader.diagnostic.code != TLV_OK)
            return detail::reader_failed(code, diagnostic.reader, diagnostic.source_offset);
        auto value = tlv::error(status(), operation::query);
        return diagnostic.has_source_offset ? value.at(diagnostic.source_offset, operation::query)
                                            : value;
    }
};
/** @cond INTERNAL */
namespace detail {
struct query_memory {
    std::vector<unsigned char> blocks;
    explicit query_memory(size_t bytes) {
        if (bytes > SIZE_MAX - 15) throw std::bad_alloc();
        blocks.resize(bytes + 15);
    }
    void* data() {
        return reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(blocks.data()) + 15) &
                                       ~uintptr_t(15));
    }
};
inline query_failure query_failed(tlv_result_t rc, tlv_query_diagnostic_t d = {}) {
    if (rc == TLV_ERR_INVALID_STATE) d.kind = TLV_QUERY_ERROR_STATE;
    return {rc, d};
}
} // namespace detail
/** @endcond */
class query_execution;
/** @brief Immutable full-language compiled Query; copies share owned program storage.
 * External-storage programs borrow the caller's aligned immutable storage. Environments,
 * callbacks and their contexts remain borrowed according to the native contract. */
class query_program {
public:
    /** @brief Copy immutable ownership; external programs keep their borrowed storage contract. */
    query_program(const query_program&) = default;
    /** @brief Share immutable ownership, leaving existing executions alive. */
    query_program& operator=(const query_program&) = default;
    /** @brief Compile with C++ declarations and borrowed capabilities.
     * @param text Query text, not retained.
     * @param options Stationary declarations; names remain alive during compilation.
     * @return Shared immutable program or complete Query failure; may allocate.
     */
    static expected<query_program, query_failure> compile(const std::string&   text,
                                                          const query_options& options) {
        return compile(text, options.view());
    }
    /** @brief Compile bounded text with checked resolver stability and owned program storage.
     * @param text Query bytes, including any embedded NUL for native diagnostics.
     * @param options Initialized native options, including typed declarations and providers.
     * @return Shared program or full native failure; allocation exceptions propagate. */
    static expected<query_program, query_failure> compile(const std::string& text,
                                                          query_settings     options = nullptr) {
        const auto*            native_options = detail::query_options_access::get(options);
        size_t                 size = 0, alignment = 0;
        tlv_query_diagnostic_t d{};
        auto rc = tlv_query_compile_prepare_size(text.data(), text.size(), native_options, &size,
                                                 &alignment, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        detail::query_memory     scratch(size);
        tlv_query_program_info_t info{};
        info.struct_size = sizeof info;
        const tlv_query_program_t* prepared = nullptr;
        rc = tlv_query_compile_prepare(text.data(), text.size(), native_options, scratch.data(),
                                       size, &prepared, &info, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        size_t validation_size = 0;
        rc = tlv_query_program_load_scratch(prepared, info.program_size, native_options,
                                            &validation_size, &alignment, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        detail::query_memory validation(validation_size);
        auto                 memory = std::make_shared<detail::query_memory>(info.program_size);
        auto result = commit_into(prepared, info.program_size, options, validation.data(),
                                  validation_size, memory->data(), info.program_size);
        if (result) result->memory_ = memory;
        return result;
    }
    /** @brief Compile using explicit aligned caller scratch and output, without C++ allocation.
     * @param text Bounded Query bytes, not retained.
     * @param size Text byte count.
     * @param options Optional initialized compiler options.
     * @param scratch Temporary aligned compiler storage.
     * @param scratch_size Scratch capacity from compile_scratch.
     * @param storage Immutable output, aligned and alive through all executions.
     * @param capacity Output bytes from a native sizing pass.
     * @return Borrowed program or full native diagnostic.
     * @note This is one native compile call. Use native compile_prepare followed by
     * commit_into for allocation-free detection of resolver changes across passes. */
    static expected<query_program, query_failure> compile_into(const char* text, size_t size,
                                                               query_settings options,
                                                               void* scratch, size_t scratch_size,
                                                               void* storage, size_t capacity) {
        const auto* native_options = detail::query_options_access::get(options);
        if (!storage) return unexpected<query_failure>(detail::query_failed(TLV_ERR_NULL_ARG));
        query_program          result;
        tlv_query_diagnostic_t d{};
        result.info_.struct_size = sizeof result.info_;
        auto rc = tlv_query_compile(text, size, native_options, scratch, scratch_size, storage,
                                    capacity, &result.info_, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        result.program_ = static_cast<const tlv_query_program_t*>(storage);
        return result;
    }
    /** @brief Check and publish a prepared program without C++ allocation.
     * @param prepared Image from native compile_prepare, alive and unchanged during this call.
     * @param size Exact prepared image extent.
     * @param options Original compiler options and current capabilities.
     * @param scratch Exclusive aligned validation storage from load_scratch.
     * @param scratch_size Available validation bytes.
     * @param storage Required aligned final image, alive through every execution.
     * @param capacity Available final program bytes.
     * @return Borrowed program or complete native failure. Failure preserves storage;
     * equal-size changes to resolved identifiers are rejected. */
    static expected<query_program, query_failure> commit_into(const void* prepared, size_t size,
                                                              query_settings options, void* scratch,
                                                              size_t scratch_size, void* storage,
                                                              size_t capacity) {
        const auto*   native_options = detail::query_options_access::get(options);
        query_program result;
        result.info_.struct_size = sizeof result.info_;
        tlv_query_diagnostic_t d{};
        auto rc = tlv_query_compile_commit(prepared, size, native_options, scratch, scratch_size,
                                           storage, capacity, &result.info_, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        result.program_ = static_cast<const tlv_query_program_t*>(storage);
        return result;
    }
    /** @brief Discover bounded external-image validation scratch without allocation.
     * @param image Readable image bytes.
     * @param size Exact available extent.
     * @param options Original compiler configuration and capabilities.
     * @param bytes Required scratch capacity output.
     * @param alignment Required scratch alignment output.
     * @return Success or complete native failure. Discovery does not validate instructions. */
    static expected<void, query_failure> load_scratch(const void* image, size_t size,
                                                      query_settings options, size_t& bytes,
                                                      size_t& alignment) {
        const auto*            native_options = detail::query_options_access::get(options);
        tlv_query_diagnostic_t d{};
        auto                   rc =
            tlv_query_program_load_scratch(image, size, native_options, &bytes, &alignment, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        return {};
    }
    /** @brief Validate and borrow an immutable aligned image, including ROM.
     * @param image Image alive and unchanged through every execution.
     * @param size Exact image extent.
     * @param options Original compilation configuration and borrowed capabilities.
     * @param scratch Exclusive aligned validation scratch.
     * @param capacity Scratch bytes from load_scratch.
     * @return Borrowed program or complete native failure. No C++ allocation occurs.
     * @note Images have release-limited compatibility and are fully reconstructed
     * by the C validator before use. The returned program never owns the image. */
    static expected<query_program, query_failure> load_external(const void* image, size_t size,
                                                                query_settings options,
                                                                void* scratch, size_t capacity) {
        const auto*   native_options = detail::query_options_access::get(options);
        query_program result;
        result.info_.struct_size = sizeof result.info_;
        tlv_query_diagnostic_t d{};
        auto rc = tlv_query_program_load(image, size, native_options, scratch, capacity,
                                         &result.program_, &result.info_, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        return result;
    }
    /** @brief Validate and borrow a static/generated C plan without the Query frontend.
     * @param image Aligned immutable native image, alive through all executions.
     * @param size Exact logical byte extent, excluding trailing C structure padding.
     * @return Borrowed program or native validation failure; no allocation occurs.
     * @note Copies continue to borrow the image. Compilation and execution share
     * the same C representation and version/capability checks. */
    static expected<query_program, query_failure> from_plan(const void* image, size_t size) {
        query_program          result;
        tlv_query_diagnostic_t diagnostic{};
        auto                   rc = tlv_query_plan_open(image, size, &result.program_, &diagnostic);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, diagnostic));
        result.info_.struct_size = sizeof result.info_;
        rc = tlv_query_plan_info(result.program_, &result.info_);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return result;
    }
    /** @brief Native whole-expression resource requirements. */
    const tlv_query_program_info_t& info() const {
        return info_;
    }
    /** @brief Whole-expression backend requirement. */
    query_level level() const noexcept {
        return static_cast<query_level>(info_.level);
    }
    /** @brief Static expression result category. */
    query_type result_type() const noexcept {
        return static_cast<query_type>(info_.result_kind);
    }
    /** @brief Number of unique referenced variables; unused declarations are excluded. */
    size_t variable_count() const {
        return tlv_query_program_variable_count(program_);
    }
    /** @brief Inspect one referenced variable; its name borrows this immutable program.
     * @param index Zero-based slot in first-reference order.
     * @return Bounded name and required type or original native status. */
    expected<tlv_query_variable_info_t, query_failure> variable(size_t index) const {
        tlv_query_variable_info_t value{};
        auto                      rc = tlv_query_program_variable(program_, index, &value);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return value;
    }
    /** @brief Canonical normalized language spelling; allocates a string. */
    std::string format() const {
        return render(false);
    }
    /** @brief Unstable internal logical IR; allocates a string. */
    std::string explain() const {
        return render(true);
    }

private:
    friend class query_execution;
    friend struct detail::query_program_access;
    /** @brief Borrow the immutable native program for interoperability. */
    const tlv_query_program_t* c_program() const {
        return program_;
    }

private:
    query_program() = default;
    std::string render(bool explain) const {
        size_t size = 0;
        auto   fn = tlv_query_program_explain;
#if OPENTLV_QUERY_FRONTEND
        if (!explain) fn = tlv_query_program_format;
#else
        if (!explain) throw std::runtime_error(tlv_strerror(TLV_ERR_UNSUPPORTED_TYPE));
#endif
        auto rc = fn(program_, nullptr, 0, &size);
        if (rc != TLV_OK) throw std::runtime_error(tlv_strerror(rc));
        std::string out(size, '\0');
        rc = fn(program_, &out[0], size, &size);
        if (rc != TLV_OK) throw std::runtime_error(tlv_strerror(rc));
        out.resize(size - 1);
        return out;
    }
    const tlv_query_program_t*            program_ = nullptr;
    tlv_query_program_info_t              info_{};
    std::shared_ptr<detail::query_memory> memory_;
};

/** @brief Independent move-only Query continuation, retaining its compiled program.
 * Borrowed input and environments must remain stable until destruction/reset. Byte/string
 * scalars and Tree events borrow input/program/workspace; copy explicitly for owned results.
 * NEED_MORE_DATA preserves state and differs from final END_OF_BUFFER. */
class query_execution {
public:
    /** @brief Allocate an independent execution using C++ capabilities.
     * @param program Immutable program retained by value.
     * @param depth Maximum nesting depth.
     * @param nodes Candidate capacity including nonmatches.
     * @param work Charged work budget.
     * @param environment Borrowed stationary providers, alive through execution.
     * @param retained Select retained evaluation instead of bounded S0/S1.
     * @return Execution or canonical failure; allocation exceptions propagate.
     */
    static expected<query_execution, query_failure> create(const query_program& program,
                                                           size_t depth, size_t nodes, size_t work,
                                                           const query_environment& environment,
                                                           bool retained = true) {
        return create(program, depth, nodes, work, environment.view(), retained);
    }
    /** @brief Reject retaining providers from a temporary environment. */
    static expected<query_execution, query_failure> create(const query_program&, size_t, size_t,
                                                           size_t, const query_environment&&,
                                                           bool = true) = delete;
    /** @brief Mutable continuations cannot be copied. */
    query_execution(const query_execution&) = delete;
    /** @brief Mutable continuations cannot be assigned by copy. */
    query_execution& operator=(const query_execution&) = delete;
    /** @brief Move without relocating native program/workspace. */
    query_execution(query_execution&& other) noexcept
        : program_(other.program_), exec_(other.exec_), memory_(std::move(other.memory_)),
          document_lifetime_(std::move(other.document_lifetime_)),
          has_document_(other.has_document_) {
        other.exec_ = nullptr;
        other.has_document_ = false;
    }
    /** @brief Transfer continuation ownership. */
    query_execution& operator=(query_execution&& other) noexcept {
        if (this != &other) {
            program_ = other.program_;
            exec_ = other.exec_;
            memory_ = std::move(other.memory_);
            document_lifetime_ = std::move(other.document_lifetime_);
            has_document_ = other.has_document_;
            other.exec_ = nullptr;
            other.has_document_ = false;
        }
        return *this;
    }
    /** @brief Allocate the selected workspace with explicit depth, element and work bounds.
     * @param program Immutable program retained by value.
     * @param depth Maximum depth.
     * @param nodes Retained-node capacity or streaming element budget, including nonmatches.
     * @param work Charged native work budget.
     * @param environment Compatible immutable borrowed providers.
     * @param retained True selects retained evaluation; false selects bounded S0/S1.
     * @return Independent continuation or native failure. */
    static expected<query_execution, query_failure> create(const query_program& program,
                                                           size_t depth, size_t nodes, size_t work,
                                                           query_capabilities environment = nullptr,
                                                           bool               retained = true) {
        size_t size = 0, alignment = 0;
        auto   rc = retained
                        ? tlv_query_eval_size(program.c_program(), depth, nodes, &size, &alignment)
                        : tlv_query_exec_size(program.c_program(), depth, &size, &alignment);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        auto memory = std::make_shared<detail::query_memory>(size);
        auto result =
            external(program, memory->data(), size, depth, nodes, work, environment, retained);
        if (result) result->memory_ = memory;
        return result;
    }
    /** @brief Initialize aligned caller storage without allocation.
     * @param program Live immutable program, retained by value.
     * @param storage Caller storage, alive and exclusive throughout execution.
     * @param capacity Bytes from eval_size (retained) or exec_size (streaming).
     * @param depth Maximum depth.
     * @param nodes Retained capacity or streaming element budget.
     * @param work Charged work budget.
     * @param environment Borrowed compatible providers; streaming currently accepts no providers.
     * @param retained True selects retained S0-S2/D; false selects bounded S0/S1.
     * @return Execution or native failure. */
    static expected<query_execution, query_failure>
    external(const query_program& program, void* storage, size_t capacity, size_t depth,
             size_t nodes, size_t work, query_capabilities environment = nullptr,
             bool retained = true) {
        query_execution result(program);
        auto rc = retained
                      ? tlv_query_eval_init(program.c_program(),
                                            detail::query_options_access::get(environment), storage,
                                            capacity, depth, nodes, work, &result.exec_)
                      : (environment ? TLV_ERR_UNSUPPORTED_TYPE
                                     : tlv_query_exec_init(program.c_program(), storage, capacity,
                                                           depth, nodes, work, &result.exec_));
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return result;
    }
    /** @brief Bind a declared integer variable before execution. */
    expected<void, query_failure> bind(const char* name, int64_t value) {
        return bind_span(name, TLV_QUERY_RESULT_INTEGER, value, nullptr, 0);
    }
    /** @brief Bind borrowed bytes or UTF-8 string before execution; no interpolation/copy. */
    expected<void, query_failure> bind(const char* name, bytes value, bool string = false) {
        return bind_span(name, string ? TLV_QUERY_RESULT_STRING : TLV_QUERY_RESULT_BYTES, 0,
                         reinterpret_cast<const uint8_t*>(value.data()), value.size());
    }
    /** @brief Select a relative preorder context before consuming events.
     * @param ordinal Traversal-scoped zero-based identity, not a Document node identity.
     * @return Success or original native status; failed selection preserves state. */
    expected<void, query_failure> context(size_t ordinal) {
        auto rc = tlv_query_exec_context(exec_, ordinal);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return {};
    }
    /** @brief Reset state, bindings and results while retaining program, providers and budgets.
     * @return Success or native invalid-state failure when invoked from an active callback.
     * @note Delegates to the allocation-free C reset; all previously borrowed results expire. */
    expected<void, query_failure> reset() {
        auto rc = tlv_query_exec_reset(exec_);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return {};
    }
    /** @brief Explicitly permit proven subtree pruning on fresh streaming execution.
     * @param enabled True permits partial structural validation of skipped subtrees.
     * @return Success or original native status; retained execution rejects pruning. */
    expected<void, query_failure> pruning(bool enabled) {
        auto rc = tlv_query_exec_pruning(exec_, enabled ? 1 : 0);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return {};
    }
    /** @brief Read counters, terminal failure state and full/partial validation coverage. */
    expected<tlv_query_exec_info_t, query_failure> info() const {
        tlv_query_exec_info_t out{};
        out.struct_size = sizeof out;
        auto rc = tlv_query_exec_info(exec_, &out);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return out;
    }
    /** @brief Test existence with explicit early-return or full-validation behavior.
     * @param reader Exclusive Tree cursor; retained input obeys visit() lifetime rules.
     * @param early_return True returns at the first match with partial coverage.
     * @return Existence or complete native diagnostic, including resumable NEED_MORE_DATA.
     * @note Resume with early_return false to validate the remaining input. */
    expected<bool, query_failure> exists(tree_reader& reader, bool early_return = false) {
        if (has_document_)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        reader.has_current_ = false;
        int                    found = 0;
        tlv_query_diagnostic_t d{};
        auto                   rc =
            reader.init_result_ == TLV_OK
                ? tlv_query_program_exists(&reader.impl_, exec_, early_return ? 1 : 0, &found, &d)
                : reader.init_result_;
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        return found != 0;
    }
    /** @brief Visit borrowed Tree results, preserving STOP/NEED_MORE_DATA continuation.
     * @param reader Exclusive borrowed Tree cursor.
     * @param visitor Callable taking tree_event and returning tlv_visit_result_t.
     * @return Success at STOP/EOF or full native diagnostic. Callback exceptions propagate
     * after returning through C. Stable input ownership is the caller's responsibility. */
    template <typename Visitor>
    expected<void, query_failure> visit(tree_reader& reader, Visitor&& visitor) {
        if (has_document_)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        struct state {
            typename std::remove_reference<Visitor>::type* visitor;
            std::exception_ptr                             failure;
            static tlv_visit_result_t call(const tlv_tree_event_t* event, void* context) {
                auto& s = *static_cast<state*>(context);
                try {
                    return static_cast<tlv_visit_result_t>(
                        (*s.visitor)(detail::tree_access::borrow(*event)));
                } catch (...) {
                    s.failure = std::current_exception();
                    return TLV_VISIT_ERROR;
                }
            }
        } s{&visitor, {}};
        reader.has_current_ = false;
        tlv_query_diagnostic_t d{};
        auto rc = reader.init_result_ == TLV_OK
                      ? tlv_query_program_visit(&reader.impl_, exec_, &state::call, &s, &d)
                      : reader.init_result_;
        if (s.failure) std::rethrow_exception(s.failure);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        return {};
    }
    /** @brief Read a finalized scalar; returned spans borrow this execution's owners.
     * @return Result or INVALID_STATE before completion, after failure, during callbacks or
     * when the backing Document has expired or changed; other native errors propagate. */
    expected<tlv_query_result_t, query_failure> result() const {
        if (has_document_ && document_lifetime_.expired())
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_STATE));
        tlv_query_result_t out{};
        auto               rc = tlv_query_exec_result(exec_, &out);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return out;
    }
    /** @brief Read a completed scalar with C++ categories and borrowed byte storage.
     * @return Result or complete Query failure; does not allocate.
     * @warning Borrowed data remains valid only until execution reset or input destruction.
     */
    expected<query_value, query_failure> scalar() const {
        const auto value = result();
        if (!value) return unexpected<query_failure>(value.error());
        return query_value{static_cast<query_type>(value->kind),
                           value->boolean != 0,
                           value->integer,
                           {reinterpret_cast<const byte*>(value->data), value->size}};
    }
    /** @brief Pull a finalized retained Tree result; END_OF_BUFFER means final exhaustion.
     * @return Event or INVALID_STATE before completion, after failure, during callbacks or
     * when the backing Document has expired or changed; other native errors propagate. */
    expected<tree_event, query_failure> next() {
        if (has_document_ && document_lifetime_.expired())
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_STATE));
        tlv_tree_event_t out{};
        auto             rc = tlv_query_result_next(exec_, &out);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return detail::tree_access::borrow(out);
    }
    /** @brief Resume Tree selection until one borrowed node, final EOF or NEED_MORE_DATA.
     * @param reader Exclusive Tree cursor, unchanged between pulls except legal input replacement.
     * @return Node, END_OF_BUFFER at final exhaustion, or the full resumable/error diagnostic.
     * @note Uses native STOP after publication. S0 publishes immediately; retained S2
     * validates to EOF first. Input and Source owners obey visit() lifetime rules.
     * Scalar programs are rejected before consuming the Reader. */
    expected<tree_event, query_failure> next(tree_reader& reader) {
        if (program_.info().result_kind != TLV_QUERY_RESULT_NODES)
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        tree_event selected{};
        bool       found = false;
        auto       status = visit(reader, [&](const tree_event& event) {
            selected = event;
            found = true;
            return TLV_VISIT_STOP;
        });
        if (!status) return unexpected<query_failure>(status.error());
        if (!found) return unexpected<query_failure>(detail::query_failed(TLV_ERR_END_OF_BUFFER));
        return selected;
    }

private:
    friend struct detail::query_program_access;
    /** @brief Borrow native continuation for optional Document/Schema adapters. */
    tlv_query_exec_t* c_exec() const {
        return exec_;
    }

private:
    explicit query_execution(const query_program& p) : program_(p) {}
    expected<void, query_failure> bind_span(const char* name, tlv_query_result_kind_t type,
                                            int64_t number, const uint8_t* data, size_t size) {
        tlv_query_diagnostic_t d{};
        auto                   rc = tlv_query_exec_bind(exec_, name, type, number, data, size, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        return {};
    }
    query_program                         program_;
    tlv_query_exec_t*                     exec_ = nullptr;
    std::shared_ptr<detail::query_memory> memory_;
    std::weak_ptr<void>                   document_lifetime_;
    bool                                  has_document_ = false;
    friend class document;
};
/// @cond INTERNAL
namespace detail {
struct query_program_access {
    static const tlv_query_program_t* get(const query_program& value) {
        return value.c_program();
    }
    static tlv_query_exec_t* get(query_execution& value) {
        return value.c_exec();
    }
};
} // namespace detail
/// @endcond
} // namespace tlv
#endif
