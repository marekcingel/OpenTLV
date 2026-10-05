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
#include "tlv/query/program.h"
#include "tlv++/reader/tree.hpp"

/** @file
 * @brief Full Query compilation and execution through the canonical C engine. */
namespace tlv {
/** @brief Original native status and complete Query diagnostic, including Reader/codec detail. */
struct query_failure {
    tlv_result_t code; /**< Original status, including NEED_MORE_DATA and END_OF_BUFFER. */
    tlv_query_diagnostic_t diagnostic; /**< Byte span, source, limit and codec context. */
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
    /** @brief Compile bounded text, allocating temporary scratch and immutable program storage.
     * @param text Query bytes, including any embedded NUL for native diagnostics.
     * @param options Initialized native options, including typed declarations and providers.
     * @return Shared program or full native failure; allocation exceptions propagate. */
    static expected<query_program, query_failure>
    compile(const std::string& text, const tlv_query_compile_options_t* options = nullptr) {
        size_t                 size = 0, alignment = 0;
        tlv_query_diagnostic_t d{};
        auto                   rc =
            tlv_query_compile_scratch(text.data(), text.size(), options, &size, &alignment, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        detail::query_memory     scratch(size);
        tlv_query_program_info_t info{};
        info.struct_size = sizeof info;
        rc = tlv_query_compile(text.data(), text.size(), options, scratch.data(), size, nullptr, 0,
                               &info, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        auto memory = std::make_shared<detail::query_memory>(info.program_size);
        auto result = compile_into(text.data(), text.size(), options, scratch.data(), size,
                                   memory->data(), info.program_size);
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
     * @return Borrowed program or full native diagnostic. */
    static expected<query_program, query_failure>
    compile_into(const char* text, size_t size, const tlv_query_compile_options_t* options,
                 void* scratch, size_t scratch_size, void* storage, size_t capacity) {
        if (!storage) return unexpected<query_failure>(detail::query_failed(TLV_ERR_NULL_ARG));
        query_program          result;
        tlv_query_diagnostic_t d{};
        result.info_.struct_size = sizeof result.info_;
        auto rc = tlv_query_compile(text, size, options, scratch, scratch_size, storage, capacity,
                                    &result.info_, &d);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc, d));
        result.program_ = static_cast<const tlv_query_program_t*>(storage);
        return result;
    }
    /** @brief Native whole-expression resource requirements. */
    const tlv_query_program_info_t& info() const {
        return info_;
    }
    /** @brief Canonical normalized language spelling; allocates a string. */
    std::string format() const {
        return render(false);
    }
    /** @brief Unstable internal logical IR; allocates a string. */
    std::string explain() const {
        return render(true);
    }
    /** @brief Borrow the immutable native program for interoperability. */
    const tlv_query_program_t* c_program() const {
        return program_;
    }

private:
    query_program() = default;
    std::string render(bool explain) const {
        size_t size = 0;
        auto   fn = explain ? tlv_query_program_explain : tlv_query_program_format;
        auto   rc = fn(program_, nullptr, 0, &size);
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
    /** @brief Allocate retained S0-S2/D workspace with explicit depth, candidate and work bounds.
     * @param program Immutable program retained by value.
     * @param depth Maximum depth.
     * @param nodes Explicit retained-node capacity, including nonmatches.
     * @param work Charged native work budget.
     * @param environment Compatible immutable borrowed providers.
     * @return Independent continuation or native failure. */
    static expected<query_execution, query_failure>
    create(const query_program& program, size_t depth, size_t nodes, size_t work,
           const tlv_query_environment_t* environment = nullptr) {
        size_t size = 0, alignment = 0;
        auto   rc = tlv_query_eval_size(program.c_program(), depth, nodes, &size, &alignment);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        auto memory = std::make_shared<detail::query_memory>(size);
        auto result = external(program, memory->data(), size, depth, nodes, work, environment);
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
             size_t nodes, size_t work, const tlv_query_environment_t* environment = nullptr,
             bool retained = true) {
        query_execution result(program);
        auto rc = retained
                      ? tlv_query_eval_init(program.c_program(), environment, storage, capacity,
                                            depth, nodes, work, &result.exec_)
                      : (environment ? TLV_ERR_UNSUPPORTED_TYPE
                                     : tlv_query_exec_init(program.c_program(), storage, capacity,
                                                           depth, nodes, work, &result.exec_));
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return std::move(result);
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
                    return (*s.visitor)(detail::tree_access::borrow(*event));
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
    /** @brief Read a finalized scalar; returned spans borrow this execution's owners. */
    expected<tlv_query_result_t, query_failure> result() const {
        if (has_document_ && document_lifetime_.expired())
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
        tlv_query_result_t out{};
        auto               rc = tlv_query_exec_result(exec_, &out);
        if (rc != TLV_OK) return unexpected<query_failure>(detail::query_failed(rc));
        return out;
    }
    /** @brief Pull a finalized retained Tree result; END_OF_BUFFER means final exhaustion. */
    expected<tree_event, query_failure> next() {
        if (has_document_ && document_lifetime_.expired())
            return unexpected<query_failure>(detail::query_failed(TLV_ERR_INVALID_ARG));
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
} // namespace tlv
#endif
