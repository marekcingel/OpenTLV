// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/config.h"
#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#if OPENTLV_READER && OPENTLV_FORMAT_BER
#include "tlv++/builtins/asn1/ber.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/reader/reader.hpp"

namespace {

enum class framing { ber, fixed };
enum class traversal { next, range };
enum class failure { eof, truncated_value, incremental, initialization };

// A valid write-only application Format lets runtime Reader initialization fail
// without manufacturing an invalid byte span or importing a native descriptor.
struct write_only_format {
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request&) const noexcept {
        return tlv::unexpected<tlv::format_failure>(tlv::format_failure(tlv::errc::unsupported));
    }
    tlv::expected<size_t, tlv::format_failure> encode(const tlv::element_view&,
                                                      tlv::span<tlv::byte>) const noexcept {
        return tlv::unexpected<tlv::format_failure>(tlv::format_failure(tlv::errc::unsupported));
    }
};

tlv::format wire_format(framing kind) {
    if (kind == framing::ber) return tlv::ber::format{};
    return tlv::fixed_format<1, 1>{};
}

// Both selected Formats encode this one-byte primitive tag/length identically.
// Keep fixture construction independent of the optional Writer capability.
std::vector<tlv::byte> flat_input(size_t count) {
    std::vector<tlv::byte> wire(count * 3);
    for (size_t i = 0; i < count; ++i) {
        wire[i * 3] = tlv::byte(0x04);
        wire[i * 3 + 1] = tlv::byte(1);
        wire[i * 3 + 2] = tlv::byte(0x5a);
    }
    return wire;
}

void reader_counters(benchmark::State& state, size_t elements, size_t attempts, size_t wire_size) {
    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(elements));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(wire_size));
    state.counters["elements/iteration"] = static_cast<double>(elements);
    state.counters["next_calls/iteration"] = static_cast<double>(attempts);
    state.counters["error_bytes"] = sizeof(tlv::error);
    state.counters["result_bytes"] = sizeof(tlv::expected<tlv::element_view, tlv::error>);
}

void cxx_reader_success(benchmark::State& state, framing kind, traversal method) {
    const size_t count = static_cast<size_t>(state.range(0));
    const auto   wire = flat_input(count);
    const auto   format = wire_format(kind);
    for (auto _ : state) {
        size_t        seen = 0;
        tlv::reader<> reader({wire.data(), wire.size()}, format);
        if (method == traversal::next) {
            for (;;) {
                auto result = reader.next();
                if (!result) {
                    if (result.error().status() != tlv::errc::end_of_input) {
                        state.SkipWithError("C++ Reader failed before final EOF");
                        return;
                    }
                    break;
                }
                benchmark::DoNotOptimize(result->value().data());
                ++seen;
            }
        } else {
            for (const auto& element : reader) {
                benchmark::DoNotOptimize(element.value().data());
                ++seen;
            }
        }
        if (seen != count || !reader.at_end()) {
            state.SkipWithError("C++ Reader did not consume the exact element count");
            return;
        }
    }
    reader_counters(state, count, method == traversal::next ? count + 1 : 0, wire.size());
}

void cxx_reader_failure(benchmark::State& state, framing kind, failure outcome) {
    const tlv::byte wire[] = {tlv::byte(0x04), tlv::byte(2), tlv::byte(0x5a)};
    const tlv::format_adapter<write_only_format> write_only;
    const auto format = outcome == failure::initialization ? write_only.view() : wire_format(kind);
    const bool incremental = outcome == failure::incremental;
    const tlv::bytes input = outcome == failure::eof || outcome == failure::initialization
                                 ? tlv::bytes{}
                                 : tlv::bytes(wire, sizeof wire);
    tlv::reader<>    reader(input, format,
                            incremental ? tlv::input_mode::incremental : tlv::input_mode::final);
    const auto       expected = outcome == failure::eof              ? tlv::errc::end_of_input
                                : outcome == failure::initialization ? tlv::errc::null_argument
                                : incremental                        ? tlv::errc::need_more_data
                                                                     : tlv::errc::buffer_too_short;
    const size_t     attempts = static_cast<size_t>(state.range(0));
    for (auto _ : state) {
        for (size_t i = 0; i < attempts; ++i) {
            auto result = reader.next();
            if (result || result.error().status() != expected) {
                state.SkipWithError("C++ Reader did not preserve the requested failure outcome");
                return;
            }
            benchmark::DoNotOptimize(result.error().message());
            benchmark::DoNotOptimize(result.error().has_offset());
        }
        if (reader.offset() != 0) {
            state.SkipWithError("A failed C++ Reader advanced its position");
            return;
        }
    }
    reader_counters(state, 0, attempts, 0);
    // Failed calls have no successfully decoded elements; the rate counts attempts.
    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(attempts));
}

void cxx_reader_resume(benchmark::State& state, framing kind) {
    const tlv::byte wire[] = {tlv::byte(0x04), tlv::byte(1), tlv::byte(0x5a)};
    const auto      format = wire_format(kind);
    const size_t    count = static_cast<size_t>(state.range(0));
    for (auto _ : state) {
        for (size_t i = 0; i < count; ++i) {
            tlv::reader<> reader({wire, 2}, format, tlv::input_mode::incremental);
            auto          partial = reader.next();
            if (partial || partial.error().status() != tlv::errc::need_more_data ||
                reader.offset() != 0 || reader.at_end()) {
                state.SkipWithError("Incomplete C++ Reader input must remain resumable");
                return;
            }
            if (!reader.set_input({wire, sizeof wire}, 0, tlv::input_mode::final)) {
                state.SkipWithError("C++ Reader input replacement failed");
                return;
            }
            auto complete = reader.next();
            if (!complete || complete->value().size() != 1 ||
                complete->value().data()[0] != tlv::byte(0x5a)) {
                state.SkipWithError("C++ Reader did not resume the incomplete element");
                return;
            }
            benchmark::DoNotOptimize(complete->value().data());
            auto eof = reader.next();
            if (eof || eof.error().status() != tlv::errc::end_of_input || !reader.at_end()) {
                state.SkipWithError("Resumed C++ Reader did not reach final EOF");
                return;
            }
        }
    }
    reader_counters(state, count, count * 3, count * sizeof wire);
}

BENCHMARK_CAPTURE(cxx_reader_success, ber_next, framing::ber, traversal::next)
    ->Name("cxx_reader/next/ber")
    ->Arg(16)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_reader_success, fixed_next, framing::fixed, traversal::next)
    ->Name("cxx_reader/next/fixed")
    ->Arg(16)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_reader_success, ber_range, framing::ber, traversal::range)
    ->Name("cxx_reader/range/ber")
    ->Arg(16)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_reader_success, fixed_range, framing::fixed, traversal::range)
    ->Name("cxx_reader/range/fixed")
    ->Arg(16)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_reader_failure, ber_eof, framing::ber, failure::eof)
    ->Name("cxx_reader/failure/ber/eof")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_failure, fixed_eof, framing::fixed, failure::eof)
    ->Name("cxx_reader/failure/fixed/eof")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_failure, ber_truncated, framing::ber, failure::truncated_value)
    ->Name("cxx_reader/failure/ber/truncated_value")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_failure, fixed_truncated, framing::fixed, failure::truncated_value)
    ->Name("cxx_reader/failure/fixed/truncated_value")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_failure, ber_incremental, framing::ber, failure::incremental)
    ->Name("cxx_reader/failure/ber/need_more_data")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_failure, fixed_incremental, framing::fixed, failure::incremental)
    ->Name("cxx_reader/failure/fixed/need_more_data")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_failure, initialization, framing::ber, failure::initialization)
    ->Name("cxx_reader/failure/initialization")
    ->Arg(1)
    ->Arg(256);
BENCHMARK_CAPTURE(cxx_reader_resume, ber, framing::ber)
    ->Name("cxx_reader/resume/ber")
    ->Arg(16)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_reader_resume, fixed, framing::fixed)
    ->Name("cxx_reader/resume/fixed")
    ->Arg(16)
    ->Arg(4096);

} // namespace
#endif

// Match the capability requirements of the public Document facade itself.
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER && OPENTLV_QUERY && OPENTLV_CODEC &&      \
    OPENTLV_FORMAT_BER
#include "tlv++/document/document.hpp"

namespace {

enum class snapshot_change { none, primitive, retirement };

void document_counters(benchmark::State& state, size_t count) {
    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(count));
    state.counters["children/document"] = static_cast<double>(count);
    state.counters["nodes/document"] = static_cast<double>(count + 1);
}

void cxx_document_child_edit(benchmark::State& state) {
    const size_t count = static_cast<size_t>(state.range(0));
    const auto   wire = flat_input(count);
    auto         document = tlv::document::create(tlv::ber::format{});
    if (!document) {
        state.SkipWithError("C++ Document creation failed");
        return;
    }
    auto parent = document->insert(tlv::tag_bytes<0xe1>(), {wire.data(), wire.size()});
    if (!parent) {
        state.SkipWithError("C++ Document child fixture creation failed");
        return;
    }
    tlv::byte value = tlv::byte(0);
    for (auto _ : state) {
        value = value == tlv::byte(0) ? tlv::byte(1) : tlv::byte(0);
        size_t seen = 0;
        for (auto child : parent->children()) {
            if (!child.set({&value, 1})) {
                state.SkipWithError("C++ Document primitive edit failed");
                return;
            }
            ++seen;
        }
        if (seen != count) {
            state.SkipWithError("C++ Document child edit skipped a node");
            return;
        }
    }
    for (auto child : parent->children()) {
        if (child.value().size() != 1 || child.value().data()[0] != value) {
            state.SkipWithError("C++ Document primitive edit produced an incorrect Value");
            return;
        }
    }
    document_counters(state, count);
}

void cxx_document_snapshot(benchmark::State& state, snapshot_change change) {
    const size_t count = static_cast<size_t>(state.range(0));
    const auto   wire = flat_input(count);
    auto         document = tlv::document::create(tlv::ber::format{});
    if (!document) {
        state.SkipWithError("C++ Document creation failed");
        return;
    }
    auto parent = document->insert(tlv::tag_bytes<0xe1>(), {wire.data(), wire.size()});
    if (!parent) {
        state.SkipWithError("C++ Document child fixture creation failed");
        return;
    }
    std::vector<tlv::node> snapshot;
    snapshot.reserve(count);
    for (auto child : parent->children()) snapshot.push_back(child);
    if (snapshot.size() != count) {
        state.SkipWithError("C++ Document snapshot missed a child");
        return;
    }
    tlv::byte edited = tlv::byte(0x5a);
    for (auto _ : state) {
        if (change != snapshot_change::none) {
            state.PauseTiming();
            if (change == snapshot_change::primitive) {
                edited = edited == tlv::byte(0) ? tlv::byte(1) : tlv::byte(0);
                if (!snapshot.back().set({&edited, 1})) {
                    state.SkipWithError("C++ Document snapshot setup edit failed");
                    return;
                }
            } else {
                auto victim = parent->insert(tlv::tag_bytes<0x04>(), {});
                if (!victim) {
                    state.SkipWithError("C++ Document retirement setup insertion failed");
                    return;
                }
                victim->erase();
                if (*victim) {
                    state.SkipWithError("C++ Document retained an erased handle");
                    return;
                }
            }
            state.ResumeTiming();
        }
        size_t checksum = 0;
        for (const auto& child : snapshot) {
            auto value = child.value();
            if (value.size() != 1) {
                state.SkipWithError("C++ Document snapshot invalidated a surviving child");
                return;
            }
            checksum += static_cast<unsigned char>(value.data()[0]);
        }
        benchmark::DoNotOptimize(checksum);
        if (checksum != (count - 1) * 0x5a + static_cast<unsigned char>(edited)) {
            state.SkipWithError("C++ Document snapshot produced an incorrect Value");
            return;
        }
    }
    document_counters(state, count);
    state.counters["retirements/iteration"] = change == snapshot_change::retirement ? 1 : 0;
}

BENCHMARK(cxx_document_child_edit)
    ->Name("cxx_document/primitive_child_edit")
    ->Arg(16)
    ->Arg(256)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_document_snapshot, cached, snapshot_change::none)
    ->Name("cxx_document/snapshot/cached")
    ->Arg(16)
    ->Arg(256)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_document_snapshot, primitive, snapshot_change::primitive)
    ->Name("cxx_document/snapshot/after_primitive_edit")
    ->Arg(16)
    ->Arg(256)
    ->Arg(4096);
BENCHMARK_CAPTURE(cxx_document_snapshot, retirement, snapshot_change::retirement)
    ->Name("cxx_document/snapshot/after_retirement")
    ->Arg(16)
    ->Arg(256)
    ->Arg(4096);

} // namespace
#endif
