// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/query/program.h"

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>

namespace {

std::vector<uint8_t> encode_stream(std::size_t value_size, std::size_t entry_count) {
    std::vector<uint8_t> value(value_size, 0x5a);
    const std::size_t    length_size = value_size < 0x80 ? 1 : value_size <= 0xff ? 2 : 3;
    std::vector<uint8_t> encoded(entry_count * (1 + length_size + value_size));
    tlv_writer_t         writer;
    if (tlv_writer_init(&writer, encoded.data(), encoded.size(), &tlv_format_ber) != TLV_OK) {
        return std::vector<uint8_t>();
    }
    for (std::size_t i = 0; i < entry_count; ++i) {
        const uint8_t tag_byte = static_cast<uint8_t>(0x80 + i % 31);
        if (tlv_writer_write(&writer, tlv_tag(&tag_byte, 1), value.data(), value.size()) !=
            TLV_OK) {
            return std::vector<uint8_t>();
        }
    }
    return encoded;
}

void parse_entries(benchmark::State& state) {
    const std::size_t          value_size = static_cast<std::size_t>(state.range(0));
    const std::vector<uint8_t> encoded = encode_stream(value_size, 1);
    if (encoded.empty()) {
        state.SkipWithError("failed to prepare encoded TLV element");
        return;
    }

    for (auto _ : state) {
        tlv_reader_t  reader;
        tlv_element_t element;
        benchmark::DoNotOptimize(
            tlv_reader_init(&reader, encoded.data(), encoded.size(), &tlv_format_ber));
        benchmark::DoNotOptimize(tlv_reader_next(&reader, &element));
        benchmark::DoNotOptimize(element.value.data);
        benchmark::DoNotOptimize(element.value.size);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(encoded.size()));
}

void encode_entries(benchmark::State& state) {
    const std::size_t          value_size = static_cast<std::size_t>(state.range(0));
    const std::vector<uint8_t> value(value_size, 0x5a);
    std::vector<uint8_t>       output(value_size + 4);

    for (auto _ : state) {
        tlv_writer_t writer;
        benchmark::DoNotOptimize(
            tlv_writer_init(&writer, output.data(), output.size(), &tlv_format_ber));
        benchmark::DoNotOptimize(
            tlv_writer_write(&writer, (TLV_TAG(0x42)), value.data(), value.size()));
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(value.size()));
}

void parse_stream(benchmark::State& state) {
    const std::size_t          entry_count = static_cast<std::size_t>(state.range(0));
    const std::vector<uint8_t> encoded = encode_stream(16, entry_count);
    if (encoded.empty()) {
        state.SkipWithError("failed to prepare encoded TLV stream");
        return;
    }

    for (auto _ : state) {
        tlv_reader_t  reader;
        tlv_element_t element;
        benchmark::DoNotOptimize(
            tlv_reader_init(&reader, encoded.data(), encoded.size(), &tlv_format_ber));
        while (!tlv_reader_at_end(&reader)) {
            benchmark::DoNotOptimize(tlv_reader_next(&reader, &element));
            benchmark::DoNotOptimize(element.value.data);
        }
    }
    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(entry_count));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(encoded.size()));
}

BENCHMARK(parse_entries)->Arg(16)->Arg(127)->Arg(128)->Arg(255)->Arg(256)->Arg(4096);
BENCHMARK(encode_entries)->Arg(16)->Arg(127)->Arg(128)->Arg(255)->Arg(256)->Arg(4096);
BENCHMARK(parse_stream)->Arg(16)->Arg(256)->Arg(4096);

tlv_visit_result_t query_match(const tlv_tree_event_t* event, void*) {
    auto offset = event->offset;
    benchmark::DoNotOptimize(offset);
    return TLV_VISIT_CONTINUE;
}

void query_s0_stream(benchmark::State& state) {
    const char* text = "//80 | //81";
    size_t      scratch_size, alignment;
    if (tlv_query_compile_scratch(text, std::strlen(text), nullptr, &scratch_size, &alignment,
                                  nullptr) != TLV_OK) {
        state.SkipWithError("Query scratch discovery failed");
        return;
    }
    std::vector<uint64_t>    scratch((scratch_size + 7) / 8);
    tlv_query_program_info_t info{};
    info.struct_size = sizeof info;
    if (tlv_query_compile(text, std::strlen(text), nullptr, scratch.data(), scratch_size, nullptr,
                          0, &info, nullptr) != TLV_OK) {
        state.SkipWithError("Query sizing failed");
        return;
    }
    std::vector<uint64_t> program((info.program_size + 7) / 8);
    if (tlv_query_compile(text, std::strlen(text), nullptr, scratch.data(), scratch_size,
                          program.data(), info.program_size, &info, nullptr) != TLV_OK) {
        state.SkipWithError("Query compilation failed");
        return;
    }
    const auto* compiled = reinterpret_cast<const tlv_query_program_t*>(program.data());
    size_t      workspace_size;
    if (tlv_query_exec_size(compiled, 0, &workspace_size, &alignment) != TLV_OK) {
        state.SkipWithError("Query workspace discovery failed");
        return;
    }
    std::vector<uint64_t> workspace((workspace_size + 7) / 8);
    const auto            encoded = encode_stream(16, static_cast<size_t>(state.range(0)));
    for (auto _ : state) {
        tlv_query_exec_t* exec;
        tlv_tree_reader_t reader;
        if (tlv_query_exec_init(compiled, workspace.data(), workspace_size, 0,
                                static_cast<size_t>(state.range(0)), SIZE_MAX, &exec) != TLV_OK ||
            tlv_tree_reader_init(&reader, encoded.data(), encoded.size(), &tlv_format_ber, nullptr,
                                 0, 0, static_cast<size_t>(state.range(0))) != TLV_OK ||
            tlv_query_program_visit(&reader, exec, query_match, nullptr, nullptr) != TLV_OK) {
            state.SkipWithError("Query execution failed");
            break;
        }
    }
    state.counters["workspace_bytes"] = static_cast<double>(workspace_size);
    state.counters["program_bytes"] = static_cast<double>(info.program_size);
    state.SetItemsProcessed(state.iterations() * state.range(0));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(encoded.size()));
}

BENCHMARK(query_s0_stream)->Arg(16)->Arg(256)->Arg(4096);

void query_v1_matcher(benchmark::State& state) {
    tlv_query_t query;
    if (tlv_query_parse("80", &query, nullptr) != TLV_OK) {
        state.SkipWithError("V1 Query parsing failed");
        return;
    }
    const uint8_t byte = 0x80;
    const auto    tag = tlv_tag(&byte, 1);
    for (auto _ : state) {
        tlv_query_matcher_t matcher;
        if (tlv_query_matcher_init(&matcher, &query) != TLV_OK) {
            state.SkipWithError("V1 matcher initialization failed");
            break;
        }
        for (int64_t i = 0; i < state.range(0); ++i) {
            auto matched = tlv_query_matcher_visit(&matcher, &tag, 0);
            benchmark::DoNotOptimize(matched);
        }
    }
    state.SetItemsProcessed(state.iterations() * state.range(0));
}

BENCHMARK(query_v1_matcher)->Arg(16)->Arg(256)->Arg(4096);

} // namespace
