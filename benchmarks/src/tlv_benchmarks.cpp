// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include "tlv/query/program.h"
#include "tlv/config.h"
#include "tlv/document/document.h"

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>
#include <string>
#include "tlv/formats/fixed.h"

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
    const char* text = "//80";
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

// Frozen V1 and S0 consume identical encoded inputs and canonical Tree events.
// This includes parsing in both paths; query_v1_matcher remains matcher-only.
void query_v1_stream(benchmark::State& state) {
    tlv_query_t query;
    if (tlv_query_parse("80", &query, nullptr) != TLV_OK) {
        state.SkipWithError("V1 Query parsing failed");
        return;
    }
    const auto encoded = encode_stream(16, static_cast<size_t>(state.range(0)));
    for (auto _ : state) {
        tlv_tree_reader_t   reader;
        tlv_query_matcher_t matcher;
        auto                rc = tlv_query_matcher_init(&matcher, &query);
        if (rc == TLV_OK)
            rc = tlv_tree_reader_init(&reader, encoded.data(), encoded.size(), &tlv_format_ber,
                                      nullptr, 0, 0, static_cast<size_t>(state.range(0)));
        if (rc != TLV_OK) {
            state.SkipWithError("V1 stream initialization");
            break;
        }
        tlv_tree_event_t event;
        while ((rc = tlv_tree_reader_next_event(&reader, &event)) == TLV_OK) {
            auto matched = tlv_query_matcher_visit(&matcher, &event.element.tag, event.depth);
            benchmark::DoNotOptimize(matched);
            if (matched) query_match(&event, nullptr);
        }
        if (rc != TLV_END) {
            state.SkipWithError("V1 stream traversal");
            break;
        }
    }
    state.SetItemsProcessed(state.iterations() * state.range(0));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(encoded.size()));
}
BENCHMARK(query_v1_stream)->Arg(16)->Arg(256)->Arg(4096);

// Project-owned synthetic captures (MIT), with independent depth, width,
// inspected Value bytes and Query-size dimensions. Setup stays outside timing.
void query_scaling(benchmark::State& state) {
    const int    kind = static_cast<int>(state.range(0));
    const size_t scale = static_cast<size_t>(state.range(1));
    std::string  text = kind == 0 ? "//9F26" : kind == 1 ? "//04" : "//80";
    auto         wire = encode_stream(kind == 3 ? scale : 8, kind == 3 || kind == 1 ? 1 : 256);
    auto         format = tlv_format_ber;
    tlv_fixed_format_t fixed{};
    if (kind == 0) {
        wire.resize(256 * 11);
        tlv_writer_t  writer;
        const uint8_t tag[] = {0x9f, 0x26};
        const uint8_t value[8] = {0};
        if (tlv_writer_init(&writer, wire.data(), wire.size(), &format) != TLV_OK) {
            state.SkipWithError("synthetic EMV-like setup");
            return;
        }
        for (size_t i = 0; i < 256; ++i)
            if (tlv_writer_write(&writer, tlv_tag(tag, 2), value, 8) != TLV_OK) {
                state.SkipWithError("synthetic EMV-like writing");
                return;
            }
        wire.resize(tlv_writer_size(&writer));
    } else if (kind == 1) {
        wire[0] = 0x04;
        for (size_t depth = 0; depth < scale; ++depth) {
            std::vector<uint8_t> wrapped(wire.size() + 8);
            tlv_writer_t         writer;
            const uint8_t        tag = 0x30;
            if (tlv_writer_init(&writer, wrapped.data(), wrapped.size(), &format) != TLV_OK ||
                tlv_writer_write(&writer, tlv_tag(&tag, 1), wire.data(), wire.size()) != TLV_OK) {
                state.SkipWithError("synthetic ASN.1 depth writing");
                return;
            }
            wrapped.resize(tlv_writer_size(&writer));
            wire.swap(wrapped);
        }
    } else if (kind == 2) {
        fixed.identifier.size = fixed.length.size = 1;
        fixed.length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN;
        if (tlv_fixed_format_init(&format, &fixed) != TLV_OK) {
            state.SkipWithError("generic Fixed setup");
            return;
        }
        wire = encode_stream(8, scale);
    } else if (kind == 3)
        text = "//80[contains(value(), x'5A5A5A5A5B')]";
    else if (kind == 4) {
        for (size_t i = 1; i < scale; ++i) text += " | //81";
    } else if (kind == 5) {
        text = "80";
        std::vector<uint8_t> nested(wire.size() + 32);
        tlv_writer_t         writer;
        const uint8_t        parent = 0x70, leaf = 0x80, value = 0;
        if (tlv_writer_init(&writer, nested.data(), nested.size(), &format) != TLV_OK ||
            tlv_writer_write(&writer, tlv_tag(&parent, 1), wire.data(), wire.size()) != TLV_OK ||
            tlv_writer_write(&writer, tlv_tag(&leaf, 1), &value, 1) != TLV_OK) {
            state.SkipWithError("pruning setup");
            return;
        }
        nested.resize(tlv_writer_size(&writer));
        wire.swap(nested);
    }
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.optimize = kind == 5 ? 1 : static_cast<int>(state.range(2));
    size_t bytes, alignment;
    auto   rc =
        tlv_query_compile_scratch(text.data(), text.size(), &options, &bytes, &alignment, nullptr);
    if (rc != TLV_OK) {
        state.SkipWithError("scaling compile scratch");
        return;
    }
    std::vector<uint64_t>    scratch((bytes + 7) / 8);
    tlv_query_program_info_t info{};
    info.struct_size = sizeof info;
    rc = tlv_query_compile(text.data(), text.size(), &options, scratch.data(), bytes, nullptr, 0,
                           &info, nullptr);
    if (rc != TLV_OK) {
        state.SkipWithError("scaling compile sizing");
        return;
    }
    std::vector<uint64_t> image((info.program_size + 7) / 8);
    rc = tlv_query_compile(text.data(), text.size(), &options, scratch.data(), bytes, image.data(),
                           info.program_size, &info, nullptr);
    const auto*  program = reinterpret_cast<const tlv_query_program_t*>(image.data());
    size_t       workspace_size;
    const size_t depth = kind == 1 ? scale + 1 : 1;
    if (rc == TLV_OK) rc = tlv_query_exec_size(program, depth, &workspace_size, &alignment);
    if (rc != TLV_OK) {
        state.SkipWithError("scaling streaming requirements");
        return;
    }
    std::vector<uint64_t>         workspace((workspace_size + 7) / 8);
    std::vector<tlv_tree_frame_t> frames(depth);
    tlv_query_exec_info_t         observed{};
    observed.struct_size = sizeof observed;
    for (auto _ : state) {
        tlv_query_exec_t* exec;
        tlv_tree_reader_t reader;
        rc = tlv_query_exec_init(program, workspace.data(), workspace_size, depth, 65536, SIZE_MAX,
                                 &exec);
        if (rc == TLV_OK && kind == 5) rc = tlv_query_exec_pruning(exec, state.range(2) != 0);
        if (rc == TLV_OK)
            rc = tlv_tree_reader_init(&reader, wire.data(), wire.size(), &format, frames.data(),
                                      frames.size(), depth, 65536);
        if (rc == TLV_OK)
            rc = tlv_query_program_visit(&reader, exec, query_match, nullptr, nullptr);
        if (rc == TLV_OK) rc = tlv_query_exec_info(exec, &observed);
        if (rc != TLV_OK) {
            state.SkipWithError("scaling execution");
            break;
        }
    }
    state.counters["work_operations"] = static_cast<double>(observed.work);
    state.counters["program_states"] = static_cast<double>(info.states);
    state.counters["workspace_bytes"] = static_cast<double>(workspace_size);
    state.counters["program_bytes"] = static_cast<double>(info.program_size);
    state.counters["retained_source_bytes"] = 0;
    state.counters["candidate_capacity"] = 0;
    state.counters["skipped_subtrees"] = static_cast<double>(observed.skipped_subtrees);
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(wire.size()));
    const char* labels[] = {"EMV-like",  "deep-ASN.1", "wide-Fixed",
                            "Value-KMP", "Query-size", "pruning"};
    state.SetLabel(labels[kind]);
}
BENCHMARK(query_scaling)
    ->Args({0, 1, 0})
    ->Args({0, 1, 1})
    ->Args({1, 8, 0})
    ->Args({1, 32, 0})
    ->Args({1, 64, 0})
    ->Args({2, 16, 0})
    ->Args({2, 256, 0})
    ->Args({2, 4096, 0})
    ->Args({3, 64, 0})
    ->Args({3, 1024, 0})
    ->Args({3, 4096, 0})
    ->Args({4, 1, 0})
    ->Args({4, 16, 0})
    ->Args({4, 64, 0})
    ->Args({4, 64, 1})
    ->Args({5, 256, 0})
    ->Args({5, 256, 1});

// Phase names keep parsing, compilation, validation and retained execution costs
// separate. Inputs are synthetic project-owned BER octet strings (MIT).
void query_phase(benchmark::State& state) {
    const int                   phase = static_cast<int>(state.range(0));
    const size_t                nodes = static_cast<size_t>(state.range(1));
    const char*                 texts[] = {"//80",
                                           "//80",
                                           "//80",
                                           "//80",
                                           "/80[exists(81)]",
                                           "(//80)[last()]",
                                           "//80/following::81",
                                           "count(//80)"};
    const char*                 text = texts[phase];
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.optimize = static_cast<int>(state.range(2));
    size_t scratch_size, alignment;
    auto   rc = tlv_query_compile_scratch(text, std::strlen(text), &options, &scratch_size,
                                          &alignment, nullptr);
    if (rc != TLV_OK) {
        state.SkipWithError("compile scratch");
        return;
    }
    std::vector<uint64_t>    scratch((scratch_size + 7) / 8);
    tlv_query_program_info_t info{};
    info.struct_size = sizeof info;
    rc = tlv_query_compile(text, std::strlen(text), &options, scratch.data(), scratch_size, nullptr,
                           0, &info, nullptr);
    if (rc != TLV_OK) {
        state.SkipWithError("compile sizing");
        return;
    }
    std::vector<uint64_t> image((info.program_size + 7) / 8);
    rc = tlv_query_compile(text, std::strlen(text), &options, scratch.data(), scratch_size,
                           image.data(), info.program_size, &info, nullptr);
    if (rc != TLV_OK) {
        state.SkipWithError("compile image");
        return;
    }
    const auto* program = reinterpret_cast<const tlv_query_program_t*>(image.data());
    size_t      validation_size;
    rc = tlv_query_program_load_scratch(program, info.program_size, &options, &validation_size,
                                        &alignment, nullptr);
    if (rc != TLV_OK) {
        state.SkipWithError("validation scratch");
        return;
    }
    std::vector<uint64_t> validation((validation_size + 7) / 8);
    size_t                workspace_size;
    bool                  retained = phase >= 5;
    rc = retained ? tlv_query_eval_size(program, 0, nodes, &workspace_size, &alignment)
                  : tlv_query_exec_size(program, 0, &workspace_size, &alignment);
    if (phase < 3)
        workspace_size = 0;
    else if (rc != TLV_OK) {
        state.SkipWithError("execution scratch");
        return;
    }
    std::vector<uint8_t> workspace(workspace_size + 15);
    void* aligned = reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(workspace.data()) + 15) &
                                            ~uintptr_t(15));
    const auto encoded = encode_stream(16, nodes);
#if OPENTLV_DOCUMENT
    tlv_document_t* document = nullptr;
    if (phase == 6) {
        tlv_document_options_t document_options;
        tlv_document_options_init(&document_options, &tlv_format_ber);
        rc = tlv_document_parse(encoded.data(), encoded.size(), &document_options, &document,
                                nullptr);
        if (rc != TLV_OK) {
            state.SkipWithError("Document setup");
            return;
        }
    }
#else
    if (phase == 6) {
        state.SkipWithError("Document disabled");
        return;
    }
#endif
    for (auto _ : state) {
        if (phase <= 1) {
            rc = tlv_query_compile(text, std::strlen(text), &options, scratch.data(), scratch_size,
                                   phase ? image.data() : nullptr, phase ? info.program_size : 0,
                                   &info, nullptr);
        } else if (phase == 2) {
            const tlv_query_program_t* loaded = nullptr;
            rc = tlv_query_program_load(program, info.program_size, &options, validation.data(),
                                        validation_size, &loaded, nullptr, nullptr);
            benchmark::DoNotOptimize(loaded);
        } else {
            tlv_query_exec_t* exec;
            rc = retained ? tlv_query_eval_init(program, nullptr, aligned, workspace_size, 0, nodes,
                                                SIZE_MAX, &exec)
                          : tlv_query_exec_init(program, aligned, workspace_size, 0, nodes,
                                                SIZE_MAX, &exec);
#if OPENTLV_DOCUMENT
            if (rc == TLV_OK && phase == 6)
                rc = tlv_document_query_evaluate(document, exec, nullptr, nullptr, 0, nullptr,
                                                 nullptr);
            else
#endif
                if (rc == TLV_OK) {
                tlv_tree_reader_t reader;
                rc = tlv_tree_reader_init(&reader, encoded.data(), encoded.size(), &tlv_format_ber,
                                          nullptr, 0, 0, nodes);
                if (rc == TLV_OK)
                    rc = tlv_query_program_visit(&reader, exec, query_match, nullptr, nullptr);
            }
        }
        if (rc != TLV_OK) {
            state.SkipWithError("Query phase failed");
            break;
        }
        benchmark::ClobberMemory();
    }
#if OPENTLV_DOCUMENT
    if (document) tlv_document_free(document);
#endif
    state.counters["program_bytes"] = static_cast<double>(info.program_size);
    state.counters["compile_scratch_bytes"] = static_cast<double>(scratch_size);
    state.counters["validation_scratch_bytes"] = static_cast<double>(validation_size);
    state.counters["workspace_bytes"] = static_cast<double>(workspace_size);
    state.counters["candidate_capacity"] = retained ? static_cast<double>(nodes) : 0;
    state.SetLabel(phase == 0   ? "sizing"
                   : phase == 1 ? "compile"
                   : phase == 2 ? "image-load"
                   : phase == 3 ? "S0"
                   : phase == 4 ? "S1"
                   : phase == 5 ? "S2"
                   : phase == 6 ? "D-prebuilt"
                                : "scalar");
}
BENCHMARK(query_phase)->ArgsProduct({{0, 1, 2, 3, 4, 5, 6, 7}, {16, 256, 4096}, {0, 1}});

#if OPENTLV_DOCUMENT
// Worst-case stale-address validation after each edit deliberately scans to the
// last node. Keep these size series to expose the documented quadratic loop cost.
void document_identity_edit_loop(benchmark::State& state) {
    const auto             encoded = encode_stream(1, static_cast<size_t>(state.range(0)));
    tlv_document_options_t options;
    tlv_document_options_init(&options, &tlv_format_ber);
    tlv_document_t* doc = nullptr;
    if (tlv_document_parse(encoded.data(), encoded.size(), &options, &doc, nullptr) != TLV_OK) {
        state.SkipWithError("Document creation failed");
        return;
    }
    tlv_node_t* last = tlv_document_first(doc);
    while (tlv_node_next(last)) last = tlv_node_next(last);
    const uint8_t value = 1;
    for (auto _ : state) {
        for (int64_t i = 0; i < state.range(0); ++i) {
            if (tlv_node_set_value(last, &value, 1) != TLV_OK) {
                state.SkipWithError("Document edit failed");
                break;
            }
            auto identity = tlv_document_node_identity(doc, last);
            benchmark::DoNotOptimize(identity);
        }
    }
    state.SetItemsProcessed(state.iterations() * state.range(0));
    tlv_document_free(doc);
}
BENCHMARK(document_identity_edit_loop)->Arg(16)->Arg(256)->Arg(4096);
#endif

} // namespace
