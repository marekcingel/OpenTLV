// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/config.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/builtins/lldp/lldp.h"
#include "tlv/formats/fixed.h"
#include "tlv/formats/variable.h"
#include "tlv/reader/tree.h"
#include "tlv/writer/writer.h"
#include "tlv/document/document.h"

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

enum class workload {
    ber_small,
    ber_large,
    ber_definite,
    ber_indefinite,
    fixed_tlv,
    fixed_ltv,
    variable_tlv,
    variable_sparse,
    packed_lldp
};

struct input {
    tlv_fixed_format_t fixed = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_variable_format_t variable = {{0x1f, 0x1f, 0x80, 0x7f, 8, nullptr},
                                      {0x80, 0x7f, TLV_BYTE_ORDER_BIG_ENDIAN, nullptr},
                                      TLV_ELEMENT_ORDER_TLV,
                                      TLV_LENGTH_SCOPE_VALUE,
                                      nullptr};
    tlv_format_t          format = {};
    std::vector<uint8_t>  wire;
    size_t                roots = 16000;
    size_t                elements = 16000;
    size_t                depth = 0;

    // Format contexts borrow members, so this fixture must never be copied/moved.
    input() = default;
    input(const input&) = delete;
    input& operator=(const input&) = delete;
};

bool encode_flat(input& data, size_t count, size_t value_size, uint8_t tag) {
    std::vector<uint8_t> value(value_size, 0x5a);
    data.wire.resize(count * (value_size + 16));
    tlv_writer_t writer;
    if (tlv_writer_init(&writer, data.wire.data(), data.wire.size(), &data.format) != TLV_OK)
        return false;
    for (size_t i = 0; i < count; ++i) {
        if (tlv_writer_write(&writer, tlv_tag(&tag, 1), value.data(), value.size()) != TLV_OK)
            return false;
    }
    data.wire.resize(tlv_writer_size(&writer));
    data.roots = data.elements = count;
    return true;
}

bool prepare(input& data, workload kind) {
    data.format = tlv_format_ber;
    if (kind == workload::fixed_tlv || kind == workload::fixed_ltv) {
        if (kind == workload::fixed_ltv) {
            data.fixed.element_order = TLV_ELEMENT_ORDER_LTV;
            data.fixed.length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE;
        }
        if (tlv_fixed_format_init(&data.format, &data.fixed) != TLV_OK) return false;
    } else if (kind == workload::variable_tlv || kind == workload::variable_sparse) {
        if (kind == workload::variable_sparse) data.variable.length.payload_mask = 0x55;
        if (tlv_variable_format_init(&data.format, &data.variable) != TLV_OK) return false;
    } else if (kind == workload::packed_lldp) {
#if OPENTLV_LLDP
        data.format = tlv_format_lldp;
#else
        return false;
#endif
    }
    if (kind == workload::ber_large) return encode_flat(data, 128, 4096, 0x04);
    if (kind != workload::ber_definite && kind != workload::ber_indefinite)
        return encode_flat(data, 16000, 1, 0x04);

    // 32 constructed ancestors and one primitive leaf per root. The indefinite
    // fixture is deliberately explicit because the canonical BER Writer emits
    // definite lengths; setup is outside the measured State loop in both cases.
    std::vector<uint8_t> subtree = {0x04, 0x01, 0x5a};
    for (size_t depth = 0; depth < 32; ++depth) {
        if (kind == workload::ber_indefinite) {
            subtree.insert(subtree.begin(), {0x30, 0x80});
            subtree.insert(subtree.end(), {0, 0});
        } else {
            std::vector<uint8_t> parent(subtree.size() + 16);
            tlv_writer_t         writer;
            const uint8_t        tag = 0x30;
            if (tlv_writer_init(&writer, parent.data(), parent.size(), &data.format) != TLV_OK ||
                tlv_writer_write(&writer, tlv_tag(&tag, 1), subtree.data(), subtree.size()) !=
                    TLV_OK)
                return false;
            parent.resize(tlv_writer_size(&writer));
            subtree.swap(parent);
        }
    }
    data.roots = 200;
    data.elements = 6600;
    data.depth = 32;
    data.wire.reserve(data.roots * subtree.size());
    for (size_t i = 0; i < data.roots; ++i)
        data.wire.insert(data.wire.end(), subtree.begin(), subtree.end());
    return true;
}

void counters(benchmark::State& state, const input& data, size_t count) {
    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(count));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(data.wire.size()));
    state.counters["elements/input"] = static_cast<double>(count);
    state.counters["wire_bytes/input"] = static_cast<double>(data.wire.size());
}

void reader_decode(benchmark::State& state, workload kind) {
    input data;
    if (!prepare(data, kind)) {
        state.SkipWithError("failed to prepare Reader workload");
        return;
    }
    for (auto _ : state) {
        tlv_reader_t  reader;
        tlv_element_t element;
        size_t        count = 0;
        tlv_result_t  rc =
            tlv_reader_init(&reader, data.wire.data(), data.wire.size(), &data.format);
        if (rc == TLV_OK) {
            while ((rc = tlv_reader_next(&reader, &element)) == TLV_OK) {
                benchmark::DoNotOptimize(element.value.data);
                ++count;
            }
        }
        if (rc != TLV_END || count != data.roots) {
            state.SkipWithError("Reader did not decode the exact root count and reach EOF");
            break;
        }
    }
    counters(state, data, data.roots);
}

void tree_decode(benchmark::State& state, workload kind) {
    input data;
    if (!prepare(data, kind)) {
        state.SkipWithError("failed to prepare Tree Reader workload");
        return;
    }
    std::vector<tlv_tree_frame_t> frames(data.depth);
    for (auto _ : state) {
        tlv_tree_reader_t reader;
        tlv_tree_event_t  event;
        size_t            count = 0, ends = 0;
        tlv_result_t      rc =
            tlv_tree_reader_init(&reader, data.wire.data(), data.wire.size(), &data.format,
                                 frames.data(), frames.size(), data.depth, data.elements);
        if (rc == TLV_OK) {
            while ((rc = tlv_tree_reader_next_event(&reader, &event)) == TLV_OK) {
                benchmark::DoNotOptimize(event.kind);
                if (event.kind == TLV_TREE_END)
                    ++ends;
                else
                    ++count;
            }
        }
        if (rc != TLV_END || count != data.elements || ends != data.roots * data.depth) {
            state.SkipWithError("Tree Reader did not decode the exact element/END counts and EOF");
            break;
        }
    }
    counters(state, data, data.elements);
}

#if OPENTLV_DOCUMENT
struct allocation_profile {
    size_t calls = 0;
    size_t releases = 0;
    size_t bytes = 0;
    size_t aligned_bytes = 0;
};

size_t aligned_size(size_t size) {
    const size_t alignment = alignof(std::max_align_t);
    return (size + alignment - 1) / alignment * alignment;
}

void* count_allocate(void* context, size_t size) {
    auto& profile = *static_cast<allocation_profile*>(context);
    ++profile.calls;
    profile.bytes += size;
    profile.aligned_bytes += aligned_size(size);
    return std::malloc(size);
}

void count_release(void* context, void* memory) {
    ++static_cast<allocation_profile*>(context)->releases;
    std::free(memory);
}

struct arena {
    std::vector<std::max_align_t> storage;
    size_t                        used = 0;
    size_t                        calls = 0;
    size_t                        releases = 0;
};

void* arena_allocate(void* context, size_t size) {
    auto&        pool = *static_cast<arena*>(context);
    const size_t reserved = aligned_size(size);
    const size_t capacity = pool.storage.size() * sizeof(std::max_align_t);
    if (reserved > capacity - pool.used) return nullptr;
    auto* result = reinterpret_cast<uint8_t*>(pool.storage.data()) + pool.used;
    pool.used += reserved;
    ++pool.calls;
    return result;
}

void arena_release(void* context, void*) {
    ++static_cast<arena*>(context)->releases;
}

void document_decode(benchmark::State& state, workload kind, bool use_arena) {
    input data;
    if (!prepare(data, kind)) {
        state.SkipWithError("failed to prepare Document workload");
        return;
    }
    tlv_document_options_t options;
    tlv_document_options_init(&options, &data.format);
    options.max_depth = data.depth;
    options.max_elements = data.elements;

    // Count malloc/free requests once outside timing, then measure the actual
    // default allocator without an instrumentation wrapper. The same exact
    // request profile sizes the benchmark-only arena without guessed node sizes.
    allocation_profile profile;
    tlv_allocator_t    counting = {&profile, count_allocate, count_release};
    options.allocator = &counting;
    tlv_document_t*    document = nullptr;
    const tlv_result_t calibration =
        tlv_document_parse(data.wire.data(), data.wire.size(), &options, &document, nullptr);
    const size_t count = document ? tlv_document_count(document) : 0;
    tlv_document_free(document);
    if (calibration != TLV_OK || count != data.elements || profile.calls != profile.releases) {
        state.SkipWithError("Document allocation calibration or element count failed");
        return;
    }
    arena pool;
    if (use_arena)
        pool.storage.resize((profile.aligned_bytes + sizeof(std::max_align_t) - 1) /
                            sizeof(std::max_align_t));
    tlv_allocator_t custom = {&pool, arena_allocate, arena_release};
    options.allocator = use_arena ? &custom : nullptr;
    for (auto _ : state) {
        document = nullptr;
        const tlv_result_t rc =
            tlv_document_parse(data.wire.data(), data.wire.size(), &options, &document, nullptr);
        const size_t actual = document ? tlv_document_count(document) : 0;
        benchmark::DoNotOptimize(document);
        tlv_document_free(document);
        const bool allocations_ok =
            !use_arena || (pool.calls == profile.calls && pool.releases == profile.releases &&
                           pool.used == profile.aligned_bytes);
        pool.used = pool.calls = pool.releases = 0;
        if (rc != TLV_OK || actual != data.elements || !allocations_ok) {
            state.SkipWithError("Document parse, exact count, or arena cleanup validation failed");
            break;
        }
    }
    counters(state, data, data.elements);
    state.counters["alloc_calls/input"] = static_cast<double>(profile.calls);
    state.counters["free_calls/input"] = static_cast<double>(profile.releases);
    state.counters["alloc_bytes/input"] = static_cast<double>(profile.bytes);
    state.counters["arena_bytes/input"] =
        use_arena ? static_cast<double>(profile.aligned_bytes) : 0;
}
#endif

bool register_decode_benchmarks() {
    struct entry {
        const char* name;
        workload    kind;
    };
    const entry entries[] = {
        {"ber_flat_small", workload::ber_small},
        {"ber_flat_large", workload::ber_large},
        {"ber_nested_definite", workload::ber_definite},
        {"ber_nested_indefinite", workload::ber_indefinite},
        {"fixed_tlv", workload::fixed_tlv},
        {"fixed_ltv", workload::fixed_ltv},
        {"variable_tlv", workload::variable_tlv},
        {"variable_sparse", workload::variable_sparse},
#if OPENTLV_LLDP
        {"packed_lldp", workload::packed_lldp},
#endif
    };
    for (const auto& entry : entries) {
        benchmark::RegisterBenchmark((std::string("reader_decode/") + entry.name).c_str(),
                                     reader_decode, entry.kind);
        benchmark::RegisterBenchmark((std::string("tree_decode/") + entry.name).c_str(),
                                     tree_decode, entry.kind);
#if OPENTLV_DOCUMENT
        benchmark::RegisterBenchmark(
            (std::string("document_decode/") + entry.name + "/default").c_str(), document_decode,
            entry.kind, false);
        benchmark::RegisterBenchmark(
            (std::string("document_decode/") + entry.name + "/arena").c_str(), document_decode,
            entry.kind, true);
#endif
    }
    return true;
}

const bool registered = register_decode_benchmarks();

} // namespace
