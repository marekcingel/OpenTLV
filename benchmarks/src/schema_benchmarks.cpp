// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Release timings for the Schema workloads also measured by the Callgrind driver.

#include "../callgrind/schema_workloads.h"

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>

namespace {

const schema_workloads_t& fixtures() {
    static schema_workloads_t value;
    static const bool         ready = (schema_workloads_init(&value), true);
    (void)ready;
    return value;
}

// Prepared handles use the new API, so they live here rather than in the
// Callgrind harness, which is also compiled against older baseline checkouts.
#if SCHEMA_WORKLOADS_GENERIC
struct generic_handles {
    tlv_schema_checked_t shared, flat, recursive;
};

const generic_handles& generic_checked() {
    static generic_handles value;
    static const bool      ready = [] {
        const schema_workloads_t& w = fixtures();
        return tlv_schema_prepare(&value.shared, &w.shared[0], nullptr) == TLV_OK &&
               tlv_schema_prepare(&value.flat, &w.flat_schema, nullptr) == TLV_OK &&
               tlv_schema_prepare(&value.recursive, &w.recursive, nullptr) == TLV_OK;
    }();
    (void)ready;
    return value;
}

int schema_validate_checked_shared(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = sizeof w->empty_sequence;
    return tlv_schema_validate_checked(&generic_checked().shared, w->empty_sequence,
                                       sizeof w->empty_sequence, &tlv_format_ber, 8, 8,
                                       nullptr) == TLV_OK;
}

int schema_validate_checked_flat(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_FLAT_WIRE;
    return tlv_schema_validate_checked(&generic_checked().flat, w->flat, SCHEMA_FLAT_WIRE,
                                       &tlv_format_ber, 8, SCHEMA_FLAT_ENTRIES, nullptr) == TLV_OK;
}

int schema_validate_checked_recursive(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_NESTED_WIRE;
    return tlv_schema_validate_checked(&generic_checked().recursive, w->nested, SCHEMA_NESTED_WIRE,
                                       &tlv_format_ber, SCHEMA_NESTED_DEPTH + 1,
                                       SCHEMA_NESTED_ELEMENTS, nullptr) == TLV_OK;
}
#endif

#if SCHEMA_WORKLOADS_DER
struct der_handles {
    tlv_der_schema_checked_t shared, flat, recursive;
};

const der_handles& der_checked() {
    static der_handles value;
    static const bool  ready = [] {
        const schema_workloads_t& w = fixtures();
        return tlv_der_schema_prepare(&value.shared, &w.der_shared[0], nullptr) == TLV_OK &&
               tlv_der_schema_prepare(&value.flat, &w.der_flat, nullptr) == TLV_OK &&
               tlv_der_schema_prepare(&value.recursive, &w.der_recursive, nullptr) == TLV_OK;
    }();
    (void)ready;
    return value;
}

int der_read_checked(const tlv_der_schema_checked_t& checked, const uint8_t* data, size_t size,
                     uint64_t* checksum) {
    tlv_element_t element;
    size_t        consumed = 0;
    if (tlv_der_schema_read_checked(&checked, data, size, nullptr, &element, &consumed, nullptr) !=
            TLV_OK ||
        consumed != size)
        return 0;
    *checksum = consumed + static_cast<uint64_t>(element.value.size);
    return 1;
}

int der_schema_read_checked_shared(const schema_workloads_t* w, uint64_t* checksum) {
    return der_read_checked(der_checked().shared, w->empty_sequence, sizeof w->empty_sequence,
                            checksum);
}

int der_schema_read_checked_flat(const schema_workloads_t* w, uint64_t* checksum) {
    return der_read_checked(der_checked().flat, w->der_flat_input, SCHEMA_DER_FLAT_WIRE, checksum);
}

int der_schema_read_checked_recursive(const schema_workloads_t* w, uint64_t* checksum) {
    return der_read_checked(der_checked().recursive, w->nested, SCHEMA_NESTED_WIRE, checksum);
}
#endif

void schema_workload(benchmark::State& state, schema_workload_fn run, size_t input_bytes) {
    const schema_workloads_t& w = fixtures();
    uint64_t                  checksum = 0;
    for (auto _ : state) {
        if (!run(&w, &checksum)) {
            state.SkipWithError("unexpected Schema result");
            return;
        }
        benchmark::DoNotOptimize(checksum);
    }
    if (input_bytes)
        state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(input_bytes));
}

bool register_schema_benchmarks() {
    struct entry {
        const char*        name;
        schema_workload_fn run;
        size_t             input_bytes;
    };
    const entry entries[] = {
#if SCHEMA_WORKLOADS_GENERIC
        {"schema/check/shared", schema_check_shared, 0},
        {"schema/validate/shared", schema_validate_shared, 2},
        {"schema/check/flat", schema_check_flat, 0},
        {"schema/validate/flat", schema_validate_flat, SCHEMA_FLAT_WIRE},
        {"schema/check/recursive", schema_check_recursive, 0},
        {"schema/validate/recursive", schema_validate_recursive, SCHEMA_NESTED_WIRE},
        {"schema/validate_checked/shared", schema_validate_checked_shared, 2},
        {"schema/validate_checked/flat", schema_validate_checked_flat, SCHEMA_FLAT_WIRE},
        {"schema/validate_checked/recursive", schema_validate_checked_recursive,
         SCHEMA_NESTED_WIRE},
#endif
#if SCHEMA_WORKLOADS_DER
        {"der_schema/check/shared", der_schema_check_shared, 0},
        {"der_schema/read/shared", der_schema_read_shared, 2},
        {"der_schema/check/flat", der_schema_check_flat, 0},
        {"der_schema/read/flat", der_schema_read_flat, SCHEMA_DER_FLAT_WIRE},
        {"der_schema/check/recursive", der_schema_check_recursive, 0},
        {"der_schema/read/recursive", der_schema_read_recursive, SCHEMA_NESTED_WIRE},
        {"der_schema/read_checked/shared", der_schema_read_checked_shared, 2},
        {"der_schema/read_checked/flat", der_schema_read_checked_flat, SCHEMA_DER_FLAT_WIRE},
        {"der_schema/read_checked/recursive", der_schema_read_checked_recursive,
         SCHEMA_NESTED_WIRE},
#endif
        {nullptr, nullptr, 0}};
    for (const auto& entry : entries)
        if (entry.name)
            benchmark::RegisterBenchmark(entry.name, schema_workload, entry.run, entry.input_bytes);
    return true;
}

const bool registered = register_schema_benchmarks();

} // namespace
