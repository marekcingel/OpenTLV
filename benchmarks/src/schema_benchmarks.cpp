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
#endif
#if SCHEMA_WORKLOADS_DER
        {"der_schema/check/shared", der_schema_check_shared, 0},
        {"der_schema/read/shared", der_schema_read_shared, 2},
        {"der_schema/check/flat", der_schema_check_flat, 0},
        {"der_schema/read/flat", der_schema_read_flat, SCHEMA_DER_FLAT_WIRE},
        {"der_schema/check/recursive", der_schema_check_recursive, 0},
        {"der_schema/read/recursive", der_schema_read_recursive, SCHEMA_NESTED_WIRE},
#endif
        {nullptr, nullptr, 0}};
    for (const auto& entry : entries)
        if (entry.name)
            benchmark::RegisterBenchmark(entry.name, schema_workload, entry.run, entry.input_bytes);
    return true;
}

const bool registered = register_schema_benchmarks();

} // namespace
