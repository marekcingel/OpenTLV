# Query hardening and release checklist

Query F1–F5 are delivery phases within the Execution Foundation and all are 1.0
prerequisites. [Epic #518](https://github.com/marekcingel/OpenTLV/issues/518)
replaces the former 44 child issues with #519–#523. Completion requires equivalent
phase evidence, rather than closed issue states alone.

Run `python scripts/check_query_release.py --output build/query-release.json` for
the inventory of every normative rule, function/axis conformance category and
public C Query capability. Mappings include the independent corpus and named
native resource/lifetime tests. Inventory success checks mappings; the report's
`ready` field separately records release readiness.

For a release candidate add `--release --evidence PATH`. Strict mode rejects dirty
candidates, wrong-commit evidence, missing capabilities and changed artifact
hashes. Evidence JSON contains `commit`, `phases` (F1–F5), `facades` (C, CLI, C++,
Rust, Python, Go, Lua, JS/WASM) and `checks`. Each record requires
`status: "passed"`, relative `artifact` and its `sha256`. Facade records list all
passed public C `capabilities`; CLI lists common corpus feature IDs. Language
facades need `surface: "idiomatic"`; raw FFI is insufficient. Required checks are
listed in the generated report: conformance, properties, ASan/UBSan fuzzing, MSan
or justified exclusion, allocation/recursion, 32/64-bit work/storage boundaries,
benchmarks and ABI snapshots. Java/C# become additional gates when supported;
this repository does not claim those implementations.

## Resource and validation boundaries

Compiler, loader and execution use caller storage; owning Documents, snapshots
and wrappers may allocate. The Clang direct-call graph audit follows internal
helpers transitively and rejects allocation dependencies and recursion. It
conservatively combines translation-unit graphs. Arbitrary external Format,
resolver, codec, Source and visitor function-pointer targets remain caller-owned
contracts; the audit does not prove arbitrary callback implementations safe.

S0 structural work grows with events times program states plus inspected Tag and
Value bytes. KMP `contains` charges comparisons including fallbacks. Inspections
of overlapping constructed Values are counted separately; wire size alone cannot
bound their total. S1 adds scope evidence. S2/D use explicit candidate capacity,
instruction frames and per-frame node sets. Arbitrary nested contexts revisit
instructions and may be superlinear. Work limits charge VM iterations, scans,
sets and bytes; exact/one-short tests verify rejection. See the canonical
[cost contract](../concepts/query-language.md#storage-and-execution) for snapshot
encoding costs. No universal O(n) claim applies to D or caller hooks.

Generated trees reuse the property's commit-to-seed mapping. Manifests separate
wire/query/typed bindings in `wire.json` from independently calculated identities
and scalars in `expected.json`. Failure records retain command, seed, tree, query,
expected result, optimization mode and legal prefix-window boundary. The oracle
checks child/descendant inclusion, set cardinalities, ordering and uniqueness
before native backend comparisons. Window tests grow retained original prefixes;
they never discard still-borrowed fragments or publish partial Elements. Fixed
fixtures additionally test every prefix boundary and the frozen V1 reference
where applicable. Generated failure records include deterministic minimized
reproducers: subtree deletion, primitive Value shortening and predicate removal
recompute independent expectations and preserve the native failure category.
Shrinking is bounded to 128 native attempts per failure; it preserves valid
framing and adjusts prefix boundaries. Provider/diagnostic fixtures retain their
original reproducer rather than using the generated-tree shrinker.

Fuzzing separates text compilation/execution from arbitrary image bytes.
`query_program` uses a grammar dictionary; `query_image` verifies bounded read-only
loading. All harnesses have finite resource bounds. Linux Clang ASan/UBSan is
supported by the fuzz workflow. MSVC lacks libFuzzer/UBSan. MSan requires compatible
instrumented runtime/dependencies; ASan/UBSan success is not MSan evidence.
For native sanitizer runs without external C++ dependencies, enable
`OPENTLV_BUILD_QUERY_TESTS=ON`, disable unit/integration/property tests, CLI and
C++, and build `test-query-conformance`. This independent C runner remains
available without GoogleTest or the CLI. `OPENTLV_BUILD_TESTS` must remain enabled.

Benchmarks separate sizing, compilation, image loading, S0, S1, S2, prebuilt D and
scalar execution, with optimization variants and program/workspace/candidate/
scratch counters. Current inputs are project-owned MIT synthetic BER sequences,
without imported captures. V1 matcher timings exclude parsing; overhead claims
require identical event workloads. Short-run ratios are advisory. Release
evidence must record platform, toolchain, repetitions, variance and an accepted
regression threshold, plus depth/width/Value scaling.

`scripts/query_benchmark_budget.py` compares aggregate medians against a supplied
baseline. Its initial advisory budget is 25% slowdown at at most 10% coefficient
of variation. Both result contexts must carry the same `query_platform` identifier
(OS, toolchain, architecture and controlled machine class). Missing/noisy/cross-
platform measurements remain unverified; `--enforce` refuses them. These initial
policy limits still need accepted per-platform release baselines, and are not an
assertion of zero overhead relative to V1. Shared-runner CI records measurements
and checks the comparison infrastructure without hard-failing noisy timings.

## Current release blockers

The [binding capability matrix](../concepts/bindings.md#capability-parity-through-the-public-facade)
marks full compiled Query missing in Rust, Python, Go and Lua and incomplete in
C++. JS/WASM lacks a full native Query/Document facade. Complete common corpus
runners and F4 evidence must precede #523 closure; V1-only success cannot satisfy
the gate. Candidate ABI matrices, MSan results/exclusions and accepted
platform-specific benchmark budgets also require release evidence. The new
inventory and strict checker make these requirements reviewable rather than
claiming the current checkout is ready for 1.0.
