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
and ABI snapshots. Java/C# become additional gates when supported;
this repository does not claim those implementations.

Benchmarks are temporarily advisory while Query functionality is completed.
Missing measurements, regressions, noisy timings and unaccepted baselines do
not block this gate. The report lists benchmarks under `advisory_checks`.
Both `work-budgets-32-64` and
`ABI-32-64` records require `pointer_bits: [32, 64]`. Artifact paths must stay
inside the evidence directory. Run `python scripts/test_query_release.py` to
check rejection of stale, malformed, incomplete or modified evidence.

The [Query release candidate workflow](../../.github/workflows/query-release.yml)
executes this strict gate through `workflow_dispatch` or `workflow_call`. Supply
the ID of a successful Actions run for the same candidate commit. That run must
contain the `query-candidate-evidence` artifact with `manifest.json` at its root
and all files referenced by the manifest. The workflow verifies the producer's
commit and successful conclusion before downloading evidence, then retains the
gate report even on failure. Release automation can depend on this reusable
workflow; an inventory-only hardening run cannot substitute for it.

Each manifest entry must describe checks that actually ran, including the exact
facade capabilities exercised. In particular, do not copy the generated list of
required C symbols into a passing facade record without corresponding tests.
The workflow validates provenance and completeness of supplied evidence; it does
not manufacture missing phase approval or capability coverage. The per-phase
[implementation audit](query-phase-audit.md) records implementation and local
validation separately from missing candidate runs.

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
require identical event workloads. Measurements are advisory; performance
optimization and accepted regression thresholds are deferred until Query
functionality is complete. Retained measurements should record platform,
toolchain, repetitions, variance and depth/width/Value scaling.

`scripts/query_benchmark_budget.py` compares aggregate medians against a supplied
baseline. Its initial advisory budget is 25% slowdown at at most 10% coefficient
of variation. Both result contexts must carry the same `query_platform` identifier
(OS, toolchain, architecture and controlled machine class). Missing/noisy/cross-
platform measurements remain unverified; `--enforce` refuses them. These initial
policy limits are available for optional local comparisons, and are not an
assertion of zero overhead relative to V1. The release gate does not invoke
`--enforce` or require accepted baselines. Shared-runner CI records measurements
without making measurement or comparison failures required checks.

## Public-facade evidence and candidate requirements

The common compiled-language corpus has public-facade runners for C++, CLI,
Rust, Python, Go, Lua and JS/WASM. These exercise optimized and unoptimized
programs, stream/retained/Document backends where exposed, prefix continuation,
scalar results and diagnostics. CLI name-resolution cases using a fixture-owned
provider remain explicit exclusions; the CLI has its own EMV resolver. V1-only
success cannot satisfy the compiled-language gate.

JS/WASM has an owning Query/Document facade over the C engine, including custom
NUM/BCD/TEXT/DATE conversion callbacks, canonical event feeding, completed
selection edits and contextual Query Schema validation. Rust, Python, Go and Lua
expose the same integration capabilities through their ownership models.
Dedicated regressions also cover semantic Tag adapters, scoped dynamic,
Definition and EMV resolvers, configured Fixed Formats, source-bearing events,
ordinals, V1 compatibility and checked two-pass compilation. The
[binding capability matrix](../concepts/bindings.md#capability-parity-through-the-public-facade)
records these Query capabilities separately from general whole-library facade
gaps. Existing Format configurations are supported; Rust shares one immutable
Fixed owner across consumers to preserve native context identity.

The ABI checker covers native 64-bit, native x86 and wasm32 layouts. Sanitizer
campaign reports retain binary hashes, commands, logs and minimized failures.
`memory_campaign.py` retries only the documented pre-main MSan shadow-mapping
failure, never a sanitizer finding. Candidate evidence must still be produced
for the exact clean commit; local checks against an uncommitted worktree cannot
be substituted for that evidence. Complete C capability coverage remains a
release gate; benchmark baselines are temporarily advisory.
