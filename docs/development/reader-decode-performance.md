# Reader decode measurements

This records the bounded optimization in
[#538](https://github.com/marekcingel/OpenTLV/issues/538). Reader, Tree Reader and
Document use the same canonical Format decoder. No public declaration, ABI,
allocation policy, borrowed lifetime or wire behavior changes.

## Scope and decisions

The issue's instrumented profile identified Reader, Format and field-composition
decoding as investigation targets. Its percentages are not uninstrumented cost
shares. The measurements here use the newer starting commit
`85513e6eed094e0b33e674f83cafe6ca837ac251`, rather than the issue's original
`12cecdd6a0e72bf01f902383bfc5b0239b675a25` profile.

Two independent changes were evaluated; only A is retained:

- **A, optional Reader error staging:** initialize Reader's temporary error
  object and request Format failure detail only when the caller requests
  diagnostics. Keep initialization on diagnostic calls because invalid Format
  arguments can return without writing detail.
- **B, contiguous payload masks:** extract low contiguous payload bits directly
  in the generic variable-field decoder. Retain the existing bit-gathering loop
  for sparse or shifted masks. This recognizes a field encoding property, not a
  protocol or builtin Format.

The B pilot reduced small-BER Reader median time by 2.4% relative to A, but an
unaffected fixed-TLV workload also decreased by 5.6%. That does not establish
an attributable improvement beyond host variation. B was removed, along with
its proposed mask-specific regression test.

Format still initializes callback result/error storage, always supplies a
non-NULL callback error object, validates complete ranges and borrowed bindings,
and publishes a decoded result only after validation. Source metadata and the
transactional result copy remain intact. Configuration checks remain in place;
this change introduces no pointer-keyed cache or new immutability assumption.

## Workloads and measurement method

The [benchmark guide](../../benchmarks/README.md) defines the datasets, exact
element denominators, allocation counters and commands. Reader reads roots;
Tree Reader visits all elements and validates matching END events. Dataset
generation and caller-owned traversal workspace allocation are outside timing.
Every timed iteration checks successful completion and exact element counts.

Document timings include parse, count verification, destruction and arena reset.
The default path uses the actual default allocator. An untimed counting pass
sizes a preallocated, aligned arena through the existing custom allocator API.
The arena retains its complete storage between iterations and does not reclaim
individual allocations. Its initial allocation is excluded from timing, so these
results describe repeated parsing with reusable capacity, not total application
startup or arbitrary edit workloads.

## Recorded Release results

Measurements on 2026-10-06 used GCC 13.3.0, Linux x86-64 under WSL2, an Intel
Core i7-1255U, Google Benchmark v1.9.4, shared OpenTLV, and `-O3 -DNDEBUG`
without profiling, sanitizers or LTO. The C library also uses `-fPIC`
and `-fvisibility=hidden`. Benchmark processes were pinned to guest CPU 2.
The dependency version context contains `-dirty` because the Windows checkout
uses CRLF; its content diff ignoring line endings is empty.

Each case used seven randomly interleaved repetitions, a 0.12-second minimum
CPU timing interval, and Google Benchmark's adaptive iteration counts.
No project build or test ran concurrently with these recorded runs. The full
matrix ran baseline then A; the independent Reader repeat ran A then baseline.
The same benchmark executable loaded saved baseline/A libraries through
`LD_LIBRARY_PATH`; `ldd` confirmed selection. The only library source difference
is the retained `tlv_read_impl()` change described above.

The [full evidence](../../benchmarks/evidence/reader-decode-538.json) and
[reverse-order repeat](../../benchmarks/evidence/reader-decode-538-repeat.json)
retain context, dataset counters, every repetition's iteration count and CPU/wall
times, medians and sample coefficient of variation (CV). Times below are CPU
microseconds per complete input, not per element. Negative changes mean less
time; CV describes variation, not a confidence interval.

| Reader workload | Baseline (us) | A (us) | Change | CV baseline/A | Repeat change |
| --- | ---: | ---: | ---: | ---: | ---: |
| BER large Values | 13.0 | 11.7 | -10.2% | 1.0/2.3% | -10.9% |
| BER small Values | 1602.3 | 1407.8 | -12.1% | 3.0/4.5% | -10.0% |
| BER nested definite | 20.0 | 17.5 | -12.3% | 7.8/9.3% | -4.9% |
| BER nested indefinite | 74.6 | 72.9 | -2.2% | 2.7/4.1% | -2.9% |
| Fixed LTV | 1245.1 | 1065.8 | -14.4% | 2.8/3.1% | -12.9% |
| Fixed TLV | 1241.6 | 1088.2 | -12.3% | 5.3/4.8% | -11.0% |
| Packed LLDP | 1269.5 | 1104.3 | -13.0% | 3.9/14.3% | -13.7% |
| Variable sparse mask | 1325.3 | 1171.1 | -11.6% | 4.5/7.3% | -13.2% |
| Variable TLV | 1331.1 | 1234.0 | -7.3% | 2.3/5.0% | -9.0% |

Small BER, large BER and Fixed-format Reader improvements repeat beyond their
observed typical dispersion. The indefinite result is within variation; no
indefinite-specific speedup is claimed. Non-BER Reader and Tree medians all
decreased in the full matrix. Tree small-BER median decreased 8.9%; Tree and
Document measurements include more noise and are not used to infer Reader-only
cost. Several samples have large outliers (CV up to 44%); this is local WSL
evidence, not a universal throughput guarantee or a hosted performance gate.

### Document allocator experiment

For 16,000 small BER elements with A, default parse+free took a median 3107.2 us
(CV 11.7%); the reusable arena took 2491.7 us (CV 4.9%), a 19.8% reduction in
this experiment. Both made 32,001 allocation and release callback requests
for 1,440,120 requested bytes. The arena reserved 1,792,128 bytes including
alignment padding, about 24.4% more than the sum of requested sizes.

These flat cases set `max_depth=0`, avoiding unused traversal-frame allocation;
this explains the one fewer allocation than the issue's 32,002-call profile.
Nested cases set `max_depth=32`. All cases bound `max_elements` to the exact
dataset count and disable source-location retention. Default allocator behavior
and public APIs are unchanged. The arena comparison is independent of the
Reader comparison: default small-BER Document time changed only -0.5% from
baseline to A, within observed noise.

### Reproducing and collecting evidence

Build the benchmark source from this change against both the starting core and
the modified core, with otherwise identical Release options. For each variant:

```sh
taskset -c 2 ./benchmark-tlv \
  '--benchmark_filter=^(reader_decode|tree_decode|document_decode)/' \
  --benchmark_min_time=0.12s --benchmark_repetitions=7 \
  --benchmark_enable_random_interleaving=true \
  --benchmark_report_aggregates_only=false \
  --benchmark_display_aggregates_only=true \
  --benchmark_out=before.json --benchmark_out_format=json \
  '--benchmark_context=commit=YOUR_COMMIT,variant=baseline,compiler=GCC-13.3.0,flags=-O3 -DNDEBUG,affinity=cpu2'
```

Repeat into `after.json` with the appropriate variant metadata, then reverse
the order using the `^reader_decode/` filter for an independent confirmation.
Preserve the actual command/build flags and do not compare different datasets.
From the repository root, collect each matching pair with:

```sh
python scripts/reader_decode_evidence.py baseline=before.json optional-error=after.json \
  --output evidence.json --markdown comparison.md
```

The collector rejects failed cases, missing raw repetitions, mismatched workload
sets/counters and invalid timings. It records observations, not a significance
test or an automatic regression threshold.

## Contract validation

The MSVC 19.44 Release build passed all 1,138 configured CTest tests, including
three new callback initialization, failure-publication and early-argument
diagnostic regressions. All 36 benchmark cases also passed a one-iteration
MSVC smoke run; that run is functional validation, not timing evidence.
The saved GCC libraries expose the same 579 symbol names; public headers are
unchanged.

Clang 18.1.3 with ASan, UBSan and leak detection passed the complete C++ unit
executable (176 tests) and 77 focused C Format, Reader, Tree, incremental,
variable-field and Visitor tests, including all new regressions. The full C
sanitizer run stopped on an existing intentional invalid-enum load in
`tests/unit/endian_test.cpp`. The focused run excludes two existing Visitor
tests with the same pattern (`CursorArgumentsAndCallbackErrors` and
`TreeStopAndErrorResumeAtChildrenAndMatchPull`). No sanitizer checks were
disabled and no unrelated tests were changed; this is not a full C sanitizer
pass. Hosted CI and WASM validation were not run locally.

## Deferred work

Repeated nested-indefinite boundary scans remain in all variants and benchmarks.
The separate [boundary-reuse follow-up](indefinite-boundary-reuse.md) records
the issue's profiling evidence and the complete-parent publication, incremental
input, workspace and lifetime constraints for a future design.
