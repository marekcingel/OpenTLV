# C++ Reader and Document performance

This follow-up to [#440](https://github.com/marekcingel/OpenTLV/issues/440)
removes redundant Reader diagnostic work and separates Document handle
invalidation from ordinary mutation. Wire behavior, diagnostic detail and Query
mutation detection remain unchanged.

## Implementation boundary

`reader::next()` no longer clears a temporary diagnostic before the canonical
C cursor fills it on failure. Successful pulls never inspect that storage.
The range path follows the same rule, with explicit initialization for a failed
C++ Reader construction. Converting a native diagnostic to `tlv::error` assigns
its offset directly instead of copying the complete error through `at()`.
Each pull still invokes the decoder at most once: retrying a failed decode to
obtain diagnostics could invoke a stateful application Format twice.

The full inline path and the error layout are retained. The measured x86-64
layout is 600 bytes for `error` and 608 bytes for
`expected<element_view, error>`. These changes do not remove the cost of rich
diagnostics or guarantee parity with the older, smaller error representation.

Document now exposes `tlv_document_retire_epoch()`. The epoch advances when an
erase or constructed Value replacement actually removes published Nodes.
Insertion, primitive Value replacement and failed individual edits preserve it.
Deferred erasure advances it at commit. Each advance retires at least one unique
identity, so identity exhaustion bounds the epoch without wraparound. Query
continues to observe the separate revision that changes on every successful edit.

C++ handles compare this epoch before scanning for their saved address and
identity. Primitive child-edit loops and retained snapshots after insertion or
primitive replacement avoid redundant membership scans. Actual retirement still
requires O(nodes) validation per retained handle, hence O(handles * nodes) for
a snapshot. Generational handles and a smaller error representation are outside
this change. Value-byte borrowing and external synchronization requirements are
unchanged.

The new accessor is an additive C ABI change; existing exported signatures and
public layouts are preserved. Updated C++ Document headers need a matching native
library that exports it.

## Workloads

The [benchmark guide](../../benchmarks/README.md) documents the 38 permanent
`cxx_reader/*` and `cxx_document/*` Google Benchmark cases. Reader cases cover
BER and Fixed framing, explicit pulls, ranges, EOF, malformed input, incremental
pauses, initialization failure and pause/resume. Each timed result is checked
for the expected status, count and cursor behavior.

Document cases cover primitive child-edit loops and retained snapshots with no
mutation, one primitive edit, or actual retirement. They use 16, 256 and 4,096
primitive children under one constructed parent. Setup, snapshot allocation and
snapshot mutation are outside timing. The child-edit loop times both edits and
traversal. The retirement control inserts and erases an extra child, then checks
the surviving snapshot. Setup warms the tree; these are not cold-cache timings.

## Measurement method

The first local comparison on 2026-10-07 uses commit
`4500ab8198267609c7a7a84ed8793f97bec78fbb` and the candidate subsequently committed
as `a2d1fd3`. Both executables compile the identical benchmark source against their
respective headers and static native libraries. This matrix compares two PR
states; the separate C diagnostic follow-up below also includes the older `main`.

Both builds use GCC 13.3.0, C++11, `-O2 -DNDEBUG`, Google Benchmark v1.9.4 and
Linux x86-64 under WSL2 on an Intel Core i7-1255U. Benchmark processes are pinned
to guest CPU 2. Profiling, sanitizers and LTO are disabled. No project builds or
tests run concurrently with the measurements.

Each case has seven raw repetitions, with workloads/repetitions randomly
interleaved within each executable and a minimum CPU timing interval of 0.08 s.
Google Benchmark chooses the iteration count. Both variants first passed all
38 cases with one iteration as a correctness smoke check. Times describe whole
workloads, not individual elements; CV is the sample coefficient of variation,
not a confidence interval. Near-noise differences do not establish improvements.

The forward run executes baseline then candidate; a separate full-matrix repeat
reverses that order. Raw samples, iteration counts, medians, compiler/CPU context
and source hashes are retained in four files:

- Forward [baseline](../../benchmarks/evidence/cxx-facade-440-baseline.json) and
  [candidate](../../benchmarks/evidence/cxx-facade-440-candidate.json).
- Reverse-order [baseline](../../benchmarks/evidence/cxx-facade-440-baseline-reverse.json)
  and [candidate](../../benchmarks/evidence/cxx-facade-440-candidate-reverse.json).

These contain 1,064 raw measurements in total. They are local observations from
one host, not release thresholds. The reverse baseline has substantial outliers,
including CV above 100% for initialization failures; retaining those samples is
essential when interpreting the results.

## Results

Reader times below are median CPU microseconds per 4,096 decoded elements or per
256 repeated failed calls, as marked. Resume cases perform one incomplete pull,
input replacement, one successful pull and final EOF for each element. Negative
changes mean less time. The CV column describes the forward baseline/candidate.

| Reader workload | Before (us) | After (us) | Change | CV before/after | Reverse change |
| --- | ---: | ---: | ---: | ---: | ---: |
| BER `next`, 4,096 elements | 469.4 | 416.5 | -11.3% | 4.0/4.0% | -26.7% |
| Fixed `next`, 4,096 elements | 371.4 | 329.1 | -11.4% | 2.1/10.9% | -5.7% |
| BER range, 4,096 elements | 457.2 | 436.1 | -4.6% | 6.3/13.1% | -15.3% |
| Fixed range, 4,096 elements | 379.4 | 357.3 | -5.8% | 5.6/11.8% | -48.2% |
| BER truncated Value, 256 calls | 52.5 | 39.9 | -24.0% | 7.0/5.0% | -40.4% |
| BER `need_more_data`, 256 calls | 53.0 | 39.3 | -25.9% | 6.5/8.6% | -22.6% |
| BER EOF, 256 calls | 32.1 | 19.9 | -38.2% | 6.8/9.2% | -34.8% |
| Fixed EOF, 256 calls | 30.7 | 19.7 | -35.8% | 8.1/7.0% | -35.1% |
| BER resume, 4,096 elements | 1,832.9 | 1,446.4 | -21.1% | 6.7/7.9% | -30.8% |
| Fixed resume, 4,096 elements | 1,765.8 | 1,260.9 | -28.6% | 10.8/5.0% | -36.6% |

The successful-pull reduction is about 11% in the forward run. Its reverse run
has baseline CV of 43% for BER and 46% for Fixed, so the reverse point estimates
do not establish a precise gain. EOF reductions repeat with much smaller
dispersion. Range differences are inconsistent relative to variation, and no
range-specific speedup is claimed. None of these results establishes parity
with the older, smaller C++ error representation.

Document times below are median CPU microseconds for the entire edit loop or
retained snapshot in the forward run:

| Primitive children | Edit before (us) | Edit after (us) | Snapshot after edit, before (us) | Snapshot after edit, after (us) |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 1.843 | 1.846 | 0.779 | 0.748 |
| 256 | 76.917 | 28.964 | 61.328 | 8.758 |
| 4,096 | 28,356.975 | 439.979 | 29,914.675 | 131.605 |

At 4,096 children, the edit loop takes about 64 times less time and the snapshot
about 227 times less time. The reverse run records 28,847.7 to 459.0 us and
29,920.9 to 136.3 us respectively, retaining the large improvement. Candidate
times scale approximately with child count; there is no material benefit for
the tiny 16-child edit fixture in the forward run. These results concern handle
validation and the measured Value edits, not arbitrary Document operations.

The cached snapshot control changes from 131.2 to 135.1 us (+2.9%); its reverse
changes from 139.2 to 133.4 us (-4.2%). The actual-retirement control remains
expensive: 27,132.1 to 30,917.8 us (+14.0%, CV 11.3/15.5%) and 30,411.2 to
32,283.2 us in reverse (+6.2%, CV 40.4/8.9%). These controls are too noisy to
attribute or exclude small timing changes. No unchanged-throughput claim is
made for them. Retirement still triggers O(handles * nodes) scans; this
optimization does not fix that case.

## Validation scope

Reader regressions check single invocation of stateful Format callbacks, complete
diagnostics, repeated failures, incremental recovery, range exceptions and the
synthetic failed-initialization path. Error conversion preserves a full 32-entry
path after the source diagnostic storage changes.

Document regressions distinguish ordinary mutations from retirement, preserve
Query revision changes, exercise deferred erasure and failed replacement, and
force both allocator address reuse and identity exhaustion. Separate capability
builds check that the native accessor works without Reader support. These tests
protect semantics; benchmark timings are local evidence rather than pass/fail
thresholds or a hosted performance gate.

Local validation includes 263 selected Windows/MSVC Debug CTest checks, 37
Reader/public API and 68 C/C++ Document tests under Clang ASan/UBSan, six Windows
shared-library capability checks and two GCC x86 capability checks. A separate
C++11 x86 executable exercises the accessor directly. C ABI enforcement reports
one added export and no changed or removed functions or public types. Focused
C++11/C++23 strict-warning checks and documentation checks pass. The complete
repository suite, full sanitizer suites, fuzz campaigns, hosted CI and WASM
runtime validation were not rerun for this follow-up.

## C diagnostic follow-up

A subsequent review of `a2d1fd3` identified a second Reader staging clear in the
native `tlv_read_impl()`. The Format wrapper already initializes the callback's
result and error storage and copies complete failure detail to its caller. Its
invalid-argument branch was the one exception. That branch now publishes empty
detail too, allowing Reader to remove its own pre-decode clear.

Callback storage still starts initialized, callbacks run at most once, and partial
or absent failure metadata is supported. Successful Format decoding leaves the
caller error output untouched; failed decoding leaves the decoded result untouched.
This changes neither signatures nor layouts. It does not remove all diagnostic
tracking inside decoders or change the 600-byte C++ error layout.

The new preflight regression fails against `a2d1fd3` and passes with the fix.
Current validation includes 940 selected Windows/MSVC Debug CTest checks and 89
focused Clang ASan/UBSan tests, including C Reader, Tree Reader, Format and C++
facade paths. Full-repository/hosted CI, fuzz campaigns and WASM runtime checks
were not rerun for this change.

The four earlier evidence files preserve every original sample and aggregate.
They now use compact standard JSON and generic host/executable identifiers; no
timing was changed during that metadata cleanup.

### Comparison with main

The separate [collector](../../scripts/reader_api_comparison.py) and
[benchmark source](../../benchmarks/tools/reader_api_comparison.cpp) build exact
revisions `89991d9f` (`main`), `a2d1fd3` (prior PR) and the working candidate with
the C diagnostic change. Each uses its own native library and C++ headers, with
matching generated capabilities, GCC 13.3, C++11 and `-O2 -DNDEBUG` without LTO.
The old Fixed template argument type is the only compatibility adapter.

The 2026-10-07 run uses the same WSL2 host and CPU affinity 2, without concurrent
project builds or tests. Each of 60 cases has seven shuffled repetitions. The
[420 raw timings](../../benchmarks/evidence/reader-api-440.csv) and
[build provenance and summaries](../../benchmarks/evidence/reader-api-440.json)
retain source commits/patches, checksums, hashes and every observation, without
hostnames or absolute paths. The benchmark uses a typed `reader<Format>` and an
elapsed wall-clock timer; its absolute times should not be mixed with the earlier
runtime-Format Google Benchmark CPU timings.

Every row below is a median in milliseconds for **2,000,000** operations. Success
and range cases consume that many three-byte elements. Failure/pause cases repeat
the same two-byte header missing its one-byte Value; they measure status polling,
not appending data and resuming. Input allocation is outside timing, while Reader
construction, all calls and result-checksum accumulation are inside. Native C
controls include both ordinary and diagnostic calls.

| Workload | main `89991d9f` | Prior PR `a2d1fd3` | C diagnostic fix |
| --- | ---: | ---: | ---: |
| BER C++ `next()` | 180.021 | 205.111 | 182.948 |
| Fixed C++ `next()` | 144.782 | 161.031 | 136.098 |
| BER C++ range | 229.424 | 210.061 | 195.734 |
| Fixed C++ range | 183.016 | 164.970 | 138.802 |
| BER C++ failed `next()` | 194.342 | 325.669 | 287.578 |
| Fixed C++ failed `next()` | 153.591 | 274.394 | 242.397 |
| BER C++ `need_more_data` | 179.520 | 335.205 | 299.132 |
| Fixed C++ `need_more_data` | 128.095 | 269.604 | 244.884 |
| BER C `tlv_reader_next()` | 175.583 | 174.458 | 181.577 |
| BER C `tlv_reader_next_diag()` | 202.597 | 199.171 | 179.012 |
| Fixed C `tlv_reader_next()` | 129.541 | 128.314 | 132.215 |
| Fixed C `tlv_reader_next_diag()` | 158.697 | 158.076 | 135.717 |

BER C++ successful pulls take 10.8% less time than the prior PR and 1.6% more than
`main` in this run. Their min/max ranges are 180.4–198.0 ms for the candidate,
199.2–250.3 ms for the prior PR and 177.7–183.0 ms for `main`. Fixed pulls show a
15.5% median reduction against the prior PR. Native diagnostic success improves
by 10.1% for BER and 14.1% for Fixed; the ordinary C control medians vary by 4.1%
and 3.0% with overlapping ranges. This supports removing redundant staging, with
successful C++ throughput close to `main` in these fixtures. It is not a guarantee
of parity for every Format or compiler.

Outliers remain, including a 622.8 ms `main` native BER pause sample. All samples
are retained, and smaller differences should be treated cautiously. Failed C++
pulls still take about 1.5–1.6 times the `main` medians; repeated pauses take about
1.7–1.9 times. The measured error/result layouts remain 600/608 bytes versus
40/48 bytes on `main`. Changing that storage or making handle validation constant
time after actual retirement remains separate work.
