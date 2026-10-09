# Valgrind memory and performance checks

The C and C++ suites can run under Valgrind Memcheck on Linux, including WSL.
This checks invalid memory accesses, uses of uninitialized memory, and leaks in
a plain native build. It complements the [sanitized fuzz targets](fuzzing.md)
and Query sanitizer jobs.

A separate workflow compares Reader, Writer, Document, Query and Schema
instruction counts with Callgrind, then measures matching workloads without
instrumentation.
These checks have separate jobs and build directories:

| Check | Build | Result |
| --- | --- | --- |
| Memcheck | GCC Debug | Memory errors and leaks fail the job; the PR check is optional and must not be required for merging. |
| Callgrind | GCC RelWithDebInfo (`-O2 -g -DNDEBUG`) | Instruction-count increases are informational. |
| Native timing | GCC Release (`-O3 -DNDEBUG`) | Repeated elapsed-time and throughput measurements provide supporting evidence. |

Memcheck is an optional, non-blocking PR check; do not make it a required status
check in branch protection. Errors remain visible in the test output and uploaded
reports, and the job reports failure in every scope. Keep it out of required
checks in both branch protection and repository rulesets; the workflow does not
modify those settings.
Callgrind and native timing remain informational, including explicitly reported
infrastructure failures.
They run independently of Memcheck so their reports do not wait for the full
memory-check suite.

## Run locally

On Ubuntu 24.04, install the tools and configure a separate build directory:

```sh
sudo apt-get update
sudo apt-get install gcc g++ cmake ninja-build valgrind python3
cmake -S . -B build/valgrind -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DOPENTLV_BUILD_TESTS=ON -DOPENTLV_BUILD_MEMCHECK=ON \
  -DOPENTLV_BUILD_EXAMPLES=OFF -DOPENTLV_BUILD_CLI=OFF \
  -DOPENTLV_BUILD_CLI_TESTS=OFF
cmake --build build/valgrind --parallel 4
ctest --test-dir build/valgrind --output-on-failure --no-tests=error --parallel 4
ctest --test-dir build/valgrind -T memcheck -LE no-memcheck --output-on-failure --no-tests=error --parallel 4
```

The last command runs the full Memcheck suite. To reproduce the shorter PR
selection, exclude the expensive conformance matrices:

```sh
ctest --test-dir build/valgrind -T memcheck \
  -LE 'no-memcheck|memcheck-full' \
  --output-on-failure --no-tests=error --parallel 4
```

`OPENTLV_BUILD_MEMCHECK` defaults to `OFF`, so ordinary builds do not require
Valgrind or the Memcheck launcher. Enabling it requires a native Linux build,
Python and Valgrind. Use a fresh build directory without ASan, UBSan or MSan
compiler/linker flags; Memcheck configuration rejects sanitizer, fuzzing and
WASM builds. Language binding jobs remain separate.

The Memcheck build registers each GoogleTest suite as a whole binary, executing
all its cases in one Valgrind process. Builds without this option retain
individual GoogleTest registrations. Other CTest commands and arguments stay
unchanged. This matters for Query conformance drivers, which require corpus arguments supplied by their
Python harness. The launcher wraps native executable arguments (`--native`,
`--cli`, and `--checker`) with Valgrind and runs the Python harness normally.
This keeps Python runtime allocations outside the C/C++ check. Other Python
harnesses need an explicit adapter or an exclusion. Each instrumented process
has a separate log, and every report is checked before returning to CTest.
A harness that expects a child to fail cannot hide a Memcheck error in that
child. Native tests also trace any further child processes they start.

The Memcheck configuration uses `--leak-check=full`,
`--errors-for-leak-kinds=definite,indirect,possible`, `--track-origins=yes`, and
a nonzero `--error-exitcode`. Still-reachable allocations are not errors.
Missing or incomplete reports also fail the check.

Select a smaller set while investigating a failure:

```sh
GTEST_FILTER='Unit_Tlv_QueryProgram.*:Unit_Tlv_Incremental.*' \
ctest --test-dir build/valgrind -T memcheck -LE no-memcheck \
  -R '^test-unit-tlv$' \
  --output-on-failure --no-tests=error
```

Memcheck extends test timeouts only after the instrumented launcher starts.
An ordinary `ctest` invocation retains the usual limits, including the
retained-input scaling regression. Grouping the GoogleTest cases avoids paying
Valgrind startup and debug-symbol loading costs for every case. Query corpus
harnesses still start individual native processes; measure the complete CTest
job when assessing CI duration.

## Memcheck CI scope

The `valgrind.yml` workflow uses four build/test workers. Relevant PR changes
run the shorter selection, retaining every case in the four C/C++ unit and
integration GoogleTest binaries and the remaining native checks. The C and C++
Query conformance matrices carry the `memcheck-full` label and run only in the
full selection, as do optional CLI Query and generated-property matrices when
registered. The CI build disables the CLI and property tests. Ordinary CTest
still runs every registered test before Memcheck.

| Trigger | Memcheck selection | Failure handling |
| --- | --- | --- |
| Relevant pull request | Shorter selection | Job fails on errors; check is not required for merging. |
| Relevant PR with the `memcheck-full` label | Full suite | Job fails on errors; check is not required for merging. |
| Weekly schedule, Sunday at 02:17 UTC | Full suite on the default branch (`main`) | Job fails on errors. |
| Tag matching `v*` or `[0-9]*.[0-9]*.[0-9]*` | Full suite at the tag | Job fails on errors. |
| Manual dispatch | Full suite at the selected revision | Job fails on errors. |

Adding or removing the `memcheck-full` PR label reevaluates the selection.
New runs cancel superseded runs for the same PR. Regular pushes to `main` do
not start Memcheck; the weekly schedule checks the latest default-branch state.
The scheduled workflow must exist on the default branch to run.

Moving the conformance matrices to full runs leaves a detection delay for memory
errors specific to those paths. Without a labeled PR, manual run or release tag,
detection waits for the next weekly run, potentially a week plus scheduling
delays. Use the PR label or a manual full run before merging changes that need
that coverage. The shorter selection is not a substitute for full conformance
coverage, and its duration must be measured independently.

## Read a report

CTest reports the failing test name. Inspect its
`Testing/Temporary/MemoryChecker.<number>.log` in the build directory for the
combined report and the retained process logs for individual child commands.
`Testing/` also contains CTest's dashboard XML and execution logs. The
`valgrind.yml` workflow uploads this directory even when a test fails.

For an uninitialized-value error, start with the first application stack frame
and the origin stack emitted by `--track-origins=yes`. The use site may be a
transactional test's `memcmp`, while the origin is an incompletely initialized
output copied by the library. For leaks, inspect the allocation stack and leak
kind. Fix the earliest underlying defect before interpreting later errors.

A test that requires an object to remain byte-for-byte unchanged must initialize
its complete representation and take the snapshot with `memcpy`. A structure
assignment need not preserve padding. Compare members when the contract only
requires semantic equality. Do not weaken output-preservation assertions to
silence a real library write of undefined bytes.

## Suppressions and exclusions

`tests/valgrind.supp` starts with no suppression rules. Every added suppression
must have a comment explaining its reason and the affected external component,
with a tracking reference where available. Keep its stack match narrow and
remove it when the dependency is fixed. OpenTLV memory defects and unsafe test
snapshots should be fixed directly.

Use the CTest `no-memcheck` label for a test that cannot run under Valgrind and
document the reason beside its registration. The `-LE no-memcheck` option in
the commands above excludes that label; such tests still run under ordinary
CTest. An exclusion must not hide a failing native memory check;
sanitized binaries, fuzz targets and WASM require their dedicated workflows.

Use `memcheck-full` for expensive native tests retained in the full Memcheck
selection. Unlike `no-memcheck`, this label does not exclude a test from full
memory checking. The shorter PR command excludes both labels; the full command
excludes only `no-memcheck`.

See the [CTest MemCheck documentation](https://cmake.org/cmake/help/latest/manual/ctest.1.html#ctest-memcheck-step)
and [Valgrind manual](https://valgrind.org/docs/manual/manual-core.html) for
report and command-line details.

## Compare instruction counts and native timings

Use two existing Git checkouts on Linux, with the candidate containing the
comparison tools. Choose a new or empty output directory and at least three
native repetitions. From the candidate checkout:

```sh
python3 scripts/callgrind_compare.py \
  --baseline-source ../OpenTLV-baseline \
  --candidate-source . \
  --output-dir build/callgrind \
  --iterations 2000 \
  --native-iterations 20000 \
  --native-repetitions 5 \
  --threshold-percent 5 \
  --threshold-instructions 0 \
  --native-threshold-percent 5 \
  --jobs 2 --cc gcc
```

The tools installed for Memcheck also support this comparison. Each library is
built twice, using the same compiler and configuration for each baseline/candidate
pair. The runner uses the candidate's `benchmarks/callgrind` harness for both
versions so changes to benchmark code cannot silently give the two versions
different inputs or iteration counts. The baseline must support the public API
used by that harness; an incompatible baseline is an infrastructure error rather
than a performance result. Existing Google Benchmark dependencies are not needed.

Local modifications are included in the build and recorded using working-tree
status and source-file hashes. A dirty checkout's recorded commit SHA identifies
its parent revision, not the exact code measured; retain its metadata and changes
when reproducing a local result. Sources must remain unchanged during the run.

Callgrind measures `Ir`, the number of executed machine instructions, for each
workload separately. The report gives baseline and
candidate counts, absolute differences, percentage differences, and function
costs. Both the percentage and absolute instruction thresholds must be exceeded
to flag a workload. For example, `--threshold-percent 5
--threshold-instructions 10000` flags an increase only when it exceeds both 5%
and 10,000 instructions. Thresholds classify the report; they do not make the
comparison command fail. Tool, build, workload and report failures return a
nonzero status and must be investigated before interpreting any available data.
If the baseline count is zero, the percentage is undefined and only the absolute
threshold applies.

The Reader, Writer, Document and Query workloads use the `ber-flat-256x16-v1`
input: 256 flat primitive BER elements, tags `0x80` through `0x8f` repeated, and
16 bytes per value, for 4,608 wire bytes. Value byte `j` in element `i` is `(i + j) % 256`. Input preparation,
Query compilation and Query workspace allocation happen before measurement.
One warmup validates the result before the measured loop; each iteration also
checks its result. The full Writer output comparison runs outside measurement.

| Workload | Measured operation per iteration |
| --- | --- |
| Reader | Initialize the Reader and traverse all 256 elements. |
| Writer | Initialize the Writer and encode all 256 elements. |
| Document | Parse the owned Document, traverse it and free it, including allocations. |
| Query | Initialize execution and a Tree Reader, then run the precompiled `//80` query and visit its 16 matches. |

The Schema workloads separate definition checking from input processing. Every
`tlv_schema_validate()` and `tlv_der_schema_read()` call first checks the whole
reachable definition, so each complete workload has a definition-check-only
counterpart (`tlv_schema_check()` or `tlv_der_schema_check()`) on the same
schema. Generic Schema validates with the BER Format; DER Schema reads one root
element. Schemas and inputs are built before measurement in
`benchmarks/callgrind/schema_workloads.h`, which the Google Benchmark suite also
uses.

| Schema shape | Generic workloads | DER workloads | Input |
| --- | --- | --- | --- |
| Shared graph, small input | `schema_check_shared`, `schema_validate_shared` | `der_schema_check_shared`, `der_schema_read_shared` | `30 00` against 200 distinct tables or types. Each references the next two, so most are shared. |
| Small schema, large input | `schema_check_flat`, `schema_validate_flat` | `der_schema_check_flat`, `der_schema_read_flat` | `ber-flat-256x16-v1` against 16 primitive rules, or the same values as a DER `SEQUENCE OF OCTET STRING` (4,612 bytes). |
| Recursive schema, nested input | `schema_check_recursive`, `schema_validate_recursive` | `der_schema_check_recursive`, `der_schema_read_recursive` | `T = SEQUENCE OF T` with one root holding 16 chains of 20 nested empty SEQUENCEs (644 bytes). |

Definition-check-only workloads read no input and report zero input bytes, so
the report gives no throughput for them. Its **Schema definition-check share**
table lists, per revision, the check's instructions per call and its share of
the complete workload. A change to definition checking shows there separately
from input processing.

Callgrind collects only the measured loop. Native timing brackets the same loop
with a monotonic clock. Throughput is the workload's input bytes multiplied by the
iteration count and divided by elapsed time; it describes the complete workload,
including the initialization and validation above. Output checksums must agree
between versions and measurement modes after accounting for iteration counts.
The harness uses Callgrind's client requests to start instrumentation, zero the
counters and dump the measured region. The `.out.1` profile contains that region;
the final `.out` termination dump is not used for comparison. See the official
[Callgrind manual](https://valgrind.org/docs/manual/cl-manual.html) for client
requests and profile interpretation.

Instruction counts depend on the compiled machine code, compiler version,
optimization flags and target architecture. Compare only runs with the same
toolchain and workload. A change in `Ir` does not establish a change in execution
time: branch prediction, caches, CPU behavior and operating-system scheduling
affect native performance. The Release measurements therefore repeat each
workload without Valgrind and report the samples and median with throughput.
Their separate `--native-threshold-percent` classification remains informational;
shared CI-runner noise prevents treating a small timing difference as proof of
a regression. Samples with a coefficient of variation above 5% are marked noisy
before classifying the timing change. Confirm performance-sensitive changes with
controlled native measurements on representative hardware and inputs.

The output directory contains:

- `report.md` and `report.json`: comparison tables and machine-readable results.
- `metadata.json`: source revisions, toolchain, configuration and iteration data.
- `profiles/`: raw Callgrind profiles for each version and workload.
- `native/`: raw measurements from the Release builds.
- `logs/`: configure, build and execution output for investigating failures.
- `build-metadata/`: the CMake caches and compilation command databases.
- `harness/`: the frozen workload source used for both revisions.

Use the raw profiles with `callgrind_annotate` or KCachegrind to inspect
individual functions and callers. Keep the metadata with the profiles when
sharing a report so the source revisions and compilation settings remain
reproducible.

## CI comparison baseline and artifacts

The `callgrind.yml` workflow runs on pull requests and pushes to `main` that
change native sources, benchmarks, Callgrind tools, CMake, or the workflow
itself. It also supports manual dispatch. It uses these revisions:

| Trigger | Baseline | Candidate |
| --- | --- | --- |
| Pull request | PR base SHA | PR head SHA |
| Push to `main` | SHA before the push | Pushed SHA |
| Manual dispatch | `baseline_ref` input, default `main` | Selected workflow revision |

Both checkouts run on the same Ubuntu 24.04 worker. CI uses 2,000 Callgrind
iterations and five native samples of 20,000 iterations per workload. Manual
dispatch exposes the instruction percentage, absolute instruction and native
timing thresholds; the command-line options above also configure iteration
counts. The job publishes the Markdown report to the Actions summary and uploads
JSON, metadata, raw profiles, native samples, logs and compilation settings even
when the comparison fails. A failed or skipped comparison is explicitly marked
in the summary and is not interpreted as a clean result.

The independent `valgrind.yml` workflow uses the [Memcheck CI scope](#memcheck-ci-scope)
described above. Its PR path filters cover native sources, tests, CMake and
Memcheck tooling. Changes limited to Callgrind tooling or benchmarks do not
trigger PR Memcheck.
