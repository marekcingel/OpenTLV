# Local benchmarks

The `reader_decode/`, `tree_decode/`, and `document_decode/` families isolate the
shared decode path from traversal and owned-tree allocation (#538). Their input
bytes, Format configuration, and traversal/arena storage are prepared before the
timed loop. Every timed iteration initializes a fresh cursor or Document and
checks the exact successful element count; Reader and Tree Reader also require
the final EOF result. Tree Reader consumes canonical BEGIN/ELEMENT/END events and
checks the number of END events separately.

| Workload | Input | Reader elements | Tree/Document elements |
| --- | --- | ---: | ---: |
| `ber_flat_small` | 16,000 one-byte Values | 16,000 | 16,000 |
| `ber_flat_large` | 128 Values of 4,096 bytes | 128 | 128 |
| `ber_nested_definite` | 200 roots, 32 constructed ancestors and one leaf per root | 200 | 6,600 |
| `ber_nested_indefinite` | Same tree, indefinite BER containers with EOC trailers | 200 | 6,600 |
| `fixed_tlv` | One-byte Tag/Length, Value-only length, 16,000 one-byte Values | 16,000 | 16,000 |
| `fixed_ltv` | One-byte Length/Tag, Tag-and-Value length, same Values | 16,000 | 16,000 |
| `variable_tlv` | Generic variable identifier/count fields, same Values | 16,000 | 16,000 |
| `variable_sparse` | Same variable fields with noncontiguous count payload mask `0x55` and long-form bit `0x80` | 16,000 | 16,000 |
| `packed_lldp` | Packed 7-bit Type/9-bit Length, same Values; requires LLDP | 16,000 | 16,000 |

Reader consumes the root sequence only; it does not traverse definite constructed
Values. BER indefinite bounds resolution must scan their framing even at the
Reader layer. Tree Reader additionally decodes every descendant, so repeated
indefinite bounds scans are visible separately. `items_per_second` counts actual
published elements, excluding END events; `bytes_per_second` counts each original
input byte once, not bytes revisited during bounds resolution.

Each Document workload has `/default` and `/arena` variants, both measuring
**parse/build plus `tlv_document_free()`**. The default variant uses the library's
ordinary allocator. Before timing, a counting malloc/free wrapper verifies one
parse and records `alloc_calls/input`, `free_calls/input`, and `alloc_bytes/input`.
These counters describe allocation requests per complete input, not rates or
live/peak memory. The same calibration sizes a benchmark-local, maximally aligned
bump arena through the public `tlv_allocator_t` callbacks; no Document code is
changed. Arena release callbacks and the final bulk reset are timed, while arena
backing allocation/destruction are outside timing. `arena_bytes/input` includes
alignment padding. The retained arena therefore represents a reusable allocator,
not the end-to-end cost of obtaining memory from the operating system. Source
location retention is disabled in both variants, matching default options.

For a focused, repeatable Release comparison, configure with
`-DOPENTLV_BUILD_BENCHMARKS=ON`, build `benchmark-tlv` in Release, and run its
executable with:

```text
"--benchmark_filter=^(reader_decode|tree_decode|document_decode)/" --benchmark_min_time=0.2s --benchmark_repetitions=10 --benchmark_out=benchmarks/results/decode-before.json --benchmark_out_format=json
```

Repeat with `decode-after.json` after the change, on the same compiler/build
configuration, CPU, and power settings. Keep the machine idle and repeat in
alternating before/after order when differences are near run-to-run variation.
Compare medians and dispersion for each workload independently; a large-value
byte rate, shallow root traversal, and full Document construction measure
different work and must not be combined into one speedup. Preserve the raw JSON
context, successful iteration counts, and individual repetitions with the report.
The standard runner below accepts the same filter/repetition flags when a
separate `latest.json` is suitable. Its default saves aggregates only, so explicitly
retain raw repetitions when collecting decode evidence:

```text
python scripts/benchmarks.py run "--benchmark_filter=^(reader_decode|tree_decode|document_decode)/" --benchmark_min_time=0.2s --benchmark_repetitions=10 --benchmark_report_aggregates_only=false --benchmark_display_aggregates_only=true
```

The report flag keeps individual repetitions in JSON; the display flag limits
terminal output to aggregates. Preserve each completed `latest.json` under a
distinct filename before starting the next variant.

The [Reader decode performance report](../docs/development/reader-decode-performance.md)
records the #538 experiments and their limitations. The separate
[indefinite boundary reuse follow-up](../docs/development/indefinite-boundary-reuse.md)
specifies future work on repeated scans; the current change does not implement it.

Collect raw runs into reviewable evidence with explicit labels:

```text
python scripts/reader_decode_evidence.py baseline=benchmarks/results/decode-before.json candidate=benchmarks/results/decode-after.json --output benchmarks/results/decode-evidence.json --markdown benchmarks/results/decode-comparison.md
```

The first label is the baseline. Add more unique `LABEL=PATH` arguments for
individual candidates or repeated runs of the same variant. The collector checks
matching workloads, input/allocation counters and complete raw repetitions;
it preserves run context and samples alongside CPU and wall-clock medians and
variation. It does not run benchmarks or establish statistical significance.
Record the source commit, variant, compiler/build flags and invocation using
Google Benchmark's `--benchmark_context` when producing each input JSON.

## Public C++ Reader and Document

The `cxx_reader/` and `cxx_document/` workloads measure the public facade itself
(#440). They complement the canonical C decode and identity benchmarks; their
different work must not be combined into one overall speedup.

| Family | Cases | Timed work per iteration |
| --- | ---: | --- |
| `cxx_reader/next/{ber,fixed}/{16,4096}` | 4 | Initialize a cursor, read every one-byte Value through `next()`, and check final EOF |
| `cxx_reader/range/{ber,fixed}/{16,4096}` | 4 | Initialize and consume the same input through the public Reader range |
| `cxx_reader/failure/{ber,fixed}/{eof,truncated_value,need_more_data}/{1,256}` | 12 | Repeat the expected failed `next()` outcome on an unchanged cursor |
| `cxx_reader/failure/initialization/{1,256}` | 2 | Repeat `next()` on a cursor initialized with a write-only application Format |
| `cxx_reader/resume/{ber,fixed}/{16,4096}` | 4 | For each element, initialize partial input, check `need_more_data`, replace the input, read successfully and check final EOF |
| `cxx_document/primitive_child_edit/{16,256,4096}` | 3 | Iterate a constructed node's children and replace each primitive Value |
| `cxx_document/snapshot/cached/{16,256,4096}` | 3 | Read Values through a retained vector of Node handles, without mutation |
| `cxx_document/snapshot/after_primitive_edit/{16,256,4096}` | 3 | First access to every retained handle after one primitive Value replacement |
| `cxx_document/snapshot/after_retirement/{16,256,4096}` | 3 | First access to every surviving retained handle after another node is erased |

The 38 cases prepare wire buffers and Document trees outside timing. Reader
success and resume cases include cursor initialization. Repeated failure cases
initialize once before timing and consume status, message and location-presence
information; they do not force the whole result through an artificial copy.
Every result is checked for the exact expected outcome. Failure never advances
the cursor, and incomplete input must remain resumable.

The Document fixture is one constructed parent with the stated number of
one-byte primitive children. The edit loop includes Value replacement and
traversal; it alternates between two Values and verifies the final contents.
Snapshot vectors are retained across iterations. Snapshot mutations are outside
timing, so the measured work is the first subsequent access to each handle,
including any validity check. The retirement control inserts and erases an extra
child during the paused setup, checks that its retained handle becomes invalid,
then reads the surviving snapshot. It deliberately preserves actual retirement
costs and does not imply constant-time access after erase. Setup touches the same
Document and warms its memory; these are not cold-cache measurements.

`items_per_second` counts decoded elements for successful Reader cases, attempted
calls for failure cases, and edited/read children for Document cases.
`next_calls/iteration` records explicit calls (`0` for range traversal).
`error_bytes` and `result_bytes` record the active C++ layout; Document counters
record the tree size and retirement count. Document creation/destruction and
snapshot allocation are excluded. These workloads do not measure thread safety.

Configure the Release benchmark target as above, then retain individual raw
repetitions for each source variant, for example:

```text
"--benchmark_filter=^cxx_(reader|document)/" --benchmark_min_time=0.2s --benchmark_repetitions=7 --benchmark_report_aggregates_only=false --benchmark_display_aggregates_only=true --benchmark_out=benchmarks/results/cxx-facade-before.json --benchmark_out_format=json --benchmark_context=variant=before
```

Repeat with a separately built candidate and distinct output/context labels.
Use the same compiler, optimization flags, capability selection, CPU affinity
and idle-machine conditions. Compare each workload's raw repetitions and median
independently; near-noise effects need repeated alternating runs. Existing Google
Benchmark JSON and `scripts/benchmarks.py compare` need no new evidence format.

These cases are added only with `OPENTLV_BUILD_CXX=ON`. Reader cases require
Reader and BER; Document cases match the public facade's Document, Reader,
Writer, Query and Codec requirements. Missing capabilities are never enabled by
the workloads. The existing top-level policy still skips the entire benchmark
target in reduced capability builds, including a Document-without-Reader profile.

`document_identity_edit_loop/{16,256,4096}` measures a Value edit followed by
possibly-stale address validation against the last node. Each revision-triggered
identity check scans O(n) nodes; a loop of n edits/checks is O(n squared). Compare
the size series as well as absolute times when changing Document handle storage.
This benchmark is available when Document is enabled and does not measure or
assert thread safety.

Use the VS Code tasks in this order:

1. **Benchmark: Build and run** configures and builds Release in `build`, runs
   Google Benchmark with ten repetitions, and replaces `benchmarks/results/latest.json`
   only after the entire run succeeds. The terminal prints the absolute path and
   run date. During the run the previous completed result stays visible.
2. **Benchmark: Update baseline from last** explicitly copies that result to
   `benchmarks/baselines/windows-msvc-x64.json` on Windows. This baseline is
   versioned in Git; review its changes before committing. Other platforms use
   the local `benchmarks/results/baseline.json`. Subsequent benchmark runs do not
   modify either baseline.
3. **Benchmark: Compare baseline with last** uses Google's `compare.py` in an
   isolated environment under `build/benchmark-tools-venv`. On Windows it compares
   the versioned Windows baseline with the local `latest.json`.

Files under `benchmarks/results/` are ignored by Git, so Source Control does
not show their changes. The Windows baseline under `benchmarks/baselines/` is tracked. Open the JSON file and inspect `context.date`, or read the completion
message in the terminal. Running the executable directly without `--benchmark_out`
prints results to the terminal only.

The same workflow is available with `python scripts/benchmarks.py run`,
`python scripts/benchmarks.py baseline`, and `python scripts/benchmarks.py compare`
(use `python3` where appropriate). Python 3.10 or 3.11 supports the NumPy/SciPy
versions pinned by Google Benchmark v1.9.4. Additional benchmark flags may be
passed to `run`, for example `--benchmark_filter=parse_entries/16$`.

For older pip versions, the comparison task exports trusted system CA
certificates into the local environment and passes them through pip's `--cert`
option. TLS verification remains enabled. An explicit `PIP_CERT`,
`REQUESTS_CA_BUNDLE`, or `CURL_CA_BUNDLE` takes precedence. A corporate CA must
already be trusted by the system or supplied in the configured certificate bundle.

To use the Windows baseline from the command line, pass
`--baseline benchmarks/baselines/windows-msvc-x64.json` to `compare` or `baseline`.
