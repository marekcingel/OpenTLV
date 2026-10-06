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
