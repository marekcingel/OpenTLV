# Local benchmarks

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
