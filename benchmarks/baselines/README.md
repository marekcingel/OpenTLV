# Benchmark baselines

This directory contains deliberately selected benchmark results that serve as
versioned reference data. Local and intermediate runs belong in
`benchmarks/results/` and are not committed.

For local comparisons, save `latest.json` as `baseline.json` using the
`Benchmark: Update baseline from last` VS Code task. Subsequent results can
be compared with the `Benchmark: Compare baseline with last` task.

The comparison task runs Google Benchmark's own `tools/compare.py` from the
dependency fetched by CMake. Its Python dependencies are installed into a
local virtual environment under `build-benchmarks/`.

Use a filename that identifies the measurement environment, for example:
`windows-msvc-x64-i7-12700h.json`.

Record the following information with every baseline:

- CPU and memory
- operating system
- compiler and version
- build configuration
- power plan and other relevant measurement conditions
- OpenTLV commit
