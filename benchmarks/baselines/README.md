# Benchmark baselines

This directory contains deliberately selected benchmark results that serve as
versioned reference data. Local and intermediate runs belong in
`benchmarks/results/` and are not committed.

The Windows VS Code tasks use `windows-msvc-x64.json` in this directory.
`Benchmark: Update baseline from last` replaces it with the local `latest.json`;
review and commit that change deliberately. `Benchmark: Compare baseline with last`
compares this versioned reference against the local latest run. Other platforms
continue to use the ignored `benchmarks/results/baseline.json`.

The initial Windows reference was copied from the existing local
baseline dated `2026-09-14T18:26:22+02:00`. Compare on the same hardware,
compiler, build configuration, and power settings; the filename alone does not
make results from different Windows machines comparable.

The comparison task runs Google Benchmark's own `tools/compare.py` from the
dependency fetched by CMake. Its Python dependencies are installed into a
local virtual environment under `build/benchmark-tools-venv/`.
See the [local benchmark workflow](../README.md) for output paths and certificate setup.

Use a filename that identifies the measurement environment, for example:
`windows-msvc-x64-i7-12700h.json`.

Record the following information with every baseline:

- CPU and memory
- operating system
- compiler and version
- build configuration
- power plan and other relevant measurement conditions
- OpenTLV commit

Baseline updates replace `context.host_name` with the baseline filename stem
(`windows-msvc-x64` for the Windows task). The local `latest.json` is unchanged.
Use `--host-label bench-pc-01` with the baseline command for a stable public
machine alias. This is a chosen label, not a hardware fingerprint; keep it
consistent for the same machine. Timing and hardware measurements are preserved.
