# Development workflow

OpenTLV uses a trunk-based workflow: `main` is the only long-lived branch.
Work happens on short-lived feature branches that are merged into `main`
through pull requests, and releases are cut by tagging `main`.

Continuous integration has three levels. Each level answers a different
question, so the expensive checks stay off the path of everyday development.

| Level | Trigger | Question it answers |
| --- | --- | --- |
| Pull request | Pull request to `main` | Is this change safe to merge? |
| Main | Push (merge) to `main` | Does `main` still work? |
| Release | Tag `X.Y.Z` or `X.Y.Z-rc.N` | Does everything work, on every platform? |

## Branches and pull requests

1. Create a branch from `main`, for example `feature/123-short-description`.
2. Open a pull request into `main`. There is no `develop` branch.
3. Wait for the pull request checks and merge when they pass.
4. Record user-facing changes in `CHANGELOG.md` under `## [Unreleased]`.

## What runs where

| Check | Pull request | Main | Release tag |
| --- | :---: | :---: | :---: |
| pre-commit (formatting, whitespace, Markdown lint) | always | yes | yes |
| Clang 18 Debug build with unit and integration tests | always | yes, with coverage and examples | yes, with coverage and examples |
| clang-tidy | if C/C++ sources or CMake changed | yes | yes |
| cppcheck | | yes | yes |
| C-only build | | Debug | Debug and Release |
| Clang 18 Release build with tests | | | yes |
| GCC and MSVC (x64, x86) builds with tests | | | yes |
| CodeQL (required by the repository rules) | always | yes | yes |
| C ABI compatibility (`abidiff`, see [ABI](abi-compatibility.md)) | if `tlv`, CMake or `scripts/abi/check.py` changed | yes | yes |
| Fuzzing | | yes | yes |
| [Valgrind Memcheck](valgrind.md#memcheck-ci-scope) (plain GCC Debug C/C++ tests) | shorter, optional selection for native/test/CMake/Memcheck changes; full with `memcheck-full` label | full weekly | full |
| [Callgrind and native comparison](valgrind.md#compare-instruction-counts-and-native-timings) (informational) | if native sources, benchmarks, CMake or Callgrind tooling changed | same | |
| Google Benchmark build and advisory Query timings | if benchmarks, `tlv` or CMake changed | same | yes |
| Rust bindings on Linux | if Rust, `tlv` or CMake changed | yes | yes |
| Rust bindings on Windows and macOS | | | yes |
| WebAssembly build and smoke test | if `tlv`, WebAssembly or CMake changed | yes | yes |
| WebAssembly reproducibility (two builds, identical hashes) | | | yes |
| Documentation validation | if documentation or public headers changed | yes | yes |
| Documentation publishing | | `latest` | `stable` (not for `-rc` tags) |

"If ... changed" rows use path filters, so a pull request that touches only
documentation does not build the C library and a pull request that touches only
the C library does not build the documentation. Pre-commit always runs.

CodeQL runs on every pull request because the repository rules require it, and
it runs in parallel with the Clang build. CodeQL and fuzzing also run weekly on
`main`.

A pull request that keeps a path-filtered check from running does not block
on it. If you make one of these checks a required status check in branch
protection, a pull request that skips it stays pending, so require only the
checks that always run (pre-commit and the Clang build).

Memcheck remains optional and non-blocking on PRs, including those requesting
the full suite with the `memcheck-full` label; do not add it to required branch
protection or repository ruleset checks. Every Memcheck run still reports a
failed job on memory errors. Its shorter PR selection keeps all C/C++ unit and
integration cases and omits the expensive Query conformance matrices. Full Memcheck runs weekly on
`main` (Sunday at 02:17 UTC), on release tags, or by manual dispatch. Memory
errors confined to the omitted matrices may therefore wait until the next full
run to be detected. Adding the label or dispatching a full run closes that gap
for a particular change.

The `benchmarks.yml` workflow builds the Google Benchmark suites and records
selected native Query phase, matcher, streaming and scaling measurements in a
Clang Release build. These shared-runner timings and Query budget checks are
advisory; run the full benchmark suite locally as needed. The separate Callgrind
workflow runs four fixed C workloads under Callgrind and in native Release
builds to compare the baseline and candidate revisions. Instruction and timing
thresholds are informational. Memcheck errors fail its independent job in every
scope; its PR check is not required for merging.

## Releasing

1. Update `CHANGELOG.md` and the version, and merge to `main`.
2. Tag a release candidate, for example `1.0.0-rc.1`, and push the tag. This
   runs the complete validation (the Release column above) but does not publish
   documentation.
3. Fix anything the release candidate finds on `main` and tag `1.0.0-rc.2`,
   and so on.
4. Tag the release, for example `1.0.0`. The same checks run again on the
   released commit and the versioned documentation is published.

Push release tags in ascending order, because the most recently published tag
becomes `stable` (see [Publishing](../../CONTRIBUTING.md#publishing)).

## Running the checks locally

The pull request checks are reproducible locally; see
[CONTRIBUTING.md](../../CONTRIBUTING.md) for `pre-commit`, `clang-tidy`,
`cppcheck` and the documentation build.
