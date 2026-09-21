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
| C ABI compatibility (`abidiff`, see [ABI](abi-compatibility.md)) | if `tlv`, CMake or `scripts/check_abi.py` changed | yes | yes |
| Fuzzing | | yes | yes |
| Benchmarks (build only) | if benchmarks or `tlv` changed | same | yes |
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

Benchmarks are never run in CI. They are only built, when they or the library
change, to confirm they still compile; run them locally.

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
